/*
 * suse-secrets: patch for Docker to implement SUSE secrets
 * Copyright (C) 2017 SUSE LLC.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package daemon

import (
	"archive/tar"
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/docker/docker/container"
	"github.com/docker/docker/pkg/archive"
	"github.com/docker/docker/pkg/idtools"
	"github.com/opencontainers/go-digest"
	"github.com/sirupsen/logrus"

	swarmtypes "github.com/docker/docker/api/types/swarm"
	swarmexec "github.com/docker/swarmkit/agent/exec"
	swarmapi "github.com/docker/swarmkit/api"
)

func init() {
	// Output to tell us in logs that SUSE:secrets is enabled.
	logrus.Infof("SUSE:secrets :: enabled")
}

// Creating a fake file.
type SuseFakeFile struct {
	Path string
	Uid  int
	Gid  int
	Mode os.FileMode
	Data []byte
}

func (s SuseFakeFile) id() string {
	// NOTE: It is _very_ important that this string always has a prefix of
	//       "suse". This is how we can ensure that we can operate on
	//       SecretReferences with a confidence that it was made by us.
	return fmt.Sprintf("suse_%s_%s", digest.FromBytes(s.Data).Hex(), s.Path)
}

func (s SuseFakeFile) toSecret() *swarmapi.Secret {
	return &swarmapi.Secret{
		ID:       s.id(),
		Internal: true,
		Spec: swarmapi.SecretSpec{
			Data: s.Data,
		},
	}
}

func (s SuseFakeFile) toSecretReference(idMaps *idtools.IDMappings) *swarmtypes.SecretReference {
	// Figure out the host-facing {uid,gid} based on the provided maps. Fall
	// back to root if the UID/GID don't match (we are guaranteed that root is
	// mapped).
	ctrUser := idtools.IDPair{UID: s.Uid, GID: s.Gid}
	hostUser := idMaps.RootPair()
	if user, err := idMaps.ToHost(ctrUser); err == nil {
		hostUser = user
	}

	// Return the secret reference as a file target.
	return &swarmtypes.SecretReference{
		SecretID:   s.id(),
		SecretName: s.id(),
		File: &swarmtypes.SecretReferenceFileTarget{
			Name: s.Path,
			UID:  fmt.Sprintf("%d", hostUser.UID),
			GID:  fmt.Sprintf("%d", hostUser.GID),
			Mode: s.Mode,
		},
	}
}

// readDir will recurse into a directory prefix/dir, and return the set of
// secrets in that directory (as a tar archive that is packed inside the "data"
// field). The Path attribute of each has the prefix stripped. Symlinks are
// dereferenced.
func readDir(prefix, dir string) ([]*SuseFakeFile, error) {
	var suseFiles []*SuseFakeFile

	path := filepath.Join(prefix, dir)
	fi, err := os.Stat(path)
	if err != nil {
		// Ignore dangling symlinks.
		if os.IsNotExist(err) {
			logrus.Warnf("SUSE:secrets :: dangling symlink: %s", path)
			return nil, nil
		}
		return nil, err
	} else if !fi.IsDir() {
		// Just to be safe.
		logrus.Warnf("SUSE:secrets :: expected %q to be a directory, but was a file", path)
		return readFile(prefix, dir)
	}
	path, err = filepath.EvalSymlinks(path)
	if err != nil {
		return nil, err
	}

	// Construct a tar archive of the source directory. We tar up the prefix
	// directory and add dir as an IncludeFiles specifically so that we
	// preserve the name of the directory itself.
	tarStream, err := archive.TarWithOptions(path, &archive.TarOptions{
		Compression:      archive.Uncompressed,
		IncludeSourceDir: true,
	})
	if err != nil {
		return nil, fmt.Errorf("SUSE:secrets :: failed to tar source directory %q: %v", path, err)
	}
	tarStreamBytes, err := ioutil.ReadAll(tarStream)
	if err != nil {
		return nil, fmt.Errorf("SUSE:secrets :: failed to read full tar archive: %v", err)
	}

	// Get a list of the symlinks in the tar archive.
	var symlinks []string
	tmpTr := tar.NewReader(bytes.NewBuffer(tarStreamBytes))
	for {
		hdr, err := tmpTr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("SUSE:secrets :: failed to read through tar reader: %v", err)
		}
		if hdr.Typeflag == tar.TypeSymlink {
			symlinks = append(symlinks, hdr.Name)
		}
	}

	// Symlinks aren't dereferenced in the above archive, so we explicitly do a
	// rewrite of the tar archive to include all symlinks to files. We cannot
	// do directories here, but lower-level directory symlinks aren't supported
	// by zypper so this isn't an issue.
	symlinkModifyMap := map[string]archive.TarModifierFunc{}
	for _, sym := range symlinks {
		logrus.Debugf("SUSE:secrets: archive(%q) %q is a need-to-rewrite symlink", path, sym)
		symlinkModifyMap[sym] = func(tarPath string, hdr *tar.Header, r io.Reader) (*tar.Header, []byte, error) {
			logrus.Debugf("SUSE:secrets: archive(%q) mapping for symlink %q", path, tarPath)
			tarFullPath := filepath.Join(path, tarPath)

			// Get a copy of the original byte stream.
			oldContent, err := ioutil.ReadAll(r)
			if err != nil {
				return nil, nil, fmt.Errorf("suse_rewrite: failed to read archive entry %q: %v", tarPath, err)
			}

			// Check that the file actually exists.
			fi, err := os.Stat(tarFullPath)
			if err != nil {
				logrus.Warnf("suse_rewrite: failed to stat archive entry %q: %v", tarFullPath, err)
				return hdr, oldContent, nil
			}

			// Read the actual contents.
			content, err := ioutil.ReadFile(tarFullPath)
			if err != nil {
				logrus.Warnf("suse_rewrite: failed to read %q: %v", tarFullPath, err)
				return hdr, oldContent, nil
			}

			newHdr, err := tar.FileInfoHeader(fi, "")
			if err != nil {
				// Fake the header.
				newHdr = &tar.Header{
					Typeflag: tar.TypeReg,
					Mode:     0644,
				}
			}

			// Update the key fields.
			hdr.Typeflag = newHdr.Typeflag
			hdr.Mode = newHdr.Mode
			hdr.Linkname = ""
			return hdr, content, nil
		}
	}

	// Create the rewritten tar stream.
	tarStream = archive.ReplaceFileTarWrapper(ioutil.NopCloser(bytes.NewBuffer(tarStreamBytes)), symlinkModifyMap)
	tarStreamBytes, err = ioutil.ReadAll(tarStream)
	if err != nil {
		return nil, fmt.Errorf("SUSE:secrets :: failed to read rewritten archive: %v", err)
	}

	// Add the tar stream as a "file".
	suseFiles = append(suseFiles, &SuseFakeFile{
		Path: dir,
		Mode: fi.Mode(),
		Data: tarStreamBytes,
	})
	return suseFiles, nil
}

// readFile returns a secret given a file under a given prefix.
func readFile(prefix, file string) ([]*SuseFakeFile, error) {
	path := filepath.Join(prefix, file)
	fi, err := os.Stat(path)
	if err != nil {
		// Ignore dangling symlinks.
		if os.IsNotExist(err) {
			logrus.Warnf("SUSE:secrets :: dangling symlink: %s", path)
			return nil, nil
		}
		return nil, err
	} else if fi.IsDir() {
		// Just to be safe.
		logrus.Warnf("SUSE:secrets :: expected %q to be a file, but was a directory", path)
		return readDir(prefix, file)
	}

	stat, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		logrus.Warnf("SUSE:secrets :: failed to cast file stat_t: defaulting to owned by root:root: %s", path)
	}

	bytes, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var suseFiles []*SuseFakeFile
	suseFiles = append(suseFiles, &SuseFakeFile{
		Path: file,
		Uid:  int(stat.Uid),
		Gid:  int(stat.Gid),
		Mode: fi.Mode(),
		Data: bytes,
	})
	return suseFiles, nil
}

// getHostSuseSecretData returns the list of SuseFakeFiles the need to be added
// as SUSE secrets.
func getHostSuseSecretData() ([]*SuseFakeFile, error) {
	secrets := []*SuseFakeFile{}

	credentials, err := readDir("/etc/zypp", "credentials.d")
	if err != nil {
		if os.IsNotExist(err) {
			credentials = []*SuseFakeFile{}
		} else {
			logrus.Errorf("SUSE:secrets :: error while reading zypp credentials: %s", err)
			return nil, err
		}
	}
	secrets = append(secrets, credentials...)

	suseConnect, err := readFile("/etc", "SUSEConnect")
	if err != nil {
		if os.IsNotExist(err) {
			suseConnect = []*SuseFakeFile{}
		} else {
			logrus.Errorf("SUSE:secrets :: error while reading /etc/SUSEConnect: %s", err)
			return nil, err
		}
	}
	secrets = append(secrets, suseConnect...)

	return secrets, nil
}

// To fake an empty store, in the case where we are operating on a container
// that was created pre-swarmkit. Otherwise segfaults and other fun things
// happen. See bsc#1057743.
type (
	suseEmptyStore  struct{}
	suseEmptySecret struct{}
	suseEmptyConfig struct{}
)

// In order to reduce the amount of code touched outside of this file, we
// implement the swarm API for DependencyGetter. This asserts that this
// requirement will always be matched. In addition, for the case of the *empty*
// getters this reduces memory usage by having a global instance.
var (
	_           swarmexec.DependencyGetter = &suseDependencyStore{}
	emptyStore  swarmexec.DependencyGetter = suseEmptyStore{}
	emptySecret swarmexec.SecretGetter     = suseEmptySecret{}
	emptyConfig swarmexec.ConfigGetter     = suseEmptyConfig{}
)

var errSuseEmptyStore = fmt.Errorf("SUSE:secrets :: tried to get a resource from empty store [this is a bug]")

func (_ suseEmptyConfig) Get(_ string) (*swarmapi.Config, error) { return nil, errSuseEmptyStore }
func (_ suseEmptySecret) Get(_ string) (*swarmapi.Secret, error) { return nil, errSuseEmptyStore }
func (_ suseEmptyStore) Secrets() swarmexec.SecretGetter         { return emptySecret }
func (_ suseEmptyStore) Configs() swarmexec.ConfigGetter         { return emptyConfig }

type suseDependencyStore struct {
	dfl     swarmexec.DependencyGetter
	secrets map[string]*swarmapi.Secret
}

// The following are effectively dumb wrappers that return ourselves, or the
// default.
func (s *suseDependencyStore) Secrets() swarmexec.SecretGetter { return s }
func (s *suseDependencyStore) Configs() swarmexec.ConfigGetter { return s.dfl.Configs() }

// Get overrides the underlying DependencyGetter with our own secrets (falling
// through to the underlying DependencyGetter if the secret isn't present).
func (s *suseDependencyStore) Get(id string) (*swarmapi.Secret, error) {
	logrus.Debugf("SUSE:secrets :: id=%s requested from suseDependencyGetter", id)

	secret, ok := s.secrets[id]
	if !ok {
		// fallthrough
		return s.dfl.Secrets().Get(id)
	}
	return secret, nil
}

// removeSuseSecrets removes any SecretReferences which were added by us
// explicitly (this is detected by checking that the prefix has a 'suse'
// prefix). See bsc#1057743.
func removeSuseSecrets(c *container.Container) {
	var without []*swarmtypes.SecretReference
	for _, secret := range c.SecretReferences {
		if strings.HasPrefix(secret.SecretID, "suse") {
			logrus.Warnf("SUSE:secrets :: removing 'old' suse secret %q from container %q", secret.SecretID, c.ID)
			continue
		}
		without = append(without, secret)
	}
	c.SecretReferences = without
}

func (daemon *Daemon) injectSuseSecretStore(c *container.Container) error {
	newDependencyStore := &suseDependencyStore{
		dfl:     c.DependencyStore,
		secrets: make(map[string]*swarmapi.Secret),
	}
	// Handle old containers. See bsc#1057743.
	if newDependencyStore.dfl == nil {
		newDependencyStore.dfl = emptyStore
	}

	// We drop any "old" SUSE secrets, as it appears that old containers (when
	// restarted) could still have references to old secrets. The .id() of all
	// secrets have a prefix of "suse" so this is much easier. See bsc#1057743
	// for details on why this could cause issues.
	removeSuseSecrets(c)

	secrets, err := getHostSuseSecretData()
	if err != nil {
		return err
	}

	idMaps := daemon.IDMappings()
	for _, secret := range secrets {
		newDependencyStore.secrets[secret.id()] = secret.toSecret()
		c.SecretReferences = append(c.SecretReferences, secret.toSecretReference(idMaps))
	}

	c.DependencyStore = newDependencyStore

	// bsc#1057743 -- In older versions of Docker we added volumes explicitly
	// to the mount list. This causes clashes because of duplicate namespaces.
	// If we see an existing mount that will clash with the in-built secrets
	// mount we assume it's our fault.
	for _, intendedMount := range c.SecretMounts() {
		mountPath := intendedMount.Destination
		if volume, ok := c.MountPoints[mountPath]; ok {
			logrus.Debugf("SUSE:secrets :: removing pre-existing %q mount: %#v", mountPath, volume)
			delete(c.MountPoints, mountPath)
		}
	}
	return nil
}
