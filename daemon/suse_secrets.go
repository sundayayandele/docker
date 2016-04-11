package daemon

// SUSE:secrets :: This is a set of functions to copy host credentials into a
// container's /run/secrets.

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"syscall"

	"github.com/Sirupsen/logrus"
	"github.com/docker/docker/pkg/idtools"
)

// TODO(SUSE): We need to reimplement this to use tar. Immediately.

// Creating a fake file.
type SuseFakeFile struct {
	Path string
	Uid  int
	Gid  int
	Mode os.FileMode
	Data []byte
}

func (s *SuseFakeFile) SaveTo(dir string, uidMap, gidMap []idtools.IDMap) error {
	// Create non-existant path components with an owner of root (other FakeFiles
	// will clean this up if the owner is critical).
	rootUid, rootGid, err := idtools.GetRootUIDGID(uidMap, gidMap)

	path := filepath.Join(dir, s.Path)
	if err := idtools.MkdirAllNewAs(filepath.Dir(path), 0755, rootUid, rootGid); err != nil && !os.IsExist(err) {
		return err
	}

	uid, err := idtools.ToHost(s.Uid, uidMap)
	if err != nil {
		return err
	}

	gid, err := idtools.ToHost(s.Gid, gidMap)
	if err != nil {
		return err
	}

	if s.Mode.IsDir() {
		if err := idtools.MkdirAs(path, s.Mode, uid, gid); err != nil {
			return err
		}
	} else {
		if err := ioutil.WriteFile(path, s.Data, s.Mode); err != nil {
			return err
		}
	}

	return os.Chown(path, uid, gid)
}

// readDir will recurse into a directory prefix/dir, and return the set of secrets
// in that directory. The Path attribute of each has the prefix stripped. Symlinks
// are evaluated.
func readDir(prefix, dir string) ([]*SuseFakeFile, error) {
	var suseFiles []*SuseFakeFile

	path := filepath.Join(prefix, dir)

	fi, err := os.Stat(path)
	if err != nil {
		// Ignore dangling symlinks.
		if os.IsNotExist(err) {
			logrus.Warnf("SUSE:secrets :: dangling symlink: %s", path)
			return suseFiles, nil
		}
		return nil, err
	}

	stat, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		logrus.Warnf("SUSE:secrets :: failed to cast directory stat_t: defaulting to owned by root:root: %s", path)
	}

	suseFiles = append(suseFiles, &SuseFakeFile{
		Path: dir,
		Uid:  int(stat.Uid),
		Gid:  int(stat.Gid),
		Mode: fi.Mode(),
	})

	files, err := ioutil.ReadDir(path)
	if err != nil {
		return nil, err
	}

	for _, f := range files {
		subpath := filepath.Join(dir, f.Name())

		if f.IsDir() {
			secrets, err := readDir(prefix, subpath)
			if err != nil {
				return nil, err
			}
			suseFiles = append(suseFiles, secrets...)
		} else {
			secrets, err := readFile(prefix, subpath)
			if err != nil {
				return nil, err
			}
			suseFiles = append(suseFiles, secrets...)
		}
	}

	return suseFiles, nil
}

func readFile(prefix, file string) ([]*SuseFakeFile, error) {
	var suseFiles []*SuseFakeFile

	path := filepath.Join(prefix, file)
	fi, err := os.Stat(path)
	if err != nil {
		// Ignore dangling symlinks.
		if os.IsNotExist(err) {
			logrus.Warnf("SUSE:secrets :: dangling symlink: %s", path)
			return suseFiles, nil
		}
		return nil, err
	}

	stat, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		logrus.Warnf("SUSE:secrets :: failed to cast file stat_t: defaulting to owned by root:root: %s", path)
	}

	if fi.IsDir() {
		secrets, err := readDir(prefix, file)
		if err != nil {
			return nil, err
		}
		suseFiles = append(suseFiles, secrets...)
	} else {
		bytes, err := ioutil.ReadFile(path)
		if err != nil {
			return nil, err
		}
		suseFiles = append(suseFiles, &SuseFakeFile{
			Path: file,
			Uid:  int(stat.Uid),
			Gid:  int(stat.Gid),
			Mode: fi.Mode(),
			Data: bytes,
		})
	}

	return suseFiles, nil
}

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
