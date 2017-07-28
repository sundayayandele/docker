package registry

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/docker/docker/opts"
	flag "github.com/docker/docker/pkg/mflag"
	"github.com/docker/docker/reference"
	registrytypes "github.com/docker/engine-api/types/registry"
	"github.com/Sirupsen/logrus"
)

// Registry holds information for a registry and its mirrors.
type Registry struct {
	// Prefix is used for the lookup of endpoints, where the given registry
	// is selected when its Prefix is a prefix of the passed reference, for
	// instance, Prefix:"docker.io/opensuse" will match a `docker pull
	// opensuse:tumleweed`.
	Prefix string `json:"Prefix,omitempty"`
	// The mirrors will be selected prior to the registry during lookup of
	// endpoints.
	Mirrors []Mirror `json:"Mirrors,omitempty"`
	// Host is the host of the registry (e.g., "docker.io")
	Host string
	// This avoids to parse the URL of each new endpoint lookup.
	URL *url.URL
	// True if the host is "docker.io".
	Official bool
	// True if URL.Scheme == "https".
	Secure bool
}

// Mirror holds information for a given registry mirror.
type Mirror struct {
	// Host is the URL specified by the user.  At deamon start, the passed
	// URL will be loaded into Mirror.URL and corresponding host stored in
	// Mirror.Host.
	Host string `json:"URL"`
	// This avoids to parse the URL of each new endpoint lookup.
	URL *url.URL
}

// ServiceOptions holds the user-specified configuration options.
type ServiceOptions struct {
	Mirrors            []string `json:"registry-mirrors,omitempty"`
	InsecureRegistries []string `json:"insecure-registries,omitempty"`

	// V2Only controls access to legacy registries.  If it is set to true via the
	// command line flag the daemon will not attempt to contact v1 legacy registries
	V2Only bool `json:"disable-legacy-registry,omitempty"`

	// Registries holds information associated with the specified registries.
	Registries []Registry `json:"registries,omitempty"`
}

// serviceConfig holds daemon configuration for the registry service.
type serviceConfig struct {
	registrytypes.ServiceConfig
	V2Only bool

	// Registries holds information associated with the specified registries.
	Registries map[string]Registry
}

var (
	// DefaultNamespace is the default namespace
	DefaultNamespace = "docker.io"
	// DefaultRegistryVersionHeader is the name of the default HTTP header
	// that carries Registry version info
	DefaultRegistryVersionHeader = "Docker-Distribution-Api-Version"

	// IndexServer is the v1 registry server used for user auth + account creation
	IndexServer = DefaultV1Registry.String() + "/v1/"
	// IndexName is the name of the index
	IndexName = "docker.io"

	// NotaryServer is the endpoint serving the Notary trust server
	NotaryServer = "https://notary.docker.io"

	// DefaultV1Registry is the URI of the default v1 registry
	DefaultV1Registry = &url.URL{
		Scheme: "https",
		Host:   "index.docker.io",
	}

	// DefaultV2Registry is the URI of the default v2 registry
	DefaultV2Registry = &url.URL{
		Scheme: "https",
		Host:   "registry-1.docker.io",
	}
)

var (
	// ErrInvalidRepositoryName is an error returned if the repository name did
	// not have the correct form
	ErrInvalidRepositoryName = errors.New("Invalid repository name (ex: \"registry.domain.tld/myrepos\")")

	emptyServiceConfig = newServiceConfig(ServiceOptions{})
)

// for mocking in unit tests
var lookupIP = net.LookupIP

// InstallCliFlags adds command-line options to the top-level flag parser for
// the current process.
func (options *ServiceOptions) InstallCliFlags(cmd *flag.FlagSet, usageFn func(string) string) {
	mirrors := opts.NewNamedListOptsRef("registry-mirrors", &options.Mirrors, ValidateMirror)
	cmd.Var(mirrors, []string{"-registry-mirror"}, usageFn("Preferred Docker registry mirror"))

	insecureRegistries := opts.NewNamedListOptsRef("insecure-registries", &options.InsecureRegistries, ValidateIndexName)
	cmd.Var(insecureRegistries, []string{"-insecure-registry"}, usageFn("Enable insecure registry communication"))

	cmd.BoolVar(&options.V2Only, []string{"-disable-legacy-registry"}, false, usageFn("Disable contacting legacy registries"))
}

// newServiceConfig returns a new instance of ServiceConfig
func newServiceConfig(options ServiceOptions) *serviceConfig {
	// The deprecated insecure-regitry flag conflicts with the semantics of
	// the new Registries options, as they do NOT fallback to an insecure
	// connection.
	if len(options.InsecureRegistries) > 0 && len(options.Registries) > 0 {
		panic("error: usage of \"registries\" with deprecated option \"insecure-registries\" is not supported")
	}

	// Localhost is by default considered as an insecure registry
	// This is a stop-gap for people who are running a private registry on localhost (especially on Boot2docker).
	//
	// TODO: should we deprecate this once it is easier for people to set up a TLS registry or change
	// daemon flags on boot2docker?
	options.InsecureRegistries = append(options.InsecureRegistries, "127.0.0.0/8")

	config := &serviceConfig{
		ServiceConfig: registrytypes.ServiceConfig{
			InsecureRegistryCIDRs: make([]*registrytypes.NetIPNet, 0),
			IndexConfigs:          make(map[string]*registrytypes.IndexInfo, 0),
			// Hack: Bypass setting the mirrors to IndexConfigs since they are going away
			// and Mirrors are only for the official registry anyways.
			Mirrors: options.Mirrors,
		},
		V2Only: options.V2Only,
	}
	// Split --insecure-registry into CIDR and registry-specific settings.
	for _, r := range options.InsecureRegistries {
		// Check if CIDR was passed to --insecure-registry
		_, ipnet, err := net.ParseCIDR(r)
		if err == nil {
			// Valid CIDR.
			config.InsecureRegistryCIDRs = append(config.InsecureRegistryCIDRs, (*registrytypes.NetIPNet)(ipnet))
		} else {
			// Assume `host:port` if not CIDR.
			config.IndexConfigs[r] = &registrytypes.IndexInfo{
				Name:     r,
				Mirrors:  make([]string, 0),
				Secure:   false,
				Official: false,
			}
		}
	}

	// Configure public registry.
	config.IndexConfigs[IndexName] = &registrytypes.IndexInfo{
		Name:     IndexName,
		Mirrors:  config.Mirrors,
		Secure:   true,
		Official: true,
	}

	if err := config.LoadRegistries(options.Registries); err != nil {
		panic(fmt.Sprintf("[proxy path] Error loading registries: %s\n", err))
	}

	// Only print if registries are specified.  This avoids some annoying
	// logs from the client, which still shares code in this version of
	// Docker.
	if len(options.Registries) > 0 {
		logrus.Infof("[proxy patch] loaded registries: %v", config.Registries)
	}

	return config
}

// checkRegistries makes sure that no mirror serves more than one registry and
// that no host is used as a registry and as a mirror simultaneously.  Notice
// that different registry prefixes can share a mirror as long as they point to
// the same registry.  It also warns if the URI schemes of a given registry and
// one of its mirrors differ.
func (config *serviceConfig) checkRegistries() error {
	inUse := make(map[string]string) // key: host, value: user

	// make sure that each mirror serves only one registry
	for _, reg := range config.Registries {
		for _, mirror := range reg.Mirrors {
			if used, conflict := inUse[mirror.Host]; conflict {
				if used != reg.URL.Host {
					return fmt.Errorf("mirror '%s' can only serve one registry", mirror.Host)
				}
			}
			inUse[mirror.Host] = reg.Host
			// also warnf if seucurity levels differ
			if reg.URL.Scheme != mirror.URL.Scheme {
				logrus.Warnf("registry '%s' and mirror '%s' have different security levels", reg.URL, mirror.URL)
			}
		}
		if reg.Secure && len(reg.Mirrors) == 0 {
			logrus.Warnf("specifying secure registry '%s' without mirrors has no effect", reg.Prefix)
		}
	}

	// make sure that no registry host is used as a mirror
	for _, reg := range config.Registries {
		if _, conflict := inUse[reg.Host]; conflict {
			return fmt.Errorf("registry '%s' cannot simultaneously serve as a mirror for '%s'", reg.URL.Host, inUse[reg.Host])
		}
	}
	return nil
}

// FindRegistry returns a registry based on the passed reference.  If more than
// one index-prefix match the reference, the longest index is returned.  In
// case of no match, regFound is false.
func (config *serviceConfig) FindRegistry(reference string) (reg Registry, regFound bool) {
	prefixStr := ""
	prefixLen := 0
	for _, reg := range config.Registries {
		if strings.HasPrefix(reference, reg.Prefix) {
			length := len(reg.Prefix)
			if length > prefixLen {
				prefixStr = reg.Prefix
				prefixLen = length
			}
		}
	}
	if prefixLen > 0 {
		logrus.Debugf("[findRegistry] found registry %v for '%s'", config.Registries[prefixStr], reference)
		return config.Registries[prefixStr], true
	}
	logrus.Debugf("[findRegistry] couldn't find registry for '%s'", reference)
	return Registry{}, false
}

// prepareMirror sets the corresponding data in mirror based on its host.
func prepareMirror(mirror *Mirror) error {
	var err error

	if !strings.HasPrefix(mirror.Host, "http://") && !strings.HasPrefix(mirror.Host, "https://") {
		mirror.Host = "https://" + mirror.Host
	}

	mirror.Host, err = ValidateMirror(mirror.Host)
	if err != nil {
		return fmt.Errorf("invalid mirror: %s", err)
	}

	mirror.URL, _ = url.Parse(mirror.Host)
	mirror.Host = mirror.URL.Host // host:port
	return nil
}

// loadRegistry loads the specified registry into config.Registries, which is
// used for endpoint lookups.  Notice that all sanity and consistency checks
// are deferred to config.checkRegistries().
func (config *serviceConfig) loadRegistry(reg Registry) error {
	if reg.Prefix == "" {
		reg.Prefix = IndexName
	}
	reg.Prefix = strings.ToLower(reg.Prefix)

	// parse and set the URL of the registry
	prefURL := reg.Prefix
	if !strings.HasPrefix(reg.Prefix, "http://") && !strings.HasPrefix(reg.Prefix, "https://") {
		prefURL = "https://" + prefURL
	}
	u, err := url.Parse(prefURL)
	if err != nil {
		return fmt.Errorf("cannot parse prefix '%s'", reg.Prefix)
	}
	// XXX: the host is used as the prefix
	reg.Prefix = u.Host // host:port
	reg.Host = u.Host   // host:port
	reg.URL = u

	if _, exists := config.Registries[reg.Prefix]; exists {
		return fmt.Errorf("multiple prefixes pointing to host '%s': unsupported for this version of Docker", reg.Host)
	}

	if reg.URL.Scheme == "https" {
		reg.Secure = true
	}

	if reg.URL.Host == IndexName || reg.URL.Host == DefaultNamespace {
		reg.Official = true
	}

	// validate and set mirrors
	for i := range reg.Mirrors {
		if err := prepareMirror(&reg.Mirrors[i]); err != nil {
			return err
		}
	}

	config.Registries[reg.Prefix] = reg

	return nil
}

// LoadRegistries loads the user-specified configuration options for registries.
func (config *serviceConfig) LoadRegistries(registries []Registry) error {
	config.Registries = make(map[string]Registry)

	for _, reg := range registries {
		if err := config.loadRegistry(reg); err != nil {
			return err
		}
	}

	if len(config.Mirrors) > 0 {
		mirrors := []Mirror{}
		for _, host := range config.Mirrors {
			mirror := Mirror{Host: host}
			if err := prepareMirror(&mirror); err != nil {
				return err
			}
			mirrors = append(mirrors, mirror)
		}
		if _, exists := config.Registries[IndexName]; !exists {
			if err := config.loadRegistry(Registry{Prefix: IndexName}); err != nil {
				return err
			}
		}
		reg := config.Registries[IndexName]
		reg.Mirrors = append(reg.Mirrors, mirrors...)
		config.Registries[IndexName] = reg
	}
	return config.checkRegistries()
}

// isSecureIndex returns false if the provided indexName is part of the list of insecure registries
// Insecure registries accept HTTP and/or accept HTTPS with certificates from unknown CAs.
//
// The list of insecure registries can contain an element with CIDR notation to specify a whole subnet.
// If the subnet contains one of the IPs of the registry specified by indexName, the latter is considered
// insecure.
//
// indexName should be a URL.Host (`host:port` or `host`) where the `host` part can be either a domain name
// or an IP address. If it is a domain name, then it will be resolved in order to check if the IP is contained
// in a subnet. If the resolving is not successful, isSecureIndex will only try to match hostname to any element
// of insecureRegistries.
func isSecureIndex(config *serviceConfig, indexName string) bool {
	// Check for configured index, first.  This is needed in case isSecureIndex
	// is called from anything besides newIndexInfo, in order to honor per-index configurations.
	if index, ok := config.IndexConfigs[indexName]; ok {
		return index.Secure
	}

	host, _, err := net.SplitHostPort(indexName)
	if err != nil {
		// assume indexName is of the form `host` without the port and go on.
		host = indexName
	}

	addrs, err := lookupIP(host)
	if err != nil {
		ip := net.ParseIP(host)
		if ip != nil {
			addrs = []net.IP{ip}
		}

		// if ip == nil, then `host` is neither an IP nor it could be looked up,
		// either because the index is unreachable, or because the index is behind an HTTP proxy.
		// So, len(addrs) == 0 and we're not aborting.
	}

	// Try CIDR notation only if addrs has any elements, i.e. if `host`'s IP could be determined.
	for _, addr := range addrs {
		for _, ipnet := range config.InsecureRegistryCIDRs {
			// check if the addr falls in the subnet
			if (*net.IPNet)(ipnet).Contains(addr) {
				return false
			}
		}
	}

	return true
}

// ValidateMirror validates an HTTP(S) registry mirror
func ValidateMirror(val string) (string, error) {
	uri, err := url.Parse(val)
	if err != nil {
		return "", fmt.Errorf("%s is not a valid URI", val)
	}

	if uri.Scheme != "http" && uri.Scheme != "https" {
		return "", fmt.Errorf("Unsupported scheme %s", uri.Scheme)
	}

	if uri.Path != "" || uri.RawQuery != "" || uri.Fragment != "" {
		return "", fmt.Errorf("Unsupported path/query/fragment at end of the URI")
	}

	return fmt.Sprintf("%s://%s/", uri.Scheme, uri.Host), nil
}

// ValidateIndexName validates an index name.
func ValidateIndexName(val string) (string, error) {
	if val == reference.LegacyDefaultHostname {
		val = reference.DefaultHostname
	}
	if strings.HasPrefix(val, "-") || strings.HasSuffix(val, "-") {
		return "", fmt.Errorf("Invalid index name (%s). Cannot begin or end with a hyphen.", val)
	}
	return val, nil
}

func validateNoScheme(reposName string) error {
	if strings.Contains(reposName, "://") {
		// It cannot contain a scheme!
		return ErrInvalidRepositoryName
	}
	return nil
}

// newIndexInfo returns IndexInfo configuration from indexName
func newIndexInfo(config *serviceConfig, indexName string) (*registrytypes.IndexInfo, error) {
	var err error
	indexName, err = ValidateIndexName(indexName)
	if err != nil {
		return nil, err
	}

	// Return any configured index info, first.
	if index, ok := config.IndexConfigs[indexName]; ok {
		return index, nil
	}

	// Construct a non-configured index info.
	index := &registrytypes.IndexInfo{
		Name:     indexName,
		Mirrors:  make([]string, 0),
		Official: false,
	}
	index.Secure = isSecureIndex(config, indexName)
	return index, nil
}

// GetAuthConfigKey special-cases using the full index address of the official
// index as the AuthConfig key, and uses the (host)name[:port] for private indexes.
func GetAuthConfigKey(index *registrytypes.IndexInfo) string {
	if index.Official {
		return IndexServer
	}
	return index.Name
}

// newRepositoryInfo validates and breaks down a repository name into a RepositoryInfo
func newRepositoryInfo(config *serviceConfig, name reference.Named) (*RepositoryInfo, error) {
	index, err := newIndexInfo(config, name.Hostname())
	if err != nil {
		return nil, err
	}
	official := !strings.ContainsRune(name.Name(), '/')
	return &RepositoryInfo{name, index, official}, nil
}

// ParseRepositoryInfo performs the breakdown of a repository name into a RepositoryInfo, but
// lacks registry configuration.
func ParseRepositoryInfo(reposName reference.Named) (*RepositoryInfo, error) {
	return newRepositoryInfo(emptyServiceConfig, reposName)
}

// ParseSearchIndexInfo will use repository name to get back an indexInfo.
func ParseSearchIndexInfo(reposName string) (*registrytypes.IndexInfo, error) {
	indexName, _ := splitReposSearchTerm(reposName)

	indexInfo, err := newIndexInfo(emptyServiceConfig, indexName)
	if err != nil {
		return nil, err
	}
	return indexInfo, nil
}
