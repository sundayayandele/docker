package registry

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/docker/go-connections/tlsconfig"
	"github.com/Sirupsen/logrus"
)

func (s *DefaultService) lookupV2Endpoints(reference string) (endpoints []APIEndpoint, err error) {
	var cfg = tlsconfig.ServerDefault
	tlsConfig := &cfg

	logrus.Debugf("[lookupV2Endpoints] reference: %s", reference)

	// as the reference can be a prefix, extract the hostname with URL.Parse()
	refURL := reference
	if !strings.HasPrefix(refURL, "http://") && !strings.HasPrefix(refURL, "https://") {
		refURL = "https://" + refURL
	}
	u, err := url.Parse(refURL)
	if err != nil {
		return nil, fmt.Errorf("[lookupV2Endpoints] error parsing reference %s: %s", reference, err)
	}

	hostname := u.Host // hostname + port (if present)
	if hostname == "" {
		return nil, fmt.Errorf("[lookupV2Endpoints] cannot determine hostname of reference %s", reference)
	}

	// create endpoints for official and configured registries
	reg, foundReg := s.config.FindRegistry(reference)
	official := false
	if hostname == DefaultNamespace || hostname == IndexName || reg.Official {
		official = true
	}
	if foundReg || official {
		// set the URL of the registry
		var endpointURL *url.URL
		if official {
			endpointURL = DefaultV2Registry
		} else {
			endpointURL = &url.URL{
				Scheme: reg.URL.Scheme,
				Host:   reg.URL.Host,
			}
		}

		// if present, add mirrors before the registry
		for _, mirror := range reg.Mirrors {
			mirrorTLSConfig, err := s.tlsConfigForMirror(mirror.URL)
			if err != nil {
				return nil, fmt.Errorf("[lookupV2Endpoints] %s", err)
			}
			endpoints = append(endpoints, APIEndpoint{
				URL:          mirror.URL,
				Version:      APIVersion2,
				Mirror:       true,
				TrimHostname: true,
				TLSConfig:    mirrorTLSConfig,
			})
		}

		// add the registry
		endpoints = append(endpoints, APIEndpoint{
			URL:          endpointURL,
			Version:      APIVersion2,
			Official:     official,
			TrimHostname: true,
			TLSConfig:    tlsConfig,
		})

		return endpoints, nil
	}

	tlsConfig, err = s.TLSConfig(hostname)
	if err != nil {
		return nil, err
	}

	endpoints = []APIEndpoint{
		{
			URL: &url.URL{
				Scheme: "https",
				Host:   hostname,
			},
			Version:      APIVersion2,
			TrimHostname: true,
			TLSConfig:    tlsConfig,
		},
	}

	if tlsConfig.InsecureSkipVerify {
		endpoints = append(endpoints, APIEndpoint{
			URL: &url.URL{
				Scheme: "http",
				Host:   hostname,
			},
			Version:      APIVersion2,
			TrimHostname: true,
			// used to check if supposed to be secure via InsecureSkipVerify
			TLSConfig: tlsConfig,
		})
	}

	return endpoints, nil
}
