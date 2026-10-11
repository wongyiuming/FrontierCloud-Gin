package node

import (
	"errors"
	"net/url"
	"strconv"
)

func MasterEndpoint(value string) (string, error) {
	origin, err := Endpoint(value)
	if err != nil {
		return "", err
	}
	u, err := url.Parse(origin)
	if err != nil {
		return "", err
	}
	if u.Port() != "" && u.Port() != "443" {
		return "", errors.New("Master HTTPS endpoint must use public port 443")
	}
	return origin, nil
}

func validateStorageTransport(profile, endpoint string) error {
	if profile == "" {
		return nil
	} // Historical peers are validated by their existing identity contract.
	u, e := url.Parse(endpoint)
	if e != nil {
		return e
	}
	port := 443
	if u.Port() != "" {
		port, e = strconv.Atoi(u.Port())
	}
	if e != nil || profile == "direct" && port != 443 || profile == "relay" && (port < 1024 || port > 65535) || profile != "direct" && profile != "relay" {
		return errors.New("storage endpoint does not match its signed network profile")
	}
	return nil
}

// Called once before runtime goroutines; transport never follows pairing state.
func (s *Service) ConfigureStorageTransport(profile string) error {
	if profile != "direct" && profile != "relay" {
		return errors.New("invalid storage transport profile")
	}
	if e := validateStorageTransport(profile, s.identity.Endpoint); s.identity.Role == "Follower" && e != nil {
		return e
	}
	s.storageTransport = profile
	return nil
}
