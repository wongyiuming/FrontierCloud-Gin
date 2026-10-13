package operator

import (
	"errors"
	"strings"
)

// These errors contain only operator-authored text. Never wrap Docker stderr:
// registry failures may contain credentials or complete signed URLs.
var (
	ErrDockerPermission   = errors.New("Docker access denied; check daemon permissions and public package access")
	ErrDockerImageMissing = errors.New("requested image is absent; select a complete published release")
	ErrDockerPlatform     = errors.New("published image does not support this architecture")
	ErrDockerIntegrity    = errors.New("image content integrity check failed; do not deploy")
	ErrDockerNetwork      = errors.New("Docker network or TLS connection failed; check DNS, registry and certificate trust")
	ErrDockerCommand      = errors.New("Docker command failed; check daemon permissions, network and selected project")
)

func ClassifyDockerFailure(diagnostic string) error {
	message := strings.ToLower(diagnostic)
	for _, category := range []struct {
		words []string
		err   error
	}{
		{[]string{"permission denied", "unauthorized", "access denied", "denied:"}, ErrDockerPermission},
		{[]string{"manifest unknown", "no such image"}, ErrDockerImageMissing},
		{[]string{"no matching manifest", "unsupported platform"}, ErrDockerPlatform},
		{[]string{"digest", "checksum"}, ErrDockerIntegrity},
		{[]string{"timeout", "connection refused", "network", "tls handshake", "x509:", "no such host"}, ErrDockerNetwork},
	} {
		for _, word := range category.words {
			if strings.Contains(message, word) {
				return category.err
			}
		}
	}
	return ErrDockerCommand
}

func safeDockerFailure(err error) error {
	for _, category := range []error{ErrDockerPermission, ErrDockerImageMissing, ErrDockerPlatform, ErrDockerIntegrity, ErrDockerNetwork, ErrDockerCommand} {
		if errors.Is(err, category) {
			return category
		}
	}
	return ErrDockerCommand
}
