package operator

import (
	"errors"
	"fmt"
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
	ErrDockerStorage      = errors.New("Docker image storage or unpack failed; inspect free space and daemon storage without deleting business data")
	ErrDockerCanceled     = errors.New("Docker command canceled")
	ErrDockerTimeout      = errors.New("Docker command deadline exceeded")
	ErrDockerOutputLimit  = errors.New("Docker command output exceeded the diagnostic limit")
	ErrInstallerOwnership = errors.New("foc installer refused an unmanaged or modified host command")
	ErrInstallerLock      = errors.New("foc installer found an active or interrupted installation lock")
	ErrInstallerPath      = errors.New("foc installer refused an unsafe host path or missing deployment receipt")
	ErrInstallerRevision  = errors.New("foc installer bundle revision does not match the selected release")
)

// CommandFailure retains execution facts without retaining secret-bearing text.
type CommandFailure struct {
	Category error
	ExitCode int
}

func (e *CommandFailure) Error() string {
	return fmt.Sprintf("%s (exit_code=%d)", safeDockerCategory(e.Category), e.ExitCode)
}
func (e *CommandFailure) Unwrap() error { return safeDockerCategory(e.Category) }

func ClassifyDockerFailure(diagnostic string) error {
	message := strings.ToLower(diagnostic)
	for _, category := range []struct {
		words []string
		err   error
	}{
		{[]string{"unmanaged foc installation", "unknown foc ownership marker", "global foc command differs"}, ErrInstallerOwnership},
		{[]string{"refusing symlinked", "unsafe global foc", "unsafe launcher identity", "existing native deployment receipt required"}, ErrInstallerPath},
		{[]string{"selected operator revision mismatch", "invalid operator bundle revision"}, ErrInstallerRevision},
		{[]string{"no space left on device", "read-only file system", "failed to extract", "failed to register layer"}, ErrDockerStorage},
		{[]string{"permission denied", "unauthorized", "access denied", "denied:"}, ErrDockerPermission},
		{[]string{"another host installation is active or interrupted"}, ErrInstallerLock},
		{[]string{"manifest unknown", "no such image"}, ErrDockerImageMissing},
		{[]string{"no matching manifest", "unsupported platform"}, ErrDockerPlatform},
		{[]string{"digest mismatch", "unexpected commit digest", "checksum mismatch", "checksum verification failed"}, ErrDockerIntegrity},
		{[]string{"timeout", "connection refused", "network", "tls handshake", "x509:", "no such host", "unexpected eof", "connection reset", "toomanyrequests", "too many requests"}, ErrDockerNetwork},
		{[]string{"context deadline exceeded"}, ErrDockerTimeout},
		{[]string{"context canceled", "context cancelled", "operation canceled"}, ErrDockerCanceled},
	} {
		for _, word := range category.words {
			if strings.Contains(message, word) {
				return category.err
			}
		}
	}
	if strings.Contains(message, "snapshot") && (strings.Contains(message, "does not exist") || strings.Contains(message, "not found") || strings.Contains(message, "failed")) {
		return ErrDockerStorage
	}
	return ErrDockerCommand
}

func safeDockerFailure(err error) error {
	var failure *CommandFailure
	if errors.As(err, &failure) {
		return &CommandFailure{Category: safeDockerCategory(failure.Category), ExitCode: failure.ExitCode}
	}
	return safeDockerCategory(err)
}

func safeDockerCategory(err error) error {
	for _, category := range []error{ErrDockerPermission, ErrDockerImageMissing, ErrDockerPlatform, ErrDockerIntegrity, ErrDockerNetwork, ErrDockerCommand, ErrDockerStorage, ErrDockerCanceled, ErrDockerTimeout, ErrDockerOutputLimit, ErrInstallerOwnership, ErrInstallerLock, ErrInstallerPath, ErrInstallerRevision} {
		if errors.Is(err, category) {
			return category
		}
	}
	return ErrDockerCommand
}
