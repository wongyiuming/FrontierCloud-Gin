// Package certificate defines read-only automatic TLS observations and browser
// export envelopes. It never loads user-selected certificate or private-key paths.
package certificate

import (
	"regexp"
	"strings"
)

type Job struct {
	State        string `json:"state"`
	Code         string `json:"code,omitempty"`
	StartedAt    int64  `json:"started_at,omitempty"`
	CompletedAt  int64  `json:"completed_at,omitempty"`
	Port80Active bool   `json:"port80_active"`
}

type View struct {
	Download           *DownloadEnvelope `json:"download,omitempty"`
	Enabled            bool              `json:"enabled"`
	ControllerRunning  bool              `json:"controller_running"`
	Mode               string            `json:"mode,omitempty"`
	SAN                []string          `json:"san,omitempty"`
	Issuer             string            `json:"issuer,omitempty"`
	RemainingSeconds   int64             `json:"remaining_seconds"`
	NextRenewal        int64             `json:"next_renewal,omitempty"`
	LastRenewal        string            `json:"last_renewal,omitempty"`
	LastError          string            `json:"last_error,omitempty"`
	ServingFingerprint string            `json:"serving_fingerprint,omitempty"`
	ServingMatches     bool              `json:"serving_matches"`
	HTTPSReady         bool              `json:"https_ready"`
	Hostname           string            `json:"hostname"`
	NotBefore          int64             `json:"not_before,omitempty"`
	NotAfter           int64             `json:"not_after,omitempty"`
	Fingerprint        string            `json:"fingerprint,omitempty"`
	State              string            `json:"state"`
	Managed            bool              `json:"managed"`
	AutoRenew          bool              `json:"auto_renew"`
	Validation         string            `json:"validation,omitempty"`
	Job                Job               `json:"job"`
}

var hostnamePattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$`)

func dnsHostname(s string) bool {
	if !hostnamePattern.MatchString(s) || !strings.Contains(s, ".") {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
	}
	return true
}
