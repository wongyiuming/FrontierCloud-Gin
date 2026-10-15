package operator

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/certificate"
)

var errInstallCertificate = errors.New("automatic TLS has not verified the configured serving certificate; preserve the prepared receipt and volumes; inspect status, DNS and certificate controller")

// Keep the prepared receipt until the native controller verifies actual HTTPS
// serving bytes. Docker controller liveness alone is not installation success.
func (d *Deployment) installCertificateReady(ctx context.Context, cfg Config) error {
	environment := cfg.Services["web"].Environment
	enabled := false
	if value := environment["TLS_ENABLED"]; value != "" {
		var err error
		enabled, err = strconv.ParseBool(value)
		if err != nil {
			return errInstallCertificate
		}
	}
	for ctx.Err() == nil {
		probe, cancel := context.WithTimeout(ctx, 5*time.Second)
		raw, err := d.Compose(probe, true, "exec", "-T", "web", "/app/frontiercloud", "certificate-status")
		cancel()
		if err == nil {
			var v certificate.View
			if json.Unmarshal(raw, &v) != nil || v.Enabled != enabled || enabled && v.Hostname != environment["SERVER_NAME"] {
				return errInstallCertificate
			}
			if v.State == "FAILED" {
				return errInstallCertificate
			}
			fingerprint, fingerprintErr := hex.DecodeString(v.Fingerprint)
			validTLS := v.HTTPSReady && v.ServingMatches && fingerprintErr == nil && len(fingerprint) == 32 && v.ServingFingerprint == v.Fingerprint
			// The native ACME retry scheduler may return to PENDING while its
			// recorded CA rejection remains authoritative. Such a retry does not
			// make an unusable certificate eligible for installation readiness.
			if !validTLS && (v.LastError == "domain_rejected" || v.LastError == "caa" || v.LastError == "authorization") {
				return errInstallCertificate
			}
			if v.ControllerRunning && (enabled && validTLS || !enabled && v.State == "DISABLED") {
				// Reuse the native readiness command immediately before changing the
				// receipt, so a failed or changed observation cannot claim success.
				probe, cancel := context.WithTimeout(ctx, 5*time.Second)
				_, err = d.Compose(probe, true, "exec", "-T", "certificate-agent", "/app/frontiercloud", "certificate-ready")
				cancel()
				if err == nil && ctx.Err() == nil {
					return nil
				}
			}
		}
		timer := time.NewTimer(time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
		case <-timer.C:
		}
	}
	return errInstallCertificate
}
