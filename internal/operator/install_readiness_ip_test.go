package operator

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/certificate"
)

func TestInstallCertificateReadinessBindsCanonicalPublicIPIdentity(t *testing.T) {
	for _, test := range []struct {
		configured, observed string
		ready                bool
	}{
		{"124.220.156.46", "124.220.156.46", true},
		{"::ffff:124.220.156.46", "124.220.156.46", true},
		{"2606:4700:4700:0:0:0:0:1111", "2606:4700:4700::1111", true},
		{"124.220.156.46", "124.220.156.47", false},
		{"2606:4700:4700::1111", "2606:4700:4700::1112", false},
		{"127.0.0.1", "127.0.0.1", false},
		{"2606:4700:4700::1111%eth0", "2606:4700:4700::1111", false},
	} {
		t.Run(test.configured+"/"+test.observed, func(t *testing.T) {
			d, base := fixture(t)
			base.config.Services["web"].Environment["TLS_ENABLED"] = "true"
			base.config.Services["web"].Environment["SERVER_NAME"] = test.configured
			r := &certificateInstallRunner{base: base, view: certificate.View{Enabled: true, ControllerRunning: true, Hostname: test.observed, State: "ACTIVE", HTTPSReady: true, ServingMatches: true, Fingerprint: strings.Repeat("a", 64), ServingFingerprint: strings.Repeat("a", 64)}}
			d.Runner = r
			ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
			defer cancel()
			err := d.installCertificateReady(ctx, base.config)
			if (err == nil) != test.ready || test.ready && r.readyCalls != 1 || !test.ready && r.readyCalls != 0 {
				t.Fatal("canonical IP readiness binding", err, r.readyCalls)
			}
		})
	}
}
