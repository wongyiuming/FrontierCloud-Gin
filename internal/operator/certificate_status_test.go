package operator

import (
	"context"
	"strings"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/certificate"
)

type certificateStatusRecorder struct {
	Runner
	calls []string
}

func (r *certificateStatusRecorder) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	r.calls = append(r.calls, name+" "+strings.Join(args, " "))
	return r.Runner.Run(ctx, name, args...)
}

func TestStatusCertificateQueriesWebAndReportsOnlySafeProbeCodes(t *testing.T) {
	for _, code := range []string{"serving_probe_timeout", "serving_dns", "serving_connection", "serving_tls_verification", "serving_tls_handshake", "serving_certificate_mismatch", "secret=must-not-escape"} {
		t.Run(code, func(t *testing.T) {
			d, base := fixture(t)
			receipt, err := d.Install(context.Background(), "", "amd64", fakeEvidence{true}, &fakeImages{})
			if err != nil {
				t.Fatal(err)
			}
			base.existingContainers = `[{"Service":"web","State":"running"}]`
			runner := &certificateStatusRecorder{Runner: &certificateInstallRunner{base: base, view: certificate.View{Enabled: true, ControllerRunning: true, LastError: code}}}
			d.Runner = runner
			base.calls = nil
			report := d.Status(context.Background(), receipt)
			found := false
			for _, check := range report.Checks {
				if strings.Contains(check.Reason, "must-not-escape") {
					t.Fatal("untrusted diagnostic leaked")
				}
				if check.Item == "certificate" {
					found = true
					if check.State != "blocked" || code != "secret=must-not-escape" && !strings.Contains(check.Reason, code) {
						t.Fatal("probe error was hidden or accepted", check)
					}
				}
			}
			if !found || !strings.Contains(strings.Join(runner.calls, "\n"), "exec -T web /app/frontiercloud certificate-status") {
				t.Fatal("status did not query Web's real certificate socket", report, runner.calls)
			}
		})
	}
}
