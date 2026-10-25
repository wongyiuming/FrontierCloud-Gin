package operator

import (
	"context"
	"testing"
)

func TestDoctorPublicIPIdentityDoesNotDependOnDNSOrClaimPublicReachability(t *testing.T) {
	for _, host := range []string{"124.220.156.46", "2606:4700:4700::1111"} {
		d, runner := fixture(t)
		runner.config.Services["web"].Environment["SERVER_NAME"] = host
		runner.config.Services["web"].Environment["TLS_ENABLED"] = "true"
		runner.requireNoWrites = true
		report := d.Doctor(context.Background())
		identity, http01, https := false, false, false
		for _, check := range report.Checks {
			switch check.Item {
			case "ip_identity":
				identity = check.State == "pass"
			case "dns":
				t.Fatal("IP literal entered DNS validation", check)
			case "inbound_http01":
				http01 = check.State == "unverified"
			case "inbound_https":
				https = check.State == "unverified"
			}
		}
		if !identity || !http01 || !https {
			t.Fatal("IP doctor omitted identity or overstated connectivity", report)
		}
	}
}
