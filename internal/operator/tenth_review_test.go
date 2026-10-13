package operator

import (
	"context"
	"testing"
)

func TestReceiptBindsTrustNetworksAndCanonicalizesOnlyEquivalentCIDRs(t *testing.T) {
	for _, key := range []string{"SECURITY_EXEMPT_NETWORKS", "TRUSTED_PROXY_NETWORKS"} {
		d, receipt, runner, _ := upgradeFixture(t)
		service := runner.config.Services["web"]
		service.Environment[key] = "0.0.0.0/0"
		runner.config.Services["web"] = service
		if _, e := d.ValidateReceipt(context.Background(), receipt); e == nil {
			t.Fatal("trust expansion admitted", key)
		}
	}
	if trustNetworks("127.8.9.10/8, ::1/128,127.0.0.0/8", "", false) != trustNetworks("::1/128,127.0.0.0/8", "", false) {
		t.Fatal("equivalent prefix sets changed selection")
	}
	if trustNetworks("invalid", "", false) == trustNetworks("127.0.0.0/8", "", false) {
		t.Fatal("invalid setting masquerades as default")
	}
}
