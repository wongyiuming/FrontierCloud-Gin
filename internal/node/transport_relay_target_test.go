package node

import "testing"

func TestRelayTargetPreservesVerifiedIPAuthority(t *testing.T) {
	for raw, want := range map[string]string{
		"https://relay.test":                         "relay.test:443",
		"https://124.220.156.46:8443":                "124.220.156.46:8443",
		"https://[2606:4700:4700:0:0:0:0:1111]:8443": "[2606:4700:4700::1111]:8443",
		"https://[fd12:3456::1]:8443":                "[fd12:3456::1]:8443",
	} {
		host, port, err := RelayTarget(raw)
		if err != nil || host+":"+port != want {
			t.Fatal(raw, host, port, err)
		}
	}
	for _, raw := range []string{"http://relay.test", "https://[::1]:8443", "https://[fe80::1%25eth0]:8443", "https://user:secret@relay.test:8443", "https://relay.test/path"} {
		if _, _, err := RelayTarget(raw); err == nil {
			t.Fatal("unsafe relay target admitted", raw)
		}
	}
}
