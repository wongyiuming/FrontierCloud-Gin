package certificate

import "testing"

func TestNormalizeCertificateSubject(t *testing.T) {
	for raw, want := range map[string]string{
		"storage.example.com":                     "storage.example.com",
		" STORAGE.Example.COM ":                   "storage.example.com",
		"124.220.156.46":                          "124.220.156.46",
		"::ffff:124.220.156.46":                   "124.220.156.46",
		"2606:4700:4700:0000:0000:0000:0000:1111": "2606:4700:4700::1111",
		"2402:4E00:1020:1404:0000:0000:0000:0001": "2402:4e00:1020:1404::1",
	} {
		got, err := NormalizeSubject(raw)
		if err != nil || got != want || !Hostname(got) {
			t.Fatalf("%q => %q, %v; want %q", raw, got, err, want)
		}
	}
	for _, raw := range []string{
		"", "localhost", "example.com.", "-bad.example", "bad-.example", "bad..example", "例子.测试", "*.example.com",
		"https://example.com", "example.com:443", "124.220.156.46:443", "[2606:4700:4700::1111]", "2606:4700:4700::1111%eth0",
		"0.0.0.0", "0.1.2.3", "10.0.0.1", "100.64.0.1", "100.127.255.254", "127.0.0.2", "169.254.169.254", "172.16.0.1", "192.168.1.1",
		"192.0.0.1", "192.0.2.1", "192.88.99.1", "198.18.0.1", "198.51.100.1", "203.0.113.1", "224.0.0.1", "240.0.0.1", "255.255.255.255",
		"::", "::1", "::ffff:127.0.0.1", "::ffff:10.0.0.1", "64:ff9b::7cdc:9c2e", "100::1", "2001::1", "2001:db8::1", "2002:7cdc:9c2e::1", "3fff::1", "5f00::1", "fc00::1", "fe80::1", "ff02::1",
		"999.999.999.999", "124.220.156.046", "124.220.156.46\nexample.com",
	} {
		if got, err := NormalizeSubject(raw); err == nil || Hostname(raw) {
			t.Fatalf("unsupported identity accepted: %q => %q", raw, got)
		}
	}
}

func TestIsIPDoesNotConflateDNSOrPublicAddressPolicy(t *testing.T) {
	for _, raw := range []string{"124.220.156.46", "2606:4700:4700::1111", "127.0.0.1", "fc00::1"} {
		if !IsIP(raw) {
			t.Fatal("literal IP not detected", raw)
		}
	}
	for _, raw := range []string{"example.com", "[2606:4700:4700::1111]", "fe80::1%eth0", "https://124.220.156.46"} {
		if IsIP(raw) {
			t.Fatal("non-bare IP detected", raw)
		}
	}
}
