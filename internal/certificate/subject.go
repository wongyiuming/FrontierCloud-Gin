package certificate

import (
	"errors"
	"net/netip"
	"strings"
)

// NormalizeSubject accepts one bare certificate identity, never a URL, port,
// bracketed IPv6 host or scoped address. DNS keeps its existing ASCII policy.
// IP certificates are limited to public unicast addresses; this is deliberately
// separate from the node transport's existing private-LAN endpoint policy.
func NormalizeSubject(raw string) (string, error) {
	value := strings.ToLower(strings.TrimSpace(raw))
	if address, err := netip.ParseAddr(value); err == nil {
		if address.Zone() != "" || !publicAddress(address.Unmap()) {
			return "", errors.New("automatic TLS requires a public IP address")
		}
		return address.Unmap().String(), nil
	}
	if strings.ContainsAny(value, ":%[]") || !dnsHostname(value) || onlyDigitsAndDots(value) {
		return "", errors.New("automatic TLS requires a DNS hostname or public IP address")
	}
	return value, nil
}

// Hostname retains the existing boolean entry point for supported managed
// certificate identities, including public IP literals.
func Hostname(value string) bool {
	_, err := NormalizeSubject(value)
	return err == nil
}

// IsIP reports a bare IP literal, independently of its public-address policy.
func IsIP(value string) bool {
	address, err := netip.ParseAddr(value)
	return err == nil && address.Zone() == ""
}

func onlyDigitsAndDots(value string) bool {
	for _, c := range value {
		if c != '.' && (c < '0' || c > '9') {
			return false
		}
	}
	return true
}

// These non-public/special-purpose ranges follow the IANA address registries.
// Reject protocol, translation and transition ranges as certificate subjects,
// rather than treating IsGlobalUnicast alone as evidence of a public identity.
var nonPublicPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("2001::/23"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("3fff::/20"),
}

func publicAddress(address netip.Addr) bool {
	if !address.IsValid() || !address.IsGlobalUnicast() || address.IsPrivate() {
		return false
	}
	// Public IPv6 identities use the assigned global-unicast space, excluding
	// special-purpose suballocations below. New allocations need explicit review.
	if address.Is6() && !netip.MustParsePrefix("2000::/3").Contains(address) {
		return false
	}
	for _, prefix := range nonPublicPrefixes {
		if prefix.Contains(address) {
			return false
		}
	}
	return true
}
