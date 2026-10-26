package s3store

import (
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const MaxGrantDuration = 5 * time.Minute

var (
	bucketName         = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)
	regionName         = regexp.MustCompile(`^[a-z]{2}(?:-[a-z0-9]+){1,4}-[0-9]$`)
	keySegment         = regexp.MustCompile(`^[A-Za-z0-9_-][A-Za-z0-9._-]*$`)
	accessKey          = regexp.MustCompile(`^[A-Za-z0-9]{8,128}$`)
	awsEndpoint        = regexp.MustCompile(`^s3(?:[.-][a-z0-9-]+|(?:-fips)?\.(?:dualstack\.)?[a-z]{2}(?:-[a-z0-9]+){1,4}-[0-9]|-accelerate\.dualstack)?\.amazonaws\.com(\.cn)?$`)
	awsPrivateEndpoint = regexp.MustCompile(`^bucket\.vpce-(?:[a-f0-9]{8}|[a-f0-9]{17})-[a-z0-9]+(?:-[a-z]{2}(?:-[a-z0-9]+){1,4}-[0-9][a-z])?\.s3(?:-fips)?\.[a-z]{2}(?:-[a-z0-9]+){1,4}-[0-9]\.vpce\.amazonaws\.com(\.cn)?$`)
)

// Normalize admits general-purpose buckets only. A compatible HTTPS service
// may be on an administrator-selected private network. It is never a public
// URL-fetch feature or permission to disable certificate verification.
func Normalize(c Config) (Config, error) {
	if !bucketName.MatchString(c.Bucket) || strings.Contains(c.Bucket, "..") || strings.Contains(c.Bucket, ".-") || strings.Contains(c.Bucket, "-.") {
		return Config{}, ErrConfig
	}
	for _, prefix := range []string{"xn--", "sthree-", "amzn-s3-demo-"} {
		if strings.HasPrefix(c.Bucket, prefix) {
			return Config{}, ErrConfig
		}
	}
	for _, suffix := range []string{"-s3alias", "--ol-s3", ".mrap", "--x-s3", "--table-s3"} {
		if strings.HasSuffix(c.Bucket, suffix) {
			return Config{}, ErrConfig
		}
	}
	if _, err := netip.ParseAddr(c.Bucket); err == nil || !regionName.MatchString(c.Region) || !validKey(c.Prefix, 256, true) {
		return Config{}, ErrConfig
	}
	custom := c.Endpoint != ""
	if !custom {
		suffix := "amazonaws.com"
		if strings.HasPrefix(c.Region, "cn-") {
			suffix += ".cn"
		}
		c.Endpoint = "https://s3." + c.Region + "." + suffix
	}
	endpoint, err := normalizeEndpoint(c.Endpoint)
	if err != nil {
		return Config{}, err
	}
	c.Endpoint = endpoint
	if c.AddressStyle == "" || c.AddressStyle == "auto" {
		c.AddressStyle = "virtual"
		if custom || strings.Contains(c.Bucket, ".") {
			c.AddressStyle = "path"
		}
	}
	if c.AddressStyle != "virtual" && c.AddressStyle != "path" {
		return Config{}, ErrConfig
	}
	if c.AddressStyle == "virtual" {
		u, _ := url.Parse(endpoint)
		if _, err := netip.ParseAddr(u.Hostname()); err == nil {
			return Config{}, ErrEndpoint
		}
	}
	return c, nil
}

func normalizeEndpoint(raw string) (string, error) {
	if len(raw) > 512 || strings.TrimSpace(raw) != raw || strings.ContainsAny(raw, "\\#\r\n\t") {
		return "", ErrEndpoint
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Opaque != "" || u.User != nil || u.Host == "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawFragment != "" || (u.Path != "" && u.Path != "/") || u.RawPath != "" {
		return "", ErrEndpoint
	}
	host := strings.ToLower(u.Hostname())
	if host == "" || strings.HasSuffix(host, ".") || strings.Contains(host, "%") {
		return "", ErrEndpoint
	}
	if strings.Contains(host, ":") && !strings.HasPrefix(u.Host, "[") {
		// URL.Hostname can otherwise treat the last IPv6 segment as a port.
		return "", ErrEndpoint
	}
	if address, err := netip.ParseAddr(host); err == nil {
		address = address.Unmap()
		if !address.IsGlobalUnicast() || address.IsLoopback() || address.IsLinkLocalUnicast() {
			return "", ErrEndpoint
		}
		host = address.String()
	} else {
		if len(host) > 253 || strings.ContainsAny(host, ":[]") {
			return "", ErrEndpoint
		}
		for _, label := range strings.Split(host, ".") {
			if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				return "", ErrEndpoint
			}
			for _, ch := range label {
				if !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '-') {
					return "", ErrEndpoint
				}
			}
		}
	}
	port := u.Port()
	if strings.HasSuffix(u.Host, ":") {
		return "", ErrEndpoint
	}
	if port != "" {
		number, err := strconv.Atoi(port)
		if err != nil || number < 1 || number > 65535 {
			return "", ErrEndpoint
		}
		port = strconv.Itoa(number)
		if port == "443" {
			port = ""
		}
	}
	if port != "" {
		host = net.JoinHostPort(host, port)
	} else if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	return "https://" + host, nil
}

func validKey(value string, maximum int, empty bool) bool {
	if value == "" {
		return empty
	}
	if len(value) > maximum {
		return false
	}
	for _, part := range strings.Split(value, "/") {
		if !keySegment.MatchString(part) || part == "." || part == ".." {
			return false
		}
	}
	return true
}

// ProviderKey adds the fixed managed prefix to a relative immutable key. User
// filenames and logical paths do not become provider object identities.
func (c Config) ProviderKey(relative string) (string, error) {
	if !validKey(c.Prefix, 256, true) || !validKey(relative, 768, false) {
		return "", ErrConfig
	}
	if c.Prefix == "" {
		return relative, nil
	}
	value := c.Prefix + "/" + relative
	if len(value) > 1024 {
		return "", ErrConfig
	}
	return value, nil
}

type Namespace struct {
	Origin string
	Bucket string
	Prefix string
}

// Namespace unifies known AWS endpoint aliases within a partition. Different
// region or address-style spellings cannot create another owner of one prefix.
// Arbitrary compatible-service DNS aliases require the operator's attention.
func (c Config) Namespace() (Namespace, error) {
	c, err := Normalize(c)
	if err != nil {
		return Namespace{}, err
	}
	u, _ := url.Parse(c.Endpoint)
	origin := c.Endpoint
	if u.Port() == "" && (awsEndpoint.MatchString(u.Hostname()) || awsPrivateEndpoint.MatchString(u.Hostname())) {
		origin = "aws"
		if strings.HasSuffix(u.Hostname(), ".cn") {
			origin = "aws-cn"
		} else if strings.Contains(u.Hostname(), "us-gov-") {
			origin = "aws-us-gov"
		}
	}
	return Namespace{Origin: origin, Bucket: c.Bucket, Prefix: c.Prefix}, nil
}

func (a Namespace) Overlaps(b Namespace) bool {
	return a.Origin == b.Origin && a.Bucket == b.Bucket && (a.Prefix == "" || b.Prefix == "" || a.Prefix == b.Prefix || strings.HasPrefix(a.Prefix, b.Prefix+"/") || strings.HasPrefix(b.Prefix, a.Prefix+"/"))
}

func printableASCII(value string, minimum, maximum int) bool {
	if len(value) < minimum || len(value) > maximum {
		return false
	}
	for _, ch := range value {
		if ch < 33 || ch > 126 {
			return false
		}
	}
	return true
}

func (c Credentials) Validate(now time.Time) error {
	if !accessKey.MatchString(c.AccessKey) || !printableASCII(c.SecretKey, 16, 256) || (c.SessionToken != "" && !printableASCII(c.SessionToken, 1, 8192)) || c.ExpiresAt < 0 || (c.SessionToken != "" && c.ExpiresAt == 0) || now.Unix() < 1 {
		return ErrCredentials
	}
	if c.ExpiresAt != 0 && c.ExpiresAt <= now.Unix()+30 {
		return ErrCredentials
	}
	return nil
}

// GrantDuration preserves a clock-skew margin and never extends a temporary
// credential's lifetime. Presigned grants remain bearer secrets until expiry.
func (c Credentials) GrantDuration(now time.Time, requested time.Duration) (time.Duration, error) {
	if err := c.Validate(now); err != nil {
		return 0, err
	}
	if requested < time.Second || requested > MaxGrantDuration || requested%time.Second != 0 {
		return 0, ErrConfig
	}
	if c.ExpiresAt != 0 {
		available := time.Unix(c.ExpiresAt, 0).Sub(now) - 30*time.Second
		available = available.Truncate(time.Second)
		if requested > available {
			requested = available
		}
	}
	if requested < time.Second {
		return 0, ErrCredentials
	}
	return requested, nil
}

func (Credentials) String() string   { return "S3 credentials [redacted]" }
func (Credentials) GoString() string { return "s3store.Credentials{[redacted]}" }
