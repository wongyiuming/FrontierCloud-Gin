package s3store

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func baseConfig() Config {
	return Config{Bucket: "frontiercloud-media", Region: "us-east-1", Prefix: "music/v1"}
}

func TestConfigIdentityNormalization(t *testing.T) {
	for _, tc := range []struct {
		name, endpoint, bucket, region, style, wantEndpoint, wantStyle string
	}{
		{"aws", "", "frontiercloud-media", "us-east-1", "auto", "https://s3.us-east-1.amazonaws.com", "virtual"},
		{"aws-china", "", "frontiercloud-media", "cn-north-1", "", "https://s3.cn-north-1.amazonaws.com.cn", "virtual"},
		{"dotted-bucket", "", "frontiercloud.media", "eu-west-1", "auto", "https://s3.eu-west-1.amazonaws.com", "path"},
		{"compatible", "https://S3.Storage.EXAMPLE:00443/", "frontiercloud-media", "us-east-1", "", "https://s3.storage.example", "path"},
		{"compatible-virtual", "https://s3.storage.example:9444", "frontiercloud-media", "us-east-1", "virtual", "https://s3.storage.example:9444", "virtual"},
		{"private-ip", "https://192.168.6.201:9444", "frontiercloud-media", "us-east-1", "path", "https://192.168.6.201:9444", "path"},
		{"private-v6", "https://[fd00:0:0:1::9]:9444/", "frontiercloud-media", "us-east-1", "auto", "https://[fd00:0:0:1::9]:9444", "path"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := Normalize(Config{Endpoint: tc.endpoint, Bucket: tc.bucket, Region: tc.region, AddressStyle: tc.style})
			if err != nil || cfg.Endpoint != tc.wantEndpoint || cfg.AddressStyle != tc.wantStyle {
				t.Fatalf("configuration mismatch: %v, %v", cfg, err)
			}
			again, err := Normalize(cfg)
			if err != nil || again != cfg {
				t.Fatal("normalization changed a previously normalized identity")
			}
		})
	}
}

func TestRejectUnsupportedBucketAndLocation(t *testing.T) {
	for _, bucket := range []string{"", "a", "AAAbucket", "bucket/other", "a..b", "a.-b", "a-.b", "192.168.1.2", "xn--bucket", "sthree-bucket", "amzn-s3-demo-bucket", "bucket-s3alias", "bucket--ol-s3", "bucket.mrap", "bucket--x-s3", "bucket--table-s3", strings.Repeat("a", 64)} {
		cfg := baseConfig()
		cfg.Bucket = bucket
		if _, err := Normalize(cfg); !errors.Is(err, ErrConfig) {
			t.Errorf("unsupported bucket accepted: %q", bucket)
		}
	}
	for _, endpoint := range []string{
		"http://s3.example", "https://user:secret@s3.example", "https://s3.example/path", "https://s3.example?secret=value", "https://s3.example?", "https://s3.example#fragment", "https://s3.example#", "https://s3.example./", "https://s3.example:", "https://s3.example:65536", "https://s3.example:0", " https://s3.example", "https://s3.example\n", "https://s3.example\\path", "https://s3.ex_ample", "https://s3..example", "https://[fe80::1%25eth0]", "https://[::1]", "https://127.0.0.1", "https://169.254.169.254", "https://[::ffff:127.0.0.1]", "https://0.0.0.0", "https://224.0.0.1", "https://2606:4700:4700::1111:9444", "https://fd00::1:9444",
	} {
		cfg := baseConfig()
		cfg.Endpoint = endpoint
		if _, err := Normalize(cfg); !errors.Is(err, ErrEndpoint) {
			t.Errorf("unsupported endpoint accepted: %q", endpoint)
		}
	}
	for _, field := range []string{"prefix", "region", "style", "ip-virtual"} {
		cfg := baseConfig()
		switch field {
		case "prefix":
			cfg.Prefix = "music/../other"
		case "region":
			cfg.Region = "us-east-1\n"
		case "style":
			cfg.AddressStyle = "other"
		case "ip-virtual":
			cfg.Endpoint, cfg.AddressStyle = "https://192.168.6.201", "virtual"
		}
		if _, err := Normalize(cfg); err == nil {
			t.Errorf("invalid %s accepted", field)
		}
	}
}

func TestManagedProviderKeyIsSeparateFromLogicalPath(t *testing.T) {
	cfg := baseConfig()
	key, err := cfg.ProviderKey("aaa/objects/bbb")
	if err != nil || key != "music/v1/aaa/objects/bbb" {
		t.Fatal("fixed prefix was not applied to the relative immutable key")
	}
	for _, key := range []string{"", "/aaa/objects/bbb", "aaa/objects/../bbb", "aaa//bbb", "aaa/%2e%2e/bbb", "aaa\\bbb", "aaa/file name", "aaa/曲名.mp3", strings.Repeat("x", 769)} {
		if _, err := cfg.ProviderKey(key); !errors.Is(err, ErrConfig) {
			t.Errorf("invalid provider identity accepted: %q", key)
		}
	}
	for _, prefix := range []string{"../aaa", "aaa/", "/aaa", "aaa//bbb", "aaa/%2e%2e", strings.Repeat("x", 257)} {
		cfg.Prefix = prefix
		if _, err := cfg.ProviderKey("aaa/objects/bbb"); !errors.Is(err, ErrConfig) {
			t.Errorf("invalid prefix accepted: %q", prefix)
		}
	}
}

func TestAWSNamespaceAliasesCannotOwnOverlappingPrefixes(t *testing.T) {
	wanted, err := baseConfig().Namespace()
	if err != nil || wanted.Origin != "aws" {
		t.Fatal("default AWS namespace missing")
	}
	for _, endpoint := range []string{
		"https://s3.amazonaws.com", "https://s3-us-west-2.amazonaws.com", "https://s3.eu-west-1.amazonaws.com", "https://s3.dualstack.ap-northeast-1.amazonaws.com", "https://s3-fips.us-east-1.amazonaws.com", "https://s3-fips.dualstack.us-east-1.amazonaws.com", "https://s3-accelerate.amazonaws.com", "https://s3-accelerate.dualstack.amazonaws.com", "https://bucket.vpce-0123456789abcdef0-abc.s3.us-east-1.vpce.amazonaws.com",
	} {
		cfg := baseConfig()
		cfg.Endpoint, cfg.Region, cfg.Prefix = endpoint, "eu-west-2", "music"
		other, err := cfg.Namespace()
		if err != nil || !wanted.Overlaps(other) || !other.Overlaps(wanted) {
			t.Errorf("AWS namespace alias admitted another parent-prefix owner: %q, %v", endpoint, err)
		}
	}
	for _, tc := range []struct{ endpoint, bucket, prefix, origin string }{
		{"https://s3.cn-north-1.amazonaws.com.cn", "frontiercloud-media", "music/v1", "aws-cn"},
		{"https://s3.us-gov-west-1.amazonaws.com", "frontiercloud-media", "music/v1", "aws-us-gov"},
		{"https://s3.compatible.example", "frontiercloud-media", "music/v1", "https://s3.compatible.example"},
		{"https://s3.amazonaws.com", "frontiercloud-other", "music/v1", "aws"},
		{"https://s3.amazonaws.com", "frontiercloud-media", "music/v11", "aws"},
	} {
		cfg := baseConfig()
		cfg.Endpoint, cfg.Bucket, cfg.Prefix = tc.endpoint, tc.bucket, tc.prefix
		other, err := cfg.Namespace()
		if err != nil || other.Origin != tc.origin || wanted.Overlaps(other) {
			t.Errorf("distinct namespace conflated: %#v, %v", other, err)
		}
	}
	for _, prefix := range []string{"", "music", "music/v1", "music/v1/child"} {
		cfg := baseConfig()
		cfg.Prefix = prefix
		other, _ := cfg.Namespace()
		if !other.Overlaps(wanted) || !wanted.Overlaps(other) {
			t.Errorf("overlap not detected: %q", prefix)
		}
	}
}

func validCredentials() Credentials {
	return Credentials{AccessKey: "EXAMPLEACCESSKEY", SecretKey: "test-only-secret-key-never-log"}
}

func TestGrantCannotOutliveExplicitCredential(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	for _, tc := range []struct {
		expires       int64
		request, want time.Duration
	}{
		{0, 5 * time.Minute, 5 * time.Minute},
		{now.Unix() + 150, 5 * time.Minute, 120 * time.Second},
		{now.Unix() + 31, 5 * time.Minute, time.Second},
		{now.Unix() + 600, time.Minute, time.Minute},
	} {
		c := validCredentials()
		c.ExpiresAt = tc.expires
		got, err := c.GrantDuration(now, tc.request)
		if err != nil || got != tc.want {
			t.Fatalf("grant expiry mismatch: %v, %v", got, err)
		}
	}
	for _, expiry := range []int64{-1, now.Unix() - 1, now.Unix(), now.Unix() + 30} {
		c := validCredentials()
		c.ExpiresAt = expiry
		if _, err := c.GrantDuration(now, time.Minute); !errors.Is(err, ErrCredentials) {
			t.Error("invalid or expiring credential granted a URL")
		}
	}
	for _, duration := range []time.Duration{0, time.Millisecond, 61 * time.Second / 2, MaxGrantDuration + time.Second} {
		if _, err := validCredentials().GrantDuration(now, duration); !errors.Is(err, ErrConfig) {
			t.Error("invalid grant duration accepted")
		}
	}
	c := validCredentials()
	c.SessionToken = "temporary-session-token"
	if err := c.Validate(now); !errors.Is(err, ErrCredentials) {
		t.Fatal("temporary credential without an explicit deadline accepted")
	}
	c.ExpiresAt = now.Unix() + 300
	if err := c.Validate(now); err != nil {
		t.Fatal("valid explicit temporary credentials refused")
	}
	for _, text := range []string{fmt.Sprint(c), fmt.Sprintf("%+v", c), fmt.Sprintf("%#v", c)} {
		if strings.Contains(text, c.AccessKey) || strings.Contains(text, c.SecretKey) || strings.Contains(text, c.SessionToken) {
			t.Fatal("credential debug rendering disclosed a secret field")
		}
	}
}
