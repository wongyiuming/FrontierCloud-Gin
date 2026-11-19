package protocol

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
)

func TestIngressMediaCapabilityVersionAndDescriptor(t *testing.T) {
	credential := Encode(bytes.Repeat([]byte{9}, 48))
	rel, master, owner, ingress := strings.Repeat("1", 32), strings.Repeat("2", 32), strings.Repeat("3", 32), strings.Repeat("4", 32)
	object, resource := strings.Repeat("a", 64), strings.Repeat("b", 64)
	meta, err := mediacrypto.NewMetadata(32)
	if err != nil {
		t.Fatal(err)
	}
	token, err := IngressMediaToken(credential, rel, master, owner, object, resource, ingress, "https://entry.example", strings.Repeat("e", 32), 7, 1000, 1300, meta.CiphertextSize, &meta)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = VerifyMediaToken(credential, token, 1001); err == nil {
		t.Fatal("legacy verifier accepted new token")
	}
	claims, err := VerifyIngressMediaToken(credential, token, 1001)
	if err != nil || claims["origin"] != "https://entry.example" || claims["ingress"] != ingress || claims["session"] != strings.Repeat("e", 32) || claims["o"] != owner || claims["i"] != object || claims["g"] != resource {
		t.Fatalf("wrong grant %v %v", claims, err)
	}
	if _, err = VerifyIngressMediaToken(credential, token, 1300); err == nil {
		t.Fatal("expired capability accepted")
	}
	if _, err = VerifyIngressMediaToken(Encode(bytes.Repeat([]byte{8}, 48)), token, 1001); err == nil {
		t.Fatal("wrong relationship key accepted")
	}
	encrypted, _ := IngressMediaDescriptor(meta.CiphertextSize, &meta)
	plaintext, _ := IngressMediaDescriptor(meta.CiphertextSize, nil)
	changed := meta
	changed.NoncePrefix = "AQIDBAUGBwg="
	other, err := IngressMediaDescriptor(meta.CiphertextSize, &changed)
	if err != nil || encrypted == plaintext || encrypted == other || claims["descriptor"] != encrypted {
		t.Fatal("descriptor failed to bind encryption and size")
	}
	digest := strings.Repeat("c", 64)
	plainToken, err := PlainIngressMediaToken(credential, rel, master, owner, object, resource, ingress, "https://entry.example", strings.Repeat("e", 32), 7, 1000, 1300, 5, digest)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyIngressMediaToken(credential, plainToken, 1001); err == nil {
		t.Fatal("v3 verifier accepted v4 plaintext grant")
	}
	if _, err := VerifyMediaToken(credential, plainToken, 1001); err == nil {
		t.Fatal("v2 verifier accepted v4 plaintext grant")
	}
	plainClaims, err := VerifyPlainIngressMediaToken(credential, plainToken, 1001)
	if err != nil || plainClaims["content_sha256"] != digest {
		t.Fatal("plaintext proof missing", err)
	}
	if _, err := VerifyPlainIngressMediaToken(credential, token, 1001); err == nil {
		t.Fatal("plaintext verifier accepted v3 encrypted grant")
	}
	blob := strings.Repeat("d", 64)
	opaque, err := OpaqueIngressMediaToken(credential, rel, master, owner, object, ingress, "https://entry.example", strings.Repeat("e", 32), blob, 7, 1000, 1300, meta.CiphertextSize, digest, &meta)
	if err != nil {
		t.Fatal(err)
	}
	for _, verify := range []func(string, string, int64) (map[string]any, error){VerifyMediaToken, VerifyIngressMediaToken, VerifyPlainIngressMediaToken} {
		if _, err := verify(credential, opaque, 1001); err == nil {
			t.Fatal("legacy verifier accepted opaque placement")
		}
	}
	opaqueClaims, err := VerifyOpaqueIngressMediaToken(credential, opaque, 1001)
	if err != nil || opaqueClaims["blob"] != blob || opaqueClaims["i"] != object || opaqueClaims["g"] != object || opaqueClaims["content_sha256"] != digest || opaqueClaims["descriptor"] != encrypted {
		t.Fatal("opaque grant lost its placement or descriptor", err)
	}
	if _, err := VerifyOpaqueIngressMediaToken(credential, opaque, 1300); err == nil {
		t.Fatal("expired opaque grant accepted")
	}
	if _, err := VerifyOpaqueIngressMediaToken(Encode(bytes.Repeat([]byte{8}, 48)), opaque, 1001); err == nil {
		t.Fatal("wrong relationship accepted")
	}
	for _, invalid := range []string{"", object, strings.Repeat("A", 64)} {
		if _, err := OpaqueIngressMediaToken(credential, rel, master, owner, object, ingress, "https://entry.example", strings.Repeat("e", 32), invalid, 7, 1000, 1300, 5, digest, nil); err == nil {
			t.Fatal("invalid blob locator accepted")
		}
	}
	opaqueClaims["blob"] = object
	forged, err := capabilityToken(credential, opaqueClaims)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyOpaqueIngressMediaToken(credential, forged, 1001); err == nil {
		t.Fatal("invalid signed blob locator accepted")
	}
	opaqueClaims["blob"], opaqueClaims["g"] = blob, resource
	forged, err = capabilityToken(credential, opaqueClaims)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyOpaqueIngressMediaToken(credential, forged, 1001); err == nil {
		t.Fatal("opaque grant included a second historical identity")
	}
	opaqueProbe, err := OpaqueIngressProbeToken(credential, rel, master, owner, strings.Repeat("f", 32), 1000)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyOpaqueIngressMediaToken(credential, opaqueProbe, 1001); err == nil {
		t.Fatal("opaque readiness probe authorized business data")
	}
	if _, err := VerifyOpaqueIngressProbeToken(credential, opaqueProbe, strings.Repeat("f", 32), 1001); err != nil {
		t.Fatal("valid opaque probe rejected", err)
	}
	if _, err := VerifyOpaqueIngressProbeToken(credential, opaqueProbe, strings.Repeat("e", 32), 1001); err == nil {
		t.Fatal("opaque probe accepted a different challenge")
	}
	challenge := strings.Repeat("f", 32)
	probe, err := PlainIngressProbeToken(credential, rel, master, owner, challenge, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyPlainIngressMediaToken(credential, probe, 1001); err == nil {
		t.Fatal("readiness probe authorized a media read")
	}
	probeClaims, err := VerifyPlainIngressProbeToken(credential, probe, challenge, 1001)
	if err != nil {
		t.Fatal("valid readiness probe rejected", err)
	}
	fixture := PlainProbeFixture()
	fixtureHash := sha256.Sum256(fixture)
	if len(fixture) != PlainProbeFixtureSize || probeClaims["content_sha256"] != hex.EncodeToString(fixtureHash[:]) {
		t.Fatal("probe token did not bind the bytes the owner reads")
	}
	probeClaims["generation"] = 2
	modifiedProbe, err := capabilityToken(credential, probeClaims)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyPlainIngressProbeToken(credential, modifiedProbe, challenge, 1001); err == nil {
		t.Fatal("probe accepted an unrelated generation")
	}
	if _, err := VerifyPlainIngressProbeToken(credential, probe, strings.Repeat("1", 32), 1001); err == nil {
		t.Fatal("replayed readiness probe accepted")
	}
	for _, invalid := range []string{"", "\"weak-etag\"", strings.Repeat("C", 64), strings.Repeat("0", 63)} {
		if _, err := PlainIngressMediaToken(credential, rel, master, owner, object, resource, ingress, "https://entry.example", strings.Repeat("e", 32), 7, 1000, 1300, 5, invalid); err == nil {
			t.Fatal("invalid content proof accepted")
		}
	}
	for _, origin := range []string{"http://entry.example", "https://entry.example/", "https://entry.example:443", "https://user@entry.example", "https://entry.example?x=1"} {
		if _, err := IngressMediaToken(credential, rel, master, owner, object, resource, ingress, origin, strings.Repeat("e", 32), 7, 1000, 1300, 5, nil); err == nil {
			t.Fatalf("accepted origin %q", origin)
		}
	}
}

func TestOpaqueEmptyMediaCapabilityBindsCanonicalDigest(t *testing.T) {
	credential := Encode(bytes.Repeat([]byte{9}, 48))
	rel, master, owner := strings.Repeat("1", 32), strings.Repeat("2", 32), strings.Repeat("3", 32)
	alias, blob := strings.Repeat("a", 64), strings.Repeat("b", 64)
	token, err := OpaqueIngressMediaToken(credential, rel, master, owner, alias, master, "https://entry.example", strings.Repeat("e", 32), blob, 7, 1000, 1300, 0, emptyOpaqueSHA256, nil)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := VerifyOpaqueIngressMediaToken(credential, token, 1001)
	if err != nil || claims["content_sha256"] != emptyOpaqueSHA256 {
		t.Fatal("valid empty capability", err)
	}
	if _, err := OpaqueIngressMediaToken(credential, rel, master, owner, alias, master, "https://entry.example", strings.Repeat("e", 32), blob, 7, 1000, 1300, 0, strings.Repeat("f", 64), nil); err == nil {
		t.Fatal("nonempty digest accepted for empty object")
	}
	claims["descriptor"] = strings.Repeat("c", 64)
	claims["revision"], _ = OpaquePlacementRevisionFromDescriptor(alias, blob, emptyOpaqueSHA256, strings.Repeat("c", 64), 1)
	forged, err := capabilityToken(credential, claims)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyOpaqueIngressMediaToken(credential, forged, 1001); err == nil {
		t.Fatal("empty object accepted a nonempty descriptor")
	}
}
