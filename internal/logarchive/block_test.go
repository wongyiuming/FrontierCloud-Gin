package logarchive

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/vault"
)

func TestLogBlockMasterBindingAndTampering(t *testing.T) {
	v, _ := vault.New(base64.URLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)))
	other, _ := vault.New(base64.URLEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32)))
	start := time.Unix(1800000000, 0)
	plain := []byte("private log IP-and-request-details")
	r, p, e := Seal(v, strings.Repeat("a", 32), Access, start, start.Add(time.Second), plain)
	if e != nil {
		t.Fatal(e)
	}
	if bytes.Contains(p, plain) || strings.Contains(r.WrappedKey, string(plain)) {
		t.Fatal("plaintext leaked")
	}
	opened, e := OpenForMaster(v, r, p)
	if e != nil || !bytes.Equal(opened, plain) {
		t.Fatal("Master read", e)
	}
	manifest, e := SealRecord(v, r)
	if e != nil {
		t.Fatal(e)
	}
	if strings.Contains(manifest, r.Header.MasterID) || strings.Contains(manifest, r.Header.ID) {
		t.Fatal("plaintext manifest identity leaked")
	}
	restored, e := OpenRecord(v, manifest)
	if e != nil || restored != r {
		t.Fatal("encrypted manifest round trip", e)
	}
	if _, e = OpenRecord(other, manifest); e == nil {
		t.Fatal("other node opened Master manifest")
	}
	if _, e = OpenForMaster(other, r, p); e == nil {
		t.Fatal("different vault accepted")
	}
	r2, p2, e := Seal(v, r.Header.MasterID, Access, start, start.Add(time.Second), plain)
	if e != nil {
		t.Fatal(e)
	}
	if r.Header.ID == r2.Header.ID || bytes.Equal(p, p2) || r.WrappedKey == r2.WrappedKey {
		t.Fatal("block identity/key/nonce reused")
	}
	swapped := r
	swapped.WrappedKey = r2.WrappedKey
	if _, e = OpenForMaster(v, swapped, p); e == nil {
		t.Fatal("swapped wrapped key accepted")
	}
	for _, change := range []func(*Record){func(v *Record) { v.Header.Kind = Audit }, func(v *Record) { v.Header.MasterID = strings.Repeat("b", 32) }, func(v *Record) { v.Header.EndMillis++ }, func(v *Record) { v.CiphertextBytes++ }} {
		bad := r
		change(&bad)
		if _, e = OpenForMaster(v, bad, p); e == nil {
			t.Fatal("manifest tampering accepted")
		}
	}
	p[len(p)-1] ^= 1
	r.CiphertextSHA256 = hash(p)
	if _, e = OpenForMaster(v, r, p); e == nil {
		t.Fatal("corrupt GCM tag accepted even with substituted hash")
	}
	if _, _, e = Seal(v, r.Header.MasterID, Access, start, start.Add(time.Second), make([]byte, MaxPlainBytes+1)); e == nil {
		t.Fatal("unbounded block admitted")
	}
}

func TestLogArchiveAdmissionAndLifecycle(t *testing.T) {
	now := time.Unix(1800000000, 0)
	d := Destination{Native: true, Active: true, Online: true, ResourceReady: true, ConfiguredTransport: "Direct", AppliedTransport: "Direct"}
	if !d.Eligible() {
		t.Fatal("ready Direct rejected")
	}
	for _, change := range []func(*Destination){func(d *Destination) { d.Native = false }, func(d *Destination) { d.AppliedTransport = "Relay" }, func(d *Destination) { d.ConfiguredTransport = "Relay" }, func(d *Destination) { d.Active = false }, func(d *Destination) { d.Online = false }, func(d *Destination) { d.ResourceReady = false }} {
		bad := d
		change(&bad)
		if bad.Eligible() {
			t.Fatal("ineligible archive node admitted")
		}
	}
	if ValidateQuery(now.Add(-6*time.Hour), now, now, Access, true) != nil {
		t.Fatal("6h keyword refused")
	}
	for _, window := range []time.Duration{12 * time.Hour, 24 * time.Hour, Retention + time.Second} {
		if ValidateQuery(now.Add(-window), now, now, Access, true) == nil {
			t.Fatal("keyword window admitted", window)
		}
	}
	if ValidateQuery(now.Add(-time.Hour), now, now, "", true) == nil {
		t.Fatal("keyword without type admitted")
	}
	if ValidateQuery(now.Add(-Retention), now, now, Audit, false) != nil {
		t.Fatal("retained selection refused")
	}
	if ReleaseLocal(now.Add(-LocalWindow), now, false) || ReleaseLocal(now.Add(-LocalWindow+time.Second), now, true) || !ReleaseLocal(now.Add(-LocalWindow), now, true) {
		t.Fatal("local release boundary")
	}
	if Expired(now.Add(-Retention+time.Second), now) || !Expired(now.Add(-Retention), now) {
		t.Fatal("retention boundary")
	}
}
