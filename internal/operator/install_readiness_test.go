package operator

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/certificate"
)

type certificateInstallRunner struct {
	base       *fakeRunner
	view       certificate.View
	invalid    bool
	readyError bool
	material   string
	readyCalls int
}

func (r *certificateInstallRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	call := strings.Join(args, " ")
	if strings.HasSuffix(call, " certificate-status") {
		if r.invalid {
			return []byte("invalid secret=must-not-escape"), nil
		}
		return json.Marshal(r.view)
	}
	if strings.HasSuffix(call, " certificate-ready") {
		r.readyCalls++
		if r.readyError {
			return nil, errors.New("secret=must-not-escape")
		}
		return nil, nil
	}
	if r.material != "" && strings.Contains(call, " up ") {
		if err := os.MkdirAll(filepath.Dir(r.material), 0700); err != nil {
			return nil, err
		}
		if err := os.WriteFile(r.material, []byte("native identity already initialized"), 0600); err != nil {
			return nil, err
		}
	}
	return r.base.Run(ctx, name, args...)
}

func TestInstallCertificateReadinessRequiresConfiguredServingBytes(t *testing.T) {
	for _, kind := range []string{"valid", "disabled", "rejected", "pending-rejection", "missing-fingerprint", "different-serving-bytes", "wrong-host", "unexpected-disabled", "invalid-status", "stale-final-ready", "controller-stopped"} {
		t.Run(kind, func(t *testing.T) {
			d, base := fixture(t)
			host := "install.fixture.test"
			base.config.Services["web"].Environment["TLS_ENABLED"] = "true"
			base.config.Services["web"].Environment["SERVER_NAME"] = host
			r := &certificateInstallRunner{base: base, view: certificate.View{Enabled: true, ControllerRunning: true, Hostname: host, State: "ACTIVE", HTTPSReady: true, ServingMatches: true, Fingerprint: strings.Repeat("a", 64), ServingFingerprint: strings.Repeat("a", 64)}}
			switch kind {
			case "disabled":
				base.config.Services["web"].Environment["TLS_ENABLED"] = "false"
				r.view = certificate.View{ControllerRunning: true, State: "DISABLED"}
			case "rejected":
				r.view.State = "FAILED"
				r.view.LastError = "domain_rejected"
				r.view.HTTPSReady = false
			case "pending-rejection":
				r.view.State = "PENDING"
				r.view.LastError = "domain_rejected"
				r.view.HTTPSReady = false
			case "missing-fingerprint":
				r.view.Fingerprint = ""
				r.view.ServingFingerprint = ""
			case "different-serving-bytes":
				r.view.ServingFingerprint = strings.Repeat("b", 64)
			case "wrong-host":
				r.view.Hostname = "foreign.fixture.test"
			case "unexpected-disabled":
				r.view.Enabled = false
			case "invalid-status":
				r.invalid = true
			case "stale-final-ready":
				r.readyError = true
			case "controller-stopped":
				r.view.ControllerRunning = false
			}
			d.Runner = r
			ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
			defer cancel()
			err := d.installCertificateReady(ctx, base.config)
			wantReady := kind == "valid" || kind == "disabled"
			if (err == nil) != wantReady {
				t.Fatalf("readiness result = %v", err)
			}
			if wantReady && r.readyCalls != 1 {
				t.Fatal("native final readiness command not checked")
			}
			if err != nil && strings.Contains(err.Error(), "must-not-escape") {
				t.Fatal("native diagnostic leaked")
			}
		})
	}
}

func TestInstallCertificateFailureRetainsPreparedReceiptAndNativeMaterial(t *testing.T) {
	d, base := fixture(t)
	base.config.Services["web"].Environment["TLS_ENABLED"] = "true"
	base.config.Services["web"].Environment["SERVER_NAME"] = "install.fixture.test"
	material := filepath.Join(d.Directory, "data", "retained-identity")
	r := &certificateInstallRunner{base: base, material: material, view: certificate.View{Enabled: true, ControllerRunning: true, Hostname: "install.fixture.test", State: "FAILED", LastError: "domain_rejected"}}
	d.Runner = r
	receipt, err := d.Install(context.Background(), "", "amd64", fakeEvidence{true}, &fakeImages{})
	if err == nil || receipt.State != "prepared" {
		t.Fatal("failed certificate installation reported ready", err)
	}
	_, persisted, err := Open(d.Directory)
	if err != nil || persisted.State != "prepared" {
		t.Fatal("prepared receipt lost", err)
	}
	before, err := os.ReadFile(filepath.Join(d.Directory, ReceiptFile))
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(material)
	if err != nil {
		t.Fatal(err)
	}
	images := &fakeImages{}
	if _, err = d.Install(context.Background(), "", "amd64", fakeEvidence{true}, images); err == nil || len(images.calls) != 0 {
		t.Fatal("failed installation reinitialized")
	}
	after, err := os.ReadFile(filepath.Join(d.Directory, ReceiptFile))
	if err != nil || string(after) != string(before) {
		t.Fatal("receipt changed")
	}
	kept, err := os.ReadFile(material)
	if err != nil || string(kept) != string(data) {
		t.Fatal("native identity changed")
	}
}
