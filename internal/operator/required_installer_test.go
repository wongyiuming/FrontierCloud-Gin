package operator

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFreshAdmissionExcludesOnlyBoundedHostInstallerPaths(t *testing.T) {
	d, runner := registrationFixture(t)
	// Replace the fixture's existing business directory with an empty directory.
	data := runner.config.Services["web"].Volumes[0].Source
	if err := os.Remove(filepath.Join(data, "frontiercloud.db")); err != nil {
		t.Fatal(err)
	}
	if err := d.Empty(context.Background(), runner.config); err != nil {
		t.Fatal("host install directories treated as nonempty business data", err)
	}
	service := runner.config.Services["foc-host-init"]
	service.Volumes = append(service.Volumes, Mount{Type: "bind", Source: data, Target: "/unapproved"})
	runner.config.Services["foc-host-init"] = service
	if err := os.WriteFile(filepath.Join(data, "existing-media"), []byte("retain"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := d.Empty(context.Background(), runner.config); err == nil {
		t.Fatal("altered installer bypassed nonempty-data guard")
	}
}

func TestHostInstallerRequiresIndependentPublishedImageProof(t *testing.T) {
	_, runner := registrationFixture(t)
	s := runner.config.Services["foc-host-init"]
	s.Environment["FOC_OPERATOR_REVISION"] = strings.Repeat("a", 40)
	if _, err := proveHostInstaller(context.Background(), s, "amd64", fakeEvidence{true}, &fakeImages{}); err != nil {
		t.Fatal(err)
	}
	if _, err := proveHostInstaller(context.Background(), s, "amd64", fakeEvidence{false}, &fakeImages{}); err == nil {
		t.Fatal("unreviewed host executable admitted")
	}
	s.Image = "ghcr.io/wongyiuming/frontiercloud-gin-web@sha256:" + strings.Repeat("e", 64)
	if _, err := proveHostInstaller(context.Background(), s, "amd64", fakeEvidence{true}, &fakeImages{}); err == nil {
		t.Fatal("different installer digest admitted")
	}
}

func TestBusinessUpgradePreservesIndependentInstallerPin(t *testing.T) {
	d, runner := registrationFixture(t)
	s := runner.config.Services["foc-host-init"]
	s.Environment["FOC_OPERATOR_REVISION"] = strings.Repeat("a", 40)
	runner.config.Services["foc-host-init"] = s
	previous := Receipt{ServiceImages: map[string]string{
		"web":           "ghcr.io/wongyiuming/frontiercloud-gin-web@sha256:" + strings.Repeat("c", 64),
		"foc-host-init": s.Image,
	}}
	_, _, services, err := d.targetImages(context.Background(), previous, strings.Repeat("b", 40), "amd64", fakeEvidence{true}, &fakeImages{})
	if err != nil || services["foc-host-init"] != s.Image {
		t.Fatal("business update changed host bootstrap pin", services, err)
	}
}
