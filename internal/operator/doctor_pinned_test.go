package operator

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/release"
)

type doctorImages struct {
	calls   []string
	drift   string
	failure bool
}

func (i *doctorImages) Prove(ctx context.Context, target, component, arch string) (release.ImageProof, error) {
	i.calls = append(i.calls, target+":"+component)
	if !release.ValidSHA(target) || i.failure {
		return release.ImageProof{}, release.ErrImageIntegrity
	}
	proof, err := (&fakeImages{}).Prove(ctx, target, component, arch)
	if component == i.drift {
		proof.Image = "ghcr.io/wongyiuming/frontiercloud-gin-" + component + "@sha256:" + strings.Repeat("f", 64)
	}
	return proof, err
}

func registryCheck(t *testing.T, report Report) Check {
	t.Helper()
	for _, c := range report.Checks {
		if c.Item == "registry" {
			return c
		}
	}
	t.Fatal("registry check missing", report)
	return Check{}
}

func TestDoctorVerifiesRecordedRevisionAndPinnedDigestWithoutWrites(t *testing.T) {
	for _, role := range []string{"master", "storage"} {
		t.Run(role, func(t *testing.T) {
			d, runner := fixture(t)
			if role == "storage" {
				var err error
				d, err = New(d.Directory, "storage", "sqlite")
				if err != nil {
					t.Fatal(err)
				}
				d.Runner = runner
				runner.config.Services["web"].Environment["DEPLOYMENT_MODE"] = "only_stroge"
			}
			receipt, err := d.Install(context.Background(), strings.Repeat("a", 40), "amd64", fakeEvidence{true}, &fakeImages{})
			if err != nil {
				t.Fatal(err)
			}
			for name, service := range runner.config.Services {
				service.Image = receipt.ServiceImages[name]
				runner.config.Services[name] = service
			}
			before := map[string][]byte{}
			for _, name := range []string{ReceiptFile, ImagesFile} {
				before[name], err = os.ReadFile(filepath.Join(d.Directory, name))
				if err != nil {
					t.Fatal(err)
				}
			}
			runner.calls = nil
			runner.requireNoWrites = true
			images := &doctorImages{}
			d.ImageInspector = images
			report := d.Doctor(context.Background())
			if check := registryCheck(t, report); check.State != "pass" {
				t.Fatal(check)
			}
			expected := []string{receipt.Revision + ":web"}
			if role == "master" {
				expected = append(expected, receipt.Revision+":nginx")
			}
			if !reflect.DeepEqual(images.calls, expected) {
				t.Fatal(images.calls, expected)
			}
			for name, bytes := range before {
				got, e := os.ReadFile(filepath.Join(d.Directory, name))
				if e != nil || string(got) != string(bytes) {
					t.Fatal("doctor changed durable state", name, e)
				}
			}
			for _, name := range []string{OperationLock, UpgradeJournal} {
				if _, e := os.Lstat(filepath.Join(d.Directory, name)); !os.IsNotExist(e) {
					t.Fatal("doctor created state", name, e)
				}
			}
			for _, call := range runner.calls {
				for _, forbidden := range []string{" pull ", " run ", " up ", " stop ", " exec "} {
					if strings.Contains(call, forbidden) {
						t.Fatal("doctor mutated", call)
					}
				}
			}
		})
	}
}

func TestDoctorRejectsPinnedDigestDriftAndRegistryErrors(t *testing.T) {
	for _, kind := range []string{"web", "nginx", "network", "receipt"} {
		t.Run(kind, func(t *testing.T) {
			d, runner := fixture(t)
			receipt, err := d.Install(context.Background(), strings.Repeat("a", 40), "amd64", fakeEvidence{true}, &fakeImages{})
			if err != nil {
				t.Fatal(err)
			}
			for name, service := range runner.config.Services {
				service.Image = receipt.ServiceImages[name]
				runner.config.Services[name] = service
			}
			images := &doctorImages{drift: kind, failure: kind == "network"}
			d.ImageInspector = images
			runner.requireNoWrites = true
			if kind == "receipt" {
				runner.config.Name = "different-project"
			}
			report := d.Doctor(context.Background())
			if check := registryCheck(t, report); check.State != "blocked" || report.ExitCode() != 2 {
				t.Fatal(check, report)
			}
			if kind == "receipt" && len(images.calls) != 0 {
				t.Fatal("invalid receipt fell back to discovery", images.calls)
			}
		})
	}
}

// Opt-in development-host network acceptance; hosted source CI never enables it.
func TestDoctorActualPublicPinnedImages(t *testing.T) {
	revision := os.Getenv("FC_DOCTOR_PUBLIC_REVISION")
	if revision == "" {
		t.Skip("development-host public registry acceptance only")
	}
	if !release.ValidSHA(revision) {
		t.Fatal("exact public revision required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	images := release.NewRegistryClient()
	defer images.Close()
	d, runner := fixture(t)
	receipt, err := d.Install(ctx, revision, "amd64", fakeEvidence{true}, images)
	if err != nil {
		t.Fatal(err)
	}
	for name, service := range runner.config.Services {
		service.Image = receipt.ServiceImages[name]
		runner.config.Services[name] = service
	}
	runner.calls = nil
	runner.requireNoWrites = true
	d.ImageInspector = images
	report := d.Doctor(ctx)
	check := registryCheck(t, report)
	if check.State != "pass" || !strings.Contains(check.Reason, revision) {
		t.Fatal(check)
	}
	for _, call := range runner.calls {
		for _, forbidden := range []string{" pull ", " run ", " up ", " stop ", " exec "} {
			if strings.Contains(call, forbidden) {
				t.Fatal("doctor mutated", call)
			}
		}
	}
}
