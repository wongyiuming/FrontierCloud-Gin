package operator

import (
	"context"
	"errors"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/recovery"
	"os"
	"path/filepath"
	"testing"
)

func TestReceiptRejectsListenerDriftAndCanonicalizesDefaults(t *testing.T) {
	d, receipt, runner, _ := upgradeFixture(t)
	service := runner.config.Services["web"]
	for _, address := range []string{":9000", "127.0.0.1:8000"} {
		service.Environment["HTTP_ADDR"] = address
		runner.config.Services["web"] = service
		if _, e := d.ValidateReceipt(context.Background(), receipt); e == nil {
			t.Fatal("listener drift admitted", address)
		}
	}
	if listenLocation(nil) != listenLocation(map[string]string{"HTTP_ADDR": ":8000"}) {
		t.Fatal("business default listener")
	}
	if listenLocation(map[string]string{"DEPLOYMENT_MODE": "only_stroge", "STORAGE_TRANSPORT": "relay"}) != ":8443" {
		t.Fatal("relay default listener")
	}
}

func TestBackupReturnsLockReleaseFailureWithoutDiscardingVerifiedArchive(t *testing.T) {
	d, receipt, runner, _ := upgradeFixture(t)
	lock := filepath.Join(d.Directory, OperationLock)
	runner.onFact = func() {
		if e := os.WriteFile(filepath.Join(lock, "retained"), []byte("release failure fixture"), 0600); e != nil {
			t.Fatal(e)
		}
	}
	output := filepath.Join(t.TempDir(), "backup.tar")
	report, e := d.Backup(context.Background(), receipt, output, true, false)
	if !errors.Is(e, ErrOperationRelease) || !report.Verified {
		t.Fatal("release failure suppressed or completed archive lost", report, e)
	}
	if _, e := recovery.Check(context.Background(), output, report.SHA256); e != nil {
		t.Fatal(e)
	}
	if _, e := d.AcquireOperation(); e == nil {
		t.Fatal("failed release permitted concurrent mutation")
	}
}

func TestOperationReleasePreservesReplacementLock(t *testing.T) {
	d, _ := fixture(t)
	release, e := d.AcquireOperation()
	if e != nil {
		t.Fatal(e)
	}
	lock := filepath.Join(d.Directory, OperationLock)
	if e := os.Rename(lock, lock+".original"); e != nil {
		t.Fatal(e)
	}
	if e := os.Mkdir(lock, 0700); e != nil {
		t.Fatal(e)
	}
	if e := release(); !errors.Is(e, ErrOperationRelease) {
		t.Fatal("replacement lock removed", e)
	}
	if _, e := os.Stat(lock); e != nil {
		t.Fatal(e)
	}
}
