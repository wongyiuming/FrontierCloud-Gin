package media

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPeriodicUploadSweepReclaimsAbandonedStagesWithoutRestart(t *testing.T) {
	for _, role := range []string{"Standalone", "Master"} {
		t.Run(role, func(t *testing.T) {
			root, _, svc := deleteFixture(t)
			if role == "Master" {
				root, _, svc = masterFixture(t)
			}
			ctx := context.Background()
			abandoned := staged(t, svc, "ID3discarded-partial-payload")
			abandoned.retain = true
			abandoned.Close()
			live := staged(t, svc, "ID3still-uploading")
			temporary := ".upload-" + strings.Repeat("b", 32) + ".journal.tmp"
			leaseOnly := ".upload-" + strings.Repeat("c", 32) + ".lease"
			for _, name := range []string{temporary, leaseOnly} {
				if err := os.WriteFile(filepath.Join(root, name), []byte("orphan"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			unrelated := filepath.Join(root, ".upload-not-a-managed-id.part")
			if err := os.WriteFile(unrelated, []byte("unrelated"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := svc.RetryExpiredUploads(ctx); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(filepath.Join(root, abandoned.name)); !os.IsNotExist(err) {
				t.Fatal("abandoned partial bytes require a restart to reclaim", err)
			}
			for _, name := range []string{temporary, leaseOnly} {
				if _, err := os.Stat(filepath.Join(root, name)); !os.IsNotExist(err) {
					t.Fatal("dead staging metadata retained", name, err)
				}
			}
			for _, name := range []string{live.name, filepath.Base(unrelated)} {
				if _, err := os.Stat(filepath.Join(root, name)); err != nil {
					t.Fatal("live/committed/unknown evidence was removed", name, err)
				}
			}
			if err := svc.RetryExpiredUploads(ctx); err != nil {
				t.Fatal("cleanup replay", err)
			}
		})
	}
}

func TestPeriodicUploadSweepPreservesPublicationEvidence(t *testing.T) {
	root, _, svc := deleteFixture(t)
	pending := staged(t, svc, "ID3publication-evidence")
	pending.retain = true
	pending.Close()
	if err := os.WriteFile(filepath.Join(root, journalPath(pending.id)), []byte("retained-publication-evidence"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := svc.RetryExpiredUploads(context.Background()); err == nil {
		t.Fatal("pending publication did not retain its recovery fence")
	}
	for _, name := range []string{pending.name, journalPath(pending.id)} {
		if _, err := os.Stat(filepath.Join(root, name)); err != nil {
			t.Fatal("publication evidence removed", name, err)
		}
	}
}

func TestPeriodicUploadSweepDoesNotFollowStageSymlinks(t *testing.T) {
	root, _, svc := deleteFixture(t)
	external := filepath.Join(t.TempDir(), "external")
	if err := os.WriteFile(external, []byte("preserve"), 0600); err != nil {
		t.Fatal(err)
	}
	name := filepath.Join(root, ".upload-"+strings.Repeat("a", 32)+".part")
	if err := os.Symlink(external, name); err != nil {
		t.Skip(err)
	}
	if err := svc.RetryExpiredUploads(context.Background()); err == nil {
		t.Fatal("unsafe stage accepted")
	}
	if value, err := os.ReadFile(external); err != nil || string(value) != "preserve" {
		t.Fatal("external bytes changed", err)
	}
}
