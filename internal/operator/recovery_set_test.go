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

	"github.com/wongyiuming/FrontierCloud-Gin/internal/maintenance"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/recovery"
)

func recoverySetFixture(t *testing.T) ([]RecoveryDeployment, []*upgradeRunner) {
	t.Helper()
	a, ar, aa, _ := upgradeFixture(t)
	b, br, bb, _ := upgradeFixture(t)
	aa.node = strings.Repeat("1", 32)
	bb.node = strings.Repeat("2", 32)
	aa.role = "Master"
	bb.role = "Follower"
	aa.relations = []NodeFact{{NodeID: bb.node, Direction: "downstream", State: "active", Protocol: 2}}
	bb.relations = []NodeFact{{NodeID: aa.node, Direction: "upstream", State: "active", Protocol: 2}}
	b.Role = "storage"
	b.Files = []string{"docker-compose.storage.yaml"}
	br.Role = "storage"
	br.Files = b.Files
	bb.config.Name = "fc-test-storage"
	br.Project = bb.config.Name
	br.SelectionHash = selectionHash(bb.config)
	if e := os.WriteFile(filepath.Join(b.Directory, b.Files[0]), []byte("services: {}\n"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := replaceJSON(filepath.Join(b.Directory, ReceiptFile), br); e != nil {
		t.Fatal(e)
	}
	return []RecoveryDeployment{{a, ar}, {b, br}}, []*upgradeRunner{aa, bb}
}

func TestRecoverySetHoldsAllNativeLeasesThroughRealArchiveCapture(t *testing.T) {
	items, runners := recoverySetFixture(t)
	ctx := context.Background()
	verifiedLeases := 0
	for _, runner := range runners {
		runner.onFact = func() {
			if !runners[0].stopped || !runners[1].stopped {
				return
			}
			for _, peer := range runners {
				gate, e := maintenance.Open(peer.data)
				if e != nil {
					t.Fatal(e)
				}
				attempt, cancel := context.WithTimeout(ctx, 5*time.Millisecond)
				e = gate.Resume(attempt, func(context.Context) error { return nil })
				cancel()
				gate.Close()
				if !errors.Is(e, context.DeadlineExceeded) {
					t.Fatal("common freeze interval was not held", e)
				}
				verifiedLeases++
			}
		}
	}
	output := filepath.Join(t.TempDir(), "set")
	report, e := BackupSet(ctx, items, output, runners[0].node, true, false)
	if e != nil {
		t.Fatal(e)
	}
	if !report.CompleteCluster || !report.Verified || report.BusinessVerified || verifiedLeases < 4 {
		t.Fatal(report, verifiedLeases)
	}
	checked, e := recovery.CheckSet(ctx, output, report.SHA256)
	if e != nil || !checked.CompleteCluster {
		t.Fatal(checked, e)
	}
	for _, member := range report.Manifest.Members {
		archive := filepath.Join(output, member.Archive)
		individual, e := recovery.Check(ctx, archive, member.SHA256)
		if e != nil {
			t.Fatal(e)
		}
		if individual.Manifest.CompleteCluster || len(individual.Manifest.Missing) != 1 {
			t.Fatal("single archive promoted to whole-cluster proof")
		}
		if _, e = recovery.Apply(ctx, archive, filepath.Join(t.TempDir(), "unsafe-single"), member.SHA256, member.NodeID); e == nil {
			t.Fatal("single-member restoration bypassed required peer")
		}
	}
	target := filepath.Join(t.TempDir(), "restored-set")
	if _, e = recovery.ApplySet(ctx, output, target, report.SHA256, runners[0].node); e != nil {
		t.Fatal(e)
	}
	for _, member := range report.Manifest.Members {
		actual, e := os.ReadFile(filepath.Join(target, member.NodeID, "data", "media", "music", "actual.mp3"))
		if e != nil || string(actual) != "ID3-actual-recovery-bytes" {
			t.Fatal("lost member payload", e)
		}
		if _, e = os.Stat(filepath.Join(target, member.NodeID, "data", maintenance.Marker)); e != nil {
			t.Fatal("lost native fence", e)
		}
		d := &Deployment{Directory: filepath.Join(target, member.NodeID, "deployment")}
		if _, e = d.ActivateRestore(ctx, Receipt{}, member.NodeID, true); e == nil {
			t.Fatal("individual activation admitted a cluster member")
		}
	}
}

func TestRecoverySetRejectsIncompleteForeignAndChangingRostersBeforeCapture(t *testing.T) {
	for _, kind := range []string{"missing-member", "foreign-master", "pending-peer", "wrong-confirmation", "duplicate-project"} {
		t.Run(kind, func(t *testing.T) {
			items, runners := recoverySetFixture(t)
			master := runners[0].node
			switch kind {
			case "missing-member":
				runners[0].relations = append(runners[0].relations, NodeFact{NodeID: strings.Repeat("3", 32), Direction: "downstream", State: "active", Protocol: 2})
			case "foreign-master":
				runners[1].relations[0].NodeID = strings.Repeat("3", 32)
			case "pending-peer":
				runners[0].relations[0].State = "pending"
			case "wrong-confirmation":
				master = strings.Repeat("3", 32)
			case "duplicate-project":
				runners[1].config.Name = runners[0].config.Name
				items[1].Receipt.Project = items[0].Receipt.Project
				items[1].Receipt.SelectionHash = selectionHash(runners[1].config)
			}
			output := filepath.Join(t.TempDir(), "set")
			if _, e := BackupSet(context.Background(), items, output, master, true, false); e == nil {
				t.Fatal("incomplete set admitted")
			}
			if _, e := os.Stat(output); !os.IsNotExist(e) {
				t.Fatal("created incomplete set", e)
			}
			for _, runner := range runners {
				if _, e := os.Stat(filepath.Join(runner.data, maintenance.Marker)); !os.IsNotExist(e) {
					t.Fatal("froze before roster approval", e)
				}
			}
		})
	}
}

func TestRecoverySetRejectsCorruptedMemberArchive(t *testing.T) {
	items, runners := recoverySetFixture(t)
	output := filepath.Join(t.TempDir(), "set")
	report, e := BackupSet(context.Background(), items, output, runners[0].node, true, false)
	if e != nil {
		t.Fatal(e)
	}
	member := report.Manifest.Members[0]
	f, e := os.OpenFile(filepath.Join(output, member.Archive), os.O_RDWR, 0600)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.WriteAt([]byte("corrupted"), 1024); e != nil {
		t.Fatal(e)
	}
	f.Close()
	if _, e = recovery.CheckSet(context.Background(), output, report.SHA256); e == nil {
		t.Fatal("corrupted member accepted")
	}
}

func TestRecoverySetRejectsMatchingIdentityFromDifferentFreezeInterval(t *testing.T) {
	items, runners := recoverySetFixture(t)
	ctx := context.Background()
	first := filepath.Join(t.TempDir(), "first")
	second := filepath.Join(t.TempDir(), "second")
	a, e := BackupSet(ctx, items, first, runners[0].node, true, false)
	if e != nil {
		t.Fatal(e)
	}
	b, e := BackupSet(ctx, items, second, runners[0].node, true, false)
	if e != nil {
		t.Fatal(e)
	}
	if a.Manifest.ID == b.Manifest.ID {
		t.Fatal("freeze ID reused")
	}
	// Even updating the outer checksum for a valid archive with the same node
	// identity cannot erase its embedded different common-freeze set identity.
	member := b.Manifest.Members[0]
	raw, e := os.ReadFile(filepath.Join(second, member.Archive))
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(first, member.Archive), raw, 0600); e != nil {
		t.Fatal(e)
	}
	for i := range a.Manifest.Members {
		if a.Manifest.Members[i].NodeID == member.NodeID {
			a.Manifest.Members[i] = member
		}
	}
	raw, e = json.Marshal(a.Manifest)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(first, recovery.SetFile), raw, 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = recovery.CheckSet(ctx, first, ""); e == nil {
		t.Fatal("archives from separate freezes combined")
	}
}
