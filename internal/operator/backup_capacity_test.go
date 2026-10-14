package operator

import (
	"context"
	"fmt"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/recovery"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestBackupCapacityIsReadOnlyAndIncludesActualManagedRoots(t *testing.T) {
	d, r, runner, _ := upgradeFixture(t)
	runner.calls = nil
	before, err := os.ReadDir(d.Directory)
	if err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "new.tar")
	p, err := d.BackupCapacity(context.Background(), r, output)
	if err != nil || !p.Fits || p.DataBytes < 1 || p.ScratchBytes < 1 || p.ArchiveBytes <= p.DataBytes || p.RequiredBytes <= p.ArchiveBytes || !p.ReadOnly {
		t.Fatal(p, err)
	}
	after, err := os.ReadDir(d.Directory)
	if err != nil || len(before) != len(after) {
		t.Fatal("capacity inspection wrote state", err)
	}
	if _, err = os.Lstat(output); !os.IsNotExist(err) {
		t.Fatal("output created", err)
	}
	for _, call := range runner.calls {
		if strings.Contains(call, " run ") && strings.Contains(call, "--pull never -T web operator-status") {
			continue
		}
		for _, bad := range []string{" pull ", " run ", " up ", " stop ", "maintenance enter"} {
			if strings.Contains(call, bad) {
				t.Fatal("capacity froze or started a writer", call)
			}
		}
	}
}

func TestInvalidMySQLBackupDoesNotInspectOrDumpBeforeConfirmation(t *testing.T) {
	d, r, runner, _ := upgradeFixture(t)
	r.Database = "mysql"
	runner.calls = nil
	if _, err := d.Backup(context.Background(), r, filepath.Join(t.TempDir(), "new.tar"), true, false); err == nil || !strings.Contains(err.Error(), "explicit confirmation") {
		t.Fatal(err)
	}
	if len(runner.calls) != 0 {
		t.Fatal("invalid backup performed I/O", runner.calls)
	}
	if _, err := os.Lstat(filepath.Join(d.Directory, OperationLock)); !os.IsNotExist(err) {
		t.Fatal("invalid backup took operation lock", err)
	}
}

func TestManifestBudgetRejectsLongEscapedMetadataWithinEntryCountLimit(t *testing.T) {
	p := BackupCapacity{}
	entry := recovery.Entry{Path: "data/" + strings.Repeat("<", 3000), SHA256: strings.Repeat("0", 64), Mode: 0600}
	for i := 0; i < 2000; i++ {
		if err := p.addManifestMetadata(entry); err != nil {
			if p.ManifestBytes <= recovery.MaxManifest || i >= recovery.MaxFiles {
				t.Fatal(p, err)
			}
			return
		}
	}
	t.Fatal("oversized escaped manifest accepted")
}

func TestOversizedSourceManifestRefusesBackupBeforeFreeze(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux host operator path boundary")
	}
	d, r, runner, _ := upgradeFixture(t)
	directory := runner.data
	for i := 0; i < 16; i++ {
		directory = filepath.Join(directory, strings.Repeat("<", 190))
		if err := os.Mkdir(directory, 0700); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 1100; i++ {
		if err := os.WriteFile(filepath.Join(directory, fmt.Sprintf("entry-%04d", i)), nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	runner.calls = nil
	output := filepath.Join(t.TempDir(), "new.tar")
	if _, err := d.Backup(context.Background(), r, output, true, false); err == nil || !strings.Contains(err.Error(), "manifest metadata exceeds") {
		t.Fatal(err)
	}
	for _, call := range runner.calls {
		if strings.Contains(call, "maintenance enter") || strings.Contains(call, " stop ") {
			t.Fatal("oversized manifest stopped source", call)
		}
	}
	if _, err := os.Lstat(output); !os.IsNotExist(err) {
		t.Fatal("archive created", err)
	}
}

func TestGeneratedScratchDirectoriesCountAgainstArchiveLimit(t *testing.T) {
	for _, database := range []string{"sqlite", "mysql"} {
		p := BackupCapacity{Directories: recovery.MaxFiles - 1}
		for i := 0; i < generatedBackupDirectories(database); i++ {
			if err := p.addSourceDirectory(); (err != nil) != (i > 0) {
				t.Fatal(database, p, err)
			}
		}
		if err := p.addSourceDirectory(); err == nil {
			t.Fatal("generated roots omitted from limit", database)
		}
	}
}

func TestRecoverySetAggregatesAllArchivesBeforeAnyMemberFreeze(t *testing.T) {
	items, runners := recoverySetFixture(t)
	output := filepath.Join(t.TempDir(), "new-set")
	first, err := items[0].Deployment.BackupCapacity(context.Background(), items[0].Receipt, filepath.Join(filepath.Dir(output), "probe.tar"))
	if err != nil {
		t.Fatal(err)
	}
	for i, item := range items {
		f, e := os.Create(filepath.Join(runners[i].data, "sparse-state.dat"))
		if e != nil {
			t.Fatal(e)
		}
		e = f.Truncate(int64(first.FreeBytes * 55 / 100))
		f.Close()
		if e != nil {
			t.Fatal(e)
		}
		p, e := item.Deployment.BackupCapacity(context.Background(), item.Receipt, filepath.Join(filepath.Dir(output), "probe.tar"))
		if e != nil || !p.Fits {
			t.Fatal("individual archive should fit", p, e)
		}
		runners[i].calls = nil
	}
	if _, err = BackupSet(context.Background(), items, output, runners[0].node, true, false); err == nil || !strings.Contains(err.Error(), "capacity insufficient") {
		t.Fatal(err)
	}
	for _, runner := range runners {
		for _, call := range runner.calls {
			if strings.Contains(call, "maintenance enter") || strings.Contains(call, " stop ") {
				t.Fatal("capacity stopped member", call)
			}
		}
	}
	if _, err = os.Lstat(output); !os.IsNotExist(err) {
		t.Fatal("capacity created set output", err)
	}
}

type liveGrowthRunner struct {
	*upgradeRunner
	directory string
	size      int64
	grown     bool
}

func (r *liveGrowthRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	if !r.grown && strings.Contains(strings.Join(args, " "), "config --format json") {
		if _, err := os.Lstat(filepath.Join(r.directory, UpgradeJournal)); err == nil {
			f, e := os.Create(filepath.Join(r.data, "growth-after-preflight.dat"))
			if e != nil {
				return nil, e
			}
			e = f.Truncate(r.size)
			f.Close()
			if e != nil {
				return nil, e
			}
			r.grown = true
		}
	}
	return r.upgradeRunner.Run(ctx, name, args...)
}

func TestCapacityGrowthAfterJournalIsRecheckedOnlyUnderActualFreeze(t *testing.T) {
	d, r, base, p := upgradeFixture(t)
	output := filepath.Join(t.TempDir(), "new.tar")
	capacity, e := d.BackupCapacity(context.Background(), r, output)
	if e != nil {
		t.Fatal(e)
	}
	runner := &liveGrowthRunner{upgradeRunner: base, directory: d.Directory, size: int64(capacity.FreeBytes) + (1 << 30)}
	d.Runner = runner
	state, e := d.ApplyUpgrade(context.Background(), r, p, p.SHA256, p.NodeID, output, false, fakeEvidence{true}, upgradeImages{})
	if e == nil || !runner.grown || state.Phase != "failed_fenced" {
		t.Fatal(state, e)
	}
	entered := false
	for _, call := range base.calls {
		if strings.Contains(call, "maintenance enter --wait-seconds 120") {
			entered = true
		}
	}
	if !entered {
		t.Fatal("capacity refusal jumped directly into failure fencing before the requested freeze")
	}
}

func TestInsufficientBackupCapacityRefusesUpgradeBeforeFreezeOrJournal(t *testing.T) {
	d, r, runner, plan := upgradeFixture(t)
	output := filepath.Join(t.TempDir(), "new.tar")
	p, err := d.BackupCapacity(context.Background(), r, output)
	if err != nil {
		t.Fatal(err)
	}
	// A sparse source proves that capacity counts logical archive bytes, not blocks.
	f, err := os.Create(filepath.Join(runner.data, "huge.dat"))
	if err != nil {
		t.Fatal(err)
	}
	err = f.Truncate(int64(p.FreeBytes) + (1 << 30))
	f.Close()
	if err != nil {
		t.Fatal(err)
	}
	runner.calls = nil
	if _, err = d.ApplyUpgrade(context.Background(), r, plan, plan.SHA256, plan.NodeID, output, false, fakeEvidence{true}, upgradeImages{}); err == nil || !strings.Contains(err.Error(), "capacity insufficient") {
		t.Fatal(err)
	}
	for _, call := range runner.calls {
		if strings.Contains(call, "maintenance enter") || strings.Contains(call, " stop ") {
			t.Fatal("capacity failure stopped source", call)
		}
	}
	for _, name := range []string{UpgradeJournal, OperationLock} {
		if _, err = os.Lstat(filepath.Join(d.Directory, name)); !os.IsNotExist(err) {
			t.Fatal("capacity failure left state", name, err)
		}
	}
}

func TestBackupCapacityRejectsOutputInsideSourceAndUnsafeEntries(t *testing.T) {
	for _, kind := range []string{"inside", "existing", "link", "missing-parent"} {
		t.Run(kind, func(t *testing.T) {
			d, r, runner, _ := upgradeFixture(t)
			output := filepath.Join(t.TempDir(), "new.tar")
			switch kind {
			case "inside":
				output = filepath.Join(runner.data, "new.tar")
			case "existing":
				if err := os.WriteFile(output, []byte("keep"), 0600); err != nil {
					t.Fatal(err)
				}
			case "link":
				if err := os.Symlink("/outside", filepath.Join(runner.data, "unsafe")); err != nil {
					t.Fatal(err)
				}
			case "missing-parent":
				output = filepath.Join(t.TempDir(), "missing", "new.tar")
			}
			if _, err := d.BackupCapacity(context.Background(), r, output); err == nil {
				t.Fatal("unsafe capacity proof accepted", kind)
			}
		})
	}
}
