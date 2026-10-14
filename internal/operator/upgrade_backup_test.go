package operator

import (
	"bytes"
	"context"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/recovery"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUpgradeAlwaysExcludesBusinessFilesAndKeepsDatabaseState(t *testing.T) {
	d, r, runner, p := upgradeFixture(t)
	lyrics := filepath.Join(runner.data, "lyrics")
	if e := os.Mkdir(lyrics, 0700); e != nil {
		t.Fatal(e)
	}
	payload := []byte("unique-lyric-business-payload")
	if e := os.WriteFile(filepath.Join(lyrics, "song.lrc"), payload, 0600); e != nil {
		t.Fatal(e)
	}
	media := filepath.Join(runner.data, "media", "music", "large.mp3")
	f, e := os.Create(media)
	if e != nil {
		t.Fatal(e)
	}
	e = f.Truncate(20 << 30)
	f.Close()
	if e != nil {
		t.Fatal(e)
	}
	output := filepath.Join(t.TempDir(), "state.tar")
	capacity, e := d.UpgradeBackupCapacity(context.Background(), r, output)
	if e != nil || !capacity.Fits || capacity.BusinessFilesIncluded || capacity.Scope != recovery.UpgradeStateScope || capacity.DataBytes > 1<<20 {
		t.Fatal(capacity, e)
	}
	state, e := d.ApplyUpgrade(context.Background(), r, p, p.SHA256, p.NodeID, output, false, fakeEvidence{true}, upgradeImages{})
	if e != nil {
		t.Fatal(e)
	}
	checked, e := recovery.Check(context.Background(), output, state.BackupSHA)
	if e != nil || checked.Manifest.Scope != recovery.UpgradeStateScope || checked.Manifest.CompleteCluster || checked.RestoreReady {
		t.Fatal(checked, e)
	}
	database := false
	for _, entry := range checked.Manifest.Files {
		if strings.HasPrefix(entry.Path, "data/media/") || strings.HasPrefix(entry.Path, "data/lyrics/") {
			t.Fatal("business file copied", entry.Path)
		}
		if entry.Path == "data/frontiercloud.db" {
			database = true
		}
	}
	if !database {
		t.Fatal("database omitted")
	}
	raw, e := os.ReadFile(output)
	if e != nil || bytes.Contains(raw, payload) || bytes.Contains(raw, []byte("ID3-actual-recovery-bytes")) {
		t.Fatal("business bytes present", e)
	}
	info, e := os.Stat(media)
	if e != nil || info.Size() != 20<<30 {
		t.Fatal("media changed", e)
	}
	current, e := os.ReadFile(filepath.Join(lyrics, "song.lrc"))
	if e != nil || !bytes.Equal(current, payload) {
		t.Fatal("lyrics changed", e)
	}
	if _, e = RestoreCheck(context.Background(), output, filepath.Join(t.TempDir(), "fresh"), state.BackupSHA); e == nil {
		t.Fatal("state-only recovery claimed fresh deployment restore")
	}
}

func TestUpgradeRejectsLegacyFullDataPlanAndUnsafeSQLiteSelection(t *testing.T) {
	d, r, runner, p := upgradeFixture(t)
	p.RecoveryScope = ""
	p.SHA256 = p.digest()
	runner.calls = nil
	if _, e := d.ApplyUpgrade(context.Background(), r, p, p.SHA256, p.NodeID, filepath.Join(t.TempDir(), "new.tar"), false, fakeEvidence{true}, upgradeImages{}); e == nil || len(runner.calls) != 0 {
		t.Fatal("legacy full backup admitted", e, runner.calls)
	}
	cfg := runner.config
	cfg.Services["web"].Environment["SQLITE_PATH"] = "/outside/database.db"
	if _, e := upgradeDataSelection(cfg, r); e == nil {
		t.Fatal("unrecorded state root accepted")
	}
}
