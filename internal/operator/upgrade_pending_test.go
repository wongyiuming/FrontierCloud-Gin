package operator

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParameterlessRetryKeepsOriginalTargetAndRejectsCorruptJournal(t *testing.T) {
	d, r, _, _ := upgradeFixture(t)
	if target, err := d.PendingUpgradeTarget(r); err != nil || target != "" {
		t.Fatal(target, err)
	}
	for _, phase := range []string{"prepared_fenced", "failed_fenced", "opening", "opened"} {
		s := UpgradeState{Version: 1, Phase: phase, Plan: UpgradePlan{Target: strings.Repeat("b", 40)}}
		s.Plan.SHA256 = s.Plan.digest()
		if err := replaceJSON(filepath.Join(d.Directory, UpgradeJournal), s); err != nil {
			t.Fatal(err)
		}
		target, err := d.PendingUpgradeTarget(r)
		want := s.Plan.Target
		if phase == "opened" {
			want = ""
		}
		if err != nil || target != want {
			t.Fatal(phase, target, err)
		}
	}
	if err := os.WriteFile(filepath.Join(d.Directory, UpgradeJournal), []byte("broken"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := d.PendingUpgradeTarget(r); err == nil {
		t.Fatal("corrupt pending journal ignored")
	}
}
