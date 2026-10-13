package operator

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRecoveredProjectSelectionCannotFollowArchivedProjectEnvironment(t *testing.T) {
	d, _ := fixture(t)
	d.Files = []string{RecoveredCompose}
	d.Project = "fc-target"
	args := strings.Join(d.composeArgs(true), " ")
	if !strings.Contains(args, "--project-name fc-target") || !strings.Contains(args, RecoveredCompose) {
		t.Fatal(args)
	}
}
func TestRestoreActivationNeverStartsUnboundOrUnconfirmedIdentity(t *testing.T) {
	d, r := fixture(t)
	_, e := d.ActivateRestore(context.Background(), Receipt{}, "", false)
	if e == nil {
		t.Fatal("unbound restore admitted")
	}
	for _, call := range r.calls {
		if strings.Contains(call, " up ") || strings.Contains(call, "maintenance resume") {
			t.Fatal("started before confirmation/binding", call)
		}
	}
}
func TestRestoreOpenCannotRemovePriorAdministratorMaintenance(t *testing.T) {
	d, r := fixture(t)
	manual := filepath.Join(d.Directory, ".frontiercloud-maintenance")
	if e := os.WriteFile(manual, []byte("manual\n"), 0600); e != nil {
		t.Fatal(e)
	}
	_, e := d.OpenRestore(context.Background(), Receipt{}, strings.Repeat("a", 32))
	if e == nil {
		t.Fatal("unverified restore opened")
	}
	content, e := os.ReadFile(manual)
	if e != nil || string(content) != "manual\n" {
		t.Fatal("prior manual state changed", e)
	}
	for _, call := range r.calls {
		if strings.Contains(call, "maintenance resume") {
			t.Fatal(call)
		}
	}
}
