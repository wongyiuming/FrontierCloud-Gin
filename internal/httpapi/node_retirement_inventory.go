package httpapi

import (
	"context"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/migrationdata"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/resourceinventory"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"os"
)

func retirementCheckpointInventory(ctx context.Context, root *os.Root, repository store.PhysicalInventoryRepository, relationship, member, master, scope string, entry resourceinventory.Entry, fact store.PhysicalInventoryFact) (store.PhysicalInventoryFact, bool) {
	if fact.Category != "migration_material" {
		return fact, false
	}
	repo, ok := repository.(store.RetirementMigrationRepository)
	if !ok {
		return fact, false
	}
	resource := "media"
	if scope == "recordings" {
		resource = "recording"
	}
	receiver, e := migrationdata.New(root, member, resource)
	if e != nil {
		return fact, false
	}
	observed, handled := receiver.InventoryTerminal(ctx, entry, func(spec migrationdata.Spec, state string) error {
		v, e := repo.RetirementMigration(ctx, relationship, member, master, spec.TaskID, spec.LogicalID)
		if e != nil {
			return e
		}
		request := migrationDataRequest{Spec: spec, Lease: store.MigrationLease{TaskID: spec.TaskID}}
		if !migrationRequestMatches(request, v) || state == "aborted" && v.State != "aborted" || state == "published" && v.State != "published" && v.State != "deleted" {
			return store.ErrMigrationState
		}
		return nil
	})
	if !handled {
		return fact, false
	}
	return observed, true
}
