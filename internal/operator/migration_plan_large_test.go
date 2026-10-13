package operator

import (
	"github.com/wongyiuming/FrontierCloud-Gin/internal/resourcemigration"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"strings"
	"testing"
)

func TestMigrationPlanClientAcceptsCompleteCountsAcrossBoundedPages(t *testing.T) {
	master := strings.Repeat("a", 32)
	v := resourcemigration.PlanView{ID: strings.Repeat("b", 32), RequestID: strings.Repeat("c", 32), State: "ready", ReviewSHA: strings.Repeat("d", 64), Source: store.StorageMember{ID: strings.Repeat("e", 32)}, Target: store.StorageMember{ID: strings.Repeat("f", 32)}, ObjectCount: 10008, UnitCount: 2, Bytes: 10008, VerifiedObjects: 10008, VerifiedBytes: 10008, CreatedAt: 10, ExpiresAt: 310, Complete: false}
	o := store.MigrationObject{ID: strings.Repeat("1", 64), Version: strings.Repeat("2", 64), Path: "music/large/one.mp3", TargetPath: "music/large/one.mp3", Bytes: 1, Resource: "media"}
	v.Objects = []store.MigrationObject{o}
	v.Next = o.ID
	if !validClientPlan(v, master, v.ID, "") {
		t.Fatal("valid large manifest rejected despite bounded page")
	}
	v.ObjectCount = v.Bytes + 1
	if validClientPlan(v, master, v.ID, "") {
		t.Fatal("impossible positive-byte count accepted")
	}
}
