package business_test

import (
	"context"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"strings"
	"testing"
)

func TestPeerRetirementFenceCannotBeErasedByIdentityReset(t *testing.T) {
	db, _, _, rel, h, _, _ := peerMigrationFixture(t, false)
	ctx := context.Background()
	repo := db.Pool().(store.RetirementFenceRepository)
	before, e := repo.BeginRetirement(ctx, rel, h.TargetID, store.NodeAudit{})
	if e != nil {
		t.Fatal(e)
	}
	next := store.NodeIdentity{ID: strings.Repeat("9", 32), Role: "Standalone", PrivateKey: "unused-test-ciphertext"}
	if _, e = db.Nodes().ResetIdentity(ctx, h.TargetID, "Follower", next, store.NodeAudit{}); e == nil {
		t.Fatal("identity reset bypassed pending retirement")
	}
	after, e := repo.RetirementFence(ctx, rel, h.TargetID)
	if e != nil || after != before {
		t.Fatal("fence changed on failed reset", after, e)
	}
}
