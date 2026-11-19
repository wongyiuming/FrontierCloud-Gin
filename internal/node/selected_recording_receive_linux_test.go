//go:build linux

package node

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func TestSelectedRecordingRequiresCurrentObservedIngress(t *testing.T) {
	ctx := context.Background()
	service, repo := ingressTestService(t, "Follower")
	relation := store.Relationship{ID: strings.Repeat("a", 32), PeerID: strings.Repeat("b", 32), Direction: "upstream", State: "active", Protocol: protocol.Version}
	repo.relation = relation
	claim := protocol.SelectedStorageUpload{
		Relationship: relation.ID, Master: relation.PeerID, AdminOrigin: "https://entry.test",
		RecordingIngressNode: strings.Repeat("c", 32), RecordingIngressGeneration: 9,
	}
	check := func(c protocol.SelectedStorageUpload, origin string, allowed bool) {
		t.Helper()
		if got := service.recordingOriginAuthorized(ctx, c, origin); got != allowed {
			t.Fatalf("origin admission = %t, want %t", got, allowed)
		}
	}
	observe := func(generation int64) {
		service.observePeerIngress(ctx, relation, map[string]any{
			"node_id": claim.RecordingIngressNode, "public_origin": claim.AdminOrigin, "generation": generation,
		})
	}
	check(claim, claim.AdminOrigin, false)
	observe(9)
	check(claim, claim.AdminOrigin, true)
	check(claim, "https://other.test", false)
	for _, change := range []func(*protocol.SelectedStorageUpload){
		func(v *protocol.SelectedStorageUpload) { v.Relationship = strings.Repeat("d", 32) },
		func(v *protocol.SelectedStorageUpload) { v.Master = strings.Repeat("d", 32) },
		func(v *protocol.SelectedStorageUpload) { v.RecordingIngressNode = strings.Repeat("d", 32) },
		func(v *protocol.SelectedStorageUpload) { v.AdminOrigin = "https://other.test" },
	} {
		changed := claim
		change(&changed)
		check(changed, claim.AdminOrigin, false)
	}
	observe(10)
	check(claim, claim.AdminOrigin, false)
	claim.RecordingIngressGeneration = 10
	check(claim, claim.AdminOrigin, true)
	service.peerIngressMu.Lock()
	service.peerIngress.observedAt = time.Now().Add(-peerIngressObservationTTL)
	service.peerIngressMu.Unlock()
	check(claim, claim.AdminOrigin, false)
}
