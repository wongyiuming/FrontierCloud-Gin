package node

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

type opaqueFenceTestAuthority struct{}

func (opaqueFenceTestAuthority) Check(ctx context.Context) error { return ctx.Err() }
func (opaqueFenceTestAuthority) Release()                        {}

// This transport pauses a synthetic signed owner ACK; the repository and the
// concurrent relationship revocation are real. It does not simulate deletion.
type opaqueFenceTestTransport struct {
	ControlClient
	owner   *Service
	entered chan struct{}
	resume  chan struct{}
}

func (c *opaqueFenceTestTransport) Request(ctx context.Context, origin, route, method string, value any, relationship, credential string) (map[string]any, error) {
	if route != protocol.OpaqueRevokePath {
		return c.ControlClient.Request(ctx, origin, route, method, value, relationship, credential)
	}
	payload, ok := value.(map[string]any)
	if !ok {
		return nil, errors.New("invalid fixture payload")
	}
	close(c.entered)
	select {
	case <-c.resume:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	identity, err := c.owner.repo.ReadIdentity(ctx)
	if err != nil {
		return nil, err
	}
	signed, err := c.owner.identity.signed(identity, payload)
	if err != nil {
		return nil, err
	}
	return signed.wire(), nil
}

func TestOpaqueOwnerRequestFencesRelationshipRevocation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	transport := &localControl{nodes: map[string]*Service{}}
	master, masterDB := testNode(t, "Master", "https://master.test", transport)
	owner, _ := testNode(t, "Follower", "https://owner.test", transport)
	transport.nodes["https://master.test"] = master
	transport.nodes["https://owner.test"] = owner
	if err := master.ConfigurePublicOrigin("https://public.test"); err != nil {
		t.Fatal(err)
	}
	pair, err := owner.CreatePair(ctx, store.NodeAudit{Actor: "test"})
	if err != nil {
		t.Fatal(err)
	}
	relationID, err := master.ImportPair(ctx, pair, store.NodeAudit{Actor: "test"})
	if err != nil {
		t.Fatal(err)
	}
	relation, err := master.repo.Relationship(ctx, relationID)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := master.repo.ReadIdentity(ctx)
	if err != nil {
		t.Fatal(err)
	}
	binding := opaqueRelationshipBinding(relation)
	receipt := protocol.OpaqueRevocationReceipt{
		Kind: "opaque-alias-revoke-v1", OperationID: strings.Repeat("a", 32),
		MasterID: identity.ID, OwnerID: relation.PeerID, RelationshipID: relationID,
		Alias: strings.Repeat("b", 64), Blob: strings.Repeat("c", 64),
		Revision: strings.Repeat("d", 64), State: "revoked",
	}
	paused := &opaqueFenceTestTransport{ControlClient: transport, owner: owner, entered: make(chan struct{}), resume: make(chan struct{})}
	master.transport = paused
	authorityCtx := store.WithOpaqueControlAuthority(ctx, binding, opaqueFenceTestAuthority{})
	requestDone := make(chan error, 1)
	go func() {
		_, err := master.RequestOpaqueOwnerRevocationReceipt(authorityCtx, receipt, binding)
		requestDone <- err
	}()
	select {
	case <-paused.entered:
	case <-ctx.Done():
		t.Fatal("owner request did not enter transport")
	}
	revocationDone := make(chan error, 1)
	go func() {
		revocationDone <- masterDB.Nodes().RevokeRelationship(ctx, relationID, true, store.NodeAudit{Actor: "test"})
	}()
	select {
	case err := <-revocationDone:
		t.Fatalf("relationship changed while owner request held the fence: %v", err)
	case <-time.After(150 * time.Millisecond):
	}
	close(paused.resume)
	if err := <-requestDone; err != nil {
		t.Fatalf("signed owner response: %v", err)
	}
	if err := <-revocationDone; err != nil {
		t.Fatalf("relationship revocation after fence release: %v", err)
	}
	if _, err := master.RequestOpaqueOwnerRevocationReceipt(authorityCtx, receipt, binding); err == nil {
		t.Fatal("revoked relationship accepted another owner request")
	}
}
