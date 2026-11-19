package preprodimport

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

func TestSyntheticSnapshotPlanRequiresEverySameGenerationBatch(t *testing.T) {
	s, _, target, sourcePub, sourcePriv, now := keyGrantFixture(t)
	one := snapshotGrantEntry{MediaID: s.MediaID, SourceObjectID: s.SourceObjectID, TargetOwnerID: s.TargetOwnerID, TargetBlobID: s.TargetBlobID, TargetReadAlias: s.TargetReadAlias, ContentSHA256: s.ContentSHA256, StoredBytes: s.StoredBytes, Challenge: s.Challenge, Descriptor: s.Descriptor}
	two := one
	two.MediaID = strings.Repeat("6", 64)
	two.SourceObjectID = strings.Repeat("7", 64)
	two.TargetBlobID = strings.Repeat("c", 64)
	two.TargetReadAlias = strings.Repeat("d", 64)
	two.Challenge = strings.Repeat("f", 64)
	two.Descriptor.FileID = strings.Repeat("d", 32)
	base := snapshotGrantBody{Version: 1, SourceNode: s.SourceNode, SourceKeyID: s.SourceKeyID, TargetNode: s.TargetNode, TargetPublic: target.PublicKey().Bytes(), Generation: strings.Repeat("e", 64), BatchCount: 2, IssuedUnix: s.IssuedUnix, ExpiresUnix: s.ExpiresUnix}
	first := base
	first.Entries = []snapshotGrantEntry{one}
	second := base
	second.BatchIndex = 1
	second.Entries = []snapshotGrantEntry{two}
	makePlan := func(a, b snapshotGrantBody) (signedSnapshotPlan, []signedSnapshotGrant) {
		t.Helper()
		ga, err := signApprovedSnapshot(a, sourcePriv, now)
		if err != nil {
			t.Fatal(err)
		}
		gb, err := signApprovedSnapshot(b, sourcePriv, now)
		if err != nil {
			t.Fatal(err)
		}
		da, err := snapshotGrantDigest(a, now)
		if err != nil {
			t.Fatal(err)
		}
		db, err := snapshotGrantDigest(b, now)
		if err != nil {
			t.Fatal(err)
		}
		body := snapshotPlanBody{Version: 1, SourceNode: base.SourceNode, SourceKeyID: base.SourceKeyID, TargetNode: base.TargetNode, TargetPublic: base.TargetPublic, Generation: base.Generation, IssuedUnix: base.IssuedUnix, ExpiresUnix: base.ExpiresUnix, Batches: []snapshotPlanBatch{{Digest: hex.EncodeToString(da), Count: len(a.Entries)}, {Digest: hex.EncodeToString(db), Count: len(b.Entries)}}}
		p, err := signApprovedSnapshotPlan(body, sourcePriv, now)
		if err != nil {
			t.Fatal(err)
		}
		return p, []signedSnapshotGrant{ga, gb}
	}
	plan, batches := makePlan(first, second)
	if err := verifyCompleteSnapshotPlan(plan, batches, sourcePub, target.PublicKey().Bytes(), now); err != nil {
		t.Fatal(err)
	}
	if err := verifyCompleteSnapshotPlan(plan, batches[:1], sourcePub, target.PublicKey().Bytes(), now); err == nil {
		t.Fatal("missing batch accepted")
	}
	if err := verifyCompleteSnapshotPlan(plan, []signedSnapshotGrant{batches[1], batches[0]}, sourcePub, target.PublicKey().Bytes(), now); err == nil {
		t.Fatal("reordered batches accepted")
	}
	other := second
	other.Generation = strings.Repeat("f", 64)
	mixed, mixedBatches := makePlan(first, other)
	if err := verifyCompleteSnapshotPlan(mixed, mixedBatches, sourcePub, target.PublicKey().Bytes(), now); err == nil {
		t.Fatal("cross-generation plan accepted")
	}
	duplicate := second
	duplicate.Entries = append([]snapshotGrantEntry(nil), second.Entries...)
	duplicate.Entries[0].SourceObjectID = one.SourceObjectID
	dupPlan, dupBatches := makePlan(first, duplicate)
	if err := verifyCompleteSnapshotPlan(dupPlan, dupBatches, sourcePub, target.PublicKey().Bytes(), now); err == nil {
		t.Fatal("cross-batch source duplicate accepted")
	}
	collision := second
	collision.Entries = append([]snapshotGrantEntry(nil), second.Entries...)
	collision.Entries[0].TargetBlobID = one.MediaID
	collisionPlan, collisionBatches := makePlan(first, collision)
	if err := verifyCompleteSnapshotPlan(collisionPlan, collisionBatches, sourcePub, target.PublicKey().Bytes(), now); err == nil {
		t.Fatal("cross-batch historical locator collision accepted")
	}
	aliasCollision := second
	aliasCollision.Entries = append([]snapshotGrantEntry(nil), second.Entries...)
	aliasCollision.Entries[0].TargetReadAlias = one.TargetBlobID
	aliasPlan, aliasBatches := makePlan(first, aliasCollision)
	if err := verifyCompleteSnapshotPlan(aliasPlan, aliasBatches, sourcePub, target.PublicKey().Bytes(), now); err == nil {
		t.Fatal("cross-batch alias/blob collision accepted")
	}
	wrongSource, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err = verifyCompleteSnapshotPlan(plan, batches, wrongSource, target.PublicKey().Bytes(), now); err == nil {
		t.Fatal("untrusted source pin accepted")
	}
	wrongTarget, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err = verifyCompleteSnapshotPlan(plan, batches, sourcePub, wrongTarget.PublicKey().Bytes(), now); err == nil {
		t.Fatal("wrong target pin accepted")
	}
	if err := verifyCompleteSnapshotPlan(plan, batches, sourcePub, target.PublicKey().Bytes(), now.Add(6*time.Minute)); err == nil {
		t.Fatal("expired plan authorized")
	}
	corrupt := plan
	corrupt.Signature = append([]byte(nil), plan.Signature...)
	corrupt.Signature[0] ^= 1
	if err := verifyCompleteSnapshotPlan(corrupt, batches, sourcePub, target.PublicKey().Bytes(), now); err == nil {
		t.Fatal("corrupt plan accepted")
	}
}
