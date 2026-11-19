package preprodimport

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
)

func TestSyntheticProjectionBindsCompleteKeyPlanWithoutPremaster(t *testing.T) {
	s, _, _, _ := fixture(t)
	now := time.Unix(2000000000, 0)
	target, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	generation, report, err := snapshotProjectionDigest(s)
	if err != nil {
		t.Fatal(err)
	}
	if report.SourceAuthenticated || report.SnapshotConsistent || report.RuntimeReady {
		t.Fatal("structural digest claimed source trust")
	}
	m := s.Media[0]
	loc := pendingLocatorBinding{BlobID: strings.Repeat("f", 64), ReadAlias: strings.Repeat("1", 64)}
	entry := snapshotGrantEntry{MediaID: m.MediaID, SourceObjectID: m.ObjectID, TargetOwnerID: s.Mappings[0].TargetID, TargetBlobID: loc.BlobID, TargetReadAlias: loc.ReadAlias, ContentSHA256: m.SHA256, StoredBytes: m.Size, Challenge: strings.Repeat("2", 64), Descriptor: *m.Encryption}
	body := snapshotGrantBody{Version: 1, SourceNode: s.Mappings[0].SourceID, SourceKeyID: s.PremasterKeyID, TargetNode: s.Mappings[0].TargetID, TargetPublic: target.PublicKey().Bytes(), Generation: generation, BatchCount: 1, IssuedUnix: now.Unix(), ExpiresUnix: now.Add(3 * time.Minute).Unix(), Entries: []snapshotGrantEntry{entry}}
	batch, err := signApprovedSnapshot(body, priv, now)
	if err != nil {
		t.Fatal(err)
	}
	batchDigest, err := snapshotGrantDigest(body, now)
	if err != nil {
		t.Fatal(err)
	}
	pb := snapshotPlanBody{Version: 1, SourceNode: body.SourceNode, SourceKeyID: body.SourceKeyID, TargetNode: body.TargetNode, TargetPublic: body.TargetPublic, Generation: generation, IssuedUnix: body.IssuedUnix, ExpiresUnix: body.ExpiresUnix, Batches: []snapshotPlanBatch{{Digest: hex.EncodeToString(batchDigest), Count: 1}}}
	plan, err := signApprovedSnapshotPlan(pb, priv, now)
	if err != nil {
		t.Fatal(err)
	}
	planDigest, err := snapshotPlanDigest(pb, now)
	if err != nil {
		t.Fatal(err)
	}
	trust := snapshotPlanTrust{SourceNode: pb.SourceNode, SourceKeyID: pb.SourceKeyID, SourcePublic: pub, TargetNode: pb.TargetNode, TargetPublic: pb.TargetPublic, Generation: generation, PlanDigest: hex.EncodeToString(planDigest)}
	locators := map[string]pendingLocatorBinding{m.MediaID: loc}
	if got, err := verifySnapshotKeyPlanBinding(s, trust, plan, []signedSnapshotGrant{batch}, locators, now); err != nil || got.SourceAuthenticated || got.SnapshotConsistent || got.RuntimeReady {
		t.Fatalf("bound shape: %+v %v", got, err)
	}
	complete := completeSnapshot{Projection: s, Facts: syntheticCompleteFacts(s)}
	completeGeneration, err := completeSnapshotDigest(complete)
	if err != nil {
		t.Fatal(err)
	}
	completeBody := body
	completeBody.Generation = completeGeneration
	completeBatch, err := signApprovedSnapshot(completeBody, priv, now)
	if err != nil {
		t.Fatal(err)
	}
	completeBatchDigest, err := snapshotGrantDigest(completeBody, now)
	if err != nil {
		t.Fatal(err)
	}
	completePlanBody := pb
	completePlanBody.Generation = completeGeneration
	completePlanBody.Batches = []snapshotPlanBatch{{Digest: hex.EncodeToString(completeBatchDigest), Count: 1}}
	completePlan, err := signApprovedSnapshotPlan(completePlanBody, priv, now)
	if err != nil {
		t.Fatal(err)
	}
	completePlanDigest, err := snapshotPlanDigest(completePlanBody, now)
	if err != nil {
		t.Fatal(err)
	}
	completeTrust := trust
	completeTrust.Generation = completeGeneration
	completeTrust.PlanDigest = hex.EncodeToString(completePlanDigest)
	if _, err = verifyCompleteSnapshotKeyPlanBinding(complete, completeTrust, completePlan, []signedSnapshotGrant{completeBatch}, locators, now); err != nil {
		t.Fatalf("complete signed facts: %v", err)
	}
	modified := complete
	modified.Facts.Placements = append([]sourcePlacementFact(nil), complete.Facts.Placements...)
	modified.Facts.Placements[0].UpdatedAt++
	if _, err = verifyCompleteSnapshotKeyPlanBinding(modified, completeTrust, completePlan, []signedSnapshotGrant{completeBatch}, locators, now); err == nil {
		t.Fatal("signed plan accepted modified source facts")
	}
	allLocators := map[string]pendingLocatorBinding{}
	stages := map[string]string{}
	i := 0
	for _, item := range s.Media {
		i++
		stages[item.MediaID] = fmt.Sprintf("%064x", 1000+i)
		allLocators[item.MediaID] = pendingLocatorBinding{BlobID: fmt.Sprintf("%064x", 2000+i), ReadAlias: fmt.Sprintf("%064x", 3000+i)}
	}
	for _, item := range s.Lyrics {
		i++
		stages[item.ID] = fmt.Sprintf("%064x", 1000+i)
		allLocators[item.ID] = pendingLocatorBinding{BlobID: fmt.Sprintf("%064x", 2000+i), ReadAlias: fmt.Sprintf("%064x", 3000+i)}
	}
	allLocators[m.MediaID] = loc
	challenges := map[string]string{"master": strings.Repeat("7", 64), "direct": strings.Repeat("8", 64), "relay": strings.Repeat("9", 64)}
	requests, err := buildStageReceiptRequests(s, trust, plan, []signedSnapshotGrant{batch}, allLocators, stages, challenges, now)
	if err != nil || len(requests) != 3 {
		t.Fatalf("stage requests: %v", err)
	}
	if _, err = buildCompleteStageReceiptRequests(complete, completeTrust, completePlan, []signedSnapshotGrant{completeBatch}, allLocators, stages, challenges, now); err != nil {
		t.Fatalf("complete stage requests: %v", err)
	}
	previous := stages[m.MediaID]
	stages[m.MediaID] = complete.Facts.Objects[0].ID
	if _, err = buildCompleteStageReceiptRequests(complete, completeTrust, completePlan, []signedSnapshotGrant{completeBatch}, allLocators, stages, challenges, now); err == nil {
		t.Fatal("source-only local object ID accepted as stage locator")
	}
	stages[m.MediaID] = previous
	for _, item := range s.Media {
		role := ""
		for _, mapping := range s.Mappings {
			if mapping.SourceID == item.SourceID {
				role = mapping.Role
			}
		}
		found := false
		for _, received := range requests[role].Items {
			if received.StageID == stages[item.MediaID] && received.Size == item.Size && received.SHA256 == item.SHA256 {
				found = true
			}
		}
		if !found {
			t.Fatal("media absent from mapped owner receipt")
		}
	}
	for _, item := range s.Lyrics {
		found := false
		for _, received := range requests["master"].Items {
			if received.StageID == stages[item.ID] && received.Size == item.Size && received.SHA256 == item.SHA256 {
				found = true
			}
		}
		if !found {
			t.Fatal("lyric absent from master receipt")
		}
	}
	pins := map[string]ed25519.PublicKey{}
	ownerKeys := map[string]ed25519.PrivateKey{}
	receipts := map[string]signedStageReceipt{}
	for role, request := range requests {
		ownerPub, ownerKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		body := stageReceiptBody{Request: request, IssuedUnix: now.Unix(), ExpiresUnix: now.Add(5 * time.Minute).Unix()}
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		receipts[role] = signedStageReceipt{Body: body, Signature: ed25519.Sign(ownerKey, append([]byte("frontiercloud:preprod-stage-receipt:v2\x00"), b...))}
		pins[role] = ownerPub
		ownerKeys[role] = ownerKey
	}
	if err := verifyCompleteStageReceipts(requests, receipts, pins, now); err != nil {
		t.Fatalf("complete receipts: %v", err)
	}
	if len(requests["master"].Items) > 0 && len(requests["direct"].Items) == 1 {
		badRequests := map[string]stageReceiptRequest{}
		for role, r := range requests {
			badRequests[role] = r
		}
		r := badRequests["direct"]
		r.Items = append([]stageReceiptItem(nil), r.Items...)
		r.Items[0].StageID = requests["master"].Items[0].StageID
		badRequests["direct"] = r
		badReceipts := map[string]signedStageReceipt{}
		for role, v := range receipts {
			badReceipts[role] = v
		}
		body := stageReceiptBody{Request: r, IssuedUnix: now.Unix(), ExpiresUnix: now.Add(5 * time.Minute).Unix()}
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		badReceipts["direct"] = signedStageReceipt{Body: body, Signature: ed25519.Sign(ownerKeys["direct"], append([]byte("frontiercloud:preprod-stage-receipt:v2\x00"), encoded...))}
		if err := verifyCompleteStageReceipts(badRequests, badReceipts, pins, now); err == nil || !strings.Contains(err.Error(), "duplicate across roles") {
			t.Fatalf("cross-owner duplicate accepted: %v", err)
		}
	}
	one := receipts["relay"]
	delete(receipts, "relay")
	if err := verifyCompleteStageReceipts(requests, receipts, pins, now); err == nil {
		t.Fatal("incomplete receipt set accepted")
	}
	receipts["relay"] = one
	pin := pins["relay"]
	pins["relay"] = pins["direct"]
	if err := verifyCompleteStageReceipts(requests, receipts, pins, now); err == nil {
		t.Fatal("reused owner key accepted")
	}
	pins["relay"] = pin
	if err := verifyCompleteStageReceipts(requests, receipts, pins, now.Add(5*time.Minute)); err == nil {
		t.Fatal("expired receipts accepted")
	}
	raw, err := json.Marshal(requests)
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range s.Media {
		if strings.Contains(string(raw), item.Path) || strings.Contains(string(raw), item.MediaID) || strings.Contains(string(raw), item.ObjectID) {
			t.Fatal("source metadata in owner request")
		}
	}
	for _, item := range s.Lyrics {
		if strings.Contains(string(raw), item.Path) || strings.Contains(string(raw), item.ID) {
			t.Fatal("lyric metadata in owner request")
		}
	}
	oldStage := stages[m.MediaID]
	stages[m.MediaID] = m.ObjectID
	if _, err = buildStageReceiptRequests(s, trust, plan, []signedSnapshotGrant{batch}, allLocators, stages, challenges, now); err == nil {
		t.Fatal("historical source ID accepted as stage locator")
	}
	stages[m.MediaID] = oldStage
	if len(s.Directories) > 0 {
		plainID := s.Media[1].MediaID
		old := allLocators[plainID]
		allLocators[plainID] = pendingLocatorBinding{BlobID: s.Directories[0].ID, ReadAlias: old.ReadAlias}
		if _, err = buildStageReceiptRequests(s, trust, plan, []signedSnapshotGrant{batch}, allLocators, stages, challenges, now); err == nil {
			t.Fatal("historical directory ID accepted as blob")
		}
		allLocators[plainID] = old
	}
	delete(stages, m.MediaID)
	if _, err = buildStageReceiptRequests(s, trust, plan, []signedSnapshotGrant{batch}, allLocators, stages, challenges, now); err == nil {
		t.Fatal("missing stage item accepted")
	}
	stages[m.MediaID] = oldStage
	bad := s
	bad.Visibility = append([]Visibility(nil), s.Visibility...)
	bad.Visibility[0].Hidden = !bad.Visibility[0].Hidden
	if _, err = verifySnapshotKeyPlanBinding(bad, trust, plan, []signedSnapshotGrant{batch}, locators, now); err == nil {
		t.Fatal("changed visibility accepted")
	}
	wrong := map[string]pendingLocatorBinding{m.MediaID: {BlobID: loc.BlobID, ReadAlias: strings.Repeat("3", 64)}}
	if _, err = verifySnapshotKeyPlanBinding(s, trust, plan, []signedSnapshotGrant{batch}, wrong, now); err == nil {
		t.Fatal("different pending alias accepted")
	}
	if _, err = verifySnapshotKeyPlanBinding(s, trust, plan, []signedSnapshotGrant{batch}, nil, now); err == nil {
		t.Fatal("missing pending locator accepted")
	}
	if _, err = verifySnapshotKeyPlanBinding(s, trust, plan, nil, locators, now); err == nil {
		t.Fatal("missing signed batch accepted")
	}
	// Even a validly signed plan for the updated generation cannot omit an
	// encrypted media object that exists in the typed projection.
	more := s
	more.Media = append([]Media(nil), s.Media...)
	meta, err := mediacrypto.NewMetadata(17)
	if err != nil {
		t.Fatal(err)
	}
	more.Media[1].Encryption = &meta
	more.Media[1].Size = meta.CiphertextSize
	more.Media[1].SHA256 = strings.Repeat("2", 64)
	moreGeneration, _, err := snapshotProjectionDigest(more)
	if err != nil {
		t.Fatal(err)
	}
	moreBody := body
	moreBody.Generation = moreGeneration
	moreBatch, err := signApprovedSnapshot(moreBody, priv, now)
	if err != nil {
		t.Fatal(err)
	}
	moreBatchDigest, err := snapshotGrantDigest(moreBody, now)
	if err != nil {
		t.Fatal(err)
	}
	morePlanBody := pb
	morePlanBody.Generation = moreGeneration
	morePlanBody.Batches = []snapshotPlanBatch{{Digest: hex.EncodeToString(moreBatchDigest), Count: 1}}
	morePlan, err := signApprovedSnapshotPlan(morePlanBody, priv, now)
	if err != nil {
		t.Fatal(err)
	}
	morePlanDigest, err := snapshotPlanDigest(morePlanBody, now)
	if err != nil {
		t.Fatal(err)
	}
	moreTrust := trust
	moreTrust.Generation = moreGeneration
	moreTrust.PlanDigest = hex.EncodeToString(morePlanDigest)
	if _, err = verifySnapshotKeyPlanBinding(more, moreTrust, morePlan, []signedSnapshotGrant{moreBatch}, locators, now); err == nil {
		t.Fatal("signed plan omitted encrypted media")
	}
}

func TestSyntheticProjectionTreeRejectsFileParentsAndPreservesExactNames(t *testing.T) {
	s, _, _, _ := fixture(t)
	child := s
	child.Media = append([]Media(nil), s.Media...)
	extra := s.Media[0]
	extra.MediaID = strings.Repeat("1", 64)
	extra.ObjectID = strings.Repeat("2", 64)
	extra.Path = "music/album/song.mp3/child.mp3"
	extra.Size = 5
	extra.SHA256 = strings.Repeat("3", 64)
	extra.Encryption = nil
	child.Media = append(child.Media, extra)
	if _, _, err := snapshotProjectionDigest(child); err == nil {
		t.Fatal("file parent accepted")
	}
	visibility := s
	visibility.Visibility = append([]Visibility(nil), s.Visibility...)
	visibility.Visibility = append(visibility.Visibility, Visibility{Path: "music/album/song.mp3/future", Hidden: true})
	if _, _, err := snapshotProjectionDigest(visibility); err == nil {
		t.Fatal("visibility descended through a file")
	}
	exact := s
	exact.Directories = append([]Directory(nil), s.Directories...)
	exact.Directories = append(exact.Directories, Directory{ID: strings.Repeat("1", 64), Path: "music/Album"}, Directory{ID: strings.Repeat("2", 64), Path: "music/é"}, Directory{ID: strings.Repeat("3", 64), Path: "music/e\u0301"})
	exact.Visibility = append([]Visibility(nil), s.Visibility...)
	exact.Visibility = append(exact.Visibility, Visibility{Path: "music/currently-empty/future", Hidden: true})
	if _, _, err := snapshotProjectionDigest(exact); err != nil {
		t.Fatalf("distinct exact names or visibility-only path rejected: %v", err)
	}
}
