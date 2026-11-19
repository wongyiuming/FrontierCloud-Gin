package preprodimport

import (
	"crypto/ed25519"
	"sort"
	"time"
)

// verifyCompleteStageReceipts requires three independently pinned owner keys
// and an exact receipt for every role. This validates signed observations, not
// source authority, a simultaneous cluster snapshot, or continued durability.
func verifyCompleteStageReceipts(expected map[string]stageReceiptRequest, received map[string]signedStageReceipt, pins map[string]ed25519.PublicKey, now time.Time) error {
	if len(expected) != 3 || len(received) != 3 || len(pins) != 3 {
		return invalid("stage receipt set")
	}
	seenKeys := map[string]bool{}
	seenOwner := map[string]bool{}
	seenChallenge := map[string]bool{}
	seenStage := map[string]bool{}
	var master, generation, plan string
	for _, role := range []string{"master", "direct", "relay"} {
		r, ok := expected[role]
		if !ok || r.Role != role || !validStageReceiptRequest(r) {
			return invalid("stage expected role")
		}
		if role == "master" {
			master = r.MasterID
			generation = r.Generation
			plan = r.PlanDigest
		} else if r.MasterID != master || r.Generation != generation || r.PlanDigest != plan {
			return invalid("stage receipt generation")
		}
		pin, ok := pins[role]
		if !ok || len(pin) != ed25519.PublicKeySize || seenKeys[string(pin)] || seenOwner[r.OwnerID] || seenChallenge[r.Challenge] {
			return invalid("stage independent identity")
		}
		seenKeys[string(pin)] = true
		seenOwner[r.OwnerID] = true
		seenChallenge[r.Challenge] = true
		for _, item := range r.Items {
			if seenStage[item.StageID] {
				return invalid("stage duplicate across roles")
			}
			seenStage[item.StageID] = true
		}
		v, ok := received[role]
		if !ok {
			return invalid("stage missing receipt")
		}
		if err := verifyStageReceipt(v, r, pin, now); err != nil {
			return err
		}
	}
	return nil
}

// buildStageReceiptRequests runs only on the trusted Master. Stage IDs and
// final locators are independent opaque values; their provenance and the
// authority of source facts must still be verified by the caller. No source
// object ID, logical path, or descriptor goes into the node-facing request.
func buildStageReceiptRequests(s Snapshot, trust snapshotPlanTrust, plan signedSnapshotPlan, batches []signedSnapshotGrant, locators map[string]pendingLocatorBinding, stages map[string]string, challenges map[string]string, now time.Time) (map[string]stageReceiptRequest, error) {
	encrypted := make(map[string]pendingLocatorBinding)
	for _, m := range s.Media {
		if m.Encryption != nil {
			encrypted[m.MediaID] = locators[m.MediaID]
		}
	}
	if _, err := verifySnapshotKeyPlanBinding(s, trust, plan, batches, encrypted, now); err != nil {
		return nil, err
	}
	return buildStageReceiptRequestsChecked(s, trust, locators, stages, challenges, nil)
}

// Real-source integration must use the complete-facts form and must first
// authenticate the source transaction and independent node identities.
func buildCompleteStageReceiptRequests(s completeSnapshot, trust snapshotPlanTrust, plan signedSnapshotPlan, batches []signedSnapshotGrant, locators map[string]pendingLocatorBinding, stages map[string]string, challenges map[string]string, now time.Time) (map[string]stageReceiptRequest, error) {
	encrypted := make(map[string]pendingLocatorBinding)
	for _, m := range s.Projection.Media {
		if m.Encryption != nil {
			encrypted[m.MediaID] = locators[m.MediaID]
		}
	}
	if _, err := verifyCompleteSnapshotKeyPlanBinding(s, trust, plan, batches, encrypted, now); err != nil {
		return nil, err
	}
	extra := map[string]bool{}
	for _, o := range s.Facts.Objects {
		extra[o.ID] = true
	}
	return buildStageReceiptRequestsChecked(s.Projection, trust, locators, stages, challenges, extra)
}

// The caller must have completed one of the signature verifications above.
func buildStageReceiptRequestsChecked(s Snapshot, trust snapshotPlanTrust, locators map[string]pendingLocatorBinding, stages map[string]string, challenges map[string]string, extra map[string]bool) (map[string]stageReceiptRequest, error) {
	if len(locators) != len(s.Media)+len(s.Lyrics) || len(stages) != len(locators) || len(challenges) != 3 {
		return nil, invalid("stage binding coverage")
	}
	historical := map[string]bool{}
	for id := range extra {
		historical[id] = true
	}
	for _, m := range s.Media {
		historical[m.MediaID] = true
		historical[m.ObjectID] = true
	}
	for _, l := range s.Lyrics {
		historical[l.ID] = true
	}
	for _, d := range s.Directories {
		historical[d.ID] = true
	}
	for _, n := range s.RetiredNonces {
		historical[n.ObjectID] = true
	}
	seen := map[string]bool{}
	for id, loc := range locators {
		stage, ok := stages[id]
		if !ok || !id64.MatchString(stage) || !id64.MatchString(loc.BlobID) || !id64.MatchString(loc.ReadAlias) {
			return nil, invalid("stage locator shape")
		}
		for _, v := range []string{stage, loc.BlobID, loc.ReadAlias} {
			if historical[v] || seen[v] {
				return nil, invalid("stage locator collision")
			}
			seen[v] = true
		}
	}
	bySource := map[string]Mapping{}
	var master Mapping
	for _, m := range s.Mappings {
		bySource[m.SourceID] = m
		if m.Role == "master" {
			master = m
		}
	}
	requests := map[string]stageReceiptRequest{}
	usedChallenge := map[string]bool{}
	for _, m := range s.Mappings {
		ch := challenges[m.Role]
		if !id64.MatchString(ch) || usedChallenge[ch] {
			return nil, invalid("stage challenge")
		}
		usedChallenge[ch] = true
		requests[m.Role] = stageReceiptRequest{Version: 1, Role: m.Role, OwnerID: m.TargetID, MasterID: master.TargetID, Generation: trust.Generation, PlanDigest: trust.PlanDigest, Challenge: ch, Items: []stageReceiptItem{}}
	}
	appendItem := func(role, id string, size int64, hash string) error {
		stage, ok := stages[id]
		if !ok {
			return invalid("stage item missing")
		}
		r, ok := requests[role]
		if !ok {
			return invalid("stage owner")
		}
		r.Items = append(r.Items, stageReceiptItem{StageID: stage, Size: size, SHA256: hash})
		requests[role] = r
		return nil
	}
	for _, m := range s.Media {
		if err := appendItem(bySource[m.SourceID].Role, m.MediaID, m.Size, m.SHA256); err != nil {
			return nil, err
		}
	}
	for _, l := range s.Lyrics {
		if err := appendItem("master", l.ID, l.Size, l.SHA256); err != nil {
			return nil, err
		}
	}
	for role, r := range requests {
		sort.Slice(r.Items, func(i, j int) bool { return r.Items[i].StageID < r.Items[j].StageID })
		if !validStageReceiptRequest(r) {
			return nil, invalid("stage receipt shape")
		}
		requests[role] = r
	}
	return requests, nil
}
