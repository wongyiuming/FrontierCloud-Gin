package preprodimport

// A synthetic completeness check. No real import/export calls this code.
// A signed generation remains only a claim until tied to an independently
// authenticated immutable source snapshot and durable anti-rollback anchor.

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"time"
)

type snapshotPlanBatch struct {
	Digest string `json:"digest"`
	Count  int    `json:"count"`
}
type snapshotPlanBody struct {
	Version      int                 `json:"version"`
	SourceNode   string              `json:"source_node"`
	SourceKeyID  string              `json:"source_key_id"`
	TargetNode   string              `json:"target_node"`
	TargetPublic []byte              `json:"target_public"`
	Generation   string              `json:"generation"`
	IssuedUnix   int64               `json:"issued_unix"`
	ExpiresUnix  int64               `json:"expires_unix"`
	Batches      []snapshotPlanBatch `json:"batches"`
}
type signedSnapshotPlan struct {
	Body      snapshotPlanBody `json:"body"`
	Signature []byte           `json:"signature"`
}

// Values must originate from a separately authenticated enrollment and job
// authorization, not from the signed plan being checked. This struct is only
// an in-memory prototype; durable trusted pin storage is not connected.
type snapshotPlanTrust struct {
	SourceNode   string
	SourceKeyID  string
	SourcePublic ed25519.PublicKey
	TargetNode   string
	TargetPublic []byte
	Generation   string
	PlanDigest   string
}

func snapshotPlanDigest(body snapshotPlanBody, now time.Time) ([]byte, error) {
	n := now.Unix()
	if body.Version != 1 || !id32.MatchString(body.SourceNode) || !id64.MatchString(body.SourceKeyID) || !id32.MatchString(body.TargetNode) || body.SourceNode == body.TargetNode || len(body.TargetPublic) != 32 || !id64.MatchString(body.Generation) || body.IssuedUnix <= 0 || body.IssuedUnix > n || body.ExpiresUnix <= n || body.ExpiresUnix <= body.IssuedUnix || body.ExpiresUnix-body.IssuedUnix > 300 || len(body.Batches) == 0 || len(body.Batches) > 64 {
		return nil, invalid("snapshot plan input")
	}
	seen := map[string]bool{}
	total := 0
	for _, b := range body.Batches {
		if !id64.MatchString(b.Digest) || b.Count <= 0 || b.Count > maxSnapshotGrantEntries || seen[b.Digest] {
			return nil, invalid("snapshot plan batch")
		}
		seen[b.Digest] = true
		total += b.Count
		if total > 8192 {
			return nil, invalid("snapshot plan size")
		}
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, invalid("snapshot plan encoding")
	}
	h := sha256.New()
	_, _ = h.Write([]byte("frontiercloud:preprod-snapshot-plan:v1\x00"))
	_, _ = h.Write(raw)
	return h.Sum(nil), nil
}

// This signer is not connected to a source authorization service.
func signApprovedSnapshotPlan(body snapshotPlanBody, signer ed25519.PrivateKey, now time.Time) (signedSnapshotPlan, error) {
	if len(signer) != ed25519.PrivateKeySize {
		return signedSnapshotPlan{}, invalid("snapshot plan signer")
	}
	digest, err := snapshotPlanDigest(body, now)
	if err != nil {
		return signedSnapshotPlan{}, err
	}
	return signedSnapshotPlan{Body: body, Signature: ed25519.Sign(signer, digest)}, nil
}

// verifyCompleteSnapshotPlan rejects missing, reordered or cross-generation
// batches and cross-batch duplicate identities/locators. It authenticates only
// the supplied pin; independently binding that pin to a real node is required.
func verifyCompleteSnapshotPlan(plan signedSnapshotPlan, batches []signedSnapshotGrant, source ed25519.PublicKey, target []byte, now time.Time) error {
	if len(source) != ed25519.PublicKeySize || len(target) != 32 || len(plan.Signature) != ed25519.SignatureSize || subtle.ConstantTimeCompare(plan.Body.TargetPublic, target) != 1 {
		return invalid("snapshot plan identity")
	}
	digest, err := snapshotPlanDigest(plan.Body, now)
	if err != nil || !ed25519.Verify(source, digest, plan.Signature) || len(batches) != len(plan.Body.Batches) {
		return invalid("snapshot plan signature or completeness")
	}
	seenMedia := map[string]bool{}
	seenSource := map[string]bool{}
	seenBlob := map[string]bool{}
	seenFile := map[string]bool{}
	seenChallenge := map[string]bool{}
	previous := ""
	for i, batch := range batches {
		b := batch.Body
		p := plan.Body
		if len(batch.Signature) != ed25519.SignatureSize || b.SourceNode != p.SourceNode || b.SourceKeyID != p.SourceKeyID || b.TargetNode != p.TargetNode || subtle.ConstantTimeCompare(b.TargetPublic, p.TargetPublic) != 1 || b.Generation != p.Generation || b.BatchIndex != i || b.BatchCount != len(batches) || b.IssuedUnix != p.IssuedUnix || b.ExpiresUnix != p.ExpiresUnix || len(b.Entries) != p.Batches[i].Count {
			return invalid("snapshot plan generation or batch")
		}
		bd, err := snapshotGrantDigest(b, now)
		if err != nil || !ed25519.Verify(source, bd, batch.Signature) || subtle.ConstantTimeCompare([]byte(hex.EncodeToString(bd)), []byte(p.Batches[i].Digest)) != 1 {
			return invalid("snapshot plan batch signature")
		}
		for _, e := range b.Entries {
			if e.MediaID <= previous || seenMedia[e.MediaID] || seenSource[e.SourceObjectID] || seenBlob[e.TargetBlobID] || seenBlob[e.TargetReadAlias] || seenFile[e.Descriptor.FileID] || seenChallenge[e.Challenge] {
				return invalid("snapshot plan duplicate")
			}
			previous = e.MediaID
			seenMedia[e.MediaID] = true
			seenSource[e.SourceObjectID] = true
			seenBlob[e.TargetBlobID] = true
			seenBlob[e.TargetReadAlias] = true
			seenFile[e.Descriptor.FileID] = true
			seenChallenge[e.Challenge] = true
		}
	}
	for blob := range seenBlob {
		if seenMedia[blob] || seenSource[blob] {
			return invalid("snapshot plan locator collision")
		}
	}
	return nil
}

func verifyPinnedSnapshotPlan(trust snapshotPlanTrust, plan signedSnapshotPlan, batches []signedSnapshotGrant, now time.Time) error {
	if !id32.MatchString(trust.SourceNode) || !id64.MatchString(trust.SourceKeyID) || len(trust.SourcePublic) != ed25519.PublicKeySize || !id32.MatchString(trust.TargetNode) || len(trust.TargetPublic) != 32 || !id64.MatchString(trust.Generation) || !id64.MatchString(trust.PlanDigest) {
		return invalid("snapshot trust input")
	}
	p := plan.Body
	if p.SourceNode != trust.SourceNode || p.SourceKeyID != trust.SourceKeyID || p.TargetNode != trust.TargetNode || p.Generation != trust.Generation || subtle.ConstantTimeCompare(p.TargetPublic, trust.TargetPublic) != 1 {
		return invalid("snapshot trust identity")
	}
	digest, err := snapshotPlanDigest(p, now)
	if err != nil || subtle.ConstantTimeCompare([]byte(hex.EncodeToString(digest)), []byte(trust.PlanDigest)) != 1 {
		return invalid("snapshot trust plan")
	}
	return verifyCompleteSnapshotPlan(plan, batches, trust.SourcePublic, trust.TargetPublic, now)
}
