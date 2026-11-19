package preprodimport

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"sort"
	"time"
)

// Receipt requests intentionally contain no business paths, user records,
// descriptors or premaster. Signer-key distribution and provenance must be
// authenticated independently; a receipt is an owner's signed observation,
// not proof that a malicious storage host actually holds the claimed bytes.
type ReceiptItem struct {
	ObjectID string `json:"object_id"`
	SHA256   string `json:"sha256"`
	Size     int64  `json:"size"`
}
type ReceiptRequest struct {
	Version                int           `json:"version"`
	Challenge              string        `json:"challenge"`
	ProjectionSHA256       string        `json:"projection_sha256"`
	SourceProjectionSHA256 string        `json:"source_projection_sha256"`
	SourceID               string        `json:"source_id"`
	TargetID               string        `json:"target_id"`
	Role                   string        `json:"role"`
	Items                  []ReceiptItem `json:"items"`
}
type ReceiptBody struct {
	Request     ReceiptRequest `json:"request"`
	IssuedUnix  int64          `json:"issued_unix"`
	ExpiresUnix int64          `json:"expires_unix"`
}
type SignedReceipt struct {
	Body      ReceiptBody `json:"body"`
	Signature []byte      `json:"signature"`
}
type ReceiptReport struct {
	ValidSignatures     bool
	CompleteDeclaredSet bool
	SourceAuthenticated bool
	SnapshotConsistent  bool
	RuntimeReady        bool
}

// ReceiptRequests is called only at the trusted Master, which already has the
// private premaster. Its output has no private key, business path or descriptor.
func ReceiptRequests(s Snapshot, premaster []byte, challenge string) ([]ReceiptRequest, error) {
	owners, report, err := validate(s, premaster)
	if err != nil {
		return nil, err
	}
	if !id64.MatchString(challenge) {
		return nil, invalid("receipt challenge")
	}
	requests := map[string]*ReceiptRequest{}
	for _, m := range s.Mappings {
		requests[m.Role] = &ReceiptRequest{Version: 1, Challenge: challenge, ProjectionSHA256: report.ProjectionSHA256, SourceProjectionSHA256: s.SourceProjectionSHA256, SourceID: m.SourceID, TargetID: m.TargetID, Role: m.Role, Items: []ReceiptItem{}}
	}
	for _, m := range s.Media {
		role := owners[m.SourceID].Role
		requests[role].Items = append(requests[role].Items, ReceiptItem{m.ObjectID, m.SHA256, m.Size})
	}
	for _, l := range s.Lyrics {
		requests["master"].Items = append(requests["master"].Items, ReceiptItem{l.ID, l.SHA256, l.Size})
	}
	out := make([]ReceiptRequest, 0, 3)
	for _, role := range []string{"master", "direct", "relay"} {
		r := requests[role]
		sort.Slice(r.Items, func(i, j int) bool { return r.Items[i].ObjectID < r.Items[j].ObjectID })
		out = append(out, *r)
	}
	return out, nil
}

func validateRequest(r ReceiptRequest) error {
	if r.Version != 1 || !id64.MatchString(r.Challenge) || !id64.MatchString(r.ProjectionSHA256) || !id64.MatchString(r.SourceProjectionSHA256) || !id32.MatchString(r.SourceID) || !id32.MatchString(r.TargetID) || r.SourceID == r.TargetID || (r.Role != "master" && r.Role != "direct" && r.Role != "relay") || len(r.Items) > 100000 {
		return invalid("receipt request")
	}
	previous := ""
	for _, item := range r.Items {
		if !id64.MatchString(item.ObjectID) || !id64.MatchString(item.SHA256) || item.Size < 0 || item.Size > 10*1024*1024*1024 || item.ObjectID <= previous {
			return invalid("receipt item")
		}
		previous = item.ObjectID
	}
	return nil
}

// SignStaged verifies the complete declared role set while holding the same
// nonblocking filesystem lock as staging. The caller supplies a private signer
// key already resident on this host; the key is never included in the receipt.
func readStageEntries(root *os.Root, name string) ([]os.DirEntry, error) {
	before, err := root.Lstat(name)
	if err != nil || !privateOwned(before, true) {
		return nil, invalid("receipt objects path")
	}
	f, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !privateOwned(info, true) || !os.SameFile(before, info) {
		return nil, invalid("receipt objects directory")
	}
	entries, err := f.ReadDir(-1)
	if err != nil {
		return nil, err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	return entries, nil
}

func SignStaged(ctx context.Context, stageDir string, r ReceiptRequest, signer ed25519.PrivateKey, opts Options) (SignedReceipt, error) {
	var result SignedReceipt
	if err := validateRequest(r); err != nil {
		return result, err
	}
	if len(signer) != ed25519.PrivateKeySize || opts.Progress == nil || opts.MaxBytesPerSecond <= 0 || opts.MaxBytesPerSecond > 4*1024*1024 {
		return result, invalid("receipt signing options")
	}
	info, err := os.Lstat(stageDir)
	if err != nil || !privateOwned(info, true) {
		return result, invalid("receipt staging root")
	}
	root, err := os.OpenRoot(stageDir)
	if err != nil {
		return result, err
	}
	defer root.Close()
	opened, err := root.Stat(".")
	if err != nil || !os.SameFile(info, opened) {
		return result, invalid("receipt staging root changed")
	}
	roleInfo, err := root.Lstat(r.Role)
	if err != nil || !privateOwned(roleInfo, true) {
		return result, invalid("receipt staging role")
	}
	lock, err := root.OpenFile(r.Role+"/.lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return result, err
	}
	defer lock.Close()
	lockInfo, err := lock.Stat()
	pathInfo, pathErr := root.Lstat(r.Role + "/.lock")
	if err != nil || pathErr != nil || !privateOwned(lockInfo, false) || !os.SameFile(lockInfo, pathInfo) {
		return result, invalid("receipt lock identity")
	}
	if err = lockStage(lock); err != nil {
		return result, invalid("receipt stage busy")
	}
	partials, err := readStageEntries(root, r.Role+"/partial")
	if err != nil || len(partials) != 0 {
		return result, invalid("incomplete staged files")
	}
	entries, err := readStageEntries(root, r.Role+"/objects")
	if err != nil {
		return result, err
	}
	if len(entries) != len(r.Items) {
		return result, invalid("receipt stage count")
	}
	limit := &limiter{start: time.Now(), rate: opts.MaxBytesPerSecond}
	if err = opts.Progress(Event{Kind: "receipt_verification_started", Role: r.Role}); err != nil {
		return result, err
	}
	for _, item := range r.Items {
		if err = verifyFile(ctx, root, r.Role, item.ObjectID, item.Size, item.SHA256, limit); err != nil {
			return result, err
		}
		if err = opts.Progress(Event{Kind: "receipt_object_verified", Role: r.Role, ObjectID: item.ObjectID, Bytes: item.Size}); err != nil {
			return result, err
		}
	}
	// Read the entry names again after hashing. No extra final file may be hidden
	// by matching only item count, and a changed directory aborts signing.
	entries, err = readStageEntries(root, r.Role+"/objects")
	if err != nil || len(entries) != len(r.Items) {
		return result, invalid("receipt stage changed")
	}
	for i, e := range entries {
		if e.Name() != r.Items[i].ObjectID+".blob" {
			return result, invalid("receipt stage coverage")
		}
	}
	partials, err = readStageEntries(root, r.Role+"/partial")
	if err != nil || len(partials) != 0 {
		return result, invalid("staged partial changed")
	}
	// A coordinator can use this callback as a cancellable barrier so faster
	// nodes keep the lock until all peers have finished their bounded scan.
	if err = opts.Progress(Event{Kind: "receipt_verification_complete", Role: r.Role}); err != nil {
		return result, err
	}
	now := time.Now()
	result.Body = ReceiptBody{Request: r, IssuedUnix: now.Unix(), ExpiresUnix: now.Add(5 * time.Minute).Unix()}
	raw, err := json.Marshal(result.Body)
	if err != nil {
		return SignedReceipt{}, err
	}
	result.Signature = ed25519.Sign(signer, raw)
	if err = opts.Progress(Event{Kind: "receipt_signed", Role: r.Role}); err != nil {
		return SignedReceipt{}, err
	}
	return result, nil
}

// VerifyReceiptSet binds all three peer observations to an exact typed
// projection, a fresh caller challenge and separately authenticated public
// keys. It cannot attest source completeness or force untrusted nodes honest.
func VerifyReceiptSet(s Snapshot, premaster []byte, challenge string, receipts []SignedReceipt, keys map[string]ed25519.PublicKey, now time.Time) (ReceiptReport, error) {
	report := ReceiptReport{}
	expected, err := ReceiptRequests(s, premaster, challenge)
	if err != nil {
		return report, err
	}
	if len(receipts) != 3 || len(keys) != 3 {
		return report, invalid("receipt set count")
	}
	byRole := map[string]ReceiptRequest{}
	for _, r := range expected {
		byRole[r.Role] = r
	}
	seen := map[string]bool{}
	seenKeys := map[string]bool{}
	for _, r := range receipts {
		req := r.Body.Request
		want, ok := byRole[req.Role]
		if !ok || seen[req.Role] {
			return report, invalid("receipt role")
		}
		seen[req.Role] = true
		actualJSON, e := json.Marshal(req)
		if e != nil {
			return report, e
		}
		wantedJSON, e := json.Marshal(want)
		if e != nil {
			return report, e
		}
		if string(actualJSON) != string(wantedJSON) || r.Body.IssuedUnix > now.Unix()+30 || r.Body.IssuedUnix < now.Unix()-300 || r.Body.ExpiresUnix <= now.Unix() || r.Body.ExpiresUnix-r.Body.IssuedUnix != 300 {
			return report, invalid("receipt binding or lifetime")
		}
		key, ok := keys[req.TargetID]
		if !ok || len(key) != ed25519.PublicKeySize || seenKeys[string(key)] {
			return report, invalid("receipt trust key")
		}
		seenKeys[string(key)] = true
		payload, e := json.Marshal(r.Body)
		if e != nil {
			return report, e
		}
		if !ed25519.Verify(key, payload, r.Signature) {
			return report, invalid("receipt signature")
		}
	}
	report.ValidSignatures = true
	report.CompleteDeclaredSet = true
	return report, nil
}
