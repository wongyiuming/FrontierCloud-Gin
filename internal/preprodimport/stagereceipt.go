package preprodimport

// A private experimental stage-owner receipt. It is not an enabled node API,
// source authorization, remote attestation, or proof that a malicious owner
// will continue to retain bytes. Only independent random stage IDs are allowed.

import (
	"context"
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"os"
	"sort"
	"time"
)

type stageReceiptItem struct {
	StageID string `json:"stage_id"`
	Size    int64  `json:"size"`
	SHA256  string `json:"sha256"`
}
type stageReceiptRequest struct {
	Version    int                `json:"version"`
	Role       string             `json:"role"`
	OwnerID    string             `json:"owner_id"`
	MasterID   string             `json:"master_id"`
	Generation string             `json:"generation"`
	PlanDigest string             `json:"plan_digest"`
	Challenge  string             `json:"challenge"`
	Items      []stageReceiptItem `json:"items"`
}
type stageReceiptBody struct {
	Request     stageReceiptRequest `json:"request"`
	IssuedUnix  int64               `json:"issued_unix"`
	ExpiresUnix int64               `json:"expires_unix"`
}
type signedStageReceipt struct {
	Body      stageReceiptBody `json:"body"`
	Signature []byte           `json:"signature"`
}

func validStageReceiptRequest(r stageReceiptRequest) bool {
	if r.Version != 1 || (r.Role != "master" && r.Role != "direct" && r.Role != "relay") || !id32.MatchString(r.OwnerID) || !id32.MatchString(r.MasterID) || (r.Role == "master") != (r.OwnerID == r.MasterID) || !id64.MatchString(r.Generation) || !id64.MatchString(r.PlanDigest) || !id64.MatchString(r.Challenge) || len(r.Items) > 25000 {
		return false
	}
	previous := ""
	for _, item := range r.Items {
		if !id64.MatchString(item.StageID) || item.StageID <= previous || !id64.MatchString(item.SHA256) || item.Size < 0 || item.Size > 10*1024*1024*1024 {
			return false
		}
		previous = item.StageID
	}
	return true
}

func stageReceiptEntries(root *os.Root, name string) ([]os.DirEntry, error) {
	before, err := root.Lstat(name)
	if err != nil || !privateOwned(before, true) {
		return nil, invalid("receipt directory")
	}
	f, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !privateOwned(opened, true) || !os.SameFile(before, opened) {
		return nil, invalid("receipt directory identity")
	}
	entries, err := f.ReadDir(25001)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if len(entries) > 25000 {
		return nil, invalid("receipt directory limit")
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	return entries, nil
}

// signStageReceipt hashes the exact stage set under the same existing lock as
// staging. The request must be independently authorized and map only opaque
// stage IDs to authenticated source facts on the trusted Master. No historic
// ID, path, media key or descriptor belongs in this node-facing request.
func signStageReceipt(ctx context.Context, stageDir string, request stageReceiptRequest, signer ed25519.PrivateKey, opts Options, now time.Time) (signedStageReceipt, error) {
	var empty signedStageReceipt
	started := time.Now()
	if ctx == nil || !validStageReceiptRequest(request) || len(signer) != ed25519.PrivateKeySize || opts.Progress == nil || opts.MaxBytesPerSecond <= 0 || opts.MaxBytesPerSecond > 4*1024*1024 || now.Unix() <= 0 {
		return empty, invalid("receipt input")
	}
	info, err := os.Lstat(stageDir)
	if err != nil || !privateOwned(info, true) {
		return empty, invalid("receipt root")
	}
	root, err := os.OpenRoot(stageDir)
	if err != nil {
		return empty, err
	}
	defer root.Close()
	opened, err := root.Stat(".")
	if err != nil || !os.SameFile(info, opened) {
		return empty, invalid("receipt root identity")
	}
	roleInfo, err := root.Lstat(request.Role)
	if err != nil || !privateOwned(roleInfo, true) {
		return empty, invalid("receipt role")
	}
	dirs := make(map[string]os.FileInfo)
	for _, name := range []string{request.Role, request.Role + "/objects", request.Role + "/partial"} {
		info, err := root.Lstat(name)
		if err != nil || !privateOwned(info, true) {
			return empty, invalid("receipt directory identity")
		}
		dirs[name] = info
	}
	quarantine := request.Role + "/quarantine"
	qinfo, qerr := root.Lstat(quarantine)
	if qerr == nil {
		if !privateOwned(qinfo, true) {
			return empty, invalid("receipt quarantine identity")
		}
		dirs[quarantine] = qinfo
	} else if !errors.Is(qerr, os.ErrNotExist) {
		return empty, invalid("receipt quarantine identity")
	}
	lock, err := root.OpenFile(request.Role+"/.lock", os.O_RDWR, 0)
	if err != nil {
		return empty, invalid("receipt lock missing")
	}
	defer lock.Close()
	lockInfo, err := lock.Stat()
	current, statErr := root.Lstat(request.Role + "/.lock")
	if err != nil || statErr != nil || !privateOwned(lockInfo, false) || !os.SameFile(lockInfo, current) {
		return empty, invalid("receipt lock identity")
	}
	if err = lockStageReceipt(lock); err != nil {
		return empty, invalid("receipt busy")
	}
	current, err = root.Lstat(request.Role + "/.lock")
	if err != nil || !os.SameFile(lockInfo, current) {
		return empty, invalid("receipt lock replaced")
	}
	checkSet := func() error {
		partial, err := stageReceiptEntries(root, request.Role+"/partial")
		if err != nil || len(partial) != 0 {
			return invalid("receipt partial")
		}
		_, err = root.Lstat(request.Role + "/quarantine")
		if err == nil {
			quarantine, qerr := stageReceiptEntries(root, request.Role+"/quarantine")
			if qerr != nil || len(quarantine) != 0 {
				return invalid("receipt quarantine")
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return invalid("receipt quarantine")
		}
		entries, err := stageReceiptEntries(root, request.Role+"/objects")
		if err != nil || len(entries) != len(request.Items) {
			return invalid("receipt objects")
		}
		for i, e := range entries {
			if e.Name() != request.Items[i].StageID+".blob" {
				return invalid("receipt set")
			}
		}
		return nil
	}
	if err = checkSet(); err != nil {
		return empty, err
	}
	limit := &limiter{start: time.Now(), rate: opts.MaxBytesPerSecond}
	verified := make([]os.FileInfo, 0, len(request.Items))
	for _, item := range request.Items {
		before, statErr := root.Lstat(request.Role + "/objects/" + item.StageID + ".blob")
		if statErr != nil || !privateOwned(before, false) || before.Size() != item.Size {
			return empty, invalid("receipt object before verification")
		}
		if err = verifyFile(ctx, root, request.Role, item.StageID, item.Size, item.SHA256, limit); err != nil {
			return empty, err
		}
		info, statErr := root.Lstat(request.Role + "/objects/" + item.StageID + ".blob")
		if statErr != nil || !privateOwned(info, false) || !os.SameFile(before, info) || info.Size() != item.Size || !info.ModTime().Equal(before.ModTime()) {
			return empty, invalid("receipt object changed")
		}
		verified = append(verified, info)
		if err = opts.Progress(Event{Kind: "stage_receipt_verified", Role: request.Role, ObjectID: item.StageID, Bytes: item.Size}); err != nil {
			return empty, err
		}
	}
	if err = checkSet(); err != nil {
		return empty, err
	}
	current, err = root.Lstat(request.Role + "/.lock")
	if err != nil || !os.SameFile(lockInfo, current) {
		return empty, invalid("receipt lock replaced")
	}
	for i, item := range request.Items {
		info, statErr := root.Lstat(request.Role + "/objects/" + item.StageID + ".blob")
		if statErr != nil || !privateOwned(info, false) || !os.SameFile(verified[i], info) || info.Size() != verified[i].Size() || !info.ModTime().Equal(verified[i].ModTime()) {
			return empty, invalid("receipt object changed")
		}
	}
	for name, before := range dirs {
		after, err := root.Lstat(name)
		if err != nil || !privateOwned(after, true) || !os.SameFile(before, after) {
			return empty, invalid("receipt directory replaced")
		}
	}
	if qerr != nil {
		if _, err := root.Lstat(quarantine); !errors.Is(err, os.ErrNotExist) {
			return empty, invalid("receipt quarantine changed")
		}
	}
	issued := now.Add(time.Since(started))
	body := stageReceiptBody{Request: request, IssuedUnix: issued.Unix(), ExpiresUnix: issued.Add(5 * time.Minute).Unix()}
	raw, err := json.Marshal(body)
	if err != nil {
		return empty, invalid("receipt encoding")
	}
	message := append([]byte("frontiercloud:preprod-stage-receipt:v2\x00"), raw...)
	return signedStageReceipt{Body: body, Signature: ed25519.Sign(signer, message)}, nil
}

// verifyStageReceipt requires expected to be built from the independently
// verified complete plan and target-only stage map, and ownerKey to be pinned
// independently to expected.OwnerID. No public-key self-assertion is trusted.
func verifyStageReceipt(receipt signedStageReceipt, expected stageReceiptRequest, ownerKey ed25519.PublicKey, now time.Time) error {
	if !validStageReceiptRequest(expected) || len(ownerKey) != ed25519.PublicKeySize || len(receipt.Signature) != ed25519.SignatureSize || receipt.Body.IssuedUnix <= 0 || receipt.Body.IssuedUnix > now.Unix() || receipt.Body.ExpiresUnix <= now.Unix() || receipt.Body.ExpiresUnix-receipt.Body.IssuedUnix != 300 {
		return invalid("receipt validation")
	}
	want, err := json.Marshal(expected)
	if err != nil {
		return invalid("receipt expected")
	}
	actual, err := json.Marshal(receipt.Body.Request)
	if err != nil || subtle.ConstantTimeCompare(want, actual) != 1 {
		return invalid("receipt request mismatch")
	}
	raw, err := json.Marshal(receipt.Body)
	if err != nil {
		return invalid("receipt body")
	}
	message := append([]byte("frontiercloud:preprod-stage-receipt:v2\x00"), raw...)
	if !ed25519.Verify(ownerKey, message, receipt.Signature) {
		return invalid("receipt signature")
	}
	return nil
}
