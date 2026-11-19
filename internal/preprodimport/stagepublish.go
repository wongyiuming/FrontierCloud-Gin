package preprodimport

// Synthetic owner-side primitive; not a registered API or a real import.
// Its caller must first authenticate and persist both the complete plan and
// the tree intent. A source key, logical path, or plaintext media key is never
// required by this owner-side operation.
import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
)

type stagePublishRequest struct {
	Version                                         int `json:"version"`
	MasterID, OwnerID, Role, Generation, PlanDigest string
	OperationID, StageID, BlobID, SHA256, Challenge string
	Size, IssuedUnix, ExpiresUnix                   int64
}
type signedStagePublishRequest struct {
	Request   stagePublishRequest
	Signature []byte
}
type stagePublishReceiptBody struct {
	Request       stagePublishRequest
	CompletedUnix int64
}
type signedStagePublishReceipt struct {
	Body      stagePublishReceiptBody
	Signature []byte
}

func stagePublishRootsOverlap(first, second string) (bool, error) {
	a, err := filepath.EvalSymlinks(first)
	if err != nil {
		return false, err
	}
	b, err := filepath.EvalSymlinks(second)
	if err != nil {
		return false, err
	}
	inside := func(parent, child string) (bool, error) {
		rel, err := filepath.Rel(parent, child)
		if err != nil {
			return false, err
		}
		return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))), nil
	}
	one, err := inside(a, b)
	if err != nil {
		return false, err
	}
	two, err := inside(b, a)
	return one || two, err
}

func validStagePublishRequest(r stagePublishRequest, now time.Time) bool {
	return r.Version == 1 && id32.MatchString(r.MasterID) && id32.MatchString(r.OwnerID) && (r.Role == "master" || r.Role == "direct" || r.Role == "relay") && ((r.Role == "master") == (r.OwnerID == r.MasterID)) && id64.MatchString(r.Generation) && id64.MatchString(r.PlanDigest) && id64.MatchString(r.OperationID) && id64.MatchString(r.StageID) && id64.MatchString(r.BlobID) && r.OperationID != r.StageID && r.OperationID != r.BlobID && r.StageID != r.BlobID && id64.MatchString(r.SHA256) && id64.MatchString(r.Challenge) && r.Size >= 0 && r.Size <= 10*1024*1024*1024 && r.IssuedUnix > 0 && r.IssuedUnix <= now.Unix() && r.ExpiresUnix > now.Unix() && r.ExpiresUnix-r.IssuedUnix <= 300
}
func signSyntheticStagePublishRequest(r stagePublishRequest, key ed25519.PrivateKey, now time.Time) (signedStagePublishRequest, error) {
	if !validStagePublishRequest(r, now) || len(key) != ed25519.PrivateKeySize {
		return signedStagePublishRequest{}, invalid("stage publish request")
	}
	b, err := json.Marshal(r)
	if err != nil {
		return signedStagePublishRequest{}, err
	}
	return signedStagePublishRequest{Request: r, Signature: ed25519.Sign(key, append([]byte("frontiercloud:stage-publish-request:v1\x00"), b...))}, nil
}
func verifyStagePublishRequest(request signedStagePublishRequest, expected stagePublishRequest, masterPin ed25519.PublicKey, now time.Time) error {
	if !validStagePublishRequest(expected, now) || len(masterPin) != ed25519.PublicKeySize || len(request.Signature) != ed25519.SignatureSize {
		return invalid("stage publish authorization")
	}
	a, err := json.Marshal(expected)
	if err != nil {
		return err
	}
	b, err := json.Marshal(request.Request)
	if err != nil || subtle.ConstantTimeCompare(a, b) != 1 || !ed25519.Verify(masterPin, append([]byte("frontiercloud:stage-publish-request:v1\x00"), b...), request.Signature) {
		return invalid("stage publish signature")
	}
	return nil
}

// publishSyntheticStagedBlob requires a private stage root, a separately
// controlled private owner root and an independently pinned Master key. It
// does not remove stage bytes or release any tree intent. A failed call may
// leave a complete final blob: retry with the same authenticated operation.
func publishSyntheticStagedBlob(ctx context.Context, stagePath, ownerPath string, journal *sql.DB, journalKey []byte, request signedStagePublishRequest, expected stagePublishRequest, masterPin ed25519.PublicKey, ownerKey ed25519.PrivateKey, opts Options, now time.Time) (signedStagePublishReceipt, error) {
	var out signedStagePublishReceipt
	started := time.Now()
	if ctx == nil || journal == nil || len(ownerKey) != ed25519.PrivateKeySize || opts.Progress == nil || opts.MaxBytesPerSecond <= 0 || opts.MaxBytesPerSecond > 4*1024*1024 {
		return out, invalid("stage publish input")
	}
	if err := verifyStagePublishRequest(request, expected, masterPin, now); err != nil {
		return out, err
	}
	stageInfo, err := os.Lstat(stagePath)
	if err != nil || !privateOwned(stageInfo, true) {
		return out, invalid("stage publish root")
	}
	ownerInfo, err := os.Lstat(ownerPath)
	if err != nil || !privateOwned(ownerInfo, true) || os.SameFile(stageInfo, ownerInfo) {
		return out, invalid("stage publish owner root")
	}
	overlap, err := stagePublishRootsOverlap(stagePath, ownerPath)
	if err != nil || overlap {
		return out, invalid("stage publish root overlap")
	}
	stage, err := os.OpenRoot(stagePath)
	if err != nil {
		return out, err
	}
	defer stage.Close()
	stageOpened, err := stage.Stat(".")
	if err != nil || !os.SameFile(stageInfo, stageOpened) {
		return out, invalid("stage publish root changed")
	}
	owner, err := os.OpenRoot(ownerPath)
	if err != nil {
		return out, err
	}
	defer owner.Close()
	ownerOpened, err := owner.Stat(".")
	if err != nil || !os.SameFile(ownerInfo, ownerOpened) {
		return out, invalid("stage publish owner changed")
	}
	name := expected.Role + "/objects/" + expected.StageID + ".blob"
	for _, p := range []string{expected.Role, expected.Role + "/objects"} {
		info, e := stage.Lstat(p)
		if e != nil || !privateOwned(info, true) {
			return out, invalid("stage publish directory")
		}
	}
	before, err := stage.Lstat(name)
	if err != nil || !privateOwned(before, false) || before.Size() != expected.Size {
		return out, invalid("stage publish source")
	}
	src, err := stage.Open(name)
	if err != nil {
		return out, err
	}
	defer src.Close()
	opened, err := src.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return out, invalid("stage publish source changed")
	}
	if err := reserveSyntheticStagePublish(ctx, journal, journalKey, expected, request.Signature); err != nil {
		return out, err
	}
	destination, err := sealedtree.BlobPath(expected.BlobID)
	if err != nil {
		return out, err
	}
	_, destinationErr := owner.Lstat(destination)
	if errors.Is(destinationErr, os.ErrNotExist) {
		pub, err := sealedtree.NewBlobPublisher(owner)
		if err != nil {
			return out, err
		}
		limit := &limiter{start: time.Now(), rate: opts.MaxBytesPerSecond}
		if err = pub.Publish(ctx, expected.OperationID, expected.BlobID, expected.Size, expected.SHA256, checkedReader{ctx, src, limit}); err != nil {
			return out, err
		}
		if err = opts.Progress(Event{Kind: "stage_blob_linked", Role: expected.Role, ObjectID: expected.StageID, Bytes: expected.Size}); err != nil {
			return out, err
		}
	} else if destinationErr != nil {
		return out, invalid("stage publish destination")
	}
	if err = finalizeSyntheticStageBlob(ctx, owner, expected, opts.MaxBytesPerSecond, opts.Progress); err != nil {
		return out, err
	}
	if err = opts.Progress(Event{Kind: "stage_blob_finalized", Role: expected.Role, ObjectID: expected.StageID, Bytes: expected.Size}); err != nil {
		return out, err
	}
	after, err := src.Stat()
	current, currentErr := stage.Lstat(name)
	if err != nil || currentErr != nil || !os.SameFile(before, after) || !os.SameFile(before, current) || after.Size() != before.Size() || current.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) || !current.ModTime().Equal(before.ModTime()) {
		return out, invalid("stage publish source changed")
	}
	if err = opts.Progress(Event{Kind: "stage_blob_published", Role: expected.Role, ObjectID: expected.StageID, Bytes: expected.Size}); err != nil {
		return out, err
	}
	completed := now.Add(time.Since(started))
	if !validStagePublishRequest(expected, completed) {
		return out, invalid("stage publish authorization expired")
	}
	body := stagePublishReceiptBody{Request: expected, CompletedUnix: completed.Unix()}
	raw, err := json.Marshal(body)
	if err != nil {
		return out, err
	}
	return signedStagePublishReceipt{Body: body, Signature: ed25519.Sign(ownerKey, append([]byte("frontiercloud:stage-publish-receipt:v1\x00"), raw...))}, nil
}

// finalizeSyntheticStageBlob verifies the persisted operation's final blob,
// then removes only the verified same-inode staging link. A prior unlink is
// recoverable only when the final object has exactly one link and the journal
// still binds this exact signed request. This does not defend against a hostile
// owner rolling back the entire journal or bypassing its cooperative fence.
func finalizeSyntheticStageBlob(ctx context.Context, owner *os.Root, r stagePublishRequest, rate int64, progress func(Event) error) error {
	dest, err := sealedtree.BlobPath(r.BlobID)
	if err != nil {
		return err
	}
	for _, name := range []string{"objects", "objects/" + r.BlobID[:2], "objects/" + r.BlobID[:2] + "/" + r.BlobID[2:4]} {
		info, e := owner.Lstat(name)
		if e != nil || !privateOwned(info, true) {
			return invalid("stage final directory")
		}
	}
	before, err := owner.Lstat(dest)
	if err != nil || !privateOwned(before, false) || before.Size() != r.Size {
		return invalid("stage final object")
	}
	f, err := owner.Open(dest)
	if err != nil {
		return err
	}
	opened, err := f.Stat()
	if err != nil || !os.SameFile(before, opened) {
		f.Close()
		return invalid("stage final changed")
	}
	h := sha256.New()
	n, readErr := io.Copy(h, io.LimitReader(checkedReader{ctx, f, &limiter{start: time.Now(), rate: rate}}, r.Size+1))
	after, statErr := f.Stat()
	closeErr := f.Close()
	current, currentErr := owner.Lstat(dest)
	if readErr != nil {
		return readErr
	}
	if statErr != nil || closeErr != nil || currentErr != nil || n != r.Size || !os.SameFile(before, after) || !os.SameFile(before, current) || after.Size() != r.Size || current.Size() != r.Size || !after.ModTime().Equal(before.ModTime()) || !current.ModTime().Equal(before.ModTime()) || hex.EncodeToString(h.Sum(nil)) != r.SHA256 {
		return invalid("stage final changed")
	}
	part := "staging/" + r.OperationID + ".part"
	stageInfo, stageErr := owner.Lstat(part)
	links, ok := stagePublishLinkCount(current)
	if !ok {
		return invalid("stage final links")
	}
	if errors.Is(stageErr, os.ErrNotExist) {
		if links != 1 {
			return invalid("stage final links")
		}
		return syncSyntheticStagingDirectory(owner)
	}
	if stageErr != nil || !privateOwned(stageInfo, false) || !os.SameFile(current, stageInfo) || links != 2 {
		return invalid("stage link mismatch")
	}
	stageDir, err := owner.Lstat("staging")
	if err != nil || !privateOwned(stageDir, true) {
		return invalid("stage final staging directory")
	}
	directory, err := owner.Open("staging")
	if err != nil {
		return err
	}
	defer directory.Close()
	openedDir, err := directory.Stat()
	if err != nil || !os.SameFile(stageDir, openedDir) {
		return invalid("stage final staging changed")
	}
	pinned, err := owner.OpenRoot("staging")
	if err != nil {
		return err
	}
	defer pinned.Close()
	pinnedDir, err := pinned.Stat(".")
	if err != nil || !os.SameFile(stageDir, pinnedDir) {
		return invalid("stage final staging changed")
	}
	partName := r.OperationID + ".part"
	pinnedPart, err := pinned.Lstat(partName)
	if err != nil || !privateOwned(pinnedPart, false) || !os.SameFile(stageInfo, pinnedPart) {
		return invalid("stage final part changed")
	}
	if err = pinned.Remove(partName); err != nil {
		return err
	}
	if err = progress(Event{Kind: "stage_blob_unlinked_before_sync", Role: r.Role, ObjectID: r.StageID, Bytes: r.Size}); err != nil {
		return err
	}
	if err = directory.Sync(); err != nil {
		return err
	}
	currentDir, err := owner.Lstat("staging")
	if err != nil || !os.SameFile(stageDir, currentDir) {
		return invalid("stage final staging changed")
	}
	final, err := owner.Lstat(dest)
	if err != nil || !os.SameFile(current, final) {
		return invalid("stage final changed")
	}
	links, ok = stagePublishLinkCount(final)
	if !ok || links != 1 {
		return invalid("stage final links")
	}
	return nil
}

// A crash may occur after unlink and before syncing its directory. Even when
// the staging link is already absent, recovery must sync the pinned directory
// before issuing a completion receipt.
func syncSyntheticStagingDirectory(owner *os.Root) error {
	before, err := owner.Lstat("staging")
	if err != nil || !privateOwned(before, true) {
		return invalid("stage final staging directory")
	}
	pinned, err := owner.OpenRoot("staging")
	if err != nil {
		return err
	}
	defer pinned.Close()
	dir, err := pinned.Open(".")
	if err != nil {
		return err
	}
	defer dir.Close()
	opened, err := dir.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return invalid("stage final staging changed")
	}
	if err = dir.Sync(); err != nil {
		return err
	}
	after, err := owner.Lstat("staging")
	if err != nil || !os.SameFile(before, after) {
		return invalid("stage final staging changed")
	}
	return nil
}

func verifyStagePublishReceipt(receipt signedStagePublishReceipt, expected stagePublishRequest, ownerPin ed25519.PublicKey, now time.Time) error {
	if !validStagePublishRequest(expected, now) || len(ownerPin) != ed25519.PublicKeySize || len(receipt.Signature) != ed25519.SignatureSize || receipt.Body.CompletedUnix < expected.IssuedUnix || receipt.Body.CompletedUnix >= expected.ExpiresUnix || receipt.Body.CompletedUnix > now.Unix() {
		return invalid("stage publish receipt")
	}
	a, err := json.Marshal(expected)
	if err != nil {
		return err
	}
	b, err := json.Marshal(receipt.Body.Request)
	if err != nil || subtle.ConstantTimeCompare(a, b) != 1 {
		return invalid("stage publish receipt binding")
	}
	raw, err := json.Marshal(receipt.Body)
	if err != nil || !ed25519.Verify(ownerPin, append([]byte("frontiercloud:stage-publish-receipt:v1\x00"), raw...), receipt.Signature) {
		return invalid("stage publish receipt signature")
	}
	return nil
}
