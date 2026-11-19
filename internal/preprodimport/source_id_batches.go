package preprodimport

import (
	"context"
	"crypto/ecdh"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"reflect"
	"sync"
	"time"
)

// SourceIDBatch is a short-lived authenticated view of at most 256 historical
// encryption IDs. The explicit empty-set path can produce one zero-ID final
// batch only after complete verification. It is valid only during its callback.
// It does not authorize
// issuing media keys, publishing rows, or marking the entire import complete.
type SourceIDBatch struct {
	mu             sync.Mutex
	active         bool
	checked        bool
	ctx            context.Context
	stage          *os.File
	stageInfo      os.FileInfo
	signed         signedSourceStream
	intent         sourceCaptureIntent
	public         string
	receiver       []byte
	manifestDigest string
	index          int64
	last           bool
	ids            []string
	digest         string
}

type SourceIDBatchView struct {
	Index          int64
	Last           bool
	IDs            []string
	Digest         string
	ManifestDigest string
}

func sourceIDBatchDigest(manifest string, index int64, last bool, ids []string) (string, error) {
	if !id64.MatchString(manifest) || index < 0 || len(ids) > 256 {
		return "", invalid("source ID batch scope")
	}
	lastID := ""
	for _, id := range ids {
		if !id32.MatchString(id) || (lastID != "" && id <= lastID) {
			return "", invalid("source ID batch order")
		}
		lastID = id
	}
	raw, err := json.Marshal(struct {
		Manifest string   `json:"manifest_sha256"`
		Index    int64    `json:"index"`
		Last     bool     `json:"last"`
		IDs      []string `json:"ids"`
	}{manifest, index, last, ids})
	if err != nil {
		return "", err
	}
	defer clear(raw)
	digest := sha256.Sum256(append([]byte("frontiercloud:source-id-batch:v1\x00"), raw...))
	return hex.EncodeToString(digest[:]), nil
}

func (b *SourceIDBatch) checkLocked() error {
	if b == nil || !b.active || b.ctx == nil || b.ctx.Err() != nil || b.stage == nil || b.stageInfo == nil {
		return invalid("source ID batch expired")
	}
	current, err := b.stage.Stat()
	if err != nil || !privateOwned(current, false) || !os.SameFile(b.stageInfo, current) || current.Size() != b.stageInfo.Size() || !current.ModTime().Equal(b.stageInfo.ModTime()) {
		return invalid("source ID stage changed")
	}
	if err = verifySourceStreamManifest(b.signed, b.intent, b.public, b.receiver, time.Now().UTC()); err != nil {
		return err
	}
	digest, err := sourceIDBatchDigest(b.manifestDigest, b.index, b.last, b.ids)
	if err != nil || subtle.ConstantTimeCompare([]byte(digest), []byte(b.digest)) != 1 {
		return invalid("source ID batch changed")
	}
	return nil
}

func (b *SourceIDBatch) View() (SourceIDBatchView, error) {
	if b == nil {
		return SourceIDBatchView{}, invalid("source ID batch")
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := b.checkLocked(); err != nil {
		return SourceIDBatchView{}, err
	}
	return SourceIDBatchView{Index: b.index, Last: b.last, IDs: append([]string(nil), b.ids...), Digest: b.digest, ManifestDigest: b.manifestDigest}, nil
}

// CheckForCommit is called inside the target's fenced transaction immediately
// before committing the exact IDs actually reserved and their progress marker.
func (b *SourceIDBatch) CheckForCommit(ids []string) error {
	if b == nil {
		return invalid("source ID batch")
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := b.checkLocked(); err != nil {
		return err
	}
	if !reflect.DeepEqual(ids, b.ids) {
		return invalid("source ID batch values changed")
	}
	b.checked = true
	return nil
}

// replayAuthenticatedSourceIDBatches first verifies the entire signed stream,
// then rescans it once with per-chunk AEAD and emits strictly ordered batches.
// Each callback must commit reservations and its authenticated checkpoint in
// one fenced target transaction. After a crash, callers must fully revalidate
// and replay in order, skipping only an exactly matching committed checkpoint.
// The final batch is emitted only after the second complete verification.
// This is unregistered internal code; target transaction and recovery wiring
// are not supplied here and remain mandatory before enabling key issuance.
func replayAuthenticatedSourceIDBatches(ctx context.Context, signed signedSourceStream, intent sourceCaptureIntent, public string, receiver *ecdh.PrivateKey, stage *os.File, accept func(*SourceIDBatch) error) error {
	return replayAuthenticatedSourceIDBatchesInternal(ctx, signed, intent, public, receiver, stage, accept, false)
}

// The explicit empty path is separate so old consumers cannot accidentally
// interpret an empty final marker as permission to issue keys.
func replayAuthenticatedSourceIDBatchesAllowEmpty(ctx context.Context, signed signedSourceStream, intent sourceCaptureIntent, public string, receiver *ecdh.PrivateKey, stage *os.File, accept func(*SourceIDBatch) error) error {
	return replayAuthenticatedSourceIDBatchesInternal(ctx, signed, intent, public, receiver, stage, accept, true)
}

func replayAuthenticatedSourceIDBatchesInternal(ctx context.Context, signed signedSourceStream, intent sourceCaptureIntent, public string, receiver *ecdh.PrivateKey, stage *os.File, accept func(*SourceIDBatch) error, allowEmpty bool) error {
	if ctx == nil || ctx.Err() != nil || receiver == nil || stage == nil || accept == nil {
		return invalid("source ID batch input")
	}
	// Freeze caller-owned mutable slices before verification and callbacks.
	raw, err := json.Marshal(signed)
	if err != nil {
		return err
	}
	var pinned signedSourceStream
	if err = json.Unmarshal(raw, &pinned); err != nil {
		return err
	}
	clear(raw)
	info, err := stage.Stat()
	if err != nil || !privateOwned(info, false) {
		return invalid("source ID stage")
	}
	if err = validateCapturedSourceStreamV2(ctx, pinned, intent, public, receiver, stage, time.Now().UTC()); err != nil {
		return err
	}
	current, err := stage.Stat()
	if err != nil || !os.SameFile(info, current) || info.Size() != current.Size() || !info.ModTime().Equal(current.ModTime()) {
		return invalid("source ID stage changed")
	}
	manifestDigest, err := sourceStreamManifestDigest(pinned.Manifest)
	if err != nil {
		return err
	}
	lastSection := pinned.Manifest.Sections[len(pinned.Manifest.Sections)-1]
	if lastSection.Name != "encryption_ids" || lastSection.Rows < 0 {
		return invalid("source ID section")
	}
	var index, seen int64
	ids := make([]string, 0, 256)
	emit := func(last bool) error {
		batchIDs := append([]string(nil), ids...)
		digest, e := sourceIDBatchDigest(manifestDigest, index, last, batchIDs)
		if e != nil {
			return e
		}
		proof := &SourceIDBatch{active: true, ctx: ctx, stage: stage, stageInfo: info, signed: pinned, intent: intent, public: public, receiver: append([]byte(nil), receiver.PublicKey().Bytes()...), manifestDigest: manifestDigest, index: index, last: last, ids: batchIDs, digest: digest}
		if _, e = proof.View(); e != nil {
			return e
		}
		checked := false
		e = func() (out error) {
			defer func() {
				proof.mu.Lock()
				checked = proof.checked
				proof.active = false
				clear(proof.ids)
				proof.mu.Unlock()
				if recover() != nil {
					out = invalid("source ID consumer panic")
				}
			}()
			return accept(proof)
		}()
		if e != nil {
			return e
		}
		if !checked {
			return invalid("source ID batch not checked for commit")
		}
		index++
		ids = ids[:0]
		return nil
	}
	visit := func(id string) error {
		seen++
		if seen > lastSection.Rows {
			return invalid("source ID count")
		}
		ids = append(ids, id)
		if len(ids) == 256 && seen < lastSection.Rows {
			return emit(false)
		}
		return nil
	}
	plainRaw, err := hex.DecodeString(pinned.Manifest.PlainSHA256)
	if err != nil || len(plainRaw) != 32 {
		return invalid("source ID plaintext digest")
	}
	cipherRaw, err := hex.DecodeString(pinned.Manifest.CipherSHA256)
	if err != nil || len(cipherRaw) != 32 {
		return invalid("source ID ciphertext digest")
	}
	var plain, cipher [32]byte
	copy(plain[:], plainRaw)
	copy(cipher[:], cipherRaw)
	reader, writer := io.Pipe()
	done := make(chan error, 1)
	go func() {
		e := verifySourceRowsV2VisitIDs(ctx, reader, pinned.Manifest.Header.PlainSize, pinned.Manifest.Sections, intent.SourceKeyID, visit)
		_ = reader.CloseWithError(e)
		done <- e
	}()
	err = openSourceStreamV2(ctx, pinned.Manifest.Header, receiver, stage, writer, plain, cipher)
	if err != nil {
		_ = writer.CloseWithError(err)
	} else {
		_ = writer.Close()
	}
	verifyErr := <-done
	if err != nil {
		return err
	}
	if verifyErr != nil {
		return verifyErr
	}
	if seen != lastSection.Rows {
		return invalid("source ID count")
	}
	if seen == 0 && !allowEmpty {
		return invalid("empty source ID set requires explicit completion")
	}
	return emit(true)
}
