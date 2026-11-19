package preprodimport

import (
	"context"
	"crypto/ecdh"
	"encoding/json"
	"os"
	"sync"
	"time"
)

// SourceIDCompletion is created only after the entire authenticated replay and
// every short-lived batch callback succeeded. It is not an import readiness or
// key-issuance capability: the target must still validate its durable batch
// chain and owner/recovery gates in the same fenced transaction.
type SourceIDCompletion struct {
	mu              sync.Mutex
	active, checked bool
	ctx             context.Context
	stage           *os.File
	stageInfo       os.FileInfo
	signed          signedSourceStream
	intent          sourceCaptureIntent
	public          string
	receiver        []byte
	view            SourceIDCompletionView
}

type SourceIDCompletionView struct {
	ManifestDigest   string
	SourceNode       string
	TargetNode       string
	SourceKeyID      string
	ScopeDigest      string
	IDCount          int64
	BatchCount       int64
	Empty            bool
	FinalBatchDigest string
}

func (p *SourceIDCompletion) checkLocked() error {
	if p == nil || !p.active || p.ctx == nil || p.ctx.Err() != nil || p.stage == nil || p.stageInfo == nil {
		return invalid("source ID completion expired")
	}
	current, err := p.stage.Stat()
	if err != nil || !privateOwned(current, false) || !os.SameFile(p.stageInfo, current) || current.Size() != p.stageInfo.Size() || !current.ModTime().Equal(p.stageInfo.ModTime()) {
		return invalid("source ID completion stage changed")
	}
	if err = verifySourceStreamManifest(p.signed, p.intent, p.public, p.receiver, time.Now().UTC()); err != nil {
		return err
	}
	digest, err := sourceStreamManifestDigest(p.signed.Manifest)
	if err != nil || digest != p.view.ManifestDigest || p.view.SourceNode != p.intent.SourceNode || p.view.TargetNode != p.intent.TargetNode || p.view.SourceKeyID != p.intent.SourceKeyID || p.view.ScopeDigest != p.intent.ScopeDigest || !id64.MatchString(p.view.FinalBatchDigest) {
		return invalid("source ID completion changed")
	}
	last := p.signed.Manifest.Sections[len(p.signed.Manifest.Sections)-1]
	if last.Name != "encryption_ids" || last.Rows != p.view.IDCount || p.view.Empty != (last.Rows == 0) {
		return invalid("source ID completion count")
	}
	count := int64(0)
	if last.Rows > 0 {
		count = (last.Rows-1)/256 + 1
	}
	if p.view.BatchCount != count {
		return invalid("source ID completion batches")
	}
	return nil
}

func (p *SourceIDCompletion) View() (SourceIDCompletionView, error) {
	if p == nil {
		return SourceIDCompletionView{}, invalid("source ID completion")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.checkLocked(); err != nil {
		return SourceIDCompletionView{}, err
	}
	return p.view, nil
}

// CheckForCommit requires the exact view the target used for its SQL writes;
// call it after checking durable batch state, immediately before commit.
func (p *SourceIDCompletion) CheckForCommit(used SourceIDCompletionView) error {
	if p == nil {
		return invalid("source ID completion")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.checkLocked(); err != nil {
		return err
	}
	if used != p.view {
		return invalid("source ID completion values changed")
	}
	p.checked = true
	return nil
}

// withAuthenticatedSourceIDCompletion never creates a completion proof until
// replay, including the final batch callback, has fully succeeded. Both batch
// and completion proofs expire when their callbacks return. No product route
// invokes this function.
func withAuthenticatedSourceIDCompletion(ctx context.Context, signed signedSourceStream, intent sourceCaptureIntent, public string, receiver *ecdh.PrivateKey, stage *os.File, accept func(*SourceIDBatch) error, finish func(*SourceIDCompletion) error) error {
	if ctx == nil || ctx.Err() != nil || receiver == nil || stage == nil || accept == nil || finish == nil {
		return invalid("source ID completion input")
	}
	raw, err := json.Marshal(signed)
	if err != nil {
		return err
	}
	defer clear(raw)
	var pinned signedSourceStream
	if err = json.Unmarshal(raw, &pinned); err != nil {
		return err
	}
	info, err := stage.Stat()
	if err != nil || !privateOwned(info, false) {
		return invalid("source ID completion stage")
	}
	manifest, err := sourceStreamManifestDigest(pinned.Manifest)
	if err != nil {
		return err
	}
	last := pinned.Manifest.Sections[len(pinned.Manifest.Sections)-1]
	if last.Name != "encryption_ids" || last.Rows < 0 {
		return invalid("source ID completion section")
	}
	var batches, seen int64
	var finalDigest string
	finalSeen := false
	err = replayAuthenticatedSourceIDBatchesAllowEmpty(ctx, pinned, intent, public, receiver, stage, func(batch *SourceIDBatch) error {
		view, e := batch.View()
		if e != nil {
			return e
		}
		if finalSeen || view.ManifestDigest != manifest || view.Index != batches || len(view.IDs) > 256 || (last.Rows > 0 && len(view.IDs) == 0) || (last.Rows == 0 && (len(view.IDs) != 0 || !view.Last || view.Index != 0)) {
			return invalid("source ID completion batch order")
		}
		seen += int64(len(view.IDs))
		if seen < 0 || seen > last.Rows {
			return invalid("source ID completion row count")
		}
		if view.Last {
			if seen != last.Rows {
				return invalid("source ID completion final count")
			}
			finalSeen = true
			finalDigest = view.Digest
		}
		if e = accept(batch); e != nil {
			return e
		}
		if last.Rows > 0 {
			batches++
		}
		return nil
	})
	if err != nil {
		return err
	}
	expected := int64(0)
	if last.Rows > 0 {
		expected = (last.Rows-1)/256 + 1
	}
	if !finalSeen || seen != last.Rows || batches != expected || !id64.MatchString(finalDigest) {
		return invalid("source ID completion incomplete")
	}
	p := &SourceIDCompletion{active: true, ctx: ctx, stage: stage, stageInfo: info, signed: pinned, intent: intent, public: public, receiver: append([]byte(nil), receiver.PublicKey().Bytes()...), view: SourceIDCompletionView{ManifestDigest: manifest, SourceNode: intent.SourceNode, TargetNode: intent.TargetNode, SourceKeyID: intent.SourceKeyID, ScopeDigest: intent.ScopeDigest, IDCount: seen, BatchCount: batches, Empty: seen == 0, FinalBatchDigest: finalDigest}}
	if _, err = p.View(); err != nil {
		return err
	}
	checked := false
	err = func() (result error) {
		defer func() {
			p.mu.Lock()
			checked = p.checked
			p.active = false
			p.mu.Unlock()
			if recover() != nil {
				result = invalid("source ID completion consumer panic")
			}
		}()
		return finish(p)
	}()
	if err != nil {
		return err
	}
	if !checked {
		return invalid("source ID completion not checked")
	}
	return nil
}
