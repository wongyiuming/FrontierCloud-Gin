package business

import (
	"context"
	"io"
	"sync"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// RecordingAudioCipherOpener is a trusted startup dependency, never a browser
// input. It opens only the opaque blob named by an authenticated intent and
// holds the underlying media read lease until Close.
type RecordingAudioCipherOpener interface {
	OpenRecordingBrowserCipher(context.Context, string, string, int64) (io.ReadSeekCloser, error)
}

// RecordingAudioStream exposes only encrypted bytes and their browser
// descriptor. Every chunk must be authenticated by the browser before use.
type RecordingAudioStream struct {
	Title       string
	ContentType string
	Size        int64
	SHA256      string
	Encryption  mediacrypto.Metadata
	mu          sync.Mutex
	reader      io.ReadSeekCloser
	authority   *mediacrypto.DirectSessionAuthority
	lease       SelectedUploadRuntimeLease
	cancel      context.CancelFunc
	ctx         context.Context
	closed      bool
}

func (s *RecordingAudioStream) Read(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.ctx.Err() != nil {
		return 0, store.ErrRecordingState
	}
	if _, _, _, ok := s.authority.Values(); !ok {
		return 0, store.ErrRecordingState
	}
	return s.reader.Read(p)
}

func (s *RecordingAudioStream) Seek(offset int64, whence int) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.ctx.Err() != nil {
		return 0, store.ErrRecordingState
	}
	if _, _, _, ok := s.authority.Values(); !ok {
		return 0, store.ErrRecordingState
	}
	return s.reader.Seek(offset, whence)
}

func (s *RecordingAudioStream) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	err := s.reader.Close()
	s.cancel()
	s.lease.Release()
	return err
}

// OpenRecordingAudioLocal is not an HTTP route. Trusted startup must provide
// the actual Local media opener and recovery-ready gate; the HTTP layer must
// authenticate the account, browser and bounded crypto session. Account
// session revocation outside this process requires separate readiness proof.
// Owner control is held only through authentication and opening the pinned
// media handle, never during the returned ciphertext stream.
func (s *SelectedUploadRuntime) OpenRecordingAudioLocal(ctx context.Context, tree *sealedtree.SQLStore, expected store.PublicIngress, user store.KaraokeUser, browser, recordingID string, opener RecordingAudioCipherOpener, checkAccount func(context.Context) error) (*RecordingAudioStream, error) {
	if s == nil || s.repo == nil || ctx == nil || tree == nil || tree != s.tree || s.crypto == nil || s.vault == nil || selectedNil(s.gate) || selectedNil(opener) || checkAccount == nil {
		return nil, store.ErrRecordingState
	}
	authority := mediacrypto.DirectSessionFromContext(ctx)
	actualBrowser, sessionID, expires, valid := authority.Values()
	if !valid || actualBrowser != browser || expires <= time.Now().Unix() || checkAccount(ctx) != nil {
		return nil, store.ErrRecordingState
	}
	bounded, cancel := context.WithDeadline(ctx, time.Unix(expires, 0))
	lease, err := s.gate.AcquireSelectedUpload(bounded, tree)
	if err != nil || selectedNil(lease) {
		cancel()
		return nil, store.ErrNodeState
	}
	if lease.Check(bounded) != nil {
		lease.Release()
		cancel()
		return nil, store.ErrNodeState
	}
	var stream *RecordingAudioStream
	err = s.repo.WithOwnerControlExclusive(bounded, func(held context.Context) error {
		var intent recordingAudioIntent
		var title string
		ready, e := s.recordingAudioReadyWithInfo(held, expected, user, browser, sessionID, recordingID, &intent, &title, true, false)
		if e != nil || !ready || lease.Check(held) != nil {
			return store.ErrRecordingState
		}
		reader, e := opener.OpenRecordingBrowserCipher(bounded, intent.BlobID, intent.Digest, intent.Bytes)
		if e != nil || selectedNil(reader) {
			return store.ErrRecordingState
		}
		if _, _, _, ok := authority.Values(); !ok || lease.Check(held) != nil {
			_ = reader.Close()
			return store.ErrRecordingState
		}
		stream = &RecordingAudioStream{Title: title, ContentType: intent.ContentType, Size: intent.Bytes, SHA256: intent.Digest, Encryption: intent.Encryption, reader: reader, authority: authority, lease: lease, cancel: cancel, ctx: bounded}
		return nil
	})
	if err != nil || stream == nil {
		if stream != nil {
			_ = stream.reader.Close()
		}
		lease.Release()
		cancel()
		return nil, store.ErrRecordingState
	}
	// Redis/account validation may involve I/O, so it runs after the Owner and
	// SQL fences have been released, but before the caller can read any bytes.
	if checkAccount(bounded) != nil || lease.Check(bounded) != nil {
		_ = stream.Close()
		return nil, store.ErrRecordingState
	}
	if _, _, _, ok := authority.Values(); !ok {
		_ = stream.Close()
		return nil, store.ErrRecordingState
	}
	return stream, nil
}
