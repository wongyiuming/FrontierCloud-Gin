//go:build linux

package httpapi

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/network"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// Pause after the actual owner handler opened and read the blob. The Relay
// handler must retain its own tree lease through this point.
type opaqueRelayBarrierTransport struct {
	*clusterHTTP
	opened chan struct{}
	resume chan struct{}
	once   sync.Once
}

// The proxy requires both deadline operations on its downstream writer.
// ResponseRecorder alone does not implement the real server's deadlines.
type opaqueProxyRecorder struct{ *httptest.ResponseRecorder }

func (opaqueProxyRecorder) SetReadDeadline(time.Time) error  { return nil }
func (opaqueProxyRecorder) SetWriteDeadline(time.Time) error { return nil }

type localIngressRouting struct {
	*masterDirectHTTPRouting
	mu         sync.RWMutex
	state      atomic.Pointer[store.PublicIngress]
	failCommit atomic.Bool
}

type localIngressLease struct {
	routing *localIngressRouting
	once    sync.Once
}

func (l *localIngressLease) Release() { l.once.Do(l.routing.mu.RUnlock) }
func (l *localIngressLease) Commit() error {
	l.Release()
	if l.routing.failCommit.Load() {
		return errors.New("fixture commit failure")
	}
	return nil
}
func (r *localIngressRouting) PublicIngress(context.Context) (store.PublicIngress, error) {
	return *r.state.Load(), nil
}
func (r *localIngressRouting) AcquireCurrentIngress(context.Context) (store.PublicIngress, store.PublicIngressLease, error) {
	r.mu.RLock()
	return *r.state.Load(), &localIngressLease{routing: r}, nil
}
func (r *localIngressRouting) ExistingPublicIngress(ctx context.Context) (store.PublicIngress, error) {
	return r.PublicIngress(ctx)
}
func (r *localIngressRouting) AcquireExistingIngress(ctx context.Context) (store.PublicIngress, store.PublicIngressLease, error) {
	return r.AcquireCurrentIngress(ctx)
}
func (r *localIngressRouting) change(value store.PublicIngress) {
	r.mu.Lock()
	r.state.Store(&value)
	r.mu.Unlock()
}

type localDrainRecorder struct {
	*httptest.ResponseRecorder
	started chan struct{}
	resume  chan struct{}
	once    sync.Once
}

func (*localDrainRecorder) SetWriteDeadline(time.Time) error { return nil }
func (r *localDrainRecorder) Write(p []byte) (int, error) {
	r.once.Do(func() { close(r.started); <-r.resume })
	return r.ResponseRecorder.Write(p)
}

func (t *opaqueRelayBarrierTransport) MediaOpaqueRelayRead(ctx context.Context, origin, alias, token, method, byteRange string, size int64) (node.FollowerRelayResponse, error) {
	response, err := t.clusterHTTP.MediaOpaqueRelayRead(ctx, origin, alias, token, method, byteRange, size)
	if err != nil {
		return response, err
	}
	t.once.Do(func() { close(t.opened) })
	select {
	case <-t.resume:
		return response, nil
	case <-ctx.Done():
		response.Body.Close()
		return node.FollowerRelayResponse{}, ctx.Err()
	}
}

// A synthetic transition fixture joins real tree/owner reads and an existing
// authorization database. It does not enable the product's migration gate.
func TestOpaqueLocalSourceUsesHeldRealTreeAndOwner(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	transport := &clusterHTTP{routers: map[string]*gin.Engine{}}
	_, db, masterDir, public, master := clusterFixture(t, "https://master.test", transport, false)
	identity, err := master.Promote(ctx, "Master", "https://master.test", 10*store.GiB, store.NodeAudit{})
	if err != nil {
		t.Fatal(err)
	}
	public.media.ConfigureCluster(db.Nodes(), db.Pool(), master)
	treeDB, err := sql.Open("sqlite", "file:"+filepath.ToSlash(filepath.Join(t.TempDir(), "tree.sqlite"))+"?_pragma=busy_timeout(10000)")
	if err != nil {
		t.Fatal(err)
	}
	defer treeDB.Close()
	codec, err := sealedtree.New(bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32))
	if err != nil {
		t.Fatal(err)
	}
	rootID, musicID, albumID, lyricsID := strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64), strings.Repeat("d", 64)
	tree, err := sealedtree.InitializeSQLite(ctx, treeDB, codec, rootID)
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{`CREATE TABLE node_identity(singleton INTEGER PRIMARY KEY,node_id TEXT NOT NULL,role TEXT NOT NULL,private_key TEXT NOT NULL,created_at INTEGER NOT NULL)`, `CREATE TABLE admin_audit_log(session_id_hash TEXT,action TEXT,target_count INTEGER,source_summary TEXT,result TEXT,detail TEXT,client_ip TEXT,user_agent TEXT,request_id TEXT,trace_id TEXT,created_at TEXT)`} {
		if _, err = treeDB.ExecContext(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = treeDB.ExecContext(ctx, `INSERT INTO node_identity VALUES(1,?,'Master','synthetic-fixture-key',1)`, identity.ID); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err = os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if _, err = sealedtree.InitializeFence(ctx, tree, root, dir); err != nil {
		t.Fatal(err)
	}
	for _, e := range []sealedtree.Entry{{ParentID: rootID, ObjectID: musicID, Kind: "directory", Name: "music"}, {ParentID: musicID, ObjectID: albumID, Kind: "directory", Name: "album"}, {ParentID: rootID, ObjectID: lyricsID, Kind: "directory", Name: "lyrics"}} {
		if err = tree.CreateDirectoryWithFacts(ctx, e, sealedtree.Facts{ObjectID: e.ObjectID}); err != nil {
			t.Fatal(err)
		}
	}
	publisher, err := sealedtree.NewBlobPublisher(root)
	if err != nil {
		t.Fatal(err)
	}
	type uploaded struct {
		id, blob, alias string
		data            []byte
	}
	publish := func(id, parent, kind, name string, plain []byte, encrypted bool) uploaded {
		t.Helper()
		content := append([]byte(nil), plain...)
		var meta *mediacrypto.Metadata
		if encrypted {
			v, e := mediacrypto.NewMetadata(int64(len(plain)))
			if e != nil {
				t.Fatal(e)
			}
			key, e := public.crypto.FileKey(v)
			if e != nil {
				t.Fatal(e)
			}
			block, e := aes.NewCipher(key)
			if e != nil {
				t.Fatal(e)
			}
			aead, e := cipher.NewGCM(block)
			if e != nil {
				t.Fatal(e)
			}
			nonce, e := v.ChunkNonce(0)
			if e != nil {
				t.Fatal(e)
			}
			content = aead.Seal(nil, nonce, plain, v.ChunkAAD(0))
			meta = &v
		}
		sum := sha256.Sum256(content)
		placement := sealedtree.Placement{ObjectID: id, NativeObjectID: id, OwnerID: identity.ID, Bytes: int64(len(content)), SHA256: hex.EncodeToString(sum[:]), State: "active", Encryption: meta}
		pending, e := tree.PrepareFileWithFreshLocators(ctx, sealedtree.Entry{ParentID: parent, ObjectID: id, Kind: kind, Name: name}, placement, sealedtree.Facts{ObjectID: id})
		if e != nil {
			t.Fatal(e)
		}
		if e = tree.PublishPending(ctx, pending.OperationID, publisher, bytes.NewReader(content)); e != nil {
			t.Fatal(e)
		}
		blobPath, e := sealedtree.BlobPath(pending.BlobID)
		if e != nil {
			t.Fatal(e)
		}
		full := filepath.Join(masterDir, "media", filepath.FromSlash(blobPath))
		if e = os.MkdirAll(filepath.Dir(full), 0700); e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(full, content, 0600); e != nil {
			t.Fatal(e)
		}
		return uploaded{id: id, blob: full, alias: pending.ReadAlias, data: content}
	}
	track := publish(strings.Repeat("1", 64), albumID, "audio", "track.mp3", []byte("synthetic audio"), true)
	lyric := publish(strings.Repeat("2", 64), lyricsID, "lyric", "song.lrc", []byte("[00:01] synthetic lyric"), true)
	plain := publish(strings.Repeat("3", 64), lyricsID, "lyric", "plain.lrc", []byte("unacceptable plaintext"), false)
	if err = tree.ApplyNativeLyricBatch(ctx, sealedtree.NativeLyricOperation{OriginID: track.id, TargetIDs: []string{lyric.id}, Changes: []sealedtree.NativeLyricChange{{TrackID: track.id, LyricID: lyric.id, ExpectedFactsRevision: 1}}}, store.AdminAudit{}); err != nil {
		t.Fatal("native lyric relation", err)
	}
	verified, err := network.WithAuthenticatedIngress(ctx, network.AuthenticatedIngress{NodeID: strings.Repeat("f", 32), Generation: 1, PublicOrigin: "https://peer.test", ClientIP: "192.0.2.1"})
	if err != nil {
		t.Fatal(err)
	}
	verified, admission := network.WithPublicAdmission(verified)
	defer admission.Abort()
	client, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	binding := "browser:v2:" + strings.Repeat("d", 64)
	session, err := public.crypto.NewSession(binding, base64.StdEncoding.EncodeToString(client.PublicKey().Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	verified, err = public.crypto.WithDirectSession(verified, binding, session.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = public.media.ResolveOpaqueLinkedLyric(verified, tree, track.id, lyric.id); err == nil {
		t.Fatal("accepted without tree lease")
	}
	lease, err := tree.AcquireReadFence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	bound := store.WithIngressPrerequisite(verified, lease)
	linked, err := public.media.ResolveOpaqueLinkedLyric(bound, tree, track.id, lyric.id)
	if err != nil || linked.Entry.ObjectID != lyric.id || linked.Placement.ReadAlias != lyric.alias || linked.Placement.Encryption == nil {
		t.Fatal("authenticated encrypted lyric", err)
	}
	reader, err := public.media.OpenOpaqueLinkedLyric(bound, tree, track.id, lyric.id)
	if err != nil {
		t.Fatal("open encrypted lyric", err)
	}
	got, readErr := io.ReadAll(reader.Reader)
	reader.Close()
	if readErr != nil || !bytes.Equal(got, lyric.data) || bytes.Contains(got, []byte("synthetic lyric")) {
		t.Fatal("ciphertext read", readErr)
	}
	if v, e := public.media.ResolveOpaqueLinkedLyric(bound, tree, track.id, plain.id); e == nil || v.Path != "" {
		t.Fatal("wrong or plaintext lyric admitted")
	}
	revokedBinding := "browser:v2:" + strings.Repeat("e", 64)
	revoked, err := public.crypto.NewSession(revokedBinding, base64.StdEncoding.EncodeToString(client.PublicKey().Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	revokedCtx, err := public.crypto.WithDirectSession(bound, revokedBinding, revoked.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	public.crypto.RevokeBinding(revokedBinding)
	if r, e := public.media.OpenOpaqueLinkedLyric(revokedCtx, tree, track.id, lyric.id); e == nil || r != nil {
		t.Fatal("revoked session admitted")
	}
	changed := append([]byte(nil), lyric.data...)
	changed[0] ^= 1
	if err = os.WriteFile(lyric.blob, changed, 0600); err != nil {
		t.Fatal(err)
	}
	if r, e := public.media.OpenOpaqueLinkedLyric(bound, tree, track.id, lyric.id); e == nil {
		leaked, readErr := io.ReadAll(r.Reader)
		r.Close()
		if readErr == nil || len(leaked) != 0 {
			t.Fatal("tampered ciphertext released", readErr)
		}
	} else if r != nil {
		r.Close()
		t.Fatal("failed open returned a reader")
	}
	if err = os.WriteFile(lyric.blob, lyric.data, 0600); err != nil {
		t.Fatal(err)
	}
	lease.Release()
	facts, revision, err := tree.GetFacts(ctx, lyricsID)
	if err != nil {
		t.Fatal(err)
	}
	facts.Visibility = &sealedtree.VisibilityFact{Hidden: 1, UpdatedAt: "2026-01-01"}
	if _, err = tree.SetFacts(ctx, facts, revision); err != nil {
		t.Fatal(err)
	}
	lease, err = tree.AcquireReadFence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	hiddenCtx := store.WithIngressPrerequisite(verified, lease)
	if v, e := public.media.ResolveOpaqueLinkedLyric(hiddenCtx, tree, track.id, lyric.id); e == nil || v.Path != "" {
		t.Fatal("hidden lyric ancestor admitted")
	}
	lease.Release()
	if r, e := public.media.OpenOpaqueLinkedLyric(hiddenCtx, tree, track.id, lyric.id); e == nil || r != nil {
		t.Fatal("released tree lease admitted")
	}
	facts, revision, err = tree.GetFacts(ctx, lyricsID)
	if err != nil {
		t.Fatal(err)
	}
	facts.Visibility.Hidden = 0
	if _, err = tree.SetFacts(ctx, facts, revision); err != nil {
		t.Fatal(err)
	}
	_, trackRevision, err := tree.GetFacts(ctx, track.id)
	if err != nil {
		t.Fatal(err)
	}
	if err = tree.ApplyNativeLyricBatch(ctx, sealedtree.NativeLyricOperation{OriginID: track.id, TargetIDs: []string{plain.id}, Changes: []sealedtree.NativeLyricChange{{TrackID: track.id, LyricID: plain.id, ExpectedFactsRevision: trackRevision}}}, store.AdminAudit{}); err != nil {
		t.Fatal(err)
	}
	lease, err = tree.AcquireReadFence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	plainCtx := store.WithIngressPrerequisite(verified, lease)
	if v, e := public.media.ResolveOpaqueLinkedLyric(plainCtx, tree, track.id, plain.id); e == nil || v.Path != "" {
		t.Fatal("linked plaintext lyric admitted")
	}
}
