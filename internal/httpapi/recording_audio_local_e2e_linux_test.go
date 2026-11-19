//go:build linux && ledger_fixture

package httpapi

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/config"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/deployment"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/maintenance"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/ownerfence"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/selectedupload"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store/business"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/vault"
)

type recordingAudioE2EDeadline struct{}

func (recordingAudioE2EDeadline) SetReadDeadline(time.Time) error { return nil }

type recordingAudioRevokingOwner struct {
	*node.SelectedLocalReceiver
	manager *mediacrypto.Manager
	browser string
}

func (o recordingAudioRevokingOwner) CleanupRecordingWithProof(ctx context.Context, claim protocol.SelectedStorageUpload, media selectedupload.CleanupMediaLease, proof *selectedupload.CleanupBlobProof, deadline selectedupload.ReadDeadline, body io.ReadCloser, authorize func(context.Context) error) (protocol.OpaqueCapacityReceipt, string, error) {
	o.manager.RevokeBinding(o.browser)
	return o.SelectedLocalReceiver.CleanupRecordingWithProof(ctx, claim, media, proof, deadline, body, authorize)
}

// The exact node.SelectedLocalReceiver, Master identity, vault, filesystem,
// tree and SQLite accounting run here. Account authorization and readiness
// are fixture-only; no recording product HTTP route is exercised.
func TestRecordingAudioRealMasterLocalOwner(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	transport := &clusterHTTP{routers: map[string]*gin.Engine{}}
	_, db, dir, public, master := clusterFixture(t, "https://master.test", transport, false)
	identity, err := master.Promote(ctx, "Master", "https://master.test", 10*store.GiB, store.NodeAudit{})
	if err != nil {
		t.Fatal(err)
	}
	var seq int
	var dbName, dbPath string
	if err = db.Database().QueryRowContext(ctx, "PRAGMA database_list").Scan(&seq, &dbName, &dbPath); err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(dbPath, 0600); err != nil {
		t.Fatal(err)
	}
	cfg := public.settings
	cfg.DataRoot, cfg.SQLitePath, cfg.DatabaseType = dir, dbPath, config.DatabaseSQLite
	treeDir := filepath.Join(dir, "recording-test-tree")
	if err = os.Mkdir(treeDir, 0700); err != nil {
		t.Fatal(err)
	}
	maintenanceGate, err := maintenance.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer maintenanceGate.Close()
	if err = maintenanceGate.Enter(ctx, func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if err = deployment.Bind(ctx, cfg, func(c context.Context) error { return master.ValidateRetainedIdentity(c, cfg.SecretsDirectory) }); err != nil {
		t.Fatal(err)
	}
	codec, err := sealedtree.New(bytes.Repeat([]byte{4}, 32), bytes.Repeat([]byte{5}, 32))
	if err != nil {
		t.Fatal(err)
	}
	rootID := strings.Repeat("a", 64)
	if err = sealedtree.FixtureInitializeExisting(ctx, cfg, maintenanceGate, codec, rootID, treeDir); err != nil {
		t.Fatal(err)
	}
	tree, err := sealedtree.OpenSQLite(ctx, db.Database(), codec, rootID)
	if err != nil {
		t.Fatal(err)
	}
	treeRoot, err := os.OpenRoot(treeDir)
	if err != nil {
		t.Fatal(err)
	}
	defer treeRoot.Close()
	if _, err = sealedtree.OpenFence(ctx, tree, treeRoot, treeDir); err != nil {
		t.Fatal(err)
	}
	if err = maintenanceGate.Resume(ctx, func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	masterVault, err := vault.OpenExisting(cfg.SecretsDirectory)
	if err != nil {
		t.Fatal(err)
	}
	mediaPath := filepath.Join(dir, "media")
	if err = os.Chmod(mediaPath, 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.Mkdir(filepath.Join(mediaPath, ".opaque-aliases"), 0700); err != nil {
		t.Fatal(err)
	}
	mediaRoot, err := os.OpenRoot(mediaPath)
	if err != nil {
		t.Fatal(err)
	}
	defer mediaRoot.Close()
	masterIdentity, err := node.Initialize(ctx, db.Nodes(), cfg.SecretsDirectory)
	if err != nil {
		t.Fatal(err)
	}
	fence, err := ownerfence.Create(mediaRoot, mediaPath, masterIdentity)
	if err != nil {
		t.Fatal(err)
	}
	repo := db.Pool().(*business.Repository)
	if err = repo.ConfigureOwnerControlFence(func(c context.Context, x bool) (store.OwnerControlLease, error) { return fence.Acquire(c, x) }); err != nil {
		t.Fatal(err)
	}
	if err = repo.InitializeOwnerControlMarker(ctx); err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{7}, 32)
	if err = repo.InitializeOpaqueCapacityKey(ctx, key); err != nil {
		t.Fatal(err)
	}
	receiver, err := node.NewSelectedLocalReceiver(ctx, master, fence)
	if err != nil {
		t.Fatal(err)
	}
	user, recordingID := strings.Repeat("1", 32), strings.Repeat("2", 32)
	if _, err = db.Database().ExecContext(ctx, `INSERT INTO karaoke_users(user_id,username,username_key,password_hash,status,quota_bytes,used_bytes,created_at,updated_at) VALUES(?,'audio-fixture','audio-fixture','!','active',?,0,1,1)`, user, store.GiB); err != nil {
		t.Fatal(err)
	}
	plain := []byte("isolated encrypted recording audio")
	meta, err := mediacrypto.NewMetadata(int64(len(plain)))
	if err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(bytes.Repeat([]byte{3}, 32))
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	prefix, err := base64.StdEncoding.DecodeString(meta.NoncePrefix)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext := aead.Seal(nil, append(prefix, 0, 0, 0, 0), plain, meta.ChunkAAD(0))
	sum := sha256.Sum256(ciphertext)
	browser := "browser:v2:" + strings.Repeat("4", 64)
	binding, err := store.RecordingAudioPreparationBinding(user, browser, recordingID)
	if err != nil {
		t.Fatal(err)
	}
	client, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := public.crypto.NewSession(browser, base64.StdEncoding.EncodeToString(client.PublicKey().Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	sessionCtx, err := public.crypto.WithDirectSession(ctx, browser, grant.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	if err = repo.ConfigurePublicOrigin("https://master.test"); err != nil {
		t.Fatal(err)
	}
	ingress, err := repo.PublicIngress(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err = repo.ReserveRecordingAudioPreparation(sessionCtx, tree, ingress, user, browser, recordingID, meta); err != nil {
		t.Fatal(err)
	}
	runtime, err := business.NewSelectedUploadRuntime(repo, tree, key, public.crypto, masterVault, "https://master.test", selectedE2EGate{})
	if err != nil {
		t.Fatal(err)
	}
	if err = runtime.ConfigureLocalOwner(receiver); err != nil {
		t.Fatal(err)
	}
	token, err := public.crypto.SignTransientPreparation(binding, meta)
	if err != nil {
		t.Fatal(err)
	}
	account := store.KaraokeUser{ID: user, PasswordHash: "!", Status: "active", CreatedAt: 1}
	ticket := store.RecordingAudioTicketRequest{RecordingID: recordingID, MemberID: identity.ID, CipherSHA256: hex.EncodeToString(sum[:]), Title: "私有录音", ContentType: "audio/webm", SessionID: grant.SessionID, Encryption: meta, PreparationToken: token}
	if err = runtime.AdmitRecordingAudioTicket(sessionCtx, tree, ingress, account, browser, ticket, store.KaraokeAudit{}); err != nil {
		var kind, transport, health, status string
		var enabled, writable, allocation, usedNow, reservedNow, physicalNow, quotaNow, userUsed int64
		memberErr := db.Database().QueryRowContext(ctx, `SELECT member_kind,transport,health,storage_enabled,writable,allocated_bytes,used_bytes,reserved_bytes,physical_free_bytes FROM cluster_storage_members WHERE member_id=?`, identity.ID).Scan(&kind, &transport, &health, &enabled, &writable, &allocation, &usedNow, &reservedNow, &physicalNow)
		userErr := db.Database().QueryRowContext(ctx, `SELECT status,quota_bytes,used_bytes FROM karaoke_users WHERE user_id=?`, user).Scan(&status, &quotaNow, &userUsed)
		localFree, freeErr := receiver.SelectedLocalFree(ctx)
		_, _, _, sessionOK := mediacrypto.DirectSessionFromContext(sessionCtx).Values()
		t.Fatalf("real runtime admission: %v; member=%s/%s/%s/%d/%d alloc=%d used=%d reserved=%d physical=%d err=%v; user=%s quota=%d used=%d err=%v; free=%d err=%v session=%t token=%t", err, kind, transport, health, enabled, writable, allocation, usedNow, reservedNow, physicalNow, memberErr, status, quotaNow, userUsed, userErr, localFree, freeErr, sessionOK, public.crypto.VerifyTransientPreparation(binding, token, meta) == nil)
	}
	blob, err := business.FixtureRecordingAudioBlob(ctx, repo, key, recordingID)
	if err != nil {
		t.Fatal(err)
	}
	checks := 0
	_, err = runtime.UploadRecordingAudioLocal(sessionCtx, tree, ingress, account, browser, recordingID, "upload", int64(len(ciphertext)), recordingAudioE2EDeadline{}, io.NopCloser(bytes.NewReader(ciphertext)), store.KaraokeAudit{}, func(context.Context) error {
		checks++
		if checks == 2 {
			return errors.New("fixture authorization interrupted")
		}
		return nil
	})
	if err == nil || checks != 2 {
		t.Fatal("interrupt after Owner publication", err)
	}
	name, err := sealedtree.BlobPath(blob)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := mediaRoot.ReadFile(name)
	if err != nil || !bytes.Equal(stored, ciphertext) || bytes.Contains(stored, plain) {
		t.Fatal("ciphertext mismatch", err)
	}
	receiver, err = node.NewSelectedLocalReceiver(ctx, master, fence)
	if err != nil {
		t.Fatal("reopen actual Local Owner", err)
	}
	runtime, err = business.NewSelectedUploadRuntime(repo, tree, key, public.crypto, masterVault, "https://master.test", selectedE2EGate{})
	if err != nil {
		t.Fatal(err)
	}
	if err = runtime.ConfigureLocalOwner(receiver); err != nil {
		t.Fatal(err)
	}
	already, err := runtime.UploadRecordingAudioLocal(sessionCtx, tree, ingress, account, browser, recordingID, "recover", 0, recordingAudioE2EDeadline{}, io.NopCloser(bytes.NewReader(nil)), store.KaraokeAudit{}, func(context.Context) error { return nil })
	if err != nil || already {
		t.Fatal("real Local Owner stage recovery", err)
	}
	already, err = runtime.UploadRecordingAudioLocal(sessionCtx, tree, ingress, account, browser, recordingID, "recover", 0, recordingAudioE2EDeadline{}, io.NopCloser(bytes.NewReader(nil)), store.KaraokeAudit{}, func(context.Context) error { return nil })
	if err != nil || !already {
		t.Fatal("completed Owner recovery must be idempotent", err)
	}
	wrongAccount := account
	wrongAccount.PasswordHash = "changed"
	if stream, e := runtime.OpenRecordingAudioLocal(sessionCtx, tree, ingress, wrongAccount, browser, recordingID, public.media, func(context.Context) error { return nil }); e == nil {
		stream.Close()
		t.Fatal("stale account opened recording")
	}
	otherBrowser := "browser:v2:" + strings.Repeat("5", 64)
	otherGrant, err := public.crypto.NewSession(otherBrowser, base64.StdEncoding.EncodeToString(client.PublicKey().Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	otherCtx, err := public.crypto.WithDirectSession(ctx, otherBrowser, otherGrant.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	otherUser := strings.Repeat("6", 32)
	if _, err = db.Database().ExecContext(ctx, `INSERT INTO karaoke_users(user_id,username,username_key,password_hash,status,quota_bytes,used_bytes,created_at,updated_at) VALUES(?,'other-fixture','other-fixture','!','active',?,0,1,1)`, otherUser, store.GiB); err != nil {
		t.Fatal(err)
	}
	otherAccount := store.KaraokeUser{ID: otherUser, PasswordHash: "!", Status: "active", CreatedAt: 1}
	if stream, e := runtime.OpenRecordingAudioLocal(otherCtx, tree, ingress, otherAccount, otherBrowser, recordingID, public.media, func(context.Context) error { return nil }); e == nil {
		stream.Close()
		t.Fatal("another account opened recording")
	}
	accountChecks := 0
	if stream, e := runtime.OpenRecordingAudioLocal(otherCtx, tree, ingress, account, otherBrowser, recordingID, public.media, func(context.Context) error {
		accountChecks++
		if accountChecks == 2 {
			lockCtx, lockCancel := context.WithTimeout(context.Background(), time.Second)
			lease, lockErr := repo.AcquireOwnerControlShared(lockCtx)
			lockCancel()
			if lockErr != nil {
				t.Error("account callback still holds global Owner lock", lockErr)
				return lockErr
			}
			lease.Release()
			return errors.New("account revoked after file open")
		}
		return nil
	}); e == nil {
		stream.Close()
		t.Fatal("revoked account received stream")
	}
	if accountChecks != 2 {
		t.Fatal("second account check was not reached")
	}
	stream, err := runtime.OpenRecordingAudioLocal(otherCtx, tree, ingress, account, otherBrowser, recordingID, public.media, func(context.Context) error { return nil })
	if err != nil {
		t.Fatal("open authenticated ciphertext", err)
	}
	if stream.Size != int64(len(ciphertext)) || stream.Encryption != meta || stream.Title != "私有录音" {
		stream.Close()
		t.Fatal("recording descriptor mismatch")
	}
	if _, err = stream.Seek(3, io.SeekStart); err != nil {
		stream.Close()
		t.Fatal(err)
	}
	part := make([]byte, 7)
	if _, err = io.ReadFull(stream, part); err != nil || !bytes.Equal(part, ciphertext[3:10]) {
		stream.Close()
		t.Fatal("ciphertext range mismatch", err)
	}
	public.crypto.RevokeBinding(otherBrowser)
	if _, err = stream.Read(part); err == nil {
		stream.Close()
		t.Fatal("revoked crypto session continued reading")
	}
	if err = stream.Close(); err != nil {
		t.Fatal(err)
	}
	existingStream, err := runtime.OpenRecordingAudioLocal(sessionCtx, tree, ingress, account, browser, recordingID, public.media, func(context.Context) error { return nil })
	if err != nil {
		t.Fatal("open pre-deletion stream", err)
	}
	defer existingStream.Close()
	if lease, e := public.media.TryRecordingCleanup(ctx); e == nil {
		lease.Release()
		t.Fatal("cleanup acquired volume while a reader was active")
	}
	if _, err = business.FixtureStageRecordingAudioDeletion(sessionCtx, runtime, tree, ingress, wrongAccount, browser, recordingID); err == nil {
		t.Fatal("stale account staged deletion")
	}
	if _, err = db.Database().ExecContext(ctx, `CREATE TRIGGER fixture_fail_recording_delete BEFORE INSERT ON karaoke_audit_log BEGIN SELECT RAISE(FAIL,'fixture'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err = business.FixtureStageRecordingAudioDeletion(sessionCtx, runtime, tree, ingress, account, browser, recordingID); err == nil {
		t.Fatal("failed audit committed deletion stage")
	}
	if _, err = db.Database().ExecContext(ctx, `DROP TRIGGER fixture_fail_recording_delete`); err != nil {
		t.Fatal(err)
	}
	var state string
	if err = db.Database().QueryRowContext(ctx, `SELECT state FROM karaoke_recordings WHERE recording_id=?`, recordingID).Scan(&state); err != nil || state != "ready" {
		t.Fatal("failed deletion stage changed state", err)
	}
	prior, err := business.FixtureStageRecordingAudioDeletion(sessionCtx, runtime, tree, ingress, account, browser, recordingID)
	if err != nil || prior {
		t.Fatal("stage deletion", err)
	}
	prior, err = business.FixtureStageRecordingAudioDeletion(sessionCtx, runtime, tree, ingress, account, browser, recordingID)
	if err != nil || !prior {
		t.Fatal("repeat staged deletion", err)
	}
	if stream, e := runtime.OpenRecordingAudioLocal(sessionCtx, tree, ingress, account, browser, recordingID, public.media, func(context.Context) error { return nil }); e == nil {
		stream.Close()
		t.Fatal("deleting recording remained readable")
	}
	if _, err = existingStream.Read(make([]byte, 1)); err != nil {
		t.Fatal("existing reader was disrupted while staging deletion", err)
	}
	if err = existingStream.Close(); err != nil {
		t.Fatal(err)
	}
	cleanupLease, err := public.media.TryRecordingCleanup(ctx)
	if err != nil {
		t.Fatal("cleanup did not acquire volume after reader drained", err)
	}
	if err = cleanupLease.CheckCleanupRoot(ctx, mediaRoot); err != nil {
		cleanupLease.Release()
		t.Fatal("cleanup lease rejected the Owner volume", err)
	}
	otherRoot, err := os.OpenRoot(t.TempDir())
	if err != nil {
		cleanupLease.Release()
		t.Fatal(err)
	}
	if err = cleanupLease.CheckCleanupRoot(ctx, otherRoot); err == nil {
		otherRoot.Close()
		cleanupLease.Release()
		t.Fatal("cleanup lease accepted a different volume")
	}
	otherRoot.Close()
	cleanupLease.Release()
	if err = cleanupLease.CheckCleanupRoot(ctx, mediaRoot); err == nil {
		t.Fatal("released cleanup lease remained valid")
	}
	stored, err = mediaRoot.ReadFile(name)
	if err != nil || !bytes.Equal(stored, ciphertext) {
		t.Fatal("staging deletion removed Owner ciphertext", err)
	}
	var userUsed int64
	if err = db.Database().QueryRowContext(ctx, `SELECT used_bytes FROM karaoke_users WHERE user_id=?`, user).Scan(&userUsed); err != nil || userUsed != int64(len(ciphertext)) {
		t.Fatal("staging deletion changed account quota", err)
	}
	claim, err := business.FixtureRecordingAudioCleanupClaim(ctx, repo, tree, key, recordingID)
	if err != nil {
		t.Fatal("authenticated cleanup claim", err)
	}
	proof, err := receiver.PrepareRecordingCleanup(ctx, claim)
	if err != nil {
		t.Fatal("prepare Local cleanup", err)
	}
	defer proof.Close()
	leaseWithoutOwner, err := public.media.TryRecordingCleanup(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = receiver.CleanupRecordingWithProof(ctx, claim, leaseWithoutOwner, proof, recordingAudioE2EDeadline{}, io.NopCloser(bytes.NewReader(nil)), func(context.Context) error { return nil }); err == nil {
		leaseWithoutOwner.Release()
		t.Fatal("cleanup accepted no exclusive Owner scope")
	}
	leaseWithoutOwner.Release()
	var cleanupReceipt protocol.OpaqueCapacityReceipt
	var cleanupSignature string
	err = repo.WithOwnerControlExclusive(ctx, func(held context.Context) error {
		lease, e := public.media.TryRecordingCleanup(held)
		if e != nil {
			return e
		}
		defer lease.Release()
		cleanupReceipt, cleanupSignature, e = receiver.CleanupRecordingWithProof(held, claim, lease, proof, recordingAudioE2EDeadline{}, io.NopCloser(bytes.NewReader(nil)), func(context.Context) error { return nil })
		return e
	})
	if err != nil {
		t.Fatal("guarded Local Owner cleanup", err)
	}
	payload, err := cleanupReceipt.Payload()
	if err != nil {
		t.Fatal(err)
	}
	masterRow, err := repo.ReadIdentity(ctx)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := masterVault.Unseal(masterRow.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := protocol.PublicKey(secret)
	if err != nil {
		t.Fatal(err)
	}
	if protocol.Verify(publicKey, payload, cleanupSignature) != nil {
		t.Fatal("invalid Owner cleanup signature")
	}
	if _, err = mediaRoot.Lstat(name); !os.IsNotExist(err) {
		t.Fatal("guarded cleanup left blob", err)
	}
	var retryReceipt protocol.OpaqueCapacityReceipt
	var retrySignature string
	err = repo.WithOwnerControlExclusive(ctx, func(held context.Context) error {
		lease, e := public.media.TryRecordingCleanup(held)
		if e != nil {
			return e
		}
		defer lease.Release()
		retryReceipt, retrySignature, e = receiver.CleanupRecordingWithProof(held, claim, lease, nil, recordingAudioE2EDeadline{}, io.NopCloser(bytes.NewReader(nil)), func(context.Context) error { return nil })
		return e
	})
	if err != nil || retryReceipt != cleanupReceipt || retrySignature != cleanupSignature {
		t.Fatal("lost Owner cleanup acknowledgement recovery", err)
	}
	if err = db.Database().QueryRowContext(ctx, `SELECT used_bytes FROM karaoke_users WHERE user_id=?`, user).Scan(&userUsed); err != nil || userUsed != int64(len(ciphertext)) {
		t.Fatal("cleanup refunded before settlement", err)
	}
	var used, reserved int64
	if err = db.Database().QueryRowContext(ctx, `SELECT used_bytes,reserved_bytes FROM cluster_storage_members WHERE member_id=?`, identity.ID).Scan(&used, &reserved); err != nil || used < int64(len(ciphertext)) || reserved != 0 {
		t.Fatal("capacity settlement", err)
	}
	usedBeforeDelete := used
	if _, err = business.FixtureFinishRecordingAudioDeletion(sessionCtx, runtime, tree, ingress, account, browser, recordingID, cleanupReceipt, "bad-signature"); err == nil {
		t.Fatal("invalid cleanup signature refunded quota")
	}
	if _, err = db.Database().ExecContext(ctx, `CREATE TRIGGER fixture_fail_recording_refund BEFORE UPDATE ON karaoke_users BEGIN SELECT RAISE(FAIL,'fixture'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err = business.FixtureFinishRecordingAudioDeletion(sessionCtx, runtime, tree, ingress, account, browser, recordingID, cleanupReceipt, cleanupSignature); err == nil {
		t.Fatal("failed refund committed")
	}
	if _, err = db.Database().ExecContext(ctx, `DROP TRIGGER fixture_fail_recording_refund`); err != nil {
		t.Fatal(err)
	}
	if err = db.Database().QueryRowContext(ctx, `SELECT state FROM karaoke_recordings WHERE recording_id=?`, recordingID).Scan(&state); err != nil || state != "deleting" {
		t.Fatal("failed refund changed deletion state", err)
	}
	if err = db.Database().QueryRowContext(ctx, `SELECT used_bytes FROM karaoke_users WHERE user_id=?`, user).Scan(&userUsed); err != nil || userUsed != int64(len(ciphertext)) {
		t.Fatal("failed refund changed quota", err)
	}
	prior, err = business.FixtureFinishRecordingAudioDeletion(sessionCtx, runtime, tree, ingress, account, browser, recordingID, cleanupReceipt, cleanupSignature)
	if err != nil || prior {
		t.Fatal("signed cleanup settlement", err)
	}
	prior, err = business.FixtureFinishRecordingAudioDeletion(sessionCtx, runtime, tree, ingress, account, browser, recordingID, cleanupReceipt, cleanupSignature)
	if err != nil || !prior {
		t.Fatal("deletion settlement retry", err)
	}
	if err = db.Database().QueryRowContext(ctx, `SELECT used_bytes FROM karaoke_users WHERE user_id=?`, user).Scan(&userUsed); err != nil || userUsed != 0 {
		t.Fatal("account refund not exact", err)
	}
	if err = db.Database().QueryRowContext(ctx, `SELECT used_bytes,reserved_bytes FROM cluster_storage_members WHERE member_id=?`, identity.ID).Scan(&used, &reserved); err != nil || used != usedBeforeDelete-int64(len(ciphertext)) || reserved != 0 {
		t.Fatal("member refund not exact", err)
	}
	// A second object exercises the complete trusted runtime operation: a live
	// reader forces a nonblocking busy result, then a retry unlinks and refunds.
	secondID := strings.Repeat("8", 32)
	secondMeta, e := mediacrypto.NewMetadata(int64(len(plain)))
	if e != nil {
		t.Fatal(e)
	}
	secondPrefix, e := base64.StdEncoding.DecodeString(secondMeta.NoncePrefix)
	if e != nil {
		t.Fatal(e)
	}
	secondCipher := aead.Seal(nil, append(secondPrefix, 0, 0, 0, 0), plain, secondMeta.ChunkAAD(0))
	secondHash := sha256.Sum256(secondCipher)
	secondBinding, e := store.RecordingAudioPreparationBinding(user, browser, secondID)
	if e != nil {
		t.Fatal(e)
	}
	if e = repo.ReserveRecordingAudioPreparation(sessionCtx, tree, ingress, user, browser, secondID, secondMeta); e != nil {
		t.Fatal(e)
	}
	secondToken, e := public.crypto.SignTransientPreparation(secondBinding, secondMeta)
	if e != nil {
		t.Fatal(e)
	}
	secondTicket := store.RecordingAudioTicketRequest{RecordingID: secondID, MemberID: identity.ID, CipherSHA256: hex.EncodeToString(secondHash[:]), Title: "另一条录音", ContentType: "audio/webm", SessionID: grant.SessionID, Encryption: secondMeta, PreparationToken: secondToken}
	if e = runtime.AdmitRecordingAudioTicket(sessionCtx, tree, ingress, account, browser, secondTicket, store.KaraokeAudit{}); e != nil {
		t.Fatal("second admission", e)
	}
	if _, e = runtime.UploadRecordingAudioLocal(sessionCtx, tree, ingress, account, browser, secondID, "upload", int64(len(secondCipher)), recordingAudioE2EDeadline{}, io.NopCloser(bytes.NewReader(secondCipher)), store.KaraokeAudit{}, func(context.Context) error { return nil }); e != nil {
		t.Fatal("second upload", e)
	}
	reader, e := runtime.OpenRecordingAudioLocal(sessionCtx, tree, ingress, account, browser, secondID, public.media, func(context.Context) error { return nil })
	if e != nil {
		t.Fatal(e)
	}
	if _, e = runtime.DeleteRecordingAudioLocal(sessionCtx, tree, ingress, account, browser, secondID, receiver, public.media, recordingAudioE2EDeadline{}, store.KaraokeAudit{}, func(context.Context) error { return nil }); e == nil {
		reader.Close()
		t.Fatal("delete ignored active reader")
	}
	if e = reader.Close(); e != nil {
		t.Fatal(e)
	}
	revokingOwner := recordingAudioRevokingOwner{SelectedLocalReceiver: receiver, manager: public.crypto, browser: browser}
	if _, e = runtime.DeleteRecordingAudioLocal(sessionCtx, tree, ingress, account, browser, secondID, revokingOwner, public.media, recordingAudioE2EDeadline{}, store.KaraokeAudit{}, func(context.Context) error { return nil }); e == nil {
		t.Fatal("revoked crypto session deleted recording")
	}
	secondBlob, e := business.FixtureRecordingAudioBlob(ctx, repo, key, secondID)
	if e != nil {
		t.Fatal(e)
	}
	secondPath, e := sealedtree.BlobPath(secondBlob)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = mediaRoot.Lstat(secondPath); e != nil {
		t.Fatal("revoked deletion removed ciphertext", e)
	}
	if e = db.Database().QueryRowContext(ctx, `SELECT used_bytes FROM karaoke_users WHERE user_id=?`, user).Scan(&userUsed); e != nil || userUsed != int64(len(secondCipher)) {
		t.Fatal("revoked deletion refunded quota", e)
	}
	grant, e = public.crypto.NewSession(browser, base64.StdEncoding.EncodeToString(client.PublicKey().Bytes()))
	if e != nil {
		t.Fatal(e)
	}
	sessionCtx, e = public.crypto.WithDirectSession(ctx, browser, grant.SessionID)
	if e != nil {
		t.Fatal(e)
	}
	prior, e = runtime.DeleteRecordingAudioLocal(sessionCtx, tree, ingress, account, browser, secondID, receiver, public.media, recordingAudioE2EDeadline{}, store.KaraokeAudit{}, func(context.Context) error { return nil })
	if e != nil || prior {
		t.Fatal("complete runtime delete", e)
	}
	if _, e = db.Database().ExecContext(ctx, `UPDATE cluster_storage_members SET writable=0 WHERE member_id=?`, identity.ID); e != nil {
		t.Fatal(e)
	}
	prior, e = runtime.DeleteRecordingAudioLocal(sessionCtx, tree, ingress, account, browser, secondID, receiver, public.media, recordingAudioE2EDeadline{}, store.KaraokeAudit{}, func(context.Context) error { return nil })
	if e != nil || !prior {
		t.Fatal("complete runtime delete retry", e)
	}
	if _, e = db.Database().ExecContext(ctx, `UPDATE cluster_storage_members SET writable=1 WHERE member_id=?`, identity.ID); e != nil {
		t.Fatal(e)
	}
	if e = db.Database().QueryRowContext(ctx, `SELECT used_bytes FROM karaoke_users WHERE user_id=?`, user).Scan(&userUsed); e != nil || userUsed != 0 {
		t.Fatal("runtime deletion quota", e)
	}
	if _, err = tree.Check(ctx); err != nil {
		t.Fatal("tree integrity", err)
	}
}
