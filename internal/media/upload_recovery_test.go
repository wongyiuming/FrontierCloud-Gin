package media

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

type pausedRecoveryUploadReader struct {
	ctx     context.Context
	reader  io.Reader
	started chan struct{}
	resume  chan struct{}
	paused  bool
}

func (r *pausedRecoveryUploadReader) Read(bytes []byte) (int, error) {
	if !r.paused {
		r.paused = true
		close(r.started)
		select {
		case <-r.resume:
		case <-r.ctx.Done():
			return 0, r.ctx.Err()
		}
	}
	return r.reader.Read(bytes)
}

func TestExpiredUploadRecoveryPreservesAdmittedLocalTransferUntilCompletion(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		name := "plain"
		if encrypted {
			name = "encrypted"
		}
		t.Run(name, func(t *testing.T) { testExpiredLocalTransfer(t, encrypted) })
	}
}

func testExpiredLocalTransfer(t *testing.T, encrypted bool) {
	_, db, svc := masterFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	payload := "ID3payload"
	var metadata *mediacrypto.Metadata
	if encrypted {
		value, err := mediacrypto.NewMetadata(int64(len(payload)))
		if err != nil {
			t.Fatal(err)
		}
		metadata = &value
		// Recovery treats ciphertext as opaque bytes. Client authentication and
		// decryption have independent real-WebCrypto regression coverage.
		payload = strings.Repeat("x", int(value.CiphertextSize))
	}
	size := int64(len(payload))
	v, err := svc.ReserveMasterEncryptedUpload(ctx, "song.mp3", "music/LiveRecovery", "", "primary", size, 255, store.AdminAudit{}, metadata)
	if err != nil {
		t.Fatal(err)
	}
	reader := &pausedRecoveryUploadReader{ctx: ctx, reader: strings.NewReader(payload), started: make(chan struct{}), resume: make(chan struct{})}
	done := make(chan error, 1)
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		_, err := svc.UploadMasterBytes(ctx, v.ID, reader, store.AdminAudit{})
		done <- err
	}()
	t.Cleanup(func() {
		cancel()
		<-finished
	})
	select {
	case <-reader.started:
	case <-ctx.Done():
		t.Fatal("upload did not enter the live body transfer", ctx.Err())
	}
	if _, err := db.Database().Exec("UPDATE cluster_upload_sessions SET expires_at=? WHERE upload_id=?", time.Now().Unix()-1, v.ID); err != nil {
		t.Fatal(err)
	}
	if err := svc.RetryExpiredUploads(ctx); err != nil {
		t.Fatal(err)
	}
	current, err := db.Pool().Upload(ctx, v.ID)
	if err != nil || current.State != "reserved" {
		t.Fatal("expiry released an admitted live upload", current, err)
	}
	masterFunds(t, db, 0, size)
	close(reader.resume)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal("admitted local upload could not complete after expiry", err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	current, err = db.Pool().Upload(ctx, v.ID)
	if err != nil || current.State != "complete" {
		t.Fatal("completed live upload was lost", current, err)
	}
	masterFunds(t, db, size, 0)
	actual, err := svc.Encryption(ctx, v.MediaID)
	if err != nil || (actual == nil) != (metadata == nil) || actual != nil && *actual != *metadata {
		t.Fatal("completion lost or changed the encryption descriptor", actual, err)
	}
}

func TestExpiredUploadRecoveryReleasesAbandonedButPreservesLiveUnknownAndComplete(t *testing.T) {
	for _, scenario := range []string{"abandoned", "live", "unknown", "complete", "unexpired", "audit-failure"} {
		t.Run(scenario, func(t *testing.T) {
			root, db, svc := masterFixture(t)
			ctx := context.Background()
			v, err := svc.ReserveMasterUpload(ctx, "song.mp3", "music/Refresh", "", "primary", 10, 255, store.AdminAudit{})
			if err != nil {
				t.Fatal(err)
			}
			if scenario == "complete" {
				if _, err := svc.UploadMasterBytes(ctx, v.ID, strings.NewReader("ID3payload"), store.AdminAudit{}); err != nil {
					t.Fatal(err)
				}
			} else if scenario == "unknown" {
				if err := os.MkdirAll(filepath.Join(root, "music/Refresh"), 0755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(root, v.Path), []byte("unknown"), 0644); err != nil {
					t.Fatal(err)
				}
			} else if scenario == "live" {
				release, err := svc.uploadSessionLease(v.ID)
				if err != nil {
					t.Fatal(err)
				}
				defer release()
			} else if scenario == "audit-failure" {
				if _, err := db.Database().Exec("CREATE TRIGGER expiry_audit_fault BEFORE INSERT ON admin_audit_log BEGIN SELECT RAISE(FAIL,'audit unavailable'); END"); err != nil {
					t.Fatal(err)
				}
			}
			if scenario != "unexpired" {
				if _, err := db.Database().Exec("UPDATE cluster_upload_sessions SET expires_at=? WHERE upload_id=?", time.Now().Unix()-1, v.ID); err != nil {
					t.Fatal(err)
				}
			}
			if err := svc.RetryExpiredUploads(ctx); err != nil {
				t.Fatal(err)
			}
			current, err := db.Pool().Upload(ctx, v.ID)
			if scenario == "abandoned" {
				if !errors.Is(err, store.ErrNodeState) {
					t.Fatal("abandoned reservation remains", current, err)
				}
				masterFunds(t, db, 0, 0)
				if _, err := svc.ReserveMasterUpload(ctx, "song.mp3", "music/Refresh", "", "primary", 10, 255, store.AdminAudit{}); err != nil {
					t.Fatal("refresh retry blocked", err)
				}
			} else if scenario == "complete" {
				if err != nil || current.State != "complete" {
					t.Fatal(current, err)
				}
				masterFunds(t, db, 10, 0)
			} else {
				if err != nil || current.State != "reserved" {
					t.Fatal("unsafe release", current, err)
				}
				masterFunds(t, db, 0, 10)
				if scenario == "unknown" {
					data, err := os.ReadFile(filepath.Join(root, v.Path))
					if err != nil || string(data) != "unknown" {
						t.Fatal("unknown bytes changed", err)
					}
				}
			}
		})
	}
}

func TestPeriodicStorageRecoveryReleasesDeadStageWithoutRestart(t *testing.T) {
	root, db, svc, rel := ownedFixture(t)
	svc.ConfigureCluster(db.Nodes(), db.Pool(), nil)
	ctx := context.Background()
	stage, err := svc.Stage(ctx, strings.NewReader("ID3payload"), 10)
	if err != nil {
		t.Fatal(err)
	}
	object := store.MediaObject{ID: strings.Repeat("5", 64), Path: "music/Refresh/song.mp3", Kind: "audio"}
	if err := db.Pool().ReserveOwnedUpload(ctx, stage.id, rel, object, 10, 10*store.GiB, store.NodeAudit{}); err != nil {
		t.Fatal(err)
	}
	// A held stage lease fences the sweep even after the browser disconnects.
	if err := svc.RetryExpiredUploads(ctx); err != nil {
		t.Fatal(err)
	}
	ownedFunds(t, db, 0, 10)
	stage.retain = true
	stage.Close()
	if err := svc.RetryExpiredUploads(ctx); err != nil {
		t.Fatal(err)
	}
	ownedFunds(t, db, 0, 0)
	if _, err := os.Stat(filepath.Join(root, ".upload-"+stage.id+".part")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("dead partial stage retained", err)
	}
	if err := svc.RetryExpiredUploads(ctx); err != nil {
		t.Fatal("recovery replay", err)
	}
	ownedFunds(t, db, 0, 0)
}

func TestVideoDestinationRejectsMP3BeforeCapacityReservation(t *testing.T) {
	_, db, svc := masterFixture(t)
	_, err := svc.ReserveMasterUpload(context.Background(), "concert.mp3", "vido/Concerts", "", "primary", 10, 255, store.AdminAudit{})
	if !errors.Is(err, ErrPath) {
		t.Fatal("audio routed into video category", err)
	}
	masterFunds(t, db, 0, 0)
}

func TestAbandonedEncryptedUploadRecoveryRetiresDescriptorAndRequiresFreshFileKey(t *testing.T) {
	_, db, svc := masterFixture(t)
	ctx := context.Background()
	metadata, err := mediacrypto.NewMetadata(10)
	if err != nil {
		t.Fatal(err)
	}
	v, err := svc.ReserveMasterEncryptedUpload(ctx, "song.mp3", "music/EncryptedRefresh", "", "primary", metadata.CiphertextSize, 255, store.AdminAudit{}, &metadata)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Database().Exec("UPDATE cluster_upload_sessions SET expires_at=? WHERE upload_id=?", time.Now().Unix()-1, v.ID); err != nil {
		t.Fatal(err)
	}
	if err := svc.RetryExpiredUploads(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Pool().Upload(ctx, v.ID); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("abandoned encrypted reservation remains", err)
	}
	masterFunds(t, db, 0, 0)
	actual, err := svc.Encryption(ctx, v.MediaID)
	if err != nil || actual != nil {
		t.Fatal("released reservation still exposes its descriptor", actual, err)
	}
	repository := db.Pool().(store.EncryptionRepository)
	used, err := repository.EncryptionUsed(ctx, metadata.FileID)
	if err != nil || !used {
		t.Fatal("cleanup discarded the file-key/nonce reuse tombstone", used, err)
	}
	if _, err := svc.ReserveMasterEncryptedUpload(ctx, "song.mp3", "music/EncryptedRefresh", "", "primary", metadata.CiphertextSize, 255, store.AdminAudit{}, &metadata); err == nil {
		t.Fatal("refresh retry reused an already consumed file key and nonce space")
	}
	masterFunds(t, db, 0, 0)
	fresh, err := mediacrypto.NewMetadata(10)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ReserveMasterEncryptedUpload(ctx, "song.mp3", "music/EncryptedRefresh", "", "primary", fresh.CiphertextSize, 255, store.AdminAudit{}, &fresh); err != nil {
		t.Fatal("fresh encryption selection could not retry the same path", err)
	}
	masterFunds(t, db, 0, fresh.CiphertextSize)
}
