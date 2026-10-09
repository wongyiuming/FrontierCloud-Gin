package media

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// Only the deliberately slow read is injected. Rotation, expiry, capacity
// accounting and cleanup use the real SQLite repository and service.
type recoveryFairnessPool struct {
	store.PoolRepository
	slowID       string
	started      chan struct{}
	deferredIDs  []string
	rotationLive bool
	rotationTime time.Duration
}

func (p *recoveryFairnessPool) Upload(ctx context.Context, id string) (store.UploadReservation, error) {
	if id == p.slowID {
		if p.started != nil {
			close(p.started)
			p.started = nil
		}
		<-ctx.Done()
		return store.UploadReservation{}, ctx.Err()
	}
	return p.PoolRepository.Upload(ctx, id)
}

func (p *recoveryFairnessPool) DeferExpiredUpload(ctx context.Context, id string) error {
	p.deferredIDs = append(p.deferredIDs, id)
	deadline, bounded := ctx.Deadline()
	p.rotationLive = ctx.Err() == nil && bounded
	p.rotationTime = time.Until(deadline)
	return p.PoolRepository.DeferExpiredUpload(ctx, id)
}

func TestExpiredRecoveryMaximumItemLeavesRotationGraceAndNextItem(t *testing.T) {
	_, db, svc := masterFixture(t)
	ctx := context.Background()
	first, err := svc.ReserveMasterUpload(ctx, "slow.mp3", "music/Fairness", "", "primary", 10, 255, store.AdminAudit{})
	if err != nil {
		t.Fatal(err)
	}
	second, err := svc.ReserveMasterUpload(ctx, "next.mp3", "music/Fairness", "", "primary", 10, 255, store.AdminAudit{})
	if err != nil {
		t.Fatal(err)
	}
	expiry := time.Now().Unix() - 10
	if _, err := db.Database().Exec("UPDATE cluster_upload_sessions SET expires_at=?,updated_at=?", expiry, expiry-20); err != nil {
		t.Fatal(err)
	}
	// This is the production maximum-size case: its item budget equals the
	// entire outer sweep budget. Ordering is explicit, not random upload IDs.
	if _, err := db.Database().Exec("UPDATE cluster_upload_sessions SET expected_bytes=?,updated_at=? WHERE upload_id=?", int64(10)*store.GiB, expiry-21, first.ID); err != nil {
		t.Fatal(err)
	}
	rows, err := db.Pool().ExpiredUploads(ctx, 50)
	if err != nil || len(rows) != 2 || rows[0].ID != first.ID || uploadRecoveryBudget(rows[0]) != 180*time.Second {
		t.Fatal("maximum item fixture", rows, err)
	}
	p := &recoveryFairnessPool{PoolRepository: db.Pool(), slowID: first.ID}
	svc.pool = p
	// Scale the 180-second sweep and five-second grace to a sub-second test.
	const sweepBudget = 800 * time.Millisecond
	const grace = 300 * time.Millisecond
	sweep, cancel := context.WithTimeout(ctx, sweepBudget)
	defer cancel()
	err = svc.retryExpiredUploads(sweep, func(store.UploadReservation) time.Duration { return sweepBudget }, grace)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("maximum item should exhaust investigation budget, not rotation grace", err)
	}
	if len(p.deferredIDs) != 1 || p.deferredIDs[0] != first.ID || !p.rotationLive || p.rotationTime <= 0 || p.rotationTime > grace {
		t.Fatalf("rotation did not receive live bounded context: %+v", p)
	}
	var currentExpiry, updated int64
	var state string
	if err := db.Database().QueryRow("SELECT expires_at,updated_at,state FROM cluster_upload_sessions WHERE upload_id=?", first.ID).Scan(&currentExpiry, &updated, &state); err != nil {
		t.Fatal(err)
	}
	if currentExpiry != expiry || updated <= expiry-21 || state != "reserved" {
		t.Fatalf("rotation renewed or released the reservation: expiry=%d updated=%d state=%s", currentExpiry, updated, state)
	}
	rows, err = db.Pool().ExpiredUploads(ctx, 50)
	if err != nil || len(rows) != 2 || rows[0].ID != second.ID {
		t.Fatal("timed-out item stayed at the front of the next sweep", rows, err)
	}
	// The next sweep really cleans the other reservation before considering
	// the slow item again; this is persisted fairness, not a callback count.
	nextSweep, nextCancel := context.WithTimeout(ctx, time.Second)
	defer nextCancel()
	if err := svc.retryExpiredUploads(nextSweep, func(store.UploadReservation) time.Duration { return 5 * time.Millisecond }, 100*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Pool().Upload(ctx, second.ID); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("next item was starved instead of really cleaned", err)
	}
	masterFunds(t, db, 0, 10)
}

func TestExpiredRecoveryParentCancellationDoesNotDetachRotation(t *testing.T) {
	_, db, svc := masterFixture(t)
	v, err := svc.ReserveMasterUpload(context.Background(), "cancel.mp3", "music/Fairness", "", "primary", 10, 255, store.AdminAudit{})
	if err != nil {
		t.Fatal(err)
	}
	expiry := time.Now().Unix() - 10
	if _, err := db.Database().Exec("UPDATE cluster_upload_sessions SET expires_at=?,updated_at=? WHERE upload_id=?", expiry, expiry-20, v.ID); err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	p := &recoveryFairnessPool{PoolRepository: db.Pool(), slowID: v.ID, started: started}
	svc.pool = p
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- svc.retryExpiredUploads(ctx, func(store.UploadReservation) time.Duration { return time.Second }, 100*time.Millisecond)
	}()
	select {
	case <-started:
		cancel()
	case <-time.After(2 * time.Second):
		cancel()
		t.Fatal("investigation did not start")
	}
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal("parent cancellation ignored", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("canceled recovery kept running")
	}
	if len(p.deferredIDs) != 0 {
		t.Fatal("SQL rotation detached from cancellation", p.deferredIDs)
	}
	var currentExpiry, updated int64
	if err := db.Database().QueryRow("SELECT expires_at,updated_at FROM cluster_upload_sessions WHERE upload_id=?", v.ID).Scan(&currentExpiry, &updated); err != nil || currentExpiry != expiry || updated != expiry-20 {
		t.Fatal("cancellation changed reservation", currentExpiry, updated, err)
	}
	masterFunds(t, db, 0, 10)
}

func TestExpiredRecoveryRotationSQLFailureIsNotSilentlyIgnored(t *testing.T) {
	_, db, svc := masterFixture(t)
	ctx := context.Background()
	v, err := svc.ReserveMasterUpload(ctx, "rotate.mp3", "music/Fairness", "", "primary", 10, 255, store.AdminAudit{})
	if err != nil {
		t.Fatal(err)
	}
	expiry := time.Now().Unix() - 10
	if _, err := db.Database().Exec("UPDATE cluster_upload_sessions SET expires_at=?,updated_at=? WHERE upload_id=?", expiry, expiry-20, v.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Database().Exec("CREATE TRIGGER rotation_fault BEFORE UPDATE OF updated_at ON cluster_upload_sessions BEGIN SELECT RAISE(FAIL,'rotation unavailable'); END"); err != nil {
		t.Fatal(err)
	}
	p := &recoveryFairnessPool{PoolRepository: db.Pool(), slowID: v.ID}
	svc.pool = p
	err = svc.retryExpiredUploads(ctx, func(store.UploadReservation) time.Duration { return 5 * time.Millisecond }, 100*time.Millisecond)
	if !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "rotation unavailable") {
		t.Fatal("rotation failure disappeared from the returned error", err)
	}
	if !p.rotationLive || len(p.deferredIDs) != 1 {
		t.Fatal("rotation did not receive bounded usable context", p)
	}
	var currentExpiry, updated int64
	if err := db.Database().QueryRow("SELECT expires_at,updated_at FROM cluster_upload_sessions WHERE upload_id=?", v.ID).Scan(&currentExpiry, &updated); err != nil || currentExpiry != expiry || updated != expiry-20 {
		t.Fatal("failed rotation changed reservation", currentExpiry, updated, err)
	}
	masterFunds(t, db, 0, 10)
}
