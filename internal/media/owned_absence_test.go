package media

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func TestOwnedAbsenceNeverDeletesCommittedOrUnknownAfterStat404(t *testing.T) {
	for _, scenario := range []string{"committed", "unknown", "live", "journal"} {
		t.Run(scenario, func(t *testing.T) {
			root, db, svc, rel := ownedFixture(t)
			ctx := context.Background()
			object := store.MediaObject{ID: strings.Repeat("2", 64), Path: "music/Absence/song.mp3", Kind: "audio"}
			if _, err := svc.StorageStat(ctx, object.ID, object.Path); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("expected original stat 404", err)
			}
			switch scenario {
			case "committed":
				if _, err := svc.OwnedUpload(ctx, rel, object, 10, strings.NewReader("ID3payload"), store.NodeAudit{}); err != nil {
					t.Fatal(err)
				}
			case "unknown":
				if err := os.MkdirAll(filepath.Dir(filepath.Join(root, object.Path)), 0755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(root, object.Path), []byte("ID3unknown"), 0600); err != nil {
					t.Fatal(err)
				}
			case "live":
				stage, err := svc.Stage(ctx, strings.NewReader("ID3payload"), 10)
				if err != nil {
					t.Fatal(err)
				}
				defer stage.Close()
				if err := db.Pool().ReserveOwnedUpload(ctx, stage.id, rel, object, 10, 10*store.GiB, store.NodeAudit{}); err != nil {
					t.Fatal(err)
				}
			case "journal":
				if err := os.WriteFile(filepath.Join(root, journalPath(strings.Repeat("7", 32))), []byte("unknown-intent"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := svc.OwnedUploadAbsence(ctx, rel, strings.Repeat("a", 32), object.ID, object.Path); err == nil {
				t.Fatal("unsafe absence receipt")
			}
			if scenario == "committed" {
				ownedFunds(t, db, 10, 0)
				found, err := db.Media().ObjectByID(ctx, object.ID)
				if err != nil || found == nil {
					t.Fatal("catalog row removed", found, err)
				}
				bytes, err := os.ReadFile(filepath.Join(root, object.Path))
				if err != nil || string(bytes) != "ID3payload" {
					t.Fatal("committed bytes removed", err)
				}
			} else if scenario == "live" {
				ownedFunds(t, db, 0, 10)
			} else {
				ownedFunds(t, db, 0, 0)
				if scenario == "unknown" {
					bytes, err := os.ReadFile(filepath.Join(root, object.Path))
					if err != nil || string(bytes) != "ID3unknown" {
						t.Fatal("unknown bytes removed", err)
					}
				}
			}
		})
	}
}

func TestOwnedAbsenceDurableGenerationRejectsLateAdmittedPUTButAllowsFreshTicket(t *testing.T) {
	root, db, svc, rel := ownedFixture(t)
	ctx := context.Background()
	object := store.MediaObject{ID: strings.Repeat("3", 64), Path: "music/Absence/song.mp3", Kind: "audio"}
	old, fresh := strings.Repeat("a", 32), strings.Repeat("b", 32)
	expires := time.Now().Unix() + 120
	// Simulate a PUT authenticated before the absence call, whose goroutine has
	// not yet reached ReserveOwnedUpload. The signed generation stays unchanged.
	receipt, err := svc.OwnedUploadAbsence(ctx, rel, old, object.ID, object.Path)
	if err != nil || receipt.UploadID != old || receipt.Fence != "durable-generation-v1" {
		t.Fatal(receipt, err)
	}
	if _, err := svc.OwnedUploadAbsence(ctx, rel, old, object.ID, object.Path); err != nil {
		t.Fatal("receipt replay", err)
	}
	// Another worker sees the durable markers, not the first worker's memory.
	other, err := New(root, db.Media(), svc.identity)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	for _, generation := range []string{old, ""} {
		reads := 0
		reader := countAbsentReads{&reads}
		if _, err := other.OwnedUploadCapability(ctx, rel, object, 10, reader, store.NodeAudit{}, generation, expires); !errors.Is(err, store.ErrNodeState) {
			t.Fatal("late writer admitted", generation, err)
		}
		if reads != 0 {
			t.Fatal("read upload bytes before fencing", reads)
		}
		ownedFunds(t, db, 0, 0)
		if _, err := db.Media().ObjectByID(ctx, object.ID); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := other.OwnedUploadCapability(ctx, rel, object, 10, strings.NewReader("ID3payload"), store.NodeAudit{}, fresh, expires); err != nil {
		t.Fatal("fresh same-path generation blocked", err)
	}
	ownedFunds(t, db, 10, 0)
}

type countAbsentReads struct{ reads *int }

func (r countAbsentReads) Read(_ []byte) (int, error) { *r.reads++; return 0, io.EOF }

func TestOwnedUploadRechecksExpiredAdmissionBeforeReserve(t *testing.T) {
	_, db, svc, rel := ownedFixture(t)
	object := store.MediaObject{ID: strings.Repeat("4", 64), Path: "music/Absence/song.mp3", Kind: "audio"}
	if _, err := svc.OwnedUploadCapability(context.Background(), rel, object, 10, strings.NewReader("ID3payload"), store.NodeAudit{}, strings.Repeat("c", 32), time.Now().Unix()-1); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("expired admitted request reserved", err)
	}
	ownedFunds(t, db, 0, 0)
}

type pausedAdmissionRepository struct {
	store.MediaRepository
	paused  atomic.Bool
	entered chan struct{}
	resume  chan struct{}
}

func (r *pausedAdmissionRepository) ObjectByID(ctx context.Context, id string) (*store.MediaObject, error) {
	if r.paused.CompareAndSwap(false, true) {
		close(r.entered)
		select {
		case <-r.resume:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return r.MediaRepository.ObjectByID(ctx, id)
}

func TestOwnedAbsenceRacesAlreadyAdmittedPUTBeforeReservation(t *testing.T) {
	_, db, svc, rel := ownedFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	object := store.MediaObject{ID: strings.Repeat("5", 64), Path: "music/Absence/raced.mp3", Kind: "audio"}
	generation := strings.Repeat("d", 32)
	repository := &pausedAdmissionRepository{MediaRepository: svc.repository, entered: make(chan struct{}), resume: make(chan struct{})}
	svc.repository = repository
	result := make(chan error, 1)
	go func() {
		_, err := svc.OwnedUploadCapability(ctx, rel, object, 10, strings.NewReader("ID3payload"), store.NodeAudit{}, generation, time.Now().Unix()+120)
		result <- err
	}()
	select {
	case <-repository.entered:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	// PUT was authenticated and entered the service, but has not yet created a
	// stage/reservation. The absence receipt must permanently fence that request.
	if _, err := svc.OwnedUploadAbsence(ctx, rel, generation, object.ID, object.Path); err != nil {
		close(repository.resume)
		t.Fatal(err)
	}
	close(repository.resume)
	select {
	case err := <-result:
		if !errors.Is(err, store.ErrNodeState) {
			t.Fatal("queued PUT survived absence fence", err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	ownedFunds(t, db, 0, 0)
	if object, err := db.Media().ObjectByID(ctx, object.ID); err != nil || object != nil {
		t.Fatal("late PUT published", object, err)
	}
}

func TestOwnedAbsenceFencePublicationIsBoundedPrivateAndNoTempRemains(t *testing.T) {
	root, _, svc, rel := ownedFixture(t)
	ctx := context.Background()
	object := store.MediaObject{ID: strings.Repeat("6", 64), Path: "music/Absence/atomic.mp3", Kind: "audio"}
	uploadID := strings.Repeat("e", 32)
	if _, err := svc.OwnedUploadAbsence(ctx, rel, uploadID, object.ID, object.Path); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".storage-fence-tmp-") {
			t.Fatal("published temporary fence was not removed", entry.Name())
		}
	}
	marker := filepath.Join(root, ".storage-abort-"+uploadID)
	info, err := os.Stat(marker)
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 2048 {
		t.Fatal("invalid final fence", info, err)
	}
	if err := svc.writeOwnedFence("../outside", []byte("bad")); !errors.Is(err, ErrPath) {
		t.Fatal("unvalidated marker name", err)
	}
	if err := svc.writeOwnedFence(".storage-abort-"+strings.Repeat("f", 32), make([]byte, 2049)); !errors.Is(err, ErrPath) {
		t.Fatal("unbounded payload", err)
	}
	// Existing malformed or mismatched final metadata is fail-closed, never
	// overwritten to manufacture absence proof.
	if err := svc.writeOwnedFence(".storage-abort-"+uploadID, []byte("different")); !errors.Is(err, ErrRecovery) {
		t.Fatal("replaced existing fence", err)
	}
	if current, err := os.Stat(marker); err != nil || current.Size() != info.Size() {
		t.Fatal("final fence changed", err)
	}
}
