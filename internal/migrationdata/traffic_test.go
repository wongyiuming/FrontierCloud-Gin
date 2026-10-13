package migrationdata

import (
	"bytes"
	"context"
	"errors"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/businesstraffic"
	"sync"
	"testing"
)

func TestCheckpointStatusReadsCompleteAtomicJournalDuringConcurrentSave(t *testing.T) {
	r, spec, _ := fixture(t, []byte("owned bytes"))
	ctx := context.Background()
	if _, e := r.Begin(ctx, spec); e != nil {
		t.Fatal(e)
	}
	var workers sync.WaitGroup
	failures := make(chan error, 2)
	workers.Add(1)
	go func() {
		defer workers.Done()
		for i := 0; i < 100; i++ {
			release, e := r.lock(ctx, spec)
			if e != nil {
				failures <- e
				return
			}
			cp, e := r.load(spec)
			if e == nil {
				cp.RecheckedAt = int64(i)
				e = r.save(cp)
			}
			release()
			if e != nil {
				failures <- e
				return
			}
		}
	}()
	for i := 0; i < 1000; i++ {
		cp, e := r.Status(ctx, spec)
		if e != nil || cp.State != "receiving" || cp.Offset != 0 || cp.Spec.SourceVersion != spec.SourceVersion || cp.PrefixSHA != sha(nil) {
			t.Errorf("atomic snapshot rejected or corrupted: %v", e)
			break
		}
	}
	workers.Wait()
	close(failures)
	for e := range failures {
		t.Fatal(e)
	}
}

func TestMigrationDiskScanYieldsWithoutFailingVerifiedBytesOrRecheck(t *testing.T) {
	data := bytes.Repeat([]byte("a"), 2*ChunkBytes)
	r, s, _ := fixture(t, data)
	ctx := context.Background()
	if _, e := r.Begin(ctx, s); e != nil {
		t.Fatal(e)
	}
	for offset := 0; offset < len(data); offset += ChunkBytes {
		chunk := data[offset : offset+ChunkBytes]
		if _, e := r.Append(ctx, s, int64(offset), chunk, sha(chunk)); e != nil {
			t.Fatal(e)
		}
	}
	reads := 0
	busy := WithScanAdmission(ctx, func() error {
		reads++
		if reads > 2 {
			return businesstraffic.ErrWait
		}
		return nil
	})
	if _, e := r.Verify(busy, s, nil); !errors.Is(e, businesstraffic.ErrWait) {
		t.Fatal(e)
	}
	if cp, e := r.Status(ctx, s); e != nil || cp.State != "received" || cp.Offset != s.Bytes {
		t.Fatal(cp, e)
	}
	if _, e := r.Verify(ctx, s, nil); e != nil {
		t.Fatal(e)
	}
	if _, e := r.Publish(ctx, s, func() error { return nil }, func(string) error { return nil }); e != nil {
		t.Fatal(e)
	}
	id := "12345678901234567890123456789012"
	busy = WithScanAdmission(ctx, func() error { return businesstraffic.ErrWait })
	if _, e := r.Recheck(busy, s, id, func() error { return nil }, func(string) error { return nil }); !errors.Is(e, businesstraffic.ErrWait) {
		t.Fatal(e)
	}
	if cp, e := r.Status(ctx, s); e != nil || cp.RecheckID == id || cp.RecheckError != "" || cp.State != "published" {
		t.Fatal(cp, e)
	}
	if cp, e := r.Recheck(ctx, s, id, func() error { return nil }, func(string) error { return nil }); e != nil || cp.RecheckID != id || cp.RecheckError != "" {
		t.Fatal(cp, e)
	}
}
