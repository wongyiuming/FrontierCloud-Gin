package business_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// These repository tests do not exercise a browser, endpoint selection or the
// new ingress transport policy. They verify the durable owner reservation only.
func TestSelectedUploadOwnerAffinityAndNoFallback(t *testing.T) {
	f := newS3SQL(t, true)
	a := f.add(t, "selected-a", true)
	b := f.add(t, "selected-b", true)
	r := f.pool.(store.SelectedUploadRepository)
	reserve := func(path, member string) (store.UploadReservation, error) {
		return r.ReserveSelectedEncryptedUpload(f.ctx, path, member, 1, 0, store.AdminAudit{}, nil)
	}
	first, err := reserve("music/SelectedOwner/a.mp3", a.ID)
	if err != nil || first.MemberID != a.ID {
		t.Fatal("requested owner was not reserved", first.MemberID, err)
	}
	if _, err = reserve("music/SelectedOwner/b.mp3", b.ID); !errors.Is(err, store.ErrNodeState) || !strings.Contains(err.Error(), "another storage member") {
		t.Fatal("different owner did not fail on folder affinity", err)
	}
	second, err := reserve("music/SelectedOwner/c.mp3", a.ID)
	if err != nil || second.MemberID != a.ID {
		t.Fatal("same owner affinity failed", second.MemberID, err)
	}
	if _, err = reserve("music/UnknownOwner/a.mp3", strings.Repeat("f", 32)); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("unknown member was silently reassigned", err)
	}
	if _, err = reserve("music/UnknownOwner/b.mp3", "https://example.invalid"); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("untrusted address was treated as member identity", err)
	}
	c := s3SQLConfig("selected-a")
	c.SealedCredentials = nil
	if _, err = f.repo.S3ConfigureMember(f.ctx, a.ID, a.Revision, c, store.NodeAudit{}); err != nil {
		t.Fatal(err)
	}
	if _, err = reserve("music/SelectedOwner/d.mp3", a.ID); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("disabled owner was silently reassigned", err)
	}
	other, err := f.repo.S3Member(f.ctx, b.ID)
	if err != nil || other.Reserved != 0 {
		t.Fatal("failure changed another member's reservation", other.Reserved, err)
	}
}

func TestSelectedUploadConcurrentFolderReservationsDoNotSplitOwners(t *testing.T) {
	f := newS3SQL(t, true)
	a, b := f.add(t, "concurrent-a", true), f.add(t, "concurrent-b", true)
	r := f.pool.(store.SelectedUploadRepository)
	start := make(chan struct{})
	type result struct {
		value store.UploadReservation
		err   error
	}
	results := make(chan result, 2)
	var wg sync.WaitGroup
	for _, item := range []struct{ path, member string }{{"music/SelectedConcurrent/a.mp3", a.ID}, {"music/SelectedConcurrent/b.mp3", b.ID}} {
		wg.Add(1)
		go func(path, member string) {
			defer wg.Done()
			<-start
			v, err := r.ReserveSelectedEncryptedUpload(context.Background(), path, member, 1, 0, store.AdminAudit{}, nil)
			results <- result{v, err}
		}(item.path, item.member)
	}
	close(start)
	wg.Wait()
	close(results)
	success, conflict := 0, 0
	for got := range results {
		if got.err == nil {
			success++
			if got.value.MemberID != a.ID && got.value.MemberID != b.ID {
				t.Fatal("unexpected owner", got.value.MemberID)
			}
		} else if errors.Is(got.err, store.ErrNodeState) {
			conflict++
		} else {
			t.Fatal(got.err)
		}
	}
	if success != 1 || conflict != 1 {
		t.Fatalf("want one reservation and one conflict, got %d/%d", success, conflict)
	}
}

func TestSelectedUploadConcurrentReservationsRespectQuotaWithoutFallback(t *testing.T) {
	f := newS3SQL(t, true)
	a, b := f.add(t, "quota-a", true), f.add(t, "quota-b", true)
	r := f.pool.(store.SelectedUploadRepository)
	start := make(chan struct{})
	type result struct {
		value store.UploadReservation
		err   error
	}
	results := make(chan result, 3)
	var wg sync.WaitGroup
	for _, path := range []string{"music/QuotaA/a.mp3", "music/QuotaB/b.mp3", "music/QuotaC/c.mp3"} {
		wg.Add(1)
		go func(path string) {
			defer wg.Done()
			<-start
			v, err := r.ReserveSelectedEncryptedUpload(context.Background(), path, a.ID, 10*store.GiB, 0, store.AdminAudit{}, nil)
			results <- result{v, err}
		}(path)
	}
	close(start)
	wg.Wait()
	close(results)
	success, conflict := 0, 0
	for got := range results {
		if got.err == nil {
			success++
			if got.value.MemberID != a.ID {
				t.Fatal("reservation moved to another member", got.value.MemberID)
			}
		} else if errors.Is(got.err, store.ErrNodeState) {
			conflict++
		} else {
			t.Fatal(got.err)
		}
	}
	if success != 2 || conflict != 1 {
		t.Fatalf("want two reservations and one capacity conflict, got %d/%d", success, conflict)
	}
	selected, err := f.repo.S3Member(f.ctx, a.ID)
	if err != nil || selected.Reserved != 20*store.GiB {
		t.Fatal("selected member reservation accounting is incorrect", selected.Reserved, err)
	}
	other, err := f.repo.S3Member(f.ctx, b.ID)
	if err != nil || other.Reserved != 0 {
		t.Fatal("capacity failure changed another member", other.Reserved, err)
	}
}
