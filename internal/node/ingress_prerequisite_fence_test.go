package node

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// This controlled fence exercises lock ordering; the production encrypted
// tree must supply its own non-revocable, verifiable implementation.
type prerequisiteTestFence struct {
	mu       sync.RWMutex
	ready    bool
	acquired chan struct{}
}
type prerequisiteTestLease struct {
	fence *prerequisiteTestFence
	once  sync.Once
}

func (l *prerequisiteTestLease) Check(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !l.fence.ready {
		return errors.New("prerequisite unavailable")
	}
	return nil
}
func (l *prerequisiteTestLease) Release() { l.once.Do(l.fence.mu.RUnlock) }
func (f *prerequisiteTestFence) acquire(ctx context.Context) (IngressPrerequisiteLease, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	f.mu.RLock()
	if !f.ready {
		f.mu.RUnlock()
		return nil, errors.New("prerequisite unavailable")
	}
	f.acquired <- struct{}{}
	return &prerequisiteTestLease{fence: f}, nil
}

func TestPrerequisiteFenceHeldThroughAdmissionAndSelection(t *testing.T) {
	ctx := context.Background()
	service, _ := testNode(t, "Master", "https://master.test", nil)
	if err := service.ConfigurePublicOrigin("https://public.test"); err != nil {
		t.Fatal(err)
	}
	if _, err := service.repo.(store.PublicRoutingRepository).PublicIngress(ctx); err != nil {
		t.Fatal(err)
	}
	if err := service.ConfigureIngressSelectionReadiness(ctx, func(context.Context) (IngressPrerequisiteLease, error) { return (*prerequisiteTestLease)(nil), nil }); err == nil {
		t.Fatal("typed-nil prerequisite enabled selection")
	}
	fence := &prerequisiteTestFence{ready: true, acquired: make(chan struct{}, 4)}
	if err := service.ConfigureIngressSelectionReadiness(ctx, fence.acquire); err != nil {
		t.Fatal(err)
	}
	<-fence.acquired
	current, admission, err := service.AcquireCurrentIngress(ctx)
	if err != nil {
		t.Fatal(err)
	}
	<-fence.acquired
	identity, err := service.IdentityState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	selected := make(chan error, 1)
	go func() {
		wait, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		_, err := service.SelectPublicIngress(wait, identity.ID, current.Generation, store.NodeAudit{Actor: "fixture"})
		selected <- err
	}()
	select {
	case <-fence.acquired:
	case <-time.After(5 * time.Second):
		t.Fatal("selection did not acquire prerequisite first")
	}
	writer, writerStarted := make(chan struct{}), make(chan struct{})
	go func() {
		close(writerStarted)
		fence.mu.Lock()
		fence.ready = false
		fence.mu.Unlock()
		close(writer)
	}()
	<-writerStarted
	select {
	case <-writer:
		t.Fatal("prerequisite changed before admission and selection committed")
	case <-time.After(100 * time.Millisecond):
	}
	if err := admission.Commit(); err != nil {
		t.Fatal("admission commit", err)
	}
	select {
	case err := <-selected:
		if err != nil {
			t.Fatal("selection after admission", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("selection deadlocked behind prerequisite writer")
	}
	select {
	case <-writer:
	case <-time.After(5 * time.Second):
		t.Fatal("prerequisite writer remained blocked")
	}
	if _, lease, err := service.AcquireCurrentIngress(ctx); err == nil || lease != nil {
		t.Fatal("new admission ignored unavailable prerequisite")
	}
}
