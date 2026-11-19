package business

import (
	"context"
	"sync"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// RunMediaDeletions joins every installed backend before returning to the
// deployment lifecycle. Scans release their tree lease before storage I/O.
func (s *SelectedUploadRuntime) RunMediaDeletions(ctx context.Context, executor MediaDeletionExecutor) {
	if s == nil || s.repo == nil || s.tree == nil || ctx == nil || selectedNil(executor) {
		return
	}
	var workers sync.WaitGroup
	run := func(work func(context.Context)) {
		workers.Add(1)
		go func() {
			defer workers.Done()
			work(ctx)
		}()
	}
	run(func(c context.Context) { s.RunFollowerMediaDeletions(c, executor) })
	run(func(c context.Context) {
		s.runMediaDeletionPages(c, protocol.OpaqueDeletionVerificationTimeout+20*time.Second, s.tree.ListMasterLocalMediaDeletionsWithLease, func(itemCtx context.Context, item store.SelectedMediaDeleteItem) {
			_ = s.AdvancePendingMasterLocalMediaDeletion(itemCtx, item, executor)
		})
	})
	run(func(c context.Context) {
		s.runMediaDeletionPages(c, 5*time.Second, s.tree.ListDirectoryDeletionsWithLease, func(itemCtx context.Context, item store.SelectedMediaDeleteItem) {
			_, _ = s.finishDirectoryDeletion(itemCtx, item, store.AdminAudit{})
		})
	})
	if s3 := s.SelectedS3(); s3 != nil {
		run(s3.RunMediaDeletions)
	}
	workers.Wait()
}

func (s *SelectedUploadRuntime) finishDirectoryDeletion(ctx context.Context, item store.SelectedMediaDeleteItem, audit store.AdminAudit) (bool, error) {
	if s == nil || s.repo == nil || s.tree == nil || ctx == nil || selectedNil(s.gate) || !item.Directory {
		return false, store.ErrNodeState
	}
	ready, err := s.gate.AcquireSelectedUpload(ctx, s.tree)
	if err != nil || selectedNil(ready) {
		return false, store.ErrNodeState
	}
	defer ready.Release()
	var done bool
	err = s.repo.withSelectedMutation(ctx, s.tree, func(c context.Context, q queryer, m *sealedtree.CoordinatedMutation) error {
		if err := ready.Check(c); err != nil {
			return err
		}
		final, changed, err := m.FinalizeDirectoryDeletionTx(c, q, item)
		if err != nil {
			return err
		}
		if changed {
			audit.Action, audit.Result, audit.TargetCount = "opaque-directory-delete", "success", 1
			audit.SourceSummary, audit.Detail = "", ""
			if err := appendAudit(c, q, audit); err != nil {
				return err
			}
		}
		done = final
		return ready.Check(c)
	})
	return done && err == nil, err
}

type pendingMediaDeletionList func(context.Context, *sealedtree.TreeLease, string, int) ([]store.SelectedMediaDeleteItem, string, error)

func (s *SelectedUploadRuntime) runMediaDeletionPages(ctx context.Context, attemptTimeout time.Duration, list pendingMediaDeletionList, advance func(context.Context, store.SelectedMediaDeleteItem)) {
	after := ""
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	for ctx.Err() == nil {
		after = s.resumeMediaDeletionPage(ctx, attemptTimeout, list, advance, after)
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

func (s *SelectedUploadRuntime) resumeMediaDeletionPage(ctx context.Context, attemptTimeout time.Duration, list pendingMediaDeletionList, advance func(context.Context, store.SelectedMediaDeleteItem), after string) string {
	c, cancel := context.WithTimeout(ctx, 5*time.Second)
	lease, err := s.tree.AcquireReadFence(c)
	if err != nil {
		cancel()
		return after
	}
	items, next, err := list(c, lease, after, 8)
	lease.Release()
	cancel()
	if err != nil {
		return after
	}
	for _, item := range items {
		if ctx.Err() != nil {
			break
		}
		c, cancel := context.WithTimeout(ctx, attemptTimeout)
		advance(c, item)
		cancel()
	}
	return next
}
