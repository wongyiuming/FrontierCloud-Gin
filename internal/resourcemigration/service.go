package resourcemigration

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

// Start joins one local task runner into the existing process lifecycle. SQL
// facts are authoritative; this goroutine owns no queue or recovery state.
func (r *Runner) Start(parent context.Context) (func() error, error) {
	raw := make([]byte, 16)
	if _, e := rand.Read(raw); e != nil {
		return nil, e
	}
	runner := hex.EncodeToString(raw)
	ctx, cancel := context.WithCancel(parent)
	var jobs sync.WaitGroup
	jobs.Add(1)
	go func() {
		defer jobs.Done()
		for ctx.Err() == nil {
			if id, e := r.Repository.NextMigrationRun(ctx); e == nil && id != "" {
				_ = r.Run(ctx, id, runner)
			}
			timer := time.NewTimer(2 * time.Second)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
		}
	}()
	var once sync.Once
	return func() error { once.Do(func() { cancel(); jobs.Wait() }); return nil }, nil
}
