package resourceinventory

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"strconv"
	"sync"
	"time"
)

type ContentRequest struct {
	ID          string  `json:"observation_id"`
	Binding     Binding `json:"binding"`
	Resource    string  `json:"resource_kind"`
	ObjectID    string  `json:"object_id"`
	MetadataSHA string  `json:"metadata_sha256"`
	Bytes       int64   `json:"expected_bytes"`
}

// ContentObservationTTL admits slow storage without inheriting cursor lifetime.
// One MiB/s is the explicit minimum throughput budget; callers can cancel sooner.
func ContentObservationTTL(bytes int64) time.Duration {
	const rate = int64(1 << 20)
	const maximum = 24 * time.Hour
	if bytes <= 0 {
		return SessionTTL
	}
	seconds := bytes / rate
	if bytes%rate != 0 {
		seconds++
	}
	if seconds >= int64((maximum-time.Minute)/time.Second) {
		return maximum
	}
	return max(SessionTTL, time.Minute+time.Duration(seconds)*time.Second)
}

type ContentJob struct {
	Request     ContentRequest      `json:"request"`
	Incarnation string              `json:"incarnation"`
	State       string              `json:"state"`
	CreatedAt   int64               `json:"created_at"`
	ExpiresAt   int64               `json:"expires_at"`
	ErrorCode   string              `json:"error_code,omitempty"`
	Observation *ContentObservation `json:"observation,omitempty"`
}

// Observe must recheck current authorization and metadata before/after reads.
// The manager does not grant path access or trust a caller-supplied digest.
type ContentObserver func(context.Context, ContentRequest) (ContentObservation, error)
type contentJobState struct {
	snapshot ContentJob
	deadline time.Time
	ctx      context.Context
	cancel   context.CancelFunc
	active   bool
}
type ContentJobs struct {
	mutex    sync.Mutex
	ctx      context.Context
	cancel   context.CancelFunc
	observe  ContentObserver
	now      func() time.Time
	queue    chan *contentJobState
	current  *contentJobState
	done     chan struct{}
	closed   bool
	validate func(ContentRequest) bool
}

func NewContentJobs(parent context.Context, observe ContentObserver, now func() time.Time) (*ContentJobs, error) {
	return newContentJobs(parent, observe, now, validContentRequest)
}

// Backup observations retain the same bounded worker lifecycle, but cannot
// admit media/recordings or arbitrary generation/path formats.
func NewBackupJobs(parent context.Context, observe ContentObserver, now func() time.Time) (*ContentJobs, error) {
	return newContentJobs(parent, observe, now, func(request ContentRequest) bool {
		generation, e := strconv.ParseInt(request.ObjectID, 10, 64)
		return e == nil && generation > 0 && strconv.FormatInt(generation, 10) == request.ObjectID && request.Resource == "backup" && request.Binding.Scope == "data" && validBinding(request.Binding) && sessionID.MatchString(request.ID) && contentHash(request.MetadataSHA) && request.Bytes >= 0
	})
}
func newContentJobs(parent context.Context, observe ContentObserver, now func() time.Time, validate func(ContentRequest) bool) (*ContentJobs, error) {
	if parent == nil || observe == nil {
		return nil, ErrSession
	}
	if now == nil {
		now = time.Now
	}
	ctx, cancel := context.WithCancel(parent)
	jobs := &ContentJobs{ctx: ctx, cancel: cancel, observe: observe, now: now, validate: validate, queue: make(chan *contentJobState, 1), done: make(chan struct{})}
	go jobs.run()
	return jobs, nil
}
func contentHash(value string) bool {
	raw, e := hex.DecodeString(value)
	return e == nil && len(raw) == 32 && hex.EncodeToString(raw) == value
}
func validContentRequest(request ContentRequest) bool {
	return sessionID.MatchString(request.ID) && validBinding(request.Binding) && request.Binding.Scope == "data" && contentHash(request.MetadataSHA) && request.Bytes >= 0 && (request.Resource == "media" && contentHash(request.ObjectID) || request.Resource == "recording" && sessionID.MatchString(request.ObjectID))
}
func contentJobCopy(job ContentJob) ContentJob {
	if job.Observation != nil {
		copy := *job.Observation
		job.Observation = &copy
	}
	return job
}
func (j *ContentJobs) expireLocked() {
	if j.current != nil && !j.now().Before(j.current.deadline) {
		j.current.cancel()
		j.current.snapshot.State = "expired"
		j.current.snapshot.Observation = nil
		j.current.snapshot.ErrorCode = "observation_expired"
	}
}
func (j *ContentJobs) Start(request ContentRequest) (ContentJob, error) {
	j.mutex.Lock()
	defer j.mutex.Unlock()
	j.expireLocked()
	if j.closed || j.ctx.Err() != nil || !j.validate(request) {
		return ContentJob{}, ErrSession
	}
	if j.current != nil {
		if j.current.snapshot.Request.ID == request.ID {
			if j.current.snapshot.Request != request || j.current.snapshot.State == "expired" {
				return ContentJob{}, ErrSession
			}
			return contentJobCopy(j.current.snapshot), nil
		}
		if j.current.active {
			return ContentJob{}, ErrBusy
		}
	}
	raw := make([]byte, 16)
	if _, e := rand.Read(raw); e != nil {
		return ContentJob{}, e
	}
	now := j.now()
	ttl := ContentObservationTTL(request.Bytes)
	ctx, cancel := context.WithTimeout(j.ctx, ttl)
	state := &contentJobState{snapshot: ContentJob{Request: request, Incarnation: hex.EncodeToString(raw), State: "queued", CreatedAt: now.Unix(), ExpiresAt: now.Add(ttl).Unix()}, deadline: now.Add(ttl), ctx: ctx, cancel: cancel, active: true}
	j.current = state
	j.queue <- state
	return contentJobCopy(state.snapshot), nil
}
func (j *ContentJobs) Status(id, incarnation string, binding Binding) (ContentJob, error) {
	j.mutex.Lock()
	defer j.mutex.Unlock()
	j.expireLocked()
	if j.closed || j.current == nil || j.current.snapshot.Request.ID != id || j.current.snapshot.Incarnation != incarnation || j.current.snapshot.Request.Binding != binding {
		return ContentJob{}, ErrSession
	}
	return contentJobCopy(j.current.snapshot), nil
}
func (j *ContentJobs) Cancel(id, incarnation string, binding Binding) (ContentJob, error) {
	j.mutex.Lock()
	defer j.mutex.Unlock()
	j.expireLocked()
	if j.closed || j.current == nil || j.current.snapshot.Request.ID != id || j.current.snapshot.Incarnation != incarnation || j.current.snapshot.Request.Binding != binding {
		return ContentJob{}, ErrSession
	}
	state := j.current
	if state.snapshot.State == "expired" {
		return contentJobCopy(state.snapshot), nil
	}
	state.cancel()
	state.snapshot.Observation = nil
	state.snapshot.ErrorCode = "observation_cancelled"
	if state.active {
		state.snapshot.State = "cancelling"
	} else {
		state.snapshot.State = "cancelled"
	}
	return contentJobCopy(state.snapshot), nil
}
func (j *ContentJobs) run() {
	defer close(j.done)
	for {
		select {
		case <-j.ctx.Done():
			return
		case state := <-j.queue:
			j.mutex.Lock()
			if state.ctx.Err() == nil {
				state.snapshot.State = "running"
			}
			j.mutex.Unlock()
			var result ContentObservation
			err := state.ctx.Err()
			if err == nil {
				result, err = j.observe(state.ctx, state.snapshot.Request)
			}
			j.mutex.Lock()
			state.active = false
			state.cancel()
			if !j.now().Before(state.deadline) || state.snapshot.State == "expired" {
				state.snapshot.State = "expired"
				state.snapshot.Observation = nil
				state.snapshot.ErrorCode = "observation_expired"
			} else if state.snapshot.State == "cancelling" || j.ctx.Err() != nil {
				state.snapshot.State = "cancelled"
				state.snapshot.Observation = nil
				state.snapshot.ErrorCode = "observation_cancelled"
			} else if err != nil || !contentHash(result.SHA256) || result.Bytes != state.snapshot.Request.Bytes || len(result.Path) > MaxPathBytes {
				state.snapshot.State = "failed"
				state.snapshot.Observation = nil
				state.snapshot.ErrorCode = "content_observation_failed"
			} else {
				state.snapshot.State = "observed"
				state.snapshot.Observation = &result
			}
			j.mutex.Unlock()
		}
	}
}

// Close cancels and joins the one worker. Borrowed roots belong to the observer.
func (j *ContentJobs) Close() {
	j.mutex.Lock()
	if !j.closed {
		j.closed = true
		j.cancel()
		if j.current != nil {
			j.current.cancel()
			j.current.snapshot.Observation = nil
			j.current.snapshot.State = "cancelled"
		}
	}
	j.mutex.Unlock()
	<-j.done
}
