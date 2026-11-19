package logarchive

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Remote interface {
	Store(context.Context, Target, Reference, []byte, int64) error
	Pull(context.Context, Target, Target, Reference, int64) error
	Verify(context.Context, Target, Reference) error
	Release(context.Context, Target, Reference, bool) error
}
type event struct {
	kind  Kind
	stamp time.Time
	raw   []byte
}
type ingestWork struct {
	node   string
	packet IngestPacket
}
type Runtime struct {
	Catalog  *Catalog
	remote   Remote
	idle     func() bool
	enabled  atomic.Bool
	dropped  atomic.Int64
	buffered atomic.Int64
	closing  atomic.Bool
	last     atomic.Value
	queue    chan event
	ingest   chan ingestWork
	cancel   context.CancelFunc
	wg       sync.WaitGroup
}

func NewRuntime(c *Catalog, remote Remote, idle func() bool) *Runtime {
	r := &Runtime{Catalog: c, remote: remote, idle: idle, queue: make(chan event, 256), ingest: make(chan ingestWork, 64)}
	r.last.Store("")
	if cfg, e := c.Configuration(context.Background()); e == nil {
		r.enabled.Store(cfg.Enabled)
	} else {
		r.last.Store("catalog_unavailable")
	}
	return r
}
func (r *Runtime) Enabled() bool { return r.enabled.Load() }
func (r *Runtime) QueueIngest(node string, p IngestPacket) {
	if !r.Enabled() || node != p.Node || p.Master != r.Catalog.master || len(p.Cipher) > 16400 {
		return
	}
	select {
	case r.ingest <- ingestWork{node, p}:
	default: /* Sender retains its durable encrypted copy until commit acknowledgement. */
	}
}
func (r *Runtime) Configure(ctx context.Context, target Target, generation int64) (Configuration, error) {
	v, e := r.Catalog.Configure(ctx, target, generation)
	if e == nil {
		r.enabled.Store(true)
	}
	return v, e
}
func (r *Runtime) Capture(kind Kind, fields map[string]any) {
	if !r.Enabled() || r.closing.Load() || !validKind(kind) {
		return
	}
	stamp := time.Now().UTC()
	copyFields := make(map[string]any, len(fields)+1)
	for k, v := range fields {
		copyFields[k] = v
	}
	copyFields["received_at_ms"] = stamp.UnixMilli()
	raw, e := json.Marshal(copyFields)
	if e != nil || len(raw) > 8192 {
		r.dropped.Add(1)
		return
	}
	select {
	case r.queue <- event{kind, stamp, raw}:
	default:
		r.dropped.Add(1)
	}
}
func (r *Runtime) Health() map[string]any {
	return map[string]any{"dropped_this_process": r.dropped.Load(), "last_error": r.last.Load(), "memory_pending": int64(len(r.queue)) + r.buffered.Load(), "flush_interval_ms": 1000}
}
func (r *Runtime) Start(parent context.Context) {
	ctx, cancel := context.WithCancel(parent)
	r.cancel = cancel
	r.wg.Add(3)
	go func() {
		defer r.wg.Done()
		timer := time.NewTicker(200 * time.Millisecond)
		defer timer.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
				if r.idle == nil || !r.idle() {
					continue
				}
				select {
				case work := <-r.ingest:
					deadline, stop := context.WithTimeout(ctx, 250*time.Millisecond)
					e := r.Catalog.Ingest(deadline, work.node, work.packet)
					stop()
					if e != nil {
						r.last.Store("node_ingest_retry")
					}
				default:
				}
			}
		}
	}()
	go func() {
		defer r.wg.Done()
		timer := time.NewTicker(time.Second)
		defer timer.Stop()
		type batch struct {
			values     []json.RawMessage
			bytes      int
			start, end time.Time
		}
		batches := map[Kind]*batch{}
		flush := func(kind Kind) bool {
			v := batches[kind]
			if v == nil || len(v.values) == 0 {
				return true
			}
			raw, _ := json.Marshal(v.values)
			deadline, stop := context.WithTimeout(context.Background(), time.Second)
			err := r.Catalog.QueueCapture(deadline, kind, v.start, v.end.Add(time.Millisecond), raw)
			stop()
			if err != nil {
				r.last.Store("capture_failed")
				return false
			}
			r.buffered.Add(-int64(len(v.values)))
			delete(batches, kind)
			return true
		}
		accept := func(e event) {
			v := batches[e.kind]
			if v != nil && v.bytes+len(e.raw)+2 > MaxPlainBytes {
				if !flush(e.kind) {
					r.dropped.Add(1)
					return
				}
				v = nil
			}
			if v == nil {
				v = &batch{start: e.stamp}
				batches[e.kind] = v
			}
			v.values = append(v.values, json.RawMessage(e.raw))
			v.bytes += len(e.raw) + 1
			v.end = e.stamp
			r.buffered.Add(1)
		}
		defer func() {
			for kind := range batches {
				flush(kind)
			}
		}()
		for {
			select {
			case <-ctx.Done():
				for {
					select {
					case e := <-r.queue:
						accept(e)
					default:
						return
					}
				}
				return
			case <-timer.C:
				for kind := range batches {
					flush(kind)
				}
			case e := <-r.queue:
				accept(e)
			}
		}
	}()
	go func() {
		defer r.wg.Done()
		timer := time.NewTicker(2 * time.Second)
		defer timer.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
				if r.Enabled() && r.idle != nil && r.idle() {
					deadline, stop := context.WithTimeout(ctx, 12*time.Second)
					r.step(deadline, time.Now())
					stop()
				}
			}
		}
	}()
}
func (r *Runtime) Close() error {
	r.closing.Store(true)
	if r.cancel != nil {
		r.cancel()
	}
	r.wg.Wait()
	e := r.Catalog.Close()
	if r.buffered.Load() != 0 || len(r.queue) != 0 {
		return errors.Join(e, errors.New("encrypted log capture remains unflushed"))
	}
	return e
}
func (r *Runtime) step(ctx context.Context, now time.Time) {
	cfg, e := r.Catalog.Configuration(ctx)
	if e != nil || !cfg.Enabled || r.remote == nil {
		return
	}
	if e = r.Catalog.PublishCapture(ctx, now, "", false); e != nil {
		r.last.Store("capture_publish_failed")
		return
	}
	expired, e := r.Catalog.ExpiryPage(ctx, now)
	if e != nil {
		r.last.Store("queue_unavailable")
		return
	}
	for _, v := range expired {
		if !r.idle() {
			return
		}
		ref := v.Record.Reference()
		for _, target := range []Target{v.Remote, v.Cleanup} {
			if target.MemberID != "" {
				_ = r.remote.Release(ctx, target, ref, true)
			}
		}
		// Lifecycle expiry is independent from upload/move release. The remote
		// replica also expires its exact ciphertext without needing Master online.
		deadline, stop := context.WithTimeout(context.Background(), time.Second)
		if e = r.Catalog.ForgetExpired(deadline, ref.ID, now); e != nil {
			r.last.Store("expiry_failed")
		}
		stop()
	}
	items, e := r.Catalog.Pending(ctx, cfg.Generation, now)
	if e != nil {
		r.last.Store("queue_unavailable")
		return
	}
	for _, v := range items {
		if !r.idle() || ctx.Err() != nil {
			return
		}
		ref := v.Record.Reference()
		e = nil
		if v.Cleanup.MemberID != "" {
			if e = r.remote.Verify(ctx, v.Remote, ref); e == nil {
				e = r.remote.Release(ctx, v.Cleanup, ref, false)
			}
			if e == nil {
				e = r.Catalog.Cleaned(ctx, ref.ID)
			}
		} else if v.RemoteGeneration != cfg.Generation {
			if v.Remote.MemberID == cfg.Target.MemberID {
				e = r.remote.Verify(ctx, cfg.Target, ref)
			} else if v.Remote.MemberID != "" {
				e = r.remote.Pull(ctx, cfg.Target, v.Remote, ref, time.UnixMilli(v.Record.Header.EndMillis).Add(Retention).Unix()+1)
			} else if len(v.Ciphertext) > 0 {
				e = r.remote.Store(ctx, cfg.Target, ref, v.Ciphertext, time.UnixMilli(v.Record.Header.EndMillis).Add(Retention).Unix()+1)
			} else {
				e = ErrBlock
			}
			if e == nil {
				e = r.remote.Verify(ctx, cfg.Target, ref)
			}
			if e == nil {
				e = r.Catalog.Acknowledge(ctx, v, cfg)
			}
		} else if ReleaseLocal(time.UnixMilli(v.Record.Header.EndMillis), now, true) {
			if e = r.remote.Verify(ctx, v.Remote, ref); e == nil {
				e = r.Catalog.ReleaseLocal(ctx, ref.ID, now)
			}
		}
		if e != nil {
			_ = r.Catalog.Retry(ctx, ref.ID, now)
			r.last.Store("transfer_failed")
		} else {
			r.last.Store("")
		}
	}
}

// Handler replaces stdout only after explicit activation; archive traffic is
// excluded to avoid logging the logger's own uploads/queries recursively.
type Handler struct {
	Runtime interface {
		Enabled() bool
		Capture(Kind, map[string]any)
	}
	Fallback slog.Handler
	Attrs    []slog.Attr
	Group    string
}

func (h *Handler) Enabled(ctx context.Context, l slog.Level) bool { return h.Fallback.Enabled(ctx, l) }
func (h *Handler) WithAttrs(a []slog.Attr) slog.Handler {
	v := *h
	v.Attrs = append(append([]slog.Attr{}, h.Attrs...), a...)
	return &v
}
func (h *Handler) WithGroup(name string) slog.Handler { v := *h; v.Group = name; return &v }
func (h *Handler) Handle(ctx context.Context, rec slog.Record) error {
	if !h.Runtime.Enabled() {
		if gate, ok := h.Runtime.(interface{ FallbackAllowed() bool }); ok && !gate.FallbackAllowed() {
			h.Runtime.Capture(Application, map[string]any{"message": "unconfigured_log_omitted"})
			return nil
		}
		return h.Fallback.WithAttrs(h.Attrs).Handle(ctx, rec)
	}
	fields := map[string]any{"time": rec.Time.UTC().Format(time.RFC3339Nano), "level": rec.Level.String(), "message": rec.Message}
	count := 0
	add := func(a slog.Attr) bool {
		if count >= 32 {
			return false
		}
		count++
		key := a.Key
		lower := strings.ToLower(key)
		for _, secret := range []string{"password", "credential", "authorization", "cookie", "token", "key"} {
			if strings.Contains(lower, secret) {
				return true
			}
		}
		a.Value = a.Value.Resolve()
		switch a.Value.Kind() {
		case slog.KindString:
			v := a.Value.String()
			if len(v) > 512 {
				v = v[:512]
			}
			fields[key] = v
		case slog.KindBool:
			fields[key] = a.Value.Bool()
		case slog.KindInt64:
			fields[key] = a.Value.Int64()
		case slog.KindUint64:
			fields[key] = a.Value.Uint64()
		case slog.KindFloat64:
			fields[key] = a.Value.Float64()
		default:
			fields[key] = "[structured value omitted]"
		}
		return true
	}
	for _, a := range h.Attrs {
		add(a)
	}
	rec.Attrs(add)
	if path, ok := fields["path"].(string); ok && (strings.Contains(path, "log-archive") || strings.HasPrefix(path, "/api/v1/media/admin/logs")) {
		return nil
	}
	kind := Application
	message := strings.ToLower(rec.Message)
	if rec.Level >= slog.LevelError {
		kind = Error
	} else if rec.Message == "request_completed" {
		kind = Access
	} else {
		for text, k := range map[string]Kind{"certificate": Certificate, "node": Node, "backup": Job, "security": Security, "webrtc": WebRTC, "audit": Audit} {
			if strings.Contains(message, text) {
				kind = k
				break
			}
		}
	}
	h.Runtime.Capture(kind, fields)
	return nil
}
