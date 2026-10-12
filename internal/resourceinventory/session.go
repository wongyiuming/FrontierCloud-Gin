package resourceinventory

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"regexp"
	"sync"
	"time"
)

const SessionTTL = 5 * time.Minute

var ErrSession = errors.New("inventory session is missing, expired, closed or incorrectly bound")
var ErrBusy = errors.New("another physical inventory observation is active")
var sessionID = regexp.MustCompile(`^[a-f0-9]{32}$`)

type Binding struct {
	MemberID       string `json:"member_id"`
	MasterID       string `json:"master_id"`
	RelationshipID string `json:"relationship_id"`
	Scope          string `json:"scope"`
}
type Session struct {
	ID          string  `json:"session_id"`
	Incarnation string  `json:"incarnation"`
	Binding     Binding `json:"binding"`
	CreatedAt   int64   `json:"created_at"`
	ExpiresAt   int64   `json:"expires_at"`
}
type SessionPage struct {
	Session Session `json:"session"`
	Page    Page    `json:"page"`
}
type observation struct {
	session          Session
	scanner          *Scanner
	closed, complete bool
}

// Sessions holds one scanner/replay page. Caller authorization must still be
// rechecked for every operation; a session ID alone conveys no authority.
type Sessions struct {
	mutex   sync.Mutex
	root    *os.Root
	now     func() time.Time
	current *observation
	closed  bool
}

func NewSessions(root *os.Root, now func() time.Time) *Sessions {
	if now == nil {
		now = time.Now
	}
	return &Sessions{root: root, now: now}
}
func validBinding(b Binding) bool {
	return sessionID.MatchString(b.MemberID) && sessionID.MatchString(b.MasterID) && b.MemberID != b.MasterID && sessionID.MatchString(b.RelationshipID) && b.Scope == "data"
}
func (s *Sessions) expire() error {
	if s.current != nil && s.current.session.ExpiresAt <= s.now().Unix() {
		e := s.current.scanner.Close()
		s.current = nil
		return e
	}
	return nil
}
func (s *Sessions) Expire() error { s.mutex.Lock(); defer s.mutex.Unlock(); return s.expire() }
func (s *Sessions) Open(ctx context.Context, id string, b Binding) (Session, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if e := ctx.Err(); e != nil {
		return Session{}, e
	}
	if s.closed || !sessionID.MatchString(id) || !validBinding(b) {
		return Session{}, ErrSession
	}
	if e := s.expire(); e != nil {
		return Session{}, e
	}
	if old := s.current; old != nil {
		if old.session.ID == id {
			if old.session.Binding != b || old.closed {
				return Session{}, ErrSession
			}
			return old.session, nil
		}
		if !old.closed && !old.complete {
			return Session{}, ErrBusy
		}
		if e := old.scanner.Close(); e != nil {
			return Session{}, e
		}
		s.current = nil
	}
	scanner, e := New(s.root)
	if e != nil {
		return Session{}, e
	}
	nonce := make([]byte, 16)
	if _, e = rand.Read(nonce); e != nil {
		scanner.Close()
		return Session{}, e
	}
	now := s.now()
	session := Session{ID: id, Incarnation: hex.EncodeToString(nonce), Binding: b, CreatedAt: now.Unix(), ExpiresAt: now.Add(SessionTTL).Unix()}
	s.current = &observation{session: session, scanner: scanner}
	return session, nil
}
func (s *Sessions) bound(id, incarnation string, b Binding) (*observation, error) {
	if s.closed || !sessionID.MatchString(id) || !sessionID.MatchString(incarnation) || !validBinding(b) {
		return nil, ErrSession
	}
	if e := s.expire(); e != nil {
		return nil, e
	}
	o := s.current
	if o == nil || o.session.ID != id || o.session.Incarnation != incarnation || o.session.Binding != b {
		return nil, ErrSession
	}
	return o, nil
}
func (s *Sessions) Page(ctx context.Context, id, incarnation string, b Binding, sequence uint64) (SessionPage, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if e := ctx.Err(); e != nil {
		return SessionPage{}, e
	}
	o, e := s.bound(id, incarnation, b)
	if e != nil {
		return SessionPage{}, e
	}
	if o.closed {
		return SessionPage{}, ErrSession
	}
	page, e := o.scanner.Next(ctx, sequence)
	if e != nil {
		// An invalid sequence does not consume the next page. Disk/cancellation
		// failures invalidate the observation and free its bounded handles.
		if !errors.Is(e, ErrSequence) {
			o.closed = true
			o.scanner.Close()
		}
		return SessionPage{}, e
	}
	// Expiry during disk work must not return a newly successful observation.
	if o.session.ExpiresAt <= s.now().Unix() {
		o.closed = true
		o.scanner.Close()
		return SessionPage{}, ErrSession
	}
	o.complete = page.Complete
	return SessionPage{o.session, page}, nil
}
func (s *Sessions) Cancel(id, incarnation string, b Binding) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	o, e := s.bound(id, incarnation, b)
	if e != nil {
		return e
	}
	if o.closed {
		return nil
	}
	o.closed = true
	return o.scanner.Close()
}
func (s *Sessions) Close() error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	if s.current != nil {
		return s.current.scanner.Close()
	}
	return nil
}

func (s *Sessions) Validate(id, incarnation string, b Binding) (Session, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	o, e := s.bound(id, incarnation, b)
	if e != nil {
		return Session{}, e
	}
	if o.closed {
		return Session{}, ErrSession
	}
	return o.session, nil
}
