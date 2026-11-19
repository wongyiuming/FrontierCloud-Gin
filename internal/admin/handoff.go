package admin

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
)

const handoffTTL = 60 * time.Second
const maxHandoffEntries = 128

// HandoffBinding must be built from validated Master configuration and the
// currently held ingress lease, never from unauthenticated browser headers.
type HandoffBinding struct {
	AdminOrigin, PublicOrigin, IngressID string
	Generation                           int64
}

type handoffFlow struct {
	CookieHash string
	Binding    HandoffBinding
	Expires    time.Time
}

type handoffGrant struct {
	CookieHash string
	Binding    HandoffBinding
	Session    Session
	Expires    time.Time
}

func validHandoffOrigin(raw string) bool {
	origin, err := node.Endpoint(raw)
	return err == nil && origin == raw
}

func validHandoffBinding(v HandoffBinding) bool {
	if !validHandoffOrigin(v.AdminOrigin) || !validHandoffOrigin(v.PublicOrigin) || v.Generation < 1 || len(v.IngressID) != 32 {
		return false
	}
	for _, ch := range v.IngressID {
		if !(ch >= '0' && ch <= '9' || ch >= 'a' && ch <= 'f') {
			return false
		}
	}
	return true
}

func handoffTokenValid(value string) bool {
	if len(value) != 43 {
		return false
	}
	for _, ch := range value {
		if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '-' || ch == '_') {
			return false
		}
	}
	return true
}

// BeginHandoff is called only on the Master management origin. The returned
// cookie is host-only and HttpOnly; the independent challenge may be sent to
// the verified public-origin opener. No browser-provided cookie hash is used.
func (s *Service) BeginHandoff(ctx context.Context, binding HandoffBinding, info RequestInfo) (cookie, challenge string, err error) {
	if !validHandoffBinding(binding) {
		return "", "", reject(403, "认证交接不可用")
	}
	if _, err := netip.ParseAddr(info.IP); err != nil {
		return "", "", reject(403, "认证交接不可用")
	}
	attempts, err := s.cache.ReserveAttempt(ctx, "admin:handoff-start:"+hash(info.IP), int(handoffTTL/time.Second))
	if err != nil {
		return "", "", err
	}
	if attempts > 12 {
		return "", "", reject(429, "认证交接请求过于频繁")
	}
	cookie, err = randomToken(32)
	if err != nil {
		return "", "", err
	}
	challenge, err = randomToken(32)
	if err != nil {
		return "", "", err
	}
	key := hash(challenge)
	flow := handoffFlow{CookieHash: hash(cookie), Binding: binding, Expires: time.Now().Add(handoffTTL)}
	s.handoffMu.Lock()
	if len(s.handoffFlows)+len(s.handoffGrants)+s.handoffPending >= maxHandoffEntries {
		s.handoffMu.Unlock()
		return "", "", reject(503, "认证交接繁忙")
	}
	if s.handoffFlows == nil {
		s.handoffFlows = make(map[string]handoffFlow)
	}
	if _, exists := s.handoffFlows[key]; exists {
		s.handoffMu.Unlock()
		return "", "", errors.New("handoff challenge collision")
	}
	s.handoffFlows[key] = flow
	s.handoffMu.Unlock()
	time.AfterFunc(handoffTTL, func() { s.handoffMu.Lock(); delete(s.handoffFlows, key); s.handoffMu.Unlock() })
	return cookie, challenge, nil
}

// CancelHandoffFlow discards an unpublished flow after a failed lease commit.
func (s *Service) CancelHandoffFlow(challenge string) {
	if !handoffTokenValid(challenge) {
		return
	}
	s.handoffMu.Lock()
	delete(s.handoffFlows, hash(challenge))
	s.handoffMu.Unlock()
}

// AuthorizeHandoff accepts only a pre-registered flow matching the verified
// current ingress. Login remains on Master. One challenge permits one attempt.
func (s *Service) AuthorizeHandoff(ctx context.Context, binding HandoffBinding, challenge, adminKey string, info RequestInfo) (string, error) {
	if !validHandoffBinding(binding) || !handoffTokenValid(challenge) {
		return "", reject(403, "认证交接无效")
	}
	flowKey := hash(challenge)
	s.handoffMu.Lock()
	flow, exists := s.handoffFlows[flowKey]
	if !exists || flow.Binding != binding || !time.Now().Before(flow.Expires) {
		s.handoffMu.Unlock()
		return "", reject(403, "认证交接无效")
	}
	delete(s.handoffFlows, flowKey)
	s.handoffPending++
	s.handoffMu.Unlock()
	defer func() { s.handoffMu.Lock(); s.handoffPending--; s.handoffMu.Unlock() }()
	session, err := s.Login(ctx, adminKey, info)
	if err != nil {
		return "", err
	}
	keep := false
	defer func() {
		if !keep {
			s.discardHandoffSession(session)
		}
	}()
	if ctx.Err() != nil || !time.Now().Before(flow.Expires) {
		return "", reject(403, "认证交接已过期")
	}
	ticket, err := randomToken(32)
	if err != nil {
		return "", err
	}
	key := hash(ticket)
	grant := handoffGrant{CookieHash: flow.CookieHash, Binding: binding, Session: session, Expires: flow.Expires}
	s.handoffMu.Lock()
	if s.handoffGrants == nil {
		s.handoffGrants = make(map[string]handoffGrant)
	}
	if _, exists := s.handoffGrants[key]; exists {
		s.handoffMu.Unlock()
		return "", errors.New("handoff ticket collision")
	}
	s.handoffGrants[key] = grant
	s.handoffMu.Unlock()
	keep = true
	time.AfterFunc(time.Until(flow.Expires), func() { s.CancelHandoff(ticket) })
	return ticket, nil
}

func (s *Service) discardHandoffSession(session Session) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = s.cache.Delete(ctx, "admin:session:"+session.Hash)
}

// CancelRedeemedHandoff revokes a consumed session whose entry lease could
// not be committed. It must be called before publishing the session cookie.
func (s *Service) CancelRedeemedHandoff(session Session) {
	s.discardHandoffSession(session)
}

// CancelHandoff discards an unexposed ticket after a failed ingress admission.
func (s *Service) CancelHandoff(ticket string) {
	if !handoffTokenValid(ticket) {
		return
	}
	key := hash(ticket)
	s.handoffMu.Lock()
	grant, exists := s.handoffGrants[key]
	delete(s.handoffGrants, key)
	s.handoffMu.Unlock()
	if exists {
		s.discardHandoffSession(grant.Session)
	}
}

// RedeemHandoff is accepted only on the configured management origin, with the
// original browser's host-only cookie. It never refreshes the session TTL.
func (s *Service) RedeemHandoff(ctx context.Context, binding HandoffBinding, ticket, cookie string) (Session, error) {
	if !validHandoffBinding(binding) || !handoffTokenValid(ticket) || !handoffTokenValid(cookie) {
		return Session{}, reject(403, "认证交接无效")
	}
	key := hash(ticket)
	s.handoffMu.Lock()
	grant, exists := s.handoffGrants[key]
	if !exists || grant.Binding != binding || !equal(grant.CookieHash, hash(cookie)) || !time.Now().Before(grant.Expires) {
		s.handoffMu.Unlock()
		return Session{}, reject(403, "认证交接无效")
	}
	delete(s.handoffGrants, key)
	s.handoffMu.Unlock()
	if _, err := s.Authenticate(ctx, grant.Session.Cookie, "", "", "GET", "passive"); err != nil {
		s.discardHandoffSession(grant.Session)
		return Session{}, err
	}
	return grant.Session, nil
}
