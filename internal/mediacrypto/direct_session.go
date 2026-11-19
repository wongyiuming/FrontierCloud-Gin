package mediacrypto

import "context"

type directSessionKey struct{}

// DirectSessionAuthority is request-local proof that a public browser's
// existing crypto session was checked. It contains no wrapping or file key.
type DirectSessionAuthority struct {
	manager  *Manager
	binding  string
	id       string
	identity *sessionIdentity
	expires  int64
}

func (m *Manager) WithDirectSession(ctx context.Context, binding, id string) (context.Context, error) {
	if m == nil || ctx == nil || binding == "" || id == "" || ctx.Err() != nil {
		return nil, ErrSession
	}
	m.mu.Lock()
	s, ok := m.sessions[id]
	if !ok || s.binding != binding || !s.expires.After(m.now()) {
		m.mu.Unlock()
		return nil, ErrSession
	}
	a := &DirectSessionAuthority{manager: m, binding: binding, id: id, identity: s.identity, expires: s.expires.Unix()}
	m.mu.Unlock()
	return context.WithValue(ctx, directSessionKey{}, a), nil
}

func (a *DirectSessionAuthority) Values() (binding, id string, expires int64, valid bool) {
	if a == nil || a.manager == nil {
		return "", "", 0, false
	}
	m := a.manager
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[a.id]
	if !ok || s.identity != a.identity || s.binding != a.binding || !s.expires.After(m.now()) || s.expires.Unix() != a.expires {
		return "", "", 0, false
	}
	return a.binding, a.id, a.expires, true
}

func DirectSessionFromContext(ctx context.Context) *DirectSessionAuthority {
	if ctx == nil {
		return nil
	}
	a, _ := ctx.Value(directSessionKey{}).(*DirectSessionAuthority)
	return a
}

// CheckDirectSession rechecks revocation and the original session deadline
// before admitting a direct resource read; it never extends that deadline.
func (m *Manager) CheckDirectSession(id string) bool {
	if m == nil || id == "" {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[id]
	return ok && s.expires.After(m.now())
}
