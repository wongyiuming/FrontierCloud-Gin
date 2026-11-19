package mediacrypto

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func sessionAdmissionKey(t *testing.T) string {
	t.Helper()
	client, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(client.PublicKey().Bytes())
}

func TestSessionAdmissionIsolatesBindingsAndAdminCapacityWithoutEviction(t *testing.T) {
	m, _ := New(bytes.Repeat([]byte{1}, 32))
	m.limits = sessionLimits{public: 4, admin: 2, binding: 2}
	now := time.Unix(1800000000, 0)
	m.now = func() time.Time { return now }
	key := sessionAdmissionKey(t)
	first, err := m.NewSession("browser:attacker", key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = m.NewSession("browser:attacker", key); err != nil {
		t.Fatal(err)
	}
	for range 10 {
		if _, err = m.NewSession("browser:attacker", key); !errors.Is(err, ErrSessionLimit) {
			t.Fatal("one binding filled shared capacity", err)
		}
	}
	for range 2 {
		if _, err = m.NewSession("browser:other", key); err != nil {
			t.Fatal("another browser denied", err)
		}
	}
	if _, err = m.NewSession("browser:new", key); !errors.Is(err, ErrSessionLimit) {
		t.Fatal("public exceeded partition", err)
	}
	admin, err := m.NewSession("admin:owner", key)
	if err != nil {
		t.Fatal("public exhausted Admin capacity", err)
	}
	if _, err = m.NewSession("admin:other", key); err != nil {
		t.Fatal(err)
	}
	if _, err = m.NewSession("admin:new", key); !errors.Is(err, ErrSessionLimit) {
		t.Fatal("Admin exceeded partition", err)
	}
	metadata, _ := NewMetadata(25)
	now = now.Add(14 * time.Minute)
	for _, grant := range []struct {
		binding string
		id      string
		expires int64
	}{
		{"browser:attacker", first.SessionID, first.ExpiresAt}, {"admin:owner", admin.SessionID, admin.ExpiresAt},
	} {
		for range 3 {
			envelope, e := m.Wrap(grant.binding, grant.id, metadata)
			if e != nil || envelope.ExpiresAt != grant.expires {
				t.Fatal("capacity rejected or renewed existing authorization", e)
			}
		}
	}
	now = time.Unix(first.ExpiresAt, 0)
	if _, err = m.NewSession("browser:new", key); err != nil {
		t.Fatal("expired capacity not reclaimed", err)
	}
	if len(m.sessions) != 1 {
		t.Fatal("expired authorizations retained", len(m.sessions))
	}
	if _, err = m.Wrap("browser:attacker", first.SessionID, metadata); !errors.Is(err, ErrSession) {
		t.Fatal("expired key reused", err)
	}
}

func TestSessionAdmissionConcurrentHandshakesCannotOverfillBinding(t *testing.T) {
	m, _ := New(bytes.Repeat([]byte{2}, 32))
	m.limits = sessionLimits{public: 4, admin: 2, binding: 2}
	key := sessionAdmissionKey(t)
	var accepted atomic.Int32
	var wg sync.WaitGroup
	for range 24 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := m.NewSession("browser:shared", key)
			if err == nil {
				accepted.Add(1)
			} else if !errors.Is(err, ErrSessionLimit) {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if accepted.Load() != 2 || len(m.sessions) != 2 {
		t.Fatal("concurrent admission escaped limit", accepted.Load(), len(m.sessions))
	}
}

func TestSessionAbortReclaimsOnlyItsOwnAdmission(t *testing.T) {
	m, _ := New(bytes.Repeat([]byte{3}, 32))
	m.limits = sessionLimits{public: 4, admin: 2, binding: 2}
	key := sessionAdmissionKey(t)
	first, err := m.NewSession("browser:shared", key)
	if err != nil {
		t.Fatal(err)
	}
	failed, abort, err := m.NewSessionWithAbort("browser:shared", key)
	if err != nil || abort == nil {
		t.Fatal("could not create rollback-capable session", err)
	}
	other, err := m.NewSession("browser:other", key)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = m.NewSessionWithAbort("browser:shared", key); !errors.Is(err, ErrSessionLimit) {
		t.Fatal("binding limit was not enforced", err)
	}

	abort()
	abort() // Rollback can safely be invoked more than once.
	meta, _ := NewMetadata(25)
	if _, err = m.Wrap("browser:shared", failed.SessionID, meta); !errors.Is(err, ErrSession) {
		t.Fatal("aborted session remained usable", err)
	}
	for _, grant := range []struct{ binding, id string }{
		{"browser:shared", first.SessionID}, {"browser:other", other.SessionID},
	} {
		if _, err = m.Wrap(grant.binding, grant.id, meta); err != nil {
			t.Fatal("abort revoked a different session", err)
		}
	}
	if _, err = m.NewSession("browser:shared", key); err != nil {
		t.Fatal("aborted session retained quota", err)
	}
}

func TestStaleSessionAbortCannotRevokeReusedID(t *testing.T) {
	m, _ := New(bytes.Repeat([]byte{4}, 32))
	key := sessionAdmissionKey(t)
	old, abort, err := m.NewSessionWithAbort("browser:shared", key)
	if err != nil {
		t.Fatal(err)
	}
	m.RevokeBinding("browser:shared")
	replacement, err := m.NewSession("browser:shared", key)
	if err != nil {
		t.Fatal(err)
	}
	// Model a later random ID reuse. The old callback must still refer only to
	// its original admission, even with the same ID and browser binding.
	m.mu.Lock()
	m.sessions[old.SessionID] = m.sessions[replacement.SessionID]
	delete(m.sessions, replacement.SessionID)
	m.mu.Unlock()
	abort()
	meta, _ := NewMetadata(25)
	if _, err = m.Wrap("browser:shared", old.SessionID, meta); err != nil {
		t.Fatal("stale callback revoked a later admission", err)
	}
}

func TestSessionAbortNotReturnedOnFailedAdmission(t *testing.T) {
	m, _ := New(bytes.Repeat([]byte{5}, 32))
	if _, abort, err := m.NewSessionWithAbort("browser:shared", "invalid-key"); err == nil || abort != nil {
		t.Fatal("failed admission returned a rollback callback", err)
	}
}
