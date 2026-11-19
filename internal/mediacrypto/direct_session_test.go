package mediacrypto

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"testing"
	"time"
)

func TestDirectSessionAuthorityRetainsOriginalDeadlineAndRevocation(t *testing.T) {
	m, err := New(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	m.now = func() time.Time { return now }
	client, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := m.NewSession("browser:test", base64.StdEncoding.EncodeToString(client.PublicKey().Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = m.WithDirectSession(context.Background(), "browser:other", grant.SessionID); !errors.Is(err, ErrSession) {
		t.Fatal("wrong binding accepted", err)
	}
	ctx, err := m.WithDirectSession(context.Background(), "browser:test", grant.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	a := DirectSessionFromContext(ctx)
	_, id, deadline, valid := a.Values()
	if !valid || id != grant.SessionID || deadline != grant.ExpiresAt || !m.CheckDirectSession(id) {
		t.Fatal("incorrect session authority")
	}
	now = now.Add(SessionLifetime)
	if _, _, _, valid := a.Values(); valid || m.CheckDirectSession(id) {
		t.Fatal("expired session extended")
	}
	now = time.Unix(1_800_000_000, 0)
	m.RevokeBinding("browser:test")
	if _, _, _, valid := a.Values(); valid || m.CheckDirectSession(id) {
		t.Fatal("revoked session remained valid")
	}
}
