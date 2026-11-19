package admin

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func handoffBinding() HandoffBinding {
	return HandoffBinding{AdminOrigin: "https://master.test", PublicOrigin: "https://entry.test", IngressID: strings.Repeat("a", 32), Generation: 7}
}

func TestHandoffRequiresRegisteredFlowCookieAndCurrentBinding(t *testing.T) {
	cache := newCache()
	s, _, key := fixture(t, cache)
	ctx := context.Background()
	binding := handoffBinding()
	cookie, challenge, err := s.BeginHandoff(context.Background(), binding, RequestInfo{IP: "192.0.2.1"})
	if err != nil {
		t.Fatal(err)
	}
	forged, _ := randomToken(32)
	if _, err := s.AuthorizeHandoff(ctx, binding, forged, key, RequestInfo{IP: "192.0.2.1"}); err == nil {
		t.Fatal("unregistered browser challenge authorized")
	}
	wrong := binding
	wrong.Generation++
	if _, err := s.AuthorizeHandoff(ctx, wrong, challenge, key, RequestInfo{IP: "192.0.2.1"}); err == nil {
		t.Fatal("different ingress generation authorized")
	}
	ticket, err := s.AuthorizeHandoff(ctx, binding, challenge, key, RequestInfo{IP: "192.0.2.1"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AuthorizeHandoff(ctx, binding, challenge, key, RequestInfo{IP: "192.0.2.1"}); err == nil {
		t.Fatal("challenge replay accepted")
	}
	wrongCookie, _ := randomToken(32)
	if _, err := s.RedeemHandoff(ctx, binding, ticket, wrongCookie); err == nil {
		t.Fatal("other browser redeemed ticket")
	}
	if _, err := s.RedeemHandoff(ctx, wrong, ticket, cookie); err == nil {
		t.Fatal("stale ingress redeemed ticket")
	}
	wrong = binding
	wrong.AdminOrigin = "https://other.test"
	if _, err := s.RedeemHandoff(ctx, wrong, ticket, cookie); err == nil {
		t.Fatal("other management origin redeemed ticket")
	}
	session, err := s.RedeemHandoff(ctx, binding, ticket, cookie)
	if err != nil || session.Cookie == "" || session.CSRF == "" {
		t.Fatal("valid flow rejected", err)
	}
	if _, err := s.RedeemHandoff(ctx, binding, ticket, cookie); err == nil {
		t.Fatal("ticket replay accepted")
	}
	if _, err := s.Authenticate(ctx, session.Cookie, session.CSRF, session.CSRF, "POST", "passive"); err != nil {
		t.Fatal(err)
	}
}

func TestHandoffConcurrentAuthorizationAndCancel(t *testing.T) {
	cache := newCache()
	s, _, key := fixture(t, cache)
	binding := handoffBinding()
	_, challenge, err := s.BeginHandoff(context.Background(), binding, RequestInfo{IP: "192.0.2.1"})
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	results := make(chan string, 16)
	for i := 0; i < cap(results); i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ticket, err := s.AuthorizeHandoff(context.Background(), binding, challenge, key, RequestInfo{IP: "192.0.2.2"})
			if err == nil {
				results <- ticket
			}
		}()
	}
	wg.Wait()
	close(results)
	var tickets []string
	for ticket := range results {
		tickets = append(tickets, ticket)
	}
	if len(tickets) != 1 {
		t.Fatalf("issued %d tickets", len(tickets))
	}
	s.handoffMu.Lock()
	grant := s.handoffGrants[hash(tickets[0])]
	s.handoffMu.Unlock()
	s.CancelHandoff(tickets[0])
	s.CancelHandoff(tickets[0])
	if value, err := cache.Session(context.Background(), "admin:session:"+grant.Session.Hash); err != nil || len(value) != 0 {
		t.Fatalf("cancel retained session: %v %v", value, err)
	}
}

func TestHandoffExpiresAndHonorsKeyRotation(t *testing.T) {
	cache := newCache()
	s, _, key := fixture(t, cache)
	ctx := context.Background()
	binding := handoffBinding()
	cookie, challenge, err := s.BeginHandoff(context.Background(), binding, RequestInfo{IP: "192.0.2.1"})
	if err != nil {
		t.Fatal(err)
	}
	s.handoffMu.Lock()
	expired := s.handoffFlows[hash(challenge)]
	expired.Expires = time.Now().Add(-time.Second)
	s.handoffFlows[hash(challenge)] = expired
	s.handoffMu.Unlock()
	if _, err := s.AuthorizeHandoff(ctx, binding, challenge, key, RequestInfo{IP: "192.0.2.3"}); err == nil {
		t.Fatal("expired flow accepted")
	}
	cookie, challenge, err = s.BeginHandoff(context.Background(), binding, RequestInfo{IP: "192.0.2.1"})
	if err != nil {
		t.Fatal(err)
	}
	ticket, err := s.AuthorizeHandoff(ctx, binding, challenge, key, RequestInfo{IP: "192.0.2.3"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.settings.SecretsDirectory, "admin_key"), []byte("rotated-admin-key"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RedeemHandoff(ctx, binding, ticket, cookie); err == nil {
		t.Fatal("rotated key did not revoke handoff")
	}
}

func TestHandoffRejectsInvalidBindingAndExpiredTicket(t *testing.T) {
	cache := newCache()
	s, _, key := fixture(t, cache)
	binding := handoffBinding()
	for _, bad := range []HandoffBinding{
		{AdminOrigin: "http://master.test", PublicOrigin: binding.PublicOrigin, IngressID: binding.IngressID, Generation: 1},
		{AdminOrigin: binding.AdminOrigin, PublicOrigin: "https://entry.test/path", IngressID: binding.IngressID, Generation: 1},
		{AdminOrigin: binding.AdminOrigin, PublicOrigin: binding.PublicOrigin, IngressID: binding.IngressID, Generation: 0},
	} {
		if _, _, err := s.BeginHandoff(context.Background(), bad, RequestInfo{IP: "192.0.2.1"}); err == nil {
			t.Fatal("invalid binding accepted", bad)
		}
	}
	cookie, challenge, err := s.BeginHandoff(context.Background(), binding, RequestInfo{IP: "192.0.2.1"})
	if err != nil {
		t.Fatal(err)
	}
	ticket, err := s.AuthorizeHandoff(context.Background(), binding, challenge, key, RequestInfo{IP: "192.0.2.4"})
	if err != nil {
		t.Fatal(err)
	}
	s.handoffMu.Lock()
	grant := s.handoffGrants[hash(ticket)]
	grant.Expires = time.Now().Add(-time.Second)
	s.handoffGrants[hash(ticket)] = grant
	s.handoffMu.Unlock()
	if _, err := s.RedeemHandoff(context.Background(), binding, ticket, cookie); err == nil {
		t.Fatal("expired ticket redeemed")
	}
	s.CancelHandoff(ticket)
	if value, err := cache.Session(context.Background(), "admin:session:"+grant.Session.Hash); err != nil || len(value) != 0 {
		t.Fatalf("expired grant retained a session: %v %v", value, err)
	}
}

func TestHandoffStartIsBoundedAndRateLimited(t *testing.T) {
	s, _, _ := fixture(t, newCache())
	ctx := context.Background()
	for i := 0; i < 12; i++ {
		_, challenge, err := s.BeginHandoff(ctx, handoffBinding(), RequestInfo{IP: "192.0.2.10"})
		if err != nil {
			t.Fatal(err)
		}
		s.CancelHandoffFlow(challenge)
	}
	if _, _, err := s.BeginHandoff(ctx, handoffBinding(), RequestInfo{IP: "192.0.2.10"}); err == nil {
		t.Fatal("per-client limit bypassed")
	}
	s.handoffMu.Lock()
	s.handoffPending = maxHandoffEntries
	s.handoffMu.Unlock()
	if _, _, err := s.BeginHandoff(ctx, handoffBinding(), RequestInfo{IP: "192.0.2.11"}); err == nil {
		t.Fatal("global admission limit bypassed")
	}
}
