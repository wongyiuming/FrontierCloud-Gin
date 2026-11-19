package node

import (
	"bytes"
	"context"
	"fmt"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"net/http"
	"testing"
	"time"
)

func TestRetirementTransportAdmitsLongResponseAndHonorsCallerCancellation(t *testing.T) {
	server, roots := privateCA(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
			return
		case <-time.After(100 * time.Millisecond):
		}
		fmt.Fprint(w, `{"complete":true}`)
	}))
	transport := testTransport(t, server, roots)
	transport.client.Timeout = 20 * time.Millisecond
	relation := "11111111111111111111111111111111"
	credential := protocol.Encode(bytes.Repeat([]byte{8}, 48))
	if _, e := transport.Request(context.Background(), "https://node.test", "/internal/v1/heartbeat", "POST", map[string]string{}, relation, credential); e == nil {
		t.Fatal("control timeout removed")
	}
	if transport.retirement.Timeout != 0 || transport.retirement.Transport.(*http.Transport).ResponseHeaderTimeout != 0 {
		t.Fatal("retirement still inherits short response timeout")
	}
	if _, e := transport.Request(context.Background(), "https://node.test", "/internal/v1/retirement", "POST", map[string]string{"action": "complete"}, relation, credential); e != nil {
		t.Fatal("retirement response cut short", e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if _, e := transport.Request(ctx, "https://node.test", "/internal/v1/retirement", "POST", map[string]string{"action": "complete"}, relation, credential); e == nil || ctx.Err() == nil {
		t.Fatal("caller cancellation ignored", e)
	}
}

func TestOpaqueDeleteTransportAdmitsLongResponseAndKeepsOtherControlBounded(t *testing.T) {
	server, roots := privateCA(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
			return
		case <-time.After(100 * time.Millisecond):
		}
		fmt.Fprint(w, `{"deleted":true}`)
	}))
	transport := testTransport(t, server, roots)
	transport.client.Timeout = 20 * time.Millisecond
	relation := "11111111111111111111111111111111"
	credential := protocol.Encode(bytes.Repeat([]byte{8}, 48))
	const origin = "https://node.test"
	for _, request := range []struct {
		route  string
		method string
	}{
		{"/internal/v1/heartbeat", http.MethodPost},
		{protocol.OpaqueRevokePath, http.MethodPost},
		{protocol.OpaqueDeletePath, http.MethodGet},
		{protocol.OpaqueDeletePath + "?extra=true", http.MethodPost},
	} {
		if _, err := transport.Request(context.Background(), origin, request.route, request.method, nil, relation, credential); err == nil {
			t.Fatalf("short control timeout lost for %s %s", request.method, request.route)
		}
	}
	if _, err := transport.Request(context.Background(), origin, protocol.OpaqueDeletePath, http.MethodPost, nil, relation, credential); err != nil {
		t.Fatal("valid delete response cut short", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := transport.Request(ctx, origin, protocol.OpaqueDeletePath, http.MethodPost, nil, relation, credential); err == nil || ctx.Err() == nil {
		t.Fatal("delete ignored the shorter caller deadline", err)
	}
}
