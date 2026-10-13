package operator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRetirementApplyClientUsesConfirmedMasterWorkflowAndBoundReceipt(t *testing.T) {
	member, master, relationship := strings.Repeat("2", 32), strings.Repeat("a", 32), strings.Repeat("1", 32)
	state, mode := "active", "success"
	calls := 0
	now := time.Now().Unix()
	receipt := store.RetirementFence{MemberID: member, MasterID: master, RelationshipID: relationship, FencedAt: now, CompletedAt: now}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/media/admin/elevate" {
			http.SetCookie(w, &http.Cookie{Name: "session", Value: "fixture", Path: "/", Secure: true, HttpOnly: true})
			http.SetCookie(w, &http.Cookie{Name: "csrf", Value: "fixture-csrf", Path: "/", Secure: true})
			fmt.Fprint(w, `{"status":"ok"}`)
			return
		}
		if _, e := r.Cookie("session"); e != nil {
			t.Error("missing session")
			w.WriteHeader(401)
			return
		}
		if r.Method == "POST" && r.Header.Get("X-CSRF-Token") != "fixture-csrf" {
			t.Error("missing CSRF")
			w.WriteHeader(403)
			return
		}
		switch r.URL.Path {
		case "/api/v1/media/admin/status":
			fmt.Fprint(w, `{"session":true,"csrf_cookie_name":"csrf"}`)
		case "/api/v1/media/admin/nodes":
			rows := []store.Relationship{{ID: relationship, PeerID: member, Direction: "downstream", State: state}}
			if mode == "ambiguous" {
				rows = append(rows, rows[0])
			}
			json.NewEncoder(w).Encode(map[string]any{"node_id": master, "role": "Master", "relationships": rows})
		case "/api/v1/media/admin/nodes/" + relationship + "/retire/apply":
			calls++
			var body map[string]string
			if r.Method != "POST" || json.NewDecoder(r.Body).Decode(&body) != nil || len(body) != 2 || body["member_id"] != member || body["confirm_member_id"] != member {
				t.Error("bad confirmation payload")
			}
			value := receipt
			if mode == "foreign" {
				value.MasterID = member
			}
			if mode == "future" {
				value.CompletedAt = now + 10000
			}
			if mode == "unfinished" {
				value.CompletedAt = 0
			}
			if mode == "incomplete" || mode == "blocked" {
				value.CompletedAt = 0
				if mode == "blocked" {
					value = store.RetirementFence{}
				}
				w.WriteHeader(409)
				json.NewEncoder(w).Encode(map[string]any{"code": "retirement_incomplete", "fence": value})
				return
			}
			json.NewEncoder(w).Encode(value)
		case "/api/v1/media/admin/logout":
			fmt.Fprint(w, `{"status":"ok"}`)
		default:
			t.Error("unexpected path", r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	client, e := NewNodeClient(server.URL)
	if e != nil {
		t.Fatal(e)
	}
	client.client.Transport = server.Client().Transport
	defer client.Close()
	ctx := context.Background()
	if e = client.Login(ctx, "private-fixture-token"); e != nil {
		t.Fatal(e)
	}
	if _, e = client.RetirementApply(ctx, member, master); !errors.Is(e, ErrNodeAuthority) || calls != 0 {
		t.Fatal("confirmation did not precede authority", e, calls)
	}
	for _, s := range []string{"active", "retiring", "revoked"} {
		state = s
		result, e := client.RetirementApply(ctx, member, member)
		if e != nil || result != receipt {
			t.Fatal("retry state", s, result, e)
		}
	}
	for _, m := range []string{"foreign", "future", "unfinished", "ambiguous"} {
		mode = m
		if _, e = client.RetirementApply(ctx, member, member); e == nil {
			t.Fatal("invalid receipt accepted", m)
		}
	}
	for _, m := range []string{"incomplete", "blocked"} {
		mode = m
		result, e := client.RetirementApply(ctx, member, member)
		if !errors.Is(e, ErrRetirementIncomplete) || result.CompletedAt != 0 || m == "incomplete" && result.FencedAt == 0 {
			t.Fatal("incomplete result lost", m, result, e)
		}
	}
}
