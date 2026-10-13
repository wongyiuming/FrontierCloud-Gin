package operator

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/noderetirement"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/resourceinventory"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNodeClientTLSCookieCSRFBoundReportsAndRedirectRefusal(t *testing.T) {
	member, master, rel := strings.Repeat("2", 32), strings.Repeat("a", 32), strings.Repeat("1", 32)
	mode := "complete"
	authenticated := false
	checked := 0
	logout := 0
	report := noderetirement.Report{MemberID: member, PreflightOnly: true, ObservationComplete: true, Concerns: []noderetirement.Concern{{Code: "backup_retention_required", Count: 1, Samples: []string{"backup"}}}, Master: store.RetirementLedger{MemberID: member, RelationshipID: rel, Role: "Master"}, Peer: store.RetirementLedger{MemberID: member, RelationshipID: rel, Role: "Follower"}}
	for _, scope := range []string{"data", "media", "recordings"} {
		report.Volumes = append(report.Volumes, noderetirement.VolumeReport{Volume: resourceinventory.Volume{Scope: scope}, ObservationSHA256: strings.Repeat("0", 64)})
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil {
			t.Error("plaintext request")
		}
		switch r.URL.Path {
		case "/api/v1/media/admin/elevate":
			r.ParseForm()
			if r.PostForm.Get("token") != "private-fixture-token" {
				t.Error("credential input")
			}
			http.SetCookie(w, &http.Cookie{Name: "custom_session", Value: "session", Path: "/", Secure: true, HttpOnly: true})
			http.SetCookie(w, &http.Cookie{Name: "custom_csrf", Value: "csrf", Path: "/", Secure: true})
			fmt.Fprint(w, `{"status":"ok"}`)
			return
		}
		cookie, e := r.Cookie("custom_session")
		if e != nil || cookie.Value != "session" {
			t.Error("missing in-memory session")
			w.WriteHeader(401)
			return
		}
		authenticated = true
		if r.Method == "POST" && r.Header.Get("X-CSRF-Token") != "csrf" {
			t.Error("missing CSRF")
			w.WriteHeader(403)
			return
		}
		switch r.URL.Path {
		case "/api/v1/media/admin/status":
			fmt.Fprint(w, `{"session":true,"csrf_cookie_name":"custom_csrf"}`)
		case "/api/v1/media/admin/nodes":
			relationships := []map[string]string{{"relationship_id": rel, "peer_id": member, "state": "active", "direction": "downstream"}}
			if mode == "ambiguous" {
				relationships = append(relationships, relationships[0])
			}
			json.NewEncoder(w).Encode(map[string]any{"node_id": master, "role": "Master", "relationships": relationships})
		case "/api/v1/media/admin/nodes/" + rel + "/retire/check":
			checked++
			var body map[string]string
			json.NewDecoder(r.Body).Decode(&body)
			if body["member_id"] != member || r.Method != "POST" {
				t.Error("incorrect retirement authority")
			}
			value := report
			switch mode {
			case "volumes":
				value.Volumes = nil
			case "foreign":
				value.MemberID = master
			case "oversized":
				fmt.Fprint(w, `{"padding":"`+strings.Repeat("x", nodeResponseBytes)+`"}`)
				return
			case "samples":
				value.Concerns = []noderetirement.Concern{{Code: "unknown", Count: 1, Samples: make([]string, 9)}}
			case "incomplete":
				w.WriteHeader(409)
				json.NewEncoder(w).Encode(map[string]any{"report": value})
				return
			}
			json.NewEncoder(w).Encode(value)
		case "/api/v1/media/admin/logout":
			logout++
			fmt.Fprint(w, `{"status":"ok"}`)
		default:
			t.Error("unexpected API", r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	client, e := NewNodeClient(server.URL)
	if e != nil {
		t.Fatal(e)
	}
	client.client.Transport = server.Client().Transport
	if e = client.Login(context.Background(), "private-fixture-token"); e != nil {
		t.Fatal(e)
	}
	result, e := client.RetirementCheck(context.Background(), member)
	if e != nil || !result.ObservationComplete || !authenticated || checked != 1 || len(result.Concerns) != 1 {
		t.Fatal("check", result, e)
	}
	for _, fault := range []string{"volumes", "ambiguous", "foreign", "samples", "oversized", "incomplete"} {
		mode = fault
		result, e = client.RetirementCheck(context.Background(), member)
		if e == nil || result.ObservationComplete {
			t.Fatal("unsafe response", fault, result, e)
		}
		if fault == "incomplete" && result.MemberID != member {
			t.Fatal("lost bounded partial report")
		}
	}
	client.Close()
	if logout != 1 {
		t.Fatal("session not logged out", logout)
	}
	hits := 0
	other := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits++ }))
	defer other.Close()
	redirect := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, other.URL, 307) }))
	defer redirect.Close()
	client, e = NewNodeClient(redirect.URL)
	if e != nil {
		t.Fatal(e)
	}
	client.client.Transport = redirect.Client().Transport
	defer client.Close()
	if e = client.Login(context.Background(), "private-fixture-token"); e == nil || hits != 0 {
		t.Fatal("credential redirect followed", hits, e)
	}
	untrusted, _ := NewNodeClient(server.URL)
	defer untrusted.Close()
	if e = untrusted.Login(context.Background(), "private-fixture-token"); e == nil || strings.Contains(e.Error(), "private-fixture-token") {
		t.Fatal("TLS trust bypass or credential error leak", e)
	}
}
func TestNodeClientRejectsCredentialURLsAndNonOrigins(t *testing.T) {
	for _, origin := range []string{"http://master.test", "https://user:secret@master.test", "https://master.test/path", "https://master.test?secret=value", "https://master.test#private", "https:///missing"} {
		if _, e := NewNodeClient(origin); e == nil || strings.Contains(e.Error(), "secret") {
			t.Fatal("unsafe origin accepted or echoed", origin, e)
		}
	}
}
