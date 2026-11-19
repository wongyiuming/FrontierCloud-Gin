package httpapi

import (
	"context"
	"strings"
	"testing"
)

type legacyAdminFixture struct{ calls int }

func (f *legacyAdminFixture) EnrollLegacyReads(context.Context, string) (string, error) {
	f.calls++
	return "active", nil
}
func (f *legacyAdminFixture) DrainLegacyReads(context.Context, string) (string, error) {
	f.calls++
	return "revoked", nil
}
func (f *legacyAdminFixture) ObserveLegacyReads(context.Context, string) (string, error) {
	f.calls++
	return "draining", nil
}
func (f *legacyAdminFixture) ResumeLegacyReads(context.Context, string) (string, error) {
	f.calls++
	return "revoked", nil
}

func TestLegacyReadAdminRequiresSessionCSRFAndRejectsCallerRandomness(t *testing.T) {
	f := newS3HTTP(t, "Master")
	coordinator := &legacyAdminFixture{}
	if err := registerLegacyReadAdmin(f.router, f.admin, coordinator); err != nil {
		t.Fatal(err)
	}
	base := "/api/v1/media/admin/legacy-read/"
	id := strings.Repeat("a", 32)
	body := `{"relationship_id":"` + id + `"}`
	for _, test := range []struct {
		name                        string
		authenticated, csrf, secure bool
	}{
		{"no-session", false, true, true}, {"no-csrf", true, false, true}, {"insecure", true, true, false},
	} {
		w := f.call("POST", base+"drain", body, test.authenticated, test.csrf, test.secure)
		if w.Code == 200 || coordinator.calls != 0 {
			t.Fatal(test.name, w.Code)
		}
	}
	for _, extra := range []string{`"operation_id":"` + strings.Repeat("b", 32) + `"`, `"challenge":"` + strings.Repeat("c", 64) + `"`, `"owner_id":"` + strings.Repeat("d", 32) + `"`, `"kind":"revoked"`, `"action":"resume"`} {
		w := f.call("POST", base+"drain", `{"relationship_id":"`+id+`",`+extra+`}`, true, true, true)
		if w.Code != 400 || coordinator.calls != 0 {
			t.Fatal("caller-supplied scope or randomness accepted", w.Code)
		}
	}
	for _, item := range []struct{ endpoint, want string }{{"enroll", "active"}, {"drain", "revoked"}, {"status", "draining"}, {"resume", "revoked"}} {
		w := f.call("POST", base+item.endpoint, body, true, true, true)
		if w.Code != 200 || !strings.Contains(w.Body.String(), `"status":"`+item.want+`"`) || strings.Contains(w.Body.String(), "challenge") || strings.Contains(w.Body.String(), "operation") {
			t.Fatal(item.endpoint, w.Code, w.Body.String())
		}
	}
	if coordinator.calls != 4 {
		t.Fatal("unexpected coordinator calls", coordinator.calls)
	}
}
