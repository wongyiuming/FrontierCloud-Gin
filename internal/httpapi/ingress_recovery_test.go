package httpapi

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

type recoveryHTTPTestControl struct {
	calls int
	actor string
}

func (*recoveryHTTPTestControl) Active() bool { return true }
func (*recoveryHTTPTestControl) Status(context.Context) (string, store.PublicIngress, error) {
	return "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", store.PublicIngress{NodeID: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", Generation: 3}, nil
}
func (f *recoveryHTTPTestControl) Restore(_ context.Context, id string, generation int64, audit store.NodeAudit) (store.PublicIngress, error) {
	f.calls++
	f.actor = audit.Actor
	if id != "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" || generation != 3 {
		return store.PublicIngress{}, store.ErrNodeState
	}
	return store.PublicIngress{NodeID: id, Generation: 4}, nil
}
func TestIngressRecoveryUsesActualAdminAuthentication(t *testing.T) {
	f := newS3HTTP(t, "Master")
	f.admin.settings.AdminOrigin = "https://master.example"
	control := &recoveryHTTPTestControl{}
	RegisterIngressRecovery(f.router, f.admin, control)
	state := "/api/v1/media/admin/ingress-recovery/state"
	restore := "/api/v1/media/admin/ingress-recovery/restore"
	if got := f.call("GET", state, "", false, false, true); got.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous state: %d", got.Code)
	}
	if got := f.call("GET", state, "", true, false, true); got.Code != http.StatusOK {
		t.Fatalf("authenticated state: %d %s", got.Code, got.Body.String())
	}
	if got := f.call("POST", restore, `{"member_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","generation":3}`, true, false, true); got.Code != http.StatusForbidden {
		t.Fatalf("missing CSRF: %d", got.Code)
	}
	if control.calls != 0 {
		t.Fatal("missing CSRF reached control")
	}
	for _, body := range []string{`{"member_id":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","generation":3}`, `{"member_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","generation":2}`} {
		got := f.call("POST", restore, body, true, true, true)
		if got.Code != http.StatusConflict {
			t.Fatalf("%s: %d %s", body, got.Code, got.Body.String())
		}
	}
	got := f.call("POST", restore, `{"member_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","generation":3}`, true, true, true)
	if got.Code != http.StatusOK || control.actor == "" {
		t.Fatal(fmt.Sprintf("restore: %d actor=%q %s", got.Code, control.actor, got.Body.String()))
	}
}
