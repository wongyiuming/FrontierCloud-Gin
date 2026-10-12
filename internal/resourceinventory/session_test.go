package resourceinventory

import (
	"context"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestSessionsBindIdentityLimitExpiryAndRestartIncarnation(t *testing.T) {
	_, root, _ := inventoryFixture(t)
	for i := 0; i < PageEntries+10; i++ {
		f, e := root.OpenFile(fmt.Sprintf("%03d", i), os.O_CREATE|os.O_WRONLY, 0600)
		if e != nil {
			t.Fatal(e)
		}
		f.Close()
	}
	clock := time.Unix(1000, 0)
	manager := NewSessions(root, func() time.Time { return clock })
	defer manager.Close()
	binding := Binding{MemberID: strings.Repeat("a", 32), MasterID: strings.Repeat("b", 32), RelationshipID: strings.Repeat("c", 32), Scope: "data"}
	id := strings.Repeat("d", 32)
	opened, e := manager.Open(context.Background(), id, binding)
	if e != nil {
		t.Fatal(e)
	}
	if opened.ExpiresAt != clock.Add(SessionTTL).Unix() || len(opened.Incarnation) != 32 {
		t.Fatal(opened)
	}
	clock = clock.Add(time.Minute)
	replay, e := manager.Open(context.Background(), id, binding)
	if e != nil || replay != opened {
		t.Fatal("open retry extended/replaced observation", replay, e)
	}
	if _, e = manager.Open(context.Background(), strings.Repeat("e", 32), binding); !errors.Is(e, ErrBusy) {
		t.Fatal("unbounded scanners", e)
	}
	wrong := binding
	wrong.RelationshipID = strings.Repeat("e", 32)
	if _, e = manager.Open(context.Background(), id, wrong); !errors.Is(e, ErrSession) {
		t.Fatal("foreign binding replaced observation", e)
	}
	if _, e = manager.Page(context.Background(), id, opened.Incarnation, wrong, 0); !errors.Is(e, ErrSession) {
		t.Fatal("foreign relation read cache", e)
	}
	if _, e = manager.Page(context.Background(), id, strings.Repeat("f", 32), binding, 0); !errors.Is(e, ErrSession) {
		t.Fatal("foreign incarnation", e)
	}
	page, e := manager.Page(context.Background(), id, opened.Incarnation, binding, 0)
	if e != nil || page.Page.Complete {
		t.Fatal(page, e)
	}
	same, e := manager.Page(context.Background(), id, opened.Incarnation, binding, 0)
	if e != nil || !reflect.DeepEqual(page, same) {
		t.Fatal("lost page acknowledgment", e)
	}
	if _, e = manager.Page(context.Background(), id, opened.Incarnation, binding, 2); !errors.Is(e, ErrSequence) {
		t.Fatal("skipped sequence", e)
	}
	restarted := NewSessions(root, func() time.Time { return clock })
	defer restarted.Close()
	fresh, e := restarted.Open(context.Background(), id, binding)
	if e != nil || fresh.Incarnation == opened.Incarnation {
		t.Fatal("restart adopted incarnation", fresh, e)
	}
	if _, e = restarted.Page(context.Background(), id, opened.Incarnation, binding, 0); !errors.Is(e, ErrSession) {
		t.Fatal("stale cursor crossed restart", e)
	}
	clock = time.Unix(opened.ExpiresAt, 0)
	if e = manager.Expire(); e != nil {
		t.Fatal(e)
	}
	if _, e = manager.Page(context.Background(), id, opened.Incarnation, binding, 1); !errors.Is(e, ErrSession) {
		t.Fatal("expired cache", e)
	}
	fresh, e = manager.Open(context.Background(), id, binding)
	if e != nil || fresh.Incarnation == opened.Incarnation {
		t.Fatal("expired observation revived", fresh, e)
	}
	for range 2 {
		if e = manager.Cancel(id, fresh.Incarnation, binding); e != nil {
			t.Fatal("close acknowledgment replay", e)
		}
	}
	if _, e = manager.Page(context.Background(), id, fresh.Incarnation, binding, 0); !errors.Is(e, ErrSession) {
		t.Fatal("cancelled observation reopened", e)
	}
	if _, e = manager.Open(context.Background(), strings.Repeat("e", 32), binding); e != nil {
		t.Fatal("closed scanner retained capacity", e)
	}
	if e = manager.Close(); e != nil {
		t.Fatal(e)
	}
	if _, e = root.Lstat("."); e != nil {
		t.Fatal("manager closed borrowed root", e)
	}
}
