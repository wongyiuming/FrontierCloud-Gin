package noderetirement

import (
	"github.com/wongyiuming/FrontierCloud-Gin/internal/resourceinventory"
	"strings"
	"testing"
	"time"
)

func TestRenewalRejectsChangedAuthorityAndUnboundedExpiry(t *testing.T) {
	now := time.Unix(1000, 0)
	old := resourceinventory.Session{ID: strings.Repeat("a", 32), Incarnation: strings.Repeat("b", 32), Binding: resourceinventory.Binding{MemberID: strings.Repeat("c", 32)}, CreatedAt: 800, ExpiresAt: 1100}
	renewed := old
	renewed.ExpiresAt = 1300
	if e := acceptSessionRenewal(old, renewed, now); e != nil {
		t.Fatal(e)
	}
	for _, change := range []func(*resourceinventory.Session){func(s *resourceinventory.Session) { s.ID = "other" }, func(s *resourceinventory.Session) { s.Incarnation = "other" }, func(s *resourceinventory.Session) { s.Binding.MasterID = "other" }, func(s *resourceinventory.Session) { s.CreatedAt++ }, func(s *resourceinventory.Session) { s.ExpiresAt = 1000 }, func(s *resourceinventory.Session) { s.ExpiresAt = 1301 }} {
		wrong := renewed
		change(&wrong)
		if e := acceptSessionRenewal(old, wrong, now); e == nil {
			t.Fatal("invalid renewal accepted", wrong)
		}
	}
}
