package s3media

import (
	"context"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/s3store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func TestSelectedProviderRejectsChangedBucketOrCredentialBeforeNetwork(t *testing.T) {
	service, repo, _, _, _ := serviceFixture(t)
	repo.member.Transport, repo.member.Enabled, repo.member.Writable, repo.member.Health = "S3", 1, 1, "online"
	repo.member.ProbeState, repo.member.ProbeRevision = "ready", repo.member.Revision
	expected := repo.member
	called := false
	use := func(_ context.Context, _ s3store.Provider) error { called = true; return nil }
	if err := service.WithSelectedProvider(context.Background(), expected, use); err != nil || !called {
		t.Fatal("matching provider", err)
	}
	for name, mutate := range map[string]func(*store.S3Member){
		"bucket":     func(v *store.S3Member) { v.Location.Bucket = "different" },
		"revision":   func(v *store.S3Member) { v.Revision++ },
		"credential": func(v *store.S3Member) { v.SealedCredentials += "changed" },
		"unprobed":   func(v *store.S3Member) { v.ProbeState = "unchecked" },
		"disabled":   func(v *store.S3Member) { v.Enabled = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			repo.member = expected
			mutate(&repo.member)
			called = false
			if err := service.WithSelectedProvider(context.Background(), expected, use); err == nil || called {
				t.Fatal("stale S3 member reached provider", err)
			}
		})
	}
}
