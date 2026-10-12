package business_test

import (
	"context"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"testing"
)

func TestRecoverySampleUsesFileIdentitiesAndExcludesDirectorySortingRows(t *testing.T) {
	db := database(t)
	ctx := context.Background()
	if _, e := db.Nodes().InitializeIdentity(ctx, store.NodeIdentity{ID: "dddddddddddddddddddddddddddddddd", Role: "Standalone", PrivateKey: "isolated-recovery-fixture"}); e != nil {
		t.Fatal(e)
	}
	objects := []store.MediaObject{{Path: "music/recovery_sample", Kind: "directory"}, {Path: "music/recovery_sample/test.mp3", Kind: "audio"}}
	if _, e := db.Media().EnsureObjects(ctx, objects); e != nil {
		t.Fatal(e)
	}
	repo := db.Maintenance().(store.RecoveryRepository)
	samples, e := repo.RecoverySamples(ctx, 32)
	if e != nil {
		t.Fatal(e)
	}
	found := false
	for _, sample := range samples {
		if sample.Kind == "directory" {
			t.Fatal("directory selected as a file read", sample)
		}
		if sample.Path == objects[1].Path {
			found = true
		}
	}
	if !found {
		t.Fatal("managed file not sampled")
	}
}
