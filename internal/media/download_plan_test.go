package media

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func issuedPlanEntry(t *testing.T, svc *Service, name string) DownloadEntry {
	t.Helper()
	d, err := svc.Download(context.Background(), []string{name})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	entries, err := d.Plan(1)
	if err != nil || len(entries) != 1 || entries[0].Snapshot == "" {
		t.Fatal("issued source plan", entries, err)
	}
	return entries[0]
}

func TestDownloadPlanRejectsSameSizeReplacementAndRename(t *testing.T) {
	for _, scenario := range []string{"delete", "rename"} {
		t.Run(scenario, func(t *testing.T) {
			_, _, svc := deleteFixture(t)
			ctx := context.Background()
			name := "music/artist/song.mp3"
			original := issuedPlanEntry(t, svc, name)
			if scenario == "delete" {
				if _, err := svc.Delete(ctx, []string{name}, store.AdminAudit{Action: "delete"}); err != nil {
					t.Fatal(err)
				}
			} else if _, err := svc.Rename(ctx, "music/artist", "renamed", store.AdminAudit{Action: "directory_rename"}); err != nil {
				t.Fatal(err)
			}
			// Publish through the normal journal/metadata transaction. A size-only
			// check would accept these different bytes at the old locator.
			stage, err := svc.Stage(ctx, strings.NewReader("ID3newone!"), original.Bytes)
			if err != nil {
				t.Fatal(err)
			}
			defer stage.Close()
			if _, err = svc.Publish(ctx, stage, "song.mp3", "", name, false, 255, store.AdminAudit{}); err != nil {
				t.Fatal(err)
			}
			d, err := svc.Download(ctx, []string{name})
			if err != nil {
				t.Fatal(err)
			}
			_, err = d.PlanDelivery(original.MediaID, original.Snapshot, "", "", false)
			d.Close()
			if !errors.Is(err, store.ErrNodeState) {
				t.Fatal("stale identity accepted same-size replacement", err)
			}
			fresh := issuedPlanEntry(t, svc, name)
			if fresh.MediaID == original.MediaID || fresh.Bytes != original.Bytes {
				t.Fatal("replacement did not retain size with a new durable identity")
			}
			d, err = svc.Download(ctx, []string{name})
			if err != nil {
				t.Fatal(err)
			}
			defer d.Close()
			delivery, err := d.PlanDelivery(fresh.MediaID, fresh.Snapshot, "", "", false)
			if err != nil {
				t.Fatal(err)
			}
			defer delivery.Stream.File.Close()
			content, err := io.ReadAll(delivery.Stream.File)
			if err != nil || string(content) != "ID3newone!" {
				t.Fatal("new plan failed to read replacement", err)
			}
		})
	}
}

func TestDownloadPlanRetainsMutationLeaseThroughPinnedRead(t *testing.T) {
	_, _, svc := deleteFixture(t)
	name := "music/artist/song.mp3"
	entry := issuedPlanEntry(t, svc, name)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	d, err := svc.Download(ctx, []string{name})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	delivery, err := d.PlanDelivery(entry.MediaID, entry.Snapshot, "", "", false)
	if err != nil {
		t.Fatal(err)
	}
	defer delivery.Stream.File.Close()
	started := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		close(started)
		_, err := svc.Delete(ctx, []string{name}, store.AdminAudit{Action: "delete"})
		done <- err
	}()
	<-started
	select {
	case err := <-done:
		t.Fatal("mutation completed before pinned read closed", err)
	case <-time.After(100 * time.Millisecond):
	}
	content, err := io.ReadAll(delivery.Stream.File)
	if err != nil || string(content) != "ID3payload" {
		t.Fatal("concurrent mutation changed issued bytes", err)
	}
	delivery.Stream.File.Close()
	d.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("mutation did not resume after read released", ctx.Err())
	}
}
