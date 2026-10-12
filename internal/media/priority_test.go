package media

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func TestDragPriorityLocalAndMasterPersistAndInvalidate(t *testing.T) {
	for _, master := range []bool{false, true} {
		t.Run(map[bool]string{false: "Local", true: "Master"}[master], func(t *testing.T) {
			fixture := deleteFixture
			if master {
				fixture = masterFixture
			}
			root, db, svc := fixture(t)
			ctx := context.Background()
			for _, name := range []string{"a.mp3", "b.mp3", "c.mp3"} {
				if master {
					r, e := svc.ReserveMasterUpload(ctx, name, "music/artist", "", "primary", 10, 255, store.AdminAudit{})
					if e != nil {
						t.Fatal(e)
					}
					if _, e = svc.UploadMasterBytes(ctx, r.ID, strings.NewReader("ID3payload"), store.AdminAudit{}); e != nil {
						t.Fatal(e)
					}
				} else if e := os.WriteFile(filepath.Join(root, "music/artist", name), []byte("ID3payload"), 0600); e != nil {
					t.Fatal(e)
				}
			}
			for name, value := range map[string]int{"a.mp3": 100, "b.mp3": 100, "c.mp3": 101, "song.mp3": 99} {
				if _, e := svc.Preference(ctx, "music/artist/"+name, value, false, store.AdminAudit{}); e != nil {
					t.Fatal(e)
				}
			}
			if e := svc.Hide(ctx, []string{"music/artist"}, true, store.AdminAudit{}); e != nil {
				t.Fatal(e)
			}
			order, e := svc.PriorityOrder(ctx, "music/artist", "media")
			if e != nil || len(order.Items) != 4 {
				t.Fatal(order, e)
			}
			g := db.Media().(interface{ CatalogGeneration() uint64 })
			before := g.CatalogGeneration()
			move := store.PriorityMove{Revision: order.Revision, Path: "music/artist/c.mp3", After: "music/artist/a.mp3", Before: "music/artist/b.mp3"}
			result, e := svc.MovePriority(ctx, "music/artist", "media", move, store.AdminAudit{Action: "priority_reorder"})
			if e != nil {
				t.Fatal(e)
			}
			if g.CatalogGeneration() <= before || result.Items[0].Path != "music/artist/a.mp3" || result.Items[1].Path != "music/artist/c.mp3" || result.Items[3].Preference != 99 {
				t.Fatal("invalidation/order", result)
			}
			if _, e = svc.MovePriority(ctx, "music/artist", "media", move, store.AdminAudit{}); !errors.Is(e, store.ErrPriorityStale) {
				t.Fatal(e)
			}
			if _, e = svc.PriorityOrder(ctx, "../music/artist", "media"); !errors.Is(e, ErrPath) {
				t.Fatal("path traversal", e)
			}
			if master {
				r, e := svc.ReserveMasterUpload(ctx, "reserved.mp3", "music/artist", "", "primary", 10, 255, store.AdminAudit{})
				if e != nil {
					t.Fatal(e)
				}
				if _, e = svc.PriorityOrder(ctx, "music/artist", "media"); !errors.Is(e, store.ErrNodeState) {
					t.Fatal("upload fence", r, e)
				}
			}
		})
	}
}
