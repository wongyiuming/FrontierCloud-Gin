package media

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func TestDirectoryCaseFoldTiesMatchPublicAdminAndDrag(t *testing.T) {
	for _, master := range []bool{false, true} {
		t.Run(map[bool]string{false: "Local", true: "Master"}[master], func(t *testing.T) {
			fixture := deleteFixture
			if master {
				fixture = masterFixture
			}
			root, _, svc := fixture(t)
			ctx := context.Background()
			if err := os.Mkdir(filepath.Join(root, "music/case-fold"), 0755); err != nil {
				t.Fatal(err)
			}
			// Create lower-case first to expose filesystem iteration order.
			for _, name := range []string{"a", "A", "b"} {
				parent := "music/case-fold/" + name
				if master {
					r, err := svc.ReserveMasterUpload(ctx, "track.mp3", parent, "", "primary", 10, 255, store.AdminAudit{})
					if err != nil {
						t.Fatal(err)
					}
					if _, err = svc.UploadMasterBytes(ctx, r.ID, strings.NewReader("ID3payload"), store.AdminAudit{}); err != nil {
						t.Fatal(err)
					}
				} else {
					if err := os.Mkdir(filepath.Join(root, parent), 0755); err != nil {
						if os.IsExist(err) {
							t.Skip("requires case-sensitive filesystem")
						}
						t.Fatal(err)
					}
					if err := os.WriteFile(filepath.Join(root, parent, "track.mp3"), []byte("ID3payload"), 0600); err != nil {
						t.Fatal(err)
					}
				}
				if _, err := svc.Preference(ctx, parent, 100, true, store.AdminAudit{}); err != nil {
					t.Fatal(err)
				}
			}
			categories, err := svc.Subcategories(ctx, "music", "music/case-fold", false)
			if err != nil {
				t.Fatal(err)
			}
			var public []string
			for _, category := range categories {
				public = append(public, "music/case-fold/"+category.Name)
			}
			order, err := svc.PriorityOrder(ctx, "music/case-fold", "directory")
			if err != nil {
				t.Fatal(err)
			}
			var admin []string
			for _, item := range order.Items {
				admin = append(admin, item.Path)
			}
			want := []string{"music/case-fold/A", "music/case-fold/a", "music/case-fold/b"}
			if !reflect.DeepEqual(public, want) || !reflect.DeepEqual(admin, want) {
				t.Fatal("case-fold tie diverged", public, admin)
			}
			prefs, err := svc.DirectoryPreferences(ctx, "music/case-fold")
			if err != nil {
				t.Fatal(err)
			}
			for i, item := range prefs {
				if item.Path != want[i] {
					t.Fatal("directory preference tie diverged", prefs)
				}
			}
			moved, err := svc.MovePriority(ctx, "music/case-fold", "directory", store.PriorityMove{Revision: order.Revision, Path: "music/case-fold/a", Before: "music/case-fold/A"}, store.AdminAudit{})
			if err != nil || moved.Items[0].Path != "music/case-fold/a" {
				t.Fatal(moved, err)
			}
			categories, err = svc.Subcategories(ctx, "music", "music/case-fold", false)
			if err != nil || categories[0].Name != "a" || categories[1].Name != "A" {
				t.Fatal("drag/public order diverged", categories, err)
			}
		})
	}
}

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
