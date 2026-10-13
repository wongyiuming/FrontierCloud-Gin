package resourcemigration

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/resourceinventory"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func TestPlanScopeCountsAllConflictsAndValidatesFinalPage(t *testing.T) {
	for _, corrupt := range []bool{false, true} {
		t.Run(fmt.Sprint(corrupt), func(t *testing.T) {
			master := strings.Repeat("a", 32)
			rel := store.Relationship{ID: strings.Repeat("b", 32), PeerID: strings.Repeat("c", 32)}
			out := PlanObservation{Plan: store.MigrationPlan{Catalog: store.MigrationCatalog{Source: store.StorageMember{ID: strings.Repeat("d", 32)}, Objects: []store.MigrationObject{{Resource: "media", TargetPath: "music/unit/selected.mp3"}}}}}
			var session resourceinventory.Session
			clock := time.Now()
			digest := sha256.New()
			pages, closed, renewed := 0, 0, 0
			r := &Runner{inventoryNow: func() time.Time { return clock }, Client: planCall(func(ctx context.Context, rel store.Relationship, route string, value any) (map[string]any, error) {
				raw, _ := json.Marshal(value)
				var req struct {
					Action   string `json:"action"`
					ID       string `json:"session_id"`
					Sequence uint64 `json:"sequence"`
				}
				if e := json.Unmarshal(raw, &req); e != nil {
					t.Fatal(e)
				}
				var result any
				switch req.Action {
				case "open":
					now := clock.Unix()
					session = resourceinventory.Session{ID: req.ID, Incarnation: strings.Repeat("e", 32), Binding: resourceinventory.Binding{MemberID: rel.PeerID, MasterID: master, RelationshipID: rel.ID, Scope: "media"}, CreatedAt: now, ExpiresAt: now + 300}
					result = session
				case "renew":
					renewed++
					session.ExpiresAt = clock.Add(resourceinventory.SessionTTL).Unix()
					result = session
				case "close":
					closed++
					return map[string]any{}, nil
				case "page":
					pages++
					page := resourceinventory.Page{Sequence: req.Sequence}
					end := min(int(req.Sequence+1)*64, 70)
					for i := int(req.Sequence) * 64; i < end; i++ {
						entry := resourceinventory.Entry{Path: fmt.Sprintf("music/unit/occupied%02d.mp3", i), Kind: "regular", LogicalBytes: 1}
						page.Entries = append(page.Entries, entry)
						raw, _ := json.Marshal(entry)
						digest.Write(raw)
						digest.Write([]byte{'\n'})
					}
					page.Complete = end == 70
					page.EntryCount, page.LogicalBytes = uint64(end), int64(end)
					page.ObservationSHA256 = hex.EncodeToString(digest.Sum(nil))
					if req.Sequence == 0 {
						clock = clock.Add(31 * time.Second)
					}
					if corrupt && page.Complete {
						page.ObservationSHA256 = strings.Repeat("f", 64)
					}
					result = struct {
						resourceinventory.SessionPage
						Facts []store.PhysicalInventoryFact `json:"facts"`
					}{resourceinventory.SessionPage{Session: session, Page: page}, make([]store.PhysicalInventoryFact, len(page.Entries))}
				default:
					t.Fatal(req.Action)
				}
				raw, _ = json.Marshal(result)
				var reply map[string]any
				if e := json.Unmarshal(raw, &reply); e != nil {
					t.Fatal(e)
				}
				return reply, nil
			})}
			e := r.observePlanScope(context.Background(), rel, master, "media", &out, nil)
			if (e != nil) != corrupt || pages != 2 || closed != 1 || renewed != 1 || out.Plan.Catalog.TotalBlockers() != 70 || len(out.Plan.Catalog.Blockers) != 64 {
				t.Fatal("scan stopped at sample limit or skipped final validation", e, pages, closed, out.Plan.Catalog.TotalBlockers(), len(out.Plan.Catalog.Blockers))
			}
		})
	}
}

func TestPlanContentFirstStatusDoesNotWaitForTransferPollInterval(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	now := time.Now().Unix()
	o := store.MigrationObject{ID: strings.Repeat("1", 64), ObjectID: strings.Repeat("2", 64), Resource: "media", Version: strings.Repeat("3", 64), Bytes: 1}
	item := store.ExpectedPhysicalItem{Path: "media/music/unit/a.mp3", MetadataSHA256: strings.Repeat("4", 64)}
	statuses := 0
	r := &Runner{Client: planCall(func(ctx context.Context, rel store.Relationship, route string, value any) (map[string]any, error) {
		if e := ctx.Err(); e != nil {
			return nil, e
		}
		raw, _ := json.Marshal(value)
		var req struct {
			Action string `json:"action"`
			resourceinventory.ContentRequest
		}
		if e := json.Unmarshal(raw, &req); e != nil {
			t.Fatal(e)
		}
		if req.Action == "cancel" {
			return map[string]any{}, nil
		}
		job := resourceinventory.ContentJob{Request: req.ContentRequest, Incarnation: strings.Repeat("5", 32), State: "queued", CreatedAt: now, ExpiresAt: now + 300}
		if req.Action == "status" {
			statuses++
			job.State = "observed"
			job.Observation = &resourceinventory.ContentObservation{Path: item.Path, Bytes: 1, SHA256: strings.Repeat("6", 64)}
		}
		raw, _ = json.Marshal(job)
		var reply map[string]any
		json.Unmarshal(raw, &reply)
		return reply, nil
	})}
	proof, e := r.observePlanContent(ctx, store.Relationship{}, strings.Repeat("7", 32), o, item)
	if e != nil || statuses != 1 || proof.Bytes != 1 {
		t.Fatal(proof, statuses, e)
	}
}
