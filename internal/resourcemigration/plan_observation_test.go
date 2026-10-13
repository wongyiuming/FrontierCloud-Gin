package resourcemigration

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/resourceinventory"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

type planCall func(context.Context, store.Relationship, string, any) (map[string]any, error)

func (f planCall) Call(ctx context.Context, rel store.Relationship, route string, value any) (map[string]any, error) {
	return f(ctx, rel, route, value)
}
func TestPlanContentRejectsReboundExpiryAndSpeculativeResult(t *testing.T) {
	for _, mode := range []string{"valid", "large_valid", "large_short_expiry", "expiry_changed", "observed_error", "speculative", "old_creation", "wrong_path", "wrong_request"} {
		t.Run(mode, func(t *testing.T) {
			now := time.Now().Unix()
			cancelled := 0
			rel := store.Relationship{ID: strings.Repeat("1", 32), PeerID: strings.Repeat("2", 32)}
			o := store.MigrationObject{ID: strings.Repeat("3", 64), ObjectID: strings.Repeat("4", 64), Resource: "media", Version: strings.Repeat("5", 64), Bytes: 7}
			if strings.HasPrefix(mode, "large_") {
				o.Bytes = 10 << 30
			}
			item := store.ExpectedPhysicalItem{Path: "media/music/unit/a.mp3", MetadataSHA256: strings.Repeat("6", 64)}
			r := &Runner{Client: planCall(func(ctx context.Context, rel store.Relationship, route string, value any) (map[string]any, error) {
				raw, _ := json.Marshal(value)
				var request struct {
					Action string `json:"action"`
					resourceinventory.ContentRequest
				}
				if e := json.Unmarshal(raw, &request); e != nil {
					t.Fatal(e)
				}
				if request.Action == "cancel" {
					cancelled++
					return map[string]any{}, nil
				}
				job := resourceinventory.ContentJob{Request: request.ContentRequest, Incarnation: strings.Repeat("7", 32), CreatedAt: now, ExpiresAt: now + int64(resourceinventory.ContentObservationTTL(o.Bytes)/time.Second), State: "observed", Observation: &resourceinventory.ContentObservation{Path: item.Path, Bytes: o.Bytes, SHA256: strings.Repeat("8", 64)}}
				switch mode {
				case "large_short_expiry":
					job.ExpiresAt = now + 300
				case "expiry_changed":
					if request.Action == "start" {
						job.State = "running"
						job.Observation = nil
					} else {
						job.CreatedAt++
						job.ExpiresAt++
					}
				case "observed_error":
					job.ErrorCode = "failed"
				case "speculative":
					job.State = "running"
				case "old_creation":
					job.CreatedAt -= 100
					job.ExpiresAt -= 100
				case "wrong_path":
					job.Observation.Path = "media/music/other.mp3"
				case "wrong_request":
					job.Request.Bytes++
				}
				raw, _ = json.Marshal(job)
				var response map[string]any
				json.Unmarshal(raw, &response)
				return response, nil
			})}
			proof, e := r.observePlanContent(context.Background(), rel, strings.Repeat("9", 32), o, item)
			if mode == "valid" || mode == "large_valid" {
				if e != nil || proof.Bytes != o.Bytes {
					t.Fatal(proof, e)
				}
			} else if e == nil {
				t.Fatal("invalid observation accepted", mode)
			}
			if cancelled != 1 {
				t.Fatal("observation not cancelled", cancelled)
			}
		})
	}
}
