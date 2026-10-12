package migrationdata

import "github.com/wongyiuming/FrontierCloud-Gin/internal/store"

func ValidRecheckID(id string) bool { return identifier.MatchString(id) }

// Request is shared by the authenticated follower route and Master runner.
// Data is bounded to one ChunkBytes message; it never carries a file key.
type Request struct {
	Lease     store.MigrationLease `json:"lease"`
	Spec      Spec                 `json:"binding"`
	Offset    int64                `json:"offset"`
	Length    int                  `json:"length"`
	Data      []byte               `json:"data,omitempty"`
	SHA       string               `json:"chunk_sha256,omitempty"`
	RecheckID string               `json:"recheck_id,omitempty"`
}
