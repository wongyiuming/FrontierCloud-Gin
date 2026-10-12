package store

import "context"

type PhysicalInventoryEntry struct {
	Path         string
	Kind         string
	LogicalBytes int64
}

// Facts classify observed metadata; MetadataSHA256 is never a file-content hash.
// Blocking describes a retirement concern, not permission to delete anything.
type PhysicalInventoryFact struct {
	Category       string `json:"category"`
	ObjectID       string `json:"object_id,omitempty"`
	State          string `json:"state,omitempty"`
	Blocking       bool   `json:"blocking"`
	Reason         string `json:"reason,omitempty"`
	MetadataSHA256 string `json:"metadata_sha256,omitempty"`
	ExpectedBytes  int64  `json:"expected_bytes,omitempty"`
	Generation     int64  `json:"generation,omitempty"`
}
type PhysicalInventoryRepository interface {
	ClassifyPhysicalInventory(context.Context, string, string, string, []PhysicalInventoryEntry) ([]PhysicalInventoryFact, error)
}

// Expected items come from local metadata, including objects absent from disk.
// A nil ExpectedBytes means plaintext media size is owned by Master metadata.
type ExpectedPhysicalItem struct {
	Cursor         string `json:"cursor,omitempty"`
	MasterID       string `json:"master_id,omitempty"`
	Generation     int64  `json:"generation,omitempty"`
	ChunkIndex     *int64 `json:"chunk_index,omitempty"`
	Backing        string `json:"backing,omitempty"`
	State          string `json:"state,omitempty"`
	ObjectID       string `json:"object_id"`
	Path           string `json:"path"`
	ExpectedBytes  *int64 `json:"expected_bytes,omitempty"`
	MetadataSHA256 string `json:"metadata_sha256"`
}
type ExpectedPhysicalPage struct {
	Resource string                 `json:"resource"`
	After    string                 `json:"after"`
	Next     string                 `json:"next"`
	Complete bool                   `json:"complete"`
	Items    []ExpectedPhysicalItem `json:"items"`
}
type ExpectedPhysicalRepository interface {
	ExpectedPhysicalInventory(context.Context, string, string, string, string, string) (ExpectedPhysicalPage, error)
}
