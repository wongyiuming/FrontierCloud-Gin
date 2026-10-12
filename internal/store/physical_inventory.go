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
