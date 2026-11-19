package store

const (
	SelectedMediaDeletePending = "pending"
	SelectedMediaDeleteDeleted = "deleted"
)

// SelectedMediaDeleteTarget identifies an exact encrypted catalog entry. An
// operation ID resumes its existing deletion and must never resolve a new
// entry at the same logical path.
type SelectedMediaDeleteTarget struct {
	Path        string `json:"path"`
	ResourceID  string `json:"resource_id"`
	OperationID string `json:"operation_id,omitempty"`
	Directory   bool   `json:"directory,omitempty"`
}

type SelectedMediaDeleteItem struct {
	SelectedMediaDeleteTarget
	State string `json:"state"`
}

type SelectedMediaDeleteResult struct {
	Items []SelectedMediaDeleteItem `json:"items"`
}
