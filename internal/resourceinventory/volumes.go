package resourceinventory

// Volume is a current filesystem capacity observation, never a write probe,
// reservation, unique-disk total or permission to retire/delete a mount.
type Volume struct {
	Scope            string `json:"scope"`
	InDataRoot       bool   `json:"in_data_root"`
	TotalBytes       int64  `json:"total_bytes"`
	FreeBytes        int64  `json:"free_bytes"`
	ObservedAt       int64  `json:"observed_at"`
	WritableVerified bool   `json:"writable_verified"`
}
