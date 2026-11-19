package runtimefacts

// TreeBackupMount is bounded read-only identity metadata. It contains no path,
// file contents, key, user activity or authorization grant.
type TreeBackupMount struct {
	Device uint64 `json:"device"`
	Inode  uint64 `json:"inode"`
	UID    uint32 `json:"uid"`
	GID    uint32 `json:"gid"`
	Mode   uint32 `json:"mode"`
}
type TreeBackupRuntime struct {
	Nonce   string          `json:"nonce"`
	UID     uint32          `json:"uid"`
	GID     uint32          `json:"gid"`
	UIDMap  string          `json:"uid_map"`
	Data    TreeBackupMount `json:"data"`
	Secrets TreeBackupMount `json:"secrets"`
	Scratch TreeBackupMount `json:"scratch"`
}
