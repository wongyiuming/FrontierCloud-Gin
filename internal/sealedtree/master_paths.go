package sealedtree

// MasterFenceDirectory is relative to the trusted Master's DATA_ROOT. It is
// shared by normal startup, offline backup and verified recovery.
const MasterFenceDirectory = ".sealed-tree"

// MasterKeyFile is relative to the trusted Master's existing SECRETS_DIR.
// Followers and resource nodes must not receive this key.
const MasterKeyFile = "tree-master.key"

// MasterRebindIntentFile is the durable, inode-bound rebind intent at the
// retained DATA_ROOT. It remains present while the host journals recovery.
const MasterRebindIntentFile = ".tree-rebind-intent-v1"

// MasterStatePaths names the exact DATA_ROOT-relative files needed by a
// state-only archive; no media directory is included.
func MasterStatePaths() []string {
	return []string{MasterFenceDirectory + "/tree-write.fence", MasterFenceDirectory + "/tree-master.binding"}
}
