//go:build !linux

package recovery

import "os"

// Linux is the supported native tree-backup runtime. Other platforms retain
// the portable identity/size/mode/mtime checks in sameArchiveSource.
func archiveSourceMetadataEqual(_, _ os.FileInfo) bool { return true }

func archiveSourceMetadataDifference(_, _ os.FileInfo) string { return "unknown" }
