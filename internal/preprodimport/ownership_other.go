//go:build !unix

package preprodimport

import "os"

// Native private ACL ownership has not been established on this platform.
func privateOwned(os.FileInfo, bool) bool { return false }
