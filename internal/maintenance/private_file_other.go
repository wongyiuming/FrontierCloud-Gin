//go:build !linux

package maintenance

import "os"

// Existing business-tree initialization is Linux-only. Other platforms must
// not claim this filesystem identity check until an equivalent is implemented.
func privateSingleLink(os.FileInfo) bool { return false }
