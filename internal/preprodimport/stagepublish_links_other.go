//go:build !linux && !darwin

package preprodimport

import "os"

func stagePublishLinkCount(os.FileInfo) (uint64, bool) { return 0, false }
