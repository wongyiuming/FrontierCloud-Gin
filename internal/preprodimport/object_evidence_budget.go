package preprodimport

// Experimental object evidence disk budget. This preflight is not a disk
// reservation: unrelated writers can still exhaust the volume afterwards.
// PRAGMA database_list exposes a pathname, not the inode held by SQLite.
// Runtime integration therefore remains blocked until the actual connection is
// bound to the same protected DB/DATA_ROOT identity under its maintenance fence.
import (
	"context"
	"database/sql"
	"errors"
	"math"
	"os"
	"path/filepath"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/fsutil"
)

const objectEvidenceFreeFloor int64 = 1 << 30
const objectEvidenceReserveFloor int64 = 32 << 20
const objectEvidenceWALFloor int64 = 32 << 20

type objectEvidenceDiskBudget struct {
	MinimumFreeBytes        int64
	TransactionReserveBytes int64
	MaximumWALBytes         int64
}

func (b objectEvidenceDiskBudget) valid() bool {
	return b.MinimumFreeBytes >= objectEvidenceFreeFloor && b.TransactionReserveBytes >= objectEvidenceReserveFloor && b.MaximumWALBytes >= objectEvidenceWALFloor && b.MinimumFreeBytes <= math.MaxInt64-b.TransactionReserveBytes
}

// checkObjectEvidenceDiskBudget must run in the final guarded transaction.
// estimated is a conservative budget input, not a promise of reserved space.
func checkObjectEvidenceDiskBudget(ctx context.Context, tx *sql.Tx, b objectEvidenceDiskBudget, estimated int64) error {
	if ctx == nil || tx == nil || !b.valid() || estimated < 0 || estimated > b.TransactionReserveBytes || estimated > b.MaximumWALBytes {
		return invalid("object evidence disk budget")
	}
	rows, err := tx.QueryContext(ctx, "PRAGMA database_list")
	if err != nil {
		return invalid("object evidence disk path")
	}
	var name string
	for rows.Next() {
		var seq int
		var kind, path string
		if rows.Scan(&seq, &kind, &path) != nil {
			rows.Close()
			return invalid("object evidence disk path")
		}
		if kind == "main" {
			name = path
		}
	}
	e := rows.Err()
	rows.Close()
	if e != nil || !filepath.IsAbs(name) || filepath.Clean(name) != name {
		return invalid("object evidence disk path")
	}
	dir := filepath.Dir(name)
	base := filepath.Base(name)
	root, err := os.OpenRoot(dir)
	if err != nil {
		return invalid("object evidence disk path")
	}
	defer root.Close()
	before, err := os.Lstat(dir)
	if err != nil || !privateOwned(before, true) {
		return invalid("object evidence disk path")
	}
	opened, err := root.Stat(".")
	if err != nil || !os.SameFile(before, opened) {
		return invalid("object evidence disk path")
	}
	dbInfo, err := root.Lstat(base)
	if err != nil || !privateOwned(dbInfo, false) {
		return invalid("object evidence disk file")
	}
	if links, ok := stagePublishLinkCount(dbInfo); !ok || links != 1 {
		return invalid("object evidence disk file links")
	}
	file, err := root.Open(base)
	if err != nil {
		return invalid("object evidence disk file")
	}
	fileInfo, e := file.Stat()
	file.Close()
	if e != nil || !os.SameFile(dbInfo, fileInfo) {
		return invalid("object evidence disk file")
	}
	var walBytes int64
	wal, err := root.Lstat(base + "-wal")
	if err == nil {
		if !privateOwned(wal, false) || wal.Size() < 0 {
			return invalid("object evidence WAL")
		}
		if links, ok := stagePublishLinkCount(wal); !ok || links != 1 {
			return invalid("object evidence WAL links")
		}
		walFile, openErr := root.Open(base + "-wal")
		if openErr != nil {
			return invalid("object evidence WAL")
		}
		openedWAL, statErr := walFile.Stat()
		currentWAL, pathErr := root.Lstat(base + "-wal")
		walFile.Close()
		if statErr != nil || pathErr != nil || !os.SameFile(wal, openedWAL) || !os.SameFile(openedWAL, currentWAL) {
			return invalid("object evidence WAL changed")
		}
		walBytes = wal.Size()
	} else if !errors.Is(err, os.ErrNotExist) {
		return invalid("object evidence WAL")
	}
	_, free, err := fsutil.DiskUsage(root)
	if err != nil || free < b.MinimumFreeBytes+b.TransactionReserveBytes || walBytes > b.MaximumWALBytes-estimated || ctx.Err() != nil {
		return invalid("object evidence disk budget exceeded")
	}
	after, err := os.Lstat(dir)
	if err != nil || !os.SameFile(opened, after) {
		return invalid("object evidence disk path changed")
	}
	return nil
}
