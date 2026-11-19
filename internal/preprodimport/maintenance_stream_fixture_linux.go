//go:build linux && ledger_fixture

package preprodimport

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"os"
	"strings"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/maintenance"
)

// FixtureEncryptedCaptureSQLite is an isolated test coordinator, not an
// import route or authority to publish. It proves neither owner fencing nor
// consistency after the held source transaction and maintenance lease end.
// Its signer, key and destination must contain test-only data.
func FixtureEncryptedCaptureSQLite(ctx context.Context, gate *maintenance.Gate, root, source string, dst *os.File, expectedMedia string, afterFirst func() error) error {
	if ctx == nil || gate == nil || dst == nil {
		return invalid("fixture maintenance capture input")
	}
	deadline, ok := ctx.Deadline()
	if !ok || time.Until(deadline) <= 0 || time.Until(deadline) > 30*time.Second {
		return invalid("fixture maintenance capture deadline")
	}
	return gate.InspectSQLiteImmediate(ctx, root, source, func(ctx context.Context, tx maintenance.SQLiteSnapshotReader, check func() error) error {
		if check() != nil {
			return maintenance.ErrState
		}
		var generation int
		if err := tx.QueryRowContext(ctx, `SELECT generation FROM frontiercloud_schema WHERE singleton=1`).Scan(&generation); err != nil {
			return err
		}
		public, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		defer clear(private)
		scope := fixtureStreamScope{Source: strings.Repeat("1", 32), Target: strings.Repeat("2", 32), Challenge: strings.Repeat("3", 64), SchemaGeneration: generation, PageSize: 17}
		signed, desc, err := fixtureCaptureSQLRows(ctx, tx, dst, private, scope, check, afterFirst)
		if err != nil {
			return err
		}
		defer clear(desc.key[:])
		if err = fixtureVerifySignedStream(ctx, signed, public, scope, desc, dst); err != nil {
			return err
		}
		if expectedMedia != "" {
			reader, e := openEncryptedSnapshotFixture(dst, desc)
			if e != nil {
				return e
			}
			defer reader.Close()
			scanner := bufio.NewScanner(io.NewSectionReader(reader, 0, desc.size))
			scanner.Buffer(make([]byte, 4096), 1<<20)
			inObjects, found := false, false
			for scanner.Scan() {
				var frame struct {
					Section string    `json:"section"`
					End     string    `json:"end"`
					Row     []*string `json:"row"`
				}
				if json.Unmarshal(scanner.Bytes(), &frame) != nil {
					return invalid("fixture WAL frame")
				}
				if frame.Section != "" {
					inObjects = frame.Section == "objects"
				}
				if frame.End != "" {
					inObjects = false
				}
				if inObjects && len(frame.Row) > 0 && frame.Row[0] != nil && *frame.Row[0] == expectedMedia {
					found = true
				}
			}
			if scanner.Err() != nil || !found {
				return invalid("fixture committed WAL row missing")
			}
		}
		if err = check(); err != nil {
			return err
		}
		return check()
	})
}
