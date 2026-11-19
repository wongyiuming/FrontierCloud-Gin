package media

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/migrationdata"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func TestRetainedLegacyMigrationReceiverRejectsTreeMarker(t *testing.T) {
	_, db, svc, _ := ownedFixture(t)
	ctx := context.Background()
	svc.nodes = db.Nodes()
	identity, err := db.Nodes().ReadIdentity(ctx)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("a"))
	spec := migrationdata.Spec{TaskID: strings.Repeat("1", 32), MasterID: strings.Repeat("2", 32), SourceID: strings.Repeat("3", 32), TargetID: identity.ID, LogicalID: strings.Repeat("4", 64), ObjectID: strings.Repeat("5", 64), Resource: "media", TargetPath: "music/retained/song.mp3", SourceVersion: strings.Repeat("6", 64), Bytes: 1, SHA256: hex.EncodeToString(digest[:])}
	receiver, err := svc.MigrationReceiver(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = receiver.Begin(ctx, spec); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Database().ExecContext(ctx, `INSERT INTO sealed_tree_meta(singleton,version,verifier,salt,root_encryption_id,root_sealed,write_fence) VALUES(1,1,?,?,?,?,0)`, strings.Repeat("a", 64), []byte{1}, strings.Repeat("b", 64), []byte{1}); err != nil {
		t.Fatal(err)
	}
	if _, err = receiver.Append(ctx, spec, 0, []byte("a"), spec.SHA256); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("retained receiver appended after marker", err)
	}
	// The isolated fixture removes the synthetic marker solely to inspect the
	// pre-existing checkpoint; production recovery must not clear the marker.
	if _, err = db.Database().ExecContext(ctx, `DELETE FROM sealed_tree_meta WHERE singleton=1`); err != nil {
		t.Fatal(err)
	}
	checkpoint, err := receiver.Begin(ctx, spec)
	if err != nil || checkpoint.Offset != 0 {
		t.Fatal("blocked append changed checkpoint", checkpoint, err)
	}
}
