package recording

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/migrationdata"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store/sqlite"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestInterruptedRecordingPublicationCancellation(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		for _, fault := range []string{"none", "foreign", "corrupt", "missing"} {
			name := map[bool]string{false: "plain", true: "encrypted"}[encrypted] + "/" + fault
			t.Run(name, func(t *testing.T) {
				ctx := context.Background()
				dir := t.TempDir()
				db, e := sqlite.Open(filepath.Join(dir, "db.sqlite"))
				if e != nil {
					t.Fatal(e)
				}
				defer db.Close()
				if e = db.Initialize(ctx); e != nil {
					t.Fatal(e)
				}
				n, e := db.Nodes().InitializeIdentity(ctx, store.NodeIdentity{ID: strings.Repeat("a", 32), Role: "Standalone", PrivateKey: "fixture"})
				if e != nil {
					t.Fatal(e)
				}
				if _, e = db.Nodes().PromoteIdentity(ctx, store.NodePromotion{Role: "Follower", Endpoint: "https://source.test"}, store.NodeAudit{}); e != nil {
					t.Fatal(e)
				}
				now := time.Now().Unix()
				pair := store.PairPackage{Nonce: strings.Repeat("b", 32), TokenHash: strings.Repeat("c", 64), ExpiresAt: now + 300}
				if _, e = db.Nodes().IssuePair(ctx, pair, now, store.NodeAudit{}); e != nil {
					t.Fatal(e)
				}
				rel := store.Relationship{ID: strings.Repeat("d", 32), PeerID: strings.Repeat("e", 32), Endpoint: "https://master.test", PublicKey: strings.Repeat("A", 43), Credential: "fixture", Direction: "upstream", Mode: "Relay", State: "pending", Protocol: 2, CreatedAt: now}
				if e = db.Nodes().ConsumePair(ctx, pair, rel, now, store.NodeAudit{}); e != nil {
					t.Fatal(e)
				}
				if e = db.Nodes().ActivateRelationship(ctx, rel.ID, store.NodeAudit{}); e != nil {
					t.Fatal(e)
				}
				cfg := store.ResourceConfiguration{}
				cfg.Storage.Enabled = true
				cfg.Storage.Allocation = store.GiB
				if e = db.Pool().AcceptFollowerConfiguration(ctx, rel.ID, cfg, 10*store.GiB); e != nil {
					t.Fatal(e)
				}
				root, e := os.OpenRoot(dir)
				if e != nil {
					t.Fatal(e)
				}
				defer root.Close()
				s, e := New(root, db.Recordings(), db.Nodes())
				if e != nil {
					t.Fatal(e)
				}

				id, user := strings.Repeat("1", 32), strings.Repeat("2", 32)
				snapshot := store.RecordingMetadata{Title: "original", Lyrics: []store.RecordingLyric{{Time: 1, Text: "line"}}}
				if encrypted {
					meta, e := mediacrypto.NewMetadata(8)
					if e != nil {
						t.Fatal(e)
					}
					snapshot.Lyrics = []store.RecordingLyric{}
					snapshot.EncryptedLyrics = &store.RecordingEncryptedLyrics{Encryption: meta, Ciphertext: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, int(meta.CiphertextSize)))}
				}
				footer, e := json.Marshal(struct {
					Version int `json:"version"`
					store.RecordingMetadata
				}{1, snapshot})
				if e != nil {
					t.Fatal(e)
				}
				payload := trailer(string(footer))
				sum := sha256.Sum256(payload)
				sha := hex.EncodeToString(sum[:])
				h := store.MigrationPeerHeader{Format: "frontiercloud-peer-migration", Version: 1, TaskID: strings.Repeat("3", 32), MasterID: rel.PeerID, SourceID: strings.Repeat("4", 32), TargetID: n.ID, SourceRelationship: strings.Repeat("5", 32), TargetRelationship: rel.ID, PlanSHA: strings.Repeat("6", 64), ObjectCount: 1, Bytes: int64(len(payload))}
				l := store.MigrationLease{TaskID: h.TaskID, RunnerID: strings.Repeat("7", 32), Epoch: 1, ExpiresAt: time.Now().Unix() + 60}
				proof := &store.RecordingProof{ID: id, UserID: user, Filename: "voice.webm", ContentType: "audio/webm", Bytes: h.Bytes, SHA256: sha, CreatedAt: now}
				if encrypted {
					proof.EncryptedLyricsEncryption = &snapshot.EncryptedLyrics.Encryption
					proof.MetadataSHA256 = store.RecordingMetadataSHA256(snapshot)
				}
				o := store.MigrationObject{ID: id, ObjectID: id, Resource: "recording", Kind: "recording", Parent: user, Path: h.SourceRelationship + "/" + user + "/" + id + ".bin", TargetPath: h.TargetRelationship + "/" + user + "/" + id + ".bin", Bytes: h.Bytes, Version: strings.Repeat("8", 64), ETag: sha, Recording: proof}
				v := store.MigrationPeerObject{Object: o, Proof: store.MigrationDiskProof{ID: id, Version: o.Version, Bytes: h.Bytes, SHA256: sha}}
				peer := db.Pool().(store.MigrationPeerRepository)
				if e = peer.RegisterPeerMigration(ctx, rel.ID, h, l, "queued", 10*store.GiB, store.NodeAudit{}); e != nil {
					t.Fatal(e)
				}
				if e = peer.RegisterPeerMigrationObject(ctx, rel.ID, l, v, store.NodeAudit{}); e != nil {
					t.Fatal(e)
				}
				spec := migrationdata.Spec{TaskID: h.TaskID, MasterID: h.MasterID, SourceID: h.SourceID, TargetID: h.TargetID, LogicalID: id, ObjectID: id, Resource: "recording", TargetPath: o.TargetPath, SourceVersion: o.Version, Bytes: h.Bytes, SHA256: sha, Recording: proof}
				receiver, e := s.MigrationReceiver(ctx)
				if e != nil {
					t.Fatal(e)
				}
				if _, e = receiver.Begin(ctx, spec); e != nil {
					t.Fatal(e)
				}
				if _, e = receiver.Append(ctx, spec, 0, payload, sha); e != nil {
					t.Fatal(e)
				}
				if _, e = receiver.Verify(ctx, spec, nil); e != nil {
					t.Fatal(e)
				}
				if e = peer.VerifyPeerMigrationObject(ctx, rel.ID, l, id, h.Bytes, sha); e != nil {
					t.Fatal(e)
				}
				if _, e = s.MigrationPublish(ctx, spec, func() error { _, e := peer.AuthorizePeerMigration(ctx, rel.ID, l, id, "publish"); return e }, func(receipt store.RecordingReceipt, free int64) error {
					return errors.New("crash before SQL publication")
				}); e == nil {
					t.Fatal("missing publication failure")
				}
				l.Epoch++
				if e = peer.RegisterPeerMigration(ctx, rel.ID, h, l, "cancelling", 10*store.GiB, store.NodeAudit{}); e != nil {
					t.Fatal(e)
				}
				unit := sha256.Sum256([]byte("recording:" + user))
				roster, e := store.MigrationUnitObjectsSHA([]store.MigrationPeerObject{v})
				if e != nil {
					t.Fatal(e)
				}
				grant := store.MigrationShadowGrant{Unit: store.MigrationUnitFinishGrant{Header: h, Unit: store.MigrationUnit{ID: hex.EncodeToString(unit[:]), Resource: "recording", Parent: user, State: "cancelled", ObjectCount: 1, Bytes: h.Bytes}, UnitVersion: strings.Repeat("9", 64), ObjectsSHA: roster}, Object: o, SourceProof: store.MigrationCleanupProof{MigrationDiskProof: v.Proof, VerifiedAt: time.Now().Unix()}}
				target := filepath.Join(dir, o.TargetPath)
				if fault == "foreign" || fault == "missing" {
					if e = os.Remove(target); e != nil {
						t.Fatal(e)
					}
				}
				if fault == "foreign" {
					if e = os.WriteFile(target, payload, 0640); e != nil {
						t.Fatal(e)
					}
				}
				if fault == "corrupt" {
					if e = os.WriteFile(target, append([]byte("!"), payload[1:]...), 0640); e != nil {
						t.Fatal(e)
					}
				}
				e = s.MigrationCancelPublication(ctx, rel.ID, l, grant, peer, store.NodeAudit{})
				if fault == "foreign" || fault == "corrupt" {
					if e == nil {
						t.Fatal("unsafe recording unlink accepted")
					}
					if _, e = os.Stat(target); e != nil {
						t.Fatal("conflicting recording removed", e)
					}
				} else {
					if e != nil {
						t.Fatal(e)
					}
					if _, e = os.Stat(target); !errors.Is(e, os.ErrNotExist) {
						t.Fatal("business link survived", e)
					}
					cp, e := receiver.Status(ctx, spec)
					if e != nil || cp.State != "aborted" || !cp.PublicationUnlinked {
						t.Fatal(cp, e)
					}
					if e = s.MigrationCancelPublication(ctx, rel.ID, l, grant, peer, store.NodeAudit{}); e != nil {
						t.Fatal("lost acknowledgment replay", e)
					}
				}
				var used, reserved int64
				if e = db.Database().QueryRow("SELECT used_bytes,reserved_bytes FROM cluster_storage_members WHERE member_id=?", n.ID).Scan(&used, &reserved); e != nil || used != 0 || reserved != h.Bytes {
					t.Fatal("publication cancellation accounting", used, reserved, e)
				}
			})
		}
	}
}
