//go:build linux

package preprodimport

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/fsutil"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/snapshotcrypt"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	sqlitestore "github.com/wongyiuming/FrontierCloud-Gin/internal/store/sqlite"
	nodevault "github.com/wongyiuming/FrontierCloud-Gin/internal/vault"
)

func TestPlainPendingReconcilesPinnedWeakETagAndSourceFacts(t *testing.T) {
	ctx := context.Background()
	s, _, _, _ := fixture(t)
	m := s.Media[1]
	s.Visibility = append(s.Visibility, Visibility{Path: m.Path, Hidden: false})
	complete := completeSourceFixture(s)
	for i := range complete.Facts.Placements {
		if complete.Facts.Placements[i].MediaID == m.MediaID {
			complete.Facts.Placements[i].ETag = `W/"legacy"`
		}
	}
	generation, err := completeSnapshotDigest(complete)
	if err != nil {
		t.Fatal(err)
	}
	seed := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32))
	private := protocol.Encode(seed.Seed())
	receiver, err := receiverFromMasterSeed(bytes.Repeat([]byte{8}, 32))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	challenge := strings.Repeat("9", 64)
	pin := sourceAuthorityPin{Version: 1, Purpose: "frontiercloud:preprod-source-authority:v1", AuthorityKind: "ssh-collector-v1", SourceSSHHostKeySHA256: strings.Repeat("a", 64), SourceTLSOrigin: "https://source.test", SourceTLSSPKISHA256: strings.Repeat("b", 64), SourceNode: s.Mappings[0].SourceID, SourceKeyID: s.PremasterKeyID, SourcePublic: seed.Public().(ed25519.PublicKey), TargetNode: s.Mappings[0].TargetID, TargetMasterPublic: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{8}, 32)).Public().(ed25519.PublicKey), TargetX25519: receiver.PublicKey().Bytes(), Generation: generation}
	pin.ImportScope = syntheticImportScope(s)
	for _, mapping := range s.Mappings {
		pin.SourceOwners = append(pin.SourceOwners, sourceOwnerPin{NodeID: mapping.SourceID, SSHHostKeySHA256: pin.SourceSSHHostKeySHA256})
	}
	app, err := sqlitestore.Open(filepath.Join(t.TempDir(), "target.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	if err = app.Initialize(ctx); err != nil {
		t.Fatal(err)
	}
	nodeDir := t.TempDir()
	if err = os.Chmod(nodeDir, 0700); err != nil {
		t.Fatal(err)
	}
	nv, err := nodevault.Open(nodeDir)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := nv.Seal(protocol.Encode(bytes.Repeat([]byte{8}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = app.Nodes().InitializeIdentity(ctx, store.NodeIdentity{ID: pin.TargetNode, Role: "Standalone", PrivateKey: sealed, CreatedAt: now.Unix()}); err != nil {
		t.Fatal(err)
	}
	if _, err = app.Nodes().PromoteIdentity(ctx, store.NodePromotion{Role: "Master", Endpoint: "https://target.test", Allocation: 5 * store.GiB, PhysicalFree: 10 * store.GiB}, store.NodeAudit{}); err != nil {
		t.Fatal(err)
	}
	if err = app.Nodes().(store.PublicRoutingRepository).ConfigurePublicOrigin("https://target.test"); err != nil {
		t.Fatal(err)
	}
	if err = provisionSourceAuthority(ctx, app, nv, pin); err != nil {
		t.Fatal(err)
	}
	vaultDir := t.TempDir()
	if err = os.Chmod(vaultDir, 0700); err != nil {
		t.Fatal(err)
	}
	vaultPath := filepath.Join(vaultDir, "source.sqlite")
	initial, err := os.OpenFile(vaultPath, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if err = initial.Close(); err != nil {
		t.Fatal(err)
	}
	evidenceDB, err := sql.Open("sqlite", vaultPath)
	if err != nil {
		t.Fatal(err)
	}
	defer evidenceDB.Close()
	evidenceDB.SetMaxOpenConns(1)
	for _, q := range []string{"PRAGMA journal_mode=WAL", "PRAGMA synchronous=FULL", "CREATE TABLE preprod_source_evidence(evidence_tag TEXT PRIMARY KEY,salt BLOB NOT NULL UNIQUE,nonce BLOB NOT NULL,cipher BLOB NOT NULL,challenge_tag TEXT NOT NULL UNIQUE)", "CREATE TABLE preprod_object_evidence(evidence_tag TEXT PRIMARY KEY,salt BLOB NOT NULL UNIQUE,nonce BLOB NOT NULL,cipher BLOB NOT NULL,challenge_tag TEXT NOT NULL UNIQUE)", "CREATE TABLE legacy_key_vault_meta(singleton INTEGER PRIMARY KEY,verifier TEXT NOT NULL)"} {
		if _, err = evidenceDB.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	if err = os.Chmod(vaultPath, 0600); err != nil {
		t.Fatal(err)
	}
	evidenceRoot := bytes.Repeat([]byte{12}, 32)
	if _, err = evidenceDB.Exec("INSERT INTO legacy_key_vault_meta VALUES(1,?)", legacyVaultTag(evidenceRoot, "verifier", pin.TargetNode)); err != nil {
		t.Fatal(err)
	}
	source := syntheticSourceForComplete(complete)
	source.Version = 1
	source.AuthorityKind = pin.AuthorityKind
	source.SourceNode = pin.SourceNode
	source.SourcePublic = protocol.Encode(pin.SourcePublic)
	source.SourceSSHHostKeySHA256 = pin.SourceSSHHostKeySHA256
	source.TargetNode = pin.TargetNode
	source.TargetReceiver = pin.TargetX25519
	source.Challenge = challenge
	source.IssuedUnix = now.Unix()
	source.ExpiresUnix = now.Add(3 * time.Minute).Unix()
	raw, err := json.Marshal(source)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(raw)
	sig, err := protocol.Sign(private, map[string]any{"kind": "frontiercloud-preprod-media-source-v1", "sha256": hex.EncodeToString(h[:]), "source_node": source.SourceNode, "target_node": source.TargetNode, "challenge": challenge})
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := snapshotcrypt.Seal(store.SignedMediaSourceSnapshot{Snapshot: source, Signature: sig}, receiver.PublicKey().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	_, sourceDigest, err := authenticateCompleteSource(envelope, receiver, pin, challenge, now, complete)
	if err != nil {
		t.Fatal(err)
	}
	sourceFacts, err := sourceObjectFactsDigest(source, m)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name               string
		badHidden, badTime bool
	}{{name: "exact"}, {name: "wrong hidden", badHidden: true}, {name: "wrong placement time", badTime: true}} {
		t.Run(tc.name, func(t *testing.T) {
			tree, err := sealedtree.New(bytes.Repeat([]byte{41}, 32), bytes.Repeat([]byte{42}, 32))
			if err != nil {
				t.Fatal(err)
			}
			db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "tree.sqlite"))
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			rootID := strings.Repeat("f", 64)
			target, err := sealedtree.InitializeSQLite(ctx, db, tree, rootID)
			if err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			if err = os.Chmod(dir, 0700); err != nil {
				t.Fatal(err)
			}
			root, err := os.OpenRoot(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			if _, err = sealedtree.InitializeFence(ctx, target, root, dir); err != nil {
				t.Fatal(err)
			}
			vido := sealedtree.Entry{ParentID: rootID, ObjectID: strings.Repeat("1", 64), Kind: "directory", Name: "vido"}
			if err = target.CreateDirectoryWithFacts(ctx, vido, sealedtree.Facts{ObjectID: vido.ObjectID}); err != nil {
				t.Fatal(err)
			}
			category := sealedtree.Entry{ParentID: vido.ObjectID, ObjectID: strings.Repeat("2", 64), Kind: "directory", Name: "category"}
			if err = target.CreateDirectoryWithFacts(ctx, category, sealedtree.Facts{ObjectID: category.ObjectID}); err != nil {
				t.Fatal(err)
			}
			hidden := int64(0)
			if tc.badHidden {
				hidden = 1
			}
			updated := int64(2)
			if tc.badTime {
				updated = 3
			}
			facts := sealedtree.Facts{ObjectID: m.MediaID, Visibility: &sealedtree.VisibilityFact{Hidden: hidden, UpdatedAt: "2026-01-01T00:00:00Z"}}
			placement := sealedtree.Placement{ObjectID: m.MediaID, NativeObjectID: m.ObjectID, OwnerID: s.Mappings[1].TargetID, Bytes: m.Size, SHA256: m.SHA256, ETag: `W/"legacy"`, State: "active", CreatedAt: 1, UpdatedAt: updated}
			prepared, err := target.PrepareFileWithFreshLocators(ctx, sealedtree.Entry{ParentID: category.ObjectID, ObjectID: m.MediaID, Kind: m.Kind, Name: "movie.mp4"}, placement, facts)
			if err != nil {
				t.Fatal(err)
			}
			scope := objectProofScope{TargetOwnerID: s.Mappings[1].TargetID, TargetBlobID: prepared.BlobID, TargetReadAlias: prepared.ReadAlias, Challenge: strings.Repeat("8", 64)}
			proof := sshObjectProof{Version: 1, SourceNode: pin.SourceNode, SourceOwnerID: m.SourceID, OwnerSSHHostKeySHA256: pin.SourceSSHHostKeySHA256, SourceSnapshotDigest: sourceDigest, BeforeFactsSHA256: sourceFacts, AfterFactsSHA256: sourceFacts, MediaID: m.MediaID, SourceObjectID: m.ObjectID, Path: m.Path, SHA256: m.SHA256, Size: m.Size, Device: 1, Inode: 2, MtimeNS: 3, CtimeNS: 4, TargetNode: pin.TargetNode, TargetOwnerID: scope.TargetOwnerID, TargetBlobID: scope.TargetBlobID, TargetReadAlias: scope.TargetReadAlias, Challenge: scope.Challenge, IssuedUnix: now.Unix(), ExpiresUnix: now.Add(3 * time.Minute).Unix()}
			body, err := json.Marshal(proof)
			if err != nil {
				t.Fatal(err)
			}
			hash := sha256.Sum256(body)
			ps, err := protocol.Sign(private, map[string]any{"kind": "frontiercloud-preprod-ssh-object-proof-v1", "sha256": hex.EncodeToString(hash[:])})
			if err != nil {
				t.Fatal(err)
			}
			body, err = json.Marshal(signedSSHObjectProof{Proof: proof, Signature: ps})
			if err != nil {
				t.Fatal(err)
			}
			proofEnvelope, err := snapshotcrypt.SealObjectProof(body, receiver.PublicKey().Bytes())
			if err != nil {
				t.Fatal(err)
			}
			var lyricProof store.EncryptedMediaSourceSnapshot
			var lyricScope objectProofScope
			var lyricID string
			if !tc.badHidden && !tc.badTime {
				lyric := s.Lyrics[0]
				lyricID = lyric.ID
				lyricMedia := Media{MediaID: lyric.ID, ObjectID: lyric.ID, SourceID: s.Mappings[0].SourceID, Path: lyric.Path, Kind: "lyric", Size: lyric.Size, SHA256: lyric.SHA256}
				lyricRoot := sealedtree.Entry{ParentID: rootID, ObjectID: strings.Repeat("3", 64), Kind: "directory", Name: "lyrics"}
				if err = target.CreateDirectoryWithFacts(ctx, lyricRoot, sealedtree.Facts{ObjectID: lyricRoot.ObjectID}); err != nil {
					t.Fatal(err)
				}
				lyricDir := sealedtree.Entry{ParentID: lyricRoot.ObjectID, ObjectID: strings.Repeat("4", 64), Kind: "directory", Name: "a"}
				if err = target.CreateDirectoryWithFacts(ctx, lyricDir, sealedtree.Facts{ObjectID: lyricDir.ObjectID}); err != nil {
					t.Fatal(err)
				}
				lyricFacts, e := sourceObjectTreeFacts(complete, lyricMedia, nil)
				if e != nil {
					t.Fatal(e)
				}
				lyricPlace := sealedtree.Placement{ObjectID: lyric.ID, NativeObjectID: lyric.ID, OwnerID: s.Mappings[0].TargetID, Bytes: lyric.Size, SHA256: lyric.SHA256, State: "active"}
				lyricPending, e := target.PrepareFileWithFreshLocators(ctx, sealedtree.Entry{ParentID: lyricDir.ObjectID, ObjectID: lyric.ID, Kind: "lyric", Name: "song.lrc"}, lyricPlace, lyricFacts)
				if e != nil {
					t.Fatal(e)
				}
				lyricScope = objectProofScope{TargetOwnerID: lyricPlace.OwnerID, TargetBlobID: lyricPending.BlobID, TargetReadAlias: lyricPending.ReadAlias, Challenge: strings.Repeat("7", 64)}
				lyricFactsDigest, e := sourceObjectFactsDigest(source, lyricMedia)
				if e != nil {
					t.Fatal(e)
				}
				lp := sshObjectProof{Version: 1, SourceNode: pin.SourceNode, SourceOwnerID: lyricMedia.SourceID, OwnerSSHHostKeySHA256: pin.SourceSSHHostKeySHA256, SourceSnapshotDigest: sourceDigest, BeforeFactsSHA256: lyricFactsDigest, AfterFactsSHA256: lyricFactsDigest, MediaID: lyric.ID, SourceObjectID: lyric.ID, Path: lyric.Path, SHA256: lyric.SHA256, Size: lyric.Size, Device: 1, Inode: 3, MtimeNS: 3, CtimeNS: 4, TargetNode: pin.TargetNode, TargetOwnerID: lyricScope.TargetOwnerID, TargetBlobID: lyricScope.TargetBlobID, TargetReadAlias: lyricScope.TargetReadAlias, Challenge: lyricScope.Challenge, IssuedUnix: now.Unix(), ExpiresUnix: now.Add(3 * time.Minute).Unix()}
				encoded, e := json.Marshal(lp)
				if e != nil {
					t.Fatal(e)
				}
				digest := sha256.Sum256(encoded)
				signature, e := protocol.Sign(private, map[string]any{"kind": "frontiercloud-preprod-ssh-object-proof-v1", "sha256": hex.EncodeToString(digest[:])})
				if e != nil {
					t.Fatal(e)
				}
				encoded, e = json.Marshal(signedSSHObjectProof{Proof: lp, Signature: signature})
				if e != nil {
					t.Fatal(e)
				}
				lyricProof, e = snapshotcrypt.SealObjectProof(encoded, receiver.PublicKey().Bytes())
				if e != nil {
					t.Fatal(e)
				}
			}
			lease, err := target.AcquireReadFence(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer lease.Release()
			got, err := reconcilePlainOrLyric(ctx, target, lease, receiver, pin, envelope, proofEnvelope, challenge, complete, m.MediaID, scope, now)
			if tc.badHidden || tc.badTime {
				if err == nil {
					t.Fatal("mismatched facts accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got.OperationID != prepared.OperationID || got.RuntimeReady || got.OwnerFinalPublished {
				t.Fatal("incorrect pending observation")
			}
			if _, err := observePlainOrLyric(ctx, app, nv, target, lease, evidenceDB, evidenceRoot, envelope, proofEnvelope, challenge, complete, m.MediaID, scope); err == nil {
				t.Fatal("unordered plain coordinator must remain disabled")
			}
			// Exercise independent evidence storage directly; it does not acquire
			// ingress or imply the unavailable coordinator has succeeded.
			guard := func(c context.Context) error { return lease.Check(c) }
			for i := 0; i < 2; i++ {
				ref, e := saveSourceEvidence(ctx, evidenceDB, evidenceRoot, receiver, pin, envelope, challenge, complete, time.Now(), guard)
				if e != nil || ref.Digest != sourceDigest {
					t.Fatal("source evidence fixture", e)
				}
			}
			if ok, err := recoverSourceEvidence(ctx, evidenceDB, evidenceRoot, receiver, pin, sourceEvidenceRef{Digest: sourceDigest}, func(c context.Context) error { return lease.Check(c) }); err != nil || !ok {
				t.Fatal("source evidence recovery", err)
			}
			var count int
			if err = evidenceDB.QueryRow("SELECT COUNT(*) FROM preprod_source_evidence").Scan(&count); err != nil || count != 1 {
				t.Fatal("evidence retry not idempotent", count, err)
			}
			acquireEvidence := evidenceFixtureAcquire(guard)
			// Even an otherwise correctly signed collector proof cannot override
			// the independently authenticated source-to-target owner mapping.
			redirected, e := decodeObjectEvidenceProof(proofEnvelope, receiver)
			if e != nil {
				t.Fatal(e)
			}
			redirectedScope := scope
			redirectedScope.TargetOwnerID = s.Mappings[0].TargetID
			redirectedScope.Challenge = strings.Repeat("5", 64)
			redirected.Proof.TargetOwnerID = redirectedScope.TargetOwnerID
			redirected.Proof.Challenge = redirectedScope.Challenge
			redirectedBody, e := json.Marshal(redirected.Proof)
			if e != nil {
				t.Fatal(e)
			}
			redirectedHash := sha256.Sum256(redirectedBody)
			redirected.Signature, e = protocol.Sign(private, map[string]any{"kind": "frontiercloud-preprod-ssh-object-proof-v1", "sha256": hex.EncodeToString(redirectedHash[:])})
			if e != nil {
				t.Fatal(e)
			}
			redirectedBody, e = json.Marshal(redirected)
			if e != nil {
				t.Fatal(e)
			}
			redirectedEnvelope, e := snapshotcrypt.SealObjectProof(redirectedBody, receiver.PublicKey().Bytes())
			if e != nil {
				t.Fatal(e)
			}
			if _, e = saveObjectEvidence(ctx, evidenceDB, evidenceRoot, receiver, pin, sourceEvidenceRef{Digest: sourceDigest}, m.MediaID, redirectedScope, redirectedEnvelope, objectEvidenceTestBudget(), acquireEvidence); e == nil {
				t.Fatal("signed but mismatched owner mapping accepted")
			}
			objectRef, err := saveObjectEvidence(ctx, evidenceDB, evidenceRoot, receiver, pin, sourceEvidenceRef{Digest: sourceDigest}, m.MediaID, scope, proofEnvelope, objectEvidenceTestBudget(), acquireEvidence)
			if err != nil {
				t.Fatal("save object evidence", err)
			}
			unsafeBudget := objectEvidenceTestBudget()
			unsafeBudget.MinimumFreeBytes = objectEvidenceFreeFloor - 1
			if _, e := saveObjectEvidence(ctx, evidenceDB, evidenceRoot, receiver, pin, sourceEvidenceRef{Digest: sourceDigest}, m.MediaID, scope, proofEnvelope, unsafeBudget, acquireEvidence); e == nil {
				t.Fatal("unsafe disk floor accepted")
			}
			// Recheck actual free space after another writer consumes blocks between
			// source verification and acquisition of the final guard.
			diskRoot, e := os.OpenRoot(vaultDir)
			if e != nil {
				t.Fatal(e)
			}
			_, freeBefore, e := fsutil.DiskUsage(diskRoot)
			diskRoot.Close()
			if e != nil {
				t.Fatal(e)
			}
			tight := objectEvidenceTestBudget()
			tight.MinimumFreeBytes = freeBefore - tight.TransactionReserveBytes - (8 << 20)
			if !tight.valid() {
				t.Fatal("fixture lacks space for disk boundary test")
			}
			consumed := false
			burnGuard := func(c context.Context) error {
				if !consumed {
					consumed = true
					f, e := os.OpenFile(filepath.Join(vaultDir, "synthetic-budget-consumer"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
					if e != nil {
						return e
					}
					block := bytes.Repeat([]byte{0x5a}, 64<<10)
					for i := 0; i < 256; i++ {
						if _, e = f.Write(block); e != nil {
							f.Close()
							return e
						}
					}
					if e = f.Sync(); e != nil {
						f.Close()
						return e
					}
					if e = f.Close(); e != nil {
						return e
					}
				}
				return lease.Check(c)
			}
			if _, e := saveObjectEvidence(ctx, evidenceDB, evidenceRoot, receiver, pin, sourceEvidenceRef{Digest: sourceDigest}, m.MediaID, scope, proofEnvelope, tight, evidenceFixtureAcquire(burnGuard)); e == nil || !strings.Contains(e.Error(), "disk budget exceeded") || !consumed {
				t.Fatal("concurrent disk pressure accepted", e)
			}
			if ok, e := recoverObjectEvidence(ctx, evidenceDB, evidenceRoot, receiver, pin, objectRef, acquireEvidence); e != nil || !ok {
				t.Fatal("disk rejection damaged prior evidence", e)
			}
			diskRoot, e = os.OpenRoot(vaultDir)
			if e != nil {
				t.Fatal(e)
			}
			_, freeAfter, e := fsutil.DiskUsage(diskRoot)
			diskRoot.Close()
			if e != nil {
				t.Fatal(e)
			}
			t.Logf("object_disk_pressure free_before=%d free_after=%d minimum_free=%d reserve=%d", freeBefore, freeAfter, tight.MinimumFreeBytes, tight.TransactionReserveBytes)
			// Grow WAL in an isolated temporary database and verify the configured
			// WAL headroom is enforced before a new proof can be committed.
			walWriter, e := sql.Open("sqlite", vaultPath)
			if e != nil {
				t.Fatal(e)
			}
			if _, e = walWriter.Exec("PRAGMA wal_autocheckpoint=0"); e != nil {
				t.Fatal(e)
			}
			if _, e = walWriter.Exec("CREATE TABLE budget_noise(v BLOB)"); e != nil {
				t.Fatal(e)
			}
			if _, e = walWriter.Exec("INSERT INTO budget_noise VALUES(zeroblob(?))", 26<<20); e != nil {
				t.Fatal(e)
			}
			walInfo, e := os.Stat(vaultPath + "-wal")
			if e != nil || walInfo.Size() < 24<<20 {
				t.Fatal("WAL fixture did not grow", e)
			}
			walTight := objectEvidenceTestBudget()
			walTight.MaximumWALBytes = objectEvidenceWALFloor
			if _, e = saveObjectEvidence(ctx, evidenceDB, evidenceRoot, receiver, pin, sourceEvidenceRef{Digest: sourceDigest}, m.MediaID, scope, proofEnvelope, walTight, acquireEvidence); e == nil || !strings.Contains(e.Error(), "disk budget exceeded") {
				t.Fatal("WAL headroom failure not enforced", e)
			}
			t.Logf("object_wal_pressure wal_bytes=%d maximum_wal=%d", walInfo.Size(), walTight.MaximumWALBytes)
			if e = walWriter.Close(); e != nil {
				t.Fatal(e)
			}
			if retryRef, e := saveObjectEvidence(ctx, evidenceDB, evidenceRoot, receiver, pin, sourceEvidenceRef{Digest: sourceDigest}, m.MediaID, scope, proofEnvelope, objectEvidenceTestBudget(), acquireEvidence); e != nil || retryRef != objectRef {
				t.Fatal("object evidence retry", e)
			}
			if ok, e := recoverObjectEvidence(ctx, evidenceDB, evidenceRoot, receiver, pin, objectRef, acquireEvidence); e != nil || !ok {
				t.Fatal("object evidence recovery", e)
			}
			badProof := proofEnvelope
			badProof.Cipher = append([]byte(nil), proofEnvelope.Cipher...)
			badProof.Cipher[len(badProof.Cipher)-1] ^= 1
			if _, e := saveObjectEvidence(ctx, evidenceDB, evidenceRoot, receiver, pin, sourceEvidenceRef{Digest: sourceDigest}, m.MediaID, scope, badProof, objectEvidenceTestBudget(), acquireEvidence); e == nil {
				t.Fatal("tampered object evidence accepted")
			}
			if _, e := saveObjectEvidence(ctx, evidenceDB, evidenceRoot, receiver, pin, sourceEvidenceRef{Digest: sourceDigest}, m.MediaID, scope, proofEnvelope, objectEvidenceTestBudget(), evidenceFixtureAcquire(func(context.Context) error { return invalid("injected guard") })); e == nil {
				t.Fatal("failed evidence guard accepted")
			}
			// Let a valid, short-lived proof expire between writer admission and
			// commit. The inserted row must roll back rather than grant a retry.
			shortSigned, e := decodeObjectEvidenceProof(proofEnvelope, receiver)
			if e != nil {
				t.Fatal(e)
			}
			shortScope := scope
			shortScope.Challenge = strings.Repeat("6", 64)
			shortSigned.Proof.Challenge = shortScope.Challenge
			shortSigned.Proof.IssuedUnix = time.Now().Unix()
			shortSigned.Proof.ExpiresUnix = shortSigned.Proof.IssuedUnix + 3
			shortBody, e := json.Marshal(shortSigned.Proof)
			if e != nil {
				t.Fatal(e)
			}
			shortDigest := sha256.Sum256(shortBody)
			shortSigned.Signature, e = protocol.Sign(private, map[string]any{"kind": "frontiercloud-preprod-ssh-object-proof-v1", "sha256": hex.EncodeToString(shortDigest[:])})
			if e != nil {
				t.Fatal(e)
			}
			shortBody, e = json.Marshal(shortSigned)
			if e != nil {
				t.Fatal(e)
			}
			shortEnvelope, e := snapshotcrypt.SealObjectProof(shortBody, receiver.PublicKey().Bytes())
			if e != nil {
				t.Fatal(e)
			}
			expiryCalls := 0
			expiryGuard := func(c context.Context) error {
				expiryCalls++
				if expiryCalls == 2 {
					wait := time.Until(time.Unix(shortSigned.Proof.ExpiresUnix, 0)) + 10*time.Millisecond
					if wait > 0 {
						time.Sleep(wait)
					}
				}
				return lease.Check(c)
			}
			if _, e = saveObjectEvidence(ctx, evidenceDB, evidenceRoot, receiver, pin, sourceEvidenceRef{Digest: sourceDigest}, m.MediaID, shortScope, shortEnvelope, objectEvidenceTestBudget(), evidenceFixtureAcquire(expiryGuard)); e == nil || expiryCalls != 2 {
				t.Fatal("expired evidence committed", e, expiryCalls)
			}
			var expiredCount int
			if e = evidenceDB.QueryRow("SELECT COUNT(*) FROM preprod_object_evidence WHERE challenge_tag=?", vaultTag(evidenceRoot, "object-evidence-challenge", shortScope.Challenge)).Scan(&expiredCount); e != nil || expiredCount != 0 {
				t.Fatal("expired evidence not rolled back", e, expiredCount)
			}
			// An unrelated committed write after the authenticated read invalidates
			// SQLite's WAL snapshot; a retry must repeat all authentication.
			other, e := sql.Open("sqlite", vaultPath)
			if e != nil {
				t.Fatal(e)
			}
			defer other.Close()
			guardCalls := 0
			changedGuard := func(c context.Context) error {
				guardCalls++
				if guardCalls == 1 {
					if _, e := other.ExecContext(c, "UPDATE preprod_source_evidence SET challenge_tag=challenge_tag || 'x'"); e != nil {
						return e
					}
				}
				return lease.Check(c)
			}
			if _, e := saveObjectEvidence(ctx, evidenceDB, evidenceRoot, receiver, pin, sourceEvidenceRef{Digest: sourceDigest}, m.MediaID, scope, proofEnvelope, objectEvidenceTestBudget(), evidenceFixtureAcquire(changedGuard)); e == nil {
				t.Fatal("stale WAL snapshot was accepted")
			}
			if _, e = other.ExecContext(ctx, "UPDATE preprod_source_evidence SET challenge_tag=?", vaultTag(evidenceRoot, "source-evidence-challenge", challenge)); e != nil {
				t.Fatal(e)
			}
			// A writer committing after final source comparison must prevent the
			// old SQLite WAL snapshot from being upgraded to a writer.
			stale, e := evidenceDB.BeginTx(ctx, nil)
			if e != nil {
				t.Fatal(e)
			}
			var oldTag string
			if e = stale.QueryRowContext(ctx, "SELECT challenge_tag FROM preprod_source_evidence").Scan(&oldTag); e != nil {
				t.Fatal(e)
			}
			if _, e = other.ExecContext(ctx, "UPDATE preprod_source_evidence SET challenge_tag=challenge_tag"); e != nil {
				t.Fatal(e)
			}
			if _, e = stale.ExecContext(ctx, "UPDATE preprod_object_evidence SET cipher=cipher WHERE evidence_tag=?", tagForEvidence(t, evidenceRoot, objectRef)); e == nil {
				stale.Rollback()
				t.Fatal("stale read snapshot promoted")
			}
			stale.Rollback()
			if ok, e := recoverObjectEvidence(ctx, evidenceDB, evidenceRoot, receiver, pin, objectRef, acquireEvidence); e != nil || !ok {
				t.Fatal("revalidation after conflict", e)
			}
			if _, err := observePlainOrLyric(ctx, app, nv, target, lease, evidenceDB, evidenceRoot, envelope, lyricProof, challenge, complete, lyricID, lyricScope); err == nil {
				t.Fatal("unordered lyric coordinator must remain disabled")
			}
			lyricRef, err := saveObjectEvidence(ctx, evidenceDB, evidenceRoot, receiver, pin, sourceEvidenceRef{Digest: sourceDigest}, lyricID, lyricScope, lyricProof, objectEvidenceTestBudget(), acquireEvidence)
			if err != nil {
				t.Fatal("save lyric object evidence", err)
			}
			if ok, e := recoverObjectEvidence(ctx, evidenceDB, evidenceRoot, receiver, pin, lyricRef, acquireEvidence); e != nil || !ok {
				t.Fatal("lyric object evidence", e)
			}
			var sealedObject []byte
			tag, e := objectEvidenceTag(evidenceRoot, objectRef.Digest)
			if e != nil {
				t.Fatal(e)
			}
			if e = evidenceDB.QueryRow("SELECT cipher FROM preprod_object_evidence WHERE evidence_tag=?", tag).Scan(&sealedObject); e != nil {
				t.Fatal(e)
			}
			if bytes.Contains(sealedObject, []byte(m.Path)) || bytes.Contains(sealedObject, []byte(m.MediaID)) {
				t.Fatal("object evidence exposed private facts")
			}
			for _, file := range []string{vaultPath, vaultPath + "-wal"} {
				link := file + ".synthetic-link"
				if e = os.Link(file, link); e != nil {
					t.Fatal(e)
				}
				if _, e = saveObjectEvidence(ctx, evidenceDB, evidenceRoot, receiver, pin, sourceEvidenceRef{Digest: sourceDigest}, m.MediaID, scope, proofEnvelope, objectEvidenceTestBudget(), acquireEvidence); e == nil {
					t.Fatal("hardlinked database or WAL accepted")
				}
				if e = os.Remove(link); e != nil {
					t.Fatal(e)
				}
			}
			// A reopened evidence store must authenticate its durable record again.
			// This models connection loss, not a process crash or publication.
			if err = evidenceDB.Close(); err != nil {
				t.Fatal(err)
			}
			childInput, e := json.Marshal(objectEvidenceRestartInput{Path: vaultPath, Root: evidenceRoot, Receiver: receiver.Bytes(), Pin: pin, Video: objectRef, Lyric: lyricRef})
			if e != nil {
				t.Fatal(e)
			}
			child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestObjectEvidenceRestartChild$")
			child.Env = append(os.Environ(), "FC_OBJECT_EVIDENCE_RESTART_CHILD=1")
			child.Stdin = bytes.NewReader(childInput)
			if output, e := child.CombinedOutput(); e != nil {
				t.Fatalf("restart evidence child failed: %v %s", e, output)
			}
			evidenceDB, err = sql.Open("sqlite", vaultPath)
			if err != nil {
				t.Fatal(err)
			}
			defer evidenceDB.Close()
			evidenceDB.SetMaxOpenConns(1)
			if _, err = evidenceDB.Exec("PRAGMA synchronous=FULL"); err != nil {
				t.Fatal(err)
			}
			if ok, e := recoverSourceEvidence(ctx, evidenceDB, evidenceRoot, receiver, pin, sourceEvidenceRef{Digest: sourceDigest}, func(c context.Context) error { return lease.Check(c) }); e != nil || !ok {
				t.Fatal("reopened source evidence", e)
			}
			if ok, e := recoverObjectEvidence(ctx, evidenceDB, evidenceRoot, receiver, pin, objectRef, acquireEvidence); e != nil || !ok {
				t.Fatal("reopened object evidence", e)
			}
			if ok, e := recoverObjectEvidence(ctx, evidenceDB, evidenceRoot, receiver, pin, lyricRef, acquireEvidence); e != nil || !ok {
				t.Fatal("reopened lyric evidence", e)
			}
			sealedObject[len(sealedObject)-1] ^= 1
			if _, e = evidenceDB.Exec("UPDATE preprod_object_evidence SET cipher=? WHERE evidence_tag=?", sealedObject, tag); e != nil {
				t.Fatal(e)
			}
			if ok, e := recoverObjectEvidence(ctx, evidenceDB, evidenceRoot, receiver, pin, objectRef, acquireEvidence); e == nil || ok {
				t.Fatal("tampered durable object evidence accepted")
			}
			if ok, e := recoverObjectEvidence(ctx, evidenceDB, evidenceRoot, receiver, pin, lyricRef, acquireEvidence); e != nil || !ok {
				t.Fatal("unrelated lyric evidence damaged", e)
			}
			if _, e := observePlainOrLyric(ctx, app, nv, target, lease, evidenceDB, evidenceRoot, envelope, lyricProof, challenge, complete, lyricID, lyricScope); e == nil {
				t.Fatal("reopened unordered coordinator must remain disabled")
			}
			// An oversized valid-shape ciphertext is rejected by SQL length before
			// it is copied into application memory; rollback preserves the source.
			oversized, e := evidenceDB.BeginTx(ctx, nil)
			if e != nil {
				t.Fatal(e)
			}
			if _, e = oversized.ExecContext(ctx, "UPDATE preprod_source_evidence SET cipher=zeroblob(?)", objectEvidenceMaxSourceCipherBytes+1); e != nil {
				t.Fatal(e)
			}
			if _, e = readObjectSourceRow(ctx, oversized, evidenceRoot, sourceEvidenceRef{Digest: sourceDigest}); e == nil {
				oversized.Rollback()
				t.Fatal("oversized source copied")
			}
			oversized.Rollback()
			if ok, e := recoverObjectEvidence(ctx, evidenceDB, evidenceRoot, receiver, pin, lyricRef, acquireEvidence); e != nil || !ok {
				t.Fatal("source changed after size rejection", e)
			}
			lease.Release()
			if _, err = observePlainOrLyric(ctx, app, nv, target, lease, evidenceDB, evidenceRoot, envelope, proofEnvelope, challenge, complete, m.MediaID, scope); err == nil {
				t.Fatal("released lease accepted")
			}
		})
	}
}

// The signed proof is additionally required to expire no later than the source.
// Test both cutoff comparisons explicitly; the second case is defensive even
// though source-before-proof is rejected earlier by proof verification.
func TestObjectEvidenceCommitChecksBothDeadlines(t *testing.T) {
	now := time.Unix(1000, 0)
	if objectEvidenceExpired(now, 1001, 1001) {
		t.Fatal("unexpired evidence rejected")
	}
	if !objectEvidenceExpired(now, 1000, 1001) {
		t.Fatal("expired object proof accepted")
	}
	if !objectEvidenceExpired(now, 1001, 1000) {
		t.Fatal("expired source snapshot accepted")
	}
}

// All input below is synthetic and sent over stdin. The child reopens the
// database in a new process; its guard is a test stub, not a production lease.
type objectEvidenceRestartInput struct {
	Path         string
	Root         []byte
	Receiver     []byte
	Pin          sourceAuthorityPin
	Video, Lyric objectEvidenceRef
}

func TestObjectEvidenceRestartChild(t *testing.T) {
	if os.Getenv("FC_OBJECT_EVIDENCE_RESTART_CHILD") != "1" {
		return
	}
	var input objectEvidenceRestartInput
	if err := json.NewDecoder(os.Stdin).Decode(&input); err != nil {
		t.Fatal(err)
	}
	receiver, err := ecdh.X25519().NewPrivateKey(input.Receiver)
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", input.Path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	if _, err = db.Exec("PRAGMA synchronous=FULL"); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	guard := func(c context.Context) error { return c.Err() }
	for _, ref := range []objectEvidenceRef{input.Video, input.Lyric} {
		if ok, e := recoverObjectEvidence(ctx, db, input.Root, receiver, input.Pin, ref, evidenceFixtureAcquire(guard)); e != nil || !ok {
			t.Fatal("restart evidence invalid", e)
		}
	}
}

type evidenceFixtureLease struct{ check func(context.Context) error }

func (l evidenceFixtureLease) Check(ctx context.Context) error { return l.check(ctx) }
func (evidenceFixtureLease) Release()                          {}
func evidenceFixtureAcquire(check func(context.Context) error) objectEvidenceAcquire {
	return func(context.Context) (objectEvidenceLease, error) { return evidenceFixtureLease{check: check}, nil }
}

type trackedEvidenceLease struct{ releases int }

func (l *trackedEvidenceLease) Check(context.Context) error { return nil }
func (l *trackedEvidenceLease) Release()                    { l.releases++ }
func TestObjectEvidenceRejectsInvalidGuardAndReleasesOnError(t *testing.T) {
	ctx := context.Background()
	var typedNil *trackedEvidenceLease
	if _, err := acquireObjectEvidenceLease(ctx, func(context.Context) (objectEvidenceLease, error) { return typedNil, nil }); err == nil {
		t.Fatal("typed nil guard accepted")
	}
	l := &trackedEvidenceLease{}
	if _, err := acquireObjectEvidenceLease(ctx, func(context.Context) (objectEvidenceLease, error) { return l, invalid("injected") }); err == nil || l.releases != 1 {
		t.Fatal("failed acquisition leaked guard", err, l.releases)
	}
}

func tagForEvidence(t *testing.T, root []byte, ref objectEvidenceRef) string {
	t.Helper()
	tag, err := objectEvidenceTag(root, ref.Digest)
	if err != nil {
		t.Fatal(err)
	}
	return tag
}

func TestObjectEvidenceSingleProcessBudget(t *testing.T) {
	ctx, release, err := enterObjectEvidence(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	deadline, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, done, e := enterObjectEvidence(deadline); e == nil {
		done()
		t.Fatal("concurrent budget accepted")
	}
	if ctx.Err() != nil {
		t.Fatal("first budget unexpectedly canceled")
	}
}

func objectEvidenceTestBudget() objectEvidenceDiskBudget {
	return objectEvidenceDiskBudget{MinimumFreeBytes: objectEvidenceFreeFloor, TransactionReserveBytes: objectEvidenceReserveFloor, MaximumWALBytes: 128 << 20}
}
