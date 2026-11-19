//go:build linux && owner_publish_fixture && ledger_fixture

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
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/snapshotcrypt"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/vault"
)

// fixtureSignedSource represents only a synthetic collector observation. Its
// source authority and SSH metadata are test inputs, and neither its evidence
// reference nor its signed proof is a publication permit.
type fixtureSignedSource struct {
	Complete         completeSnapshot
	Pin              sourceAuthorityPin
	Envelope         store.EncryptedMediaSourceSnapshot
	Receiver         *ecdh.PrivateKey
	Challenge        string
	SourceDigest     string
	Source           store.MediaSourceSnapshot
	CollectorPrivate string
	EvidenceDB       *sql.DB
	EvidencePath     string
	EvidenceRoot     []byte
	EvidenceRef      sourceEvidenceRef
	Media            Media
}

// The Master identity and vault are genuine test fixtures already created by
// the caller. The selected source media is plaintext audio, owned by the
// source member whose explicit target mapping is the supplied Owner.
func makeSignedSourceForOwnerFixture(t *testing.T, master store.Store, masterVault *vault.Vault, ownerID, mediaID, objectID string, data []byte) fixtureSignedSource {
	t.Helper()
	ctx := context.Background()
	identity, e := master.Nodes().ReadIdentity(ctx)
	if e != nil || identity.Role != "Master" {
		t.Fatal("master identity", e)
	}
	encoded, e := masterVault.Unseal(identity.PrivateKey)
	if e != nil {
		t.Fatal(e)
	}
	masterSeed, e := protocol.Decode(encoded)
	if e != nil || len(masterSeed) != ed25519.SeedSize {
		t.Fatal("master seed", e)
	}
	defer clear(masterSeed)
	receiver, e := receiverFromMasterSeed(masterSeed)
	if e != nil {
		t.Fatal(e)
	}
	projection, _, _, _ := fixture(t)
	projection.Mappings[0].TargetID = identity.ID
	projection.Mappings[1].TargetID = ownerID
	// Keep the other source object independent of the selected physical object.
	projection.Media[0].ObjectID = strings.Repeat("9", 64)
	selected := projection.Media[1]
	selected.MediaID = mediaID
	selected.ObjectID = objectID
	selected.Path = "music/fixture/track.mp3"
	selected.Kind = "audio"
	selected.Size = int64(len(data))
	selected.SHA256 = digest(data)
	selected.Encryption = nil
	projection.Media[1] = selected
	complete := completeSourceFixture(projection)
	for _, m := range projection.Media {
		complete.Facts.Objects = append(complete.Facts.Objects, sourceObjectFact{ID: m.MediaID, Kind: m.Kind, Path: m.Path, CreatedAt: "1", UpdatedAt: "2"})
	}
	for i := range complete.Facts.Placements {
		if complete.Facts.Placements[i].MediaID == mediaID {
			complete.Facts.Placements[i].ETag = `W/"legacy"`
		}
	}
	generation, e := completeSnapshotDigest(complete)
	if e != nil {
		t.Fatal("projection digest", e)
	}
	collector := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32))
	collectorPrivate := protocol.Encode(collector.Seed())
	pin := sourceAuthorityPin{Version: 1, Purpose: "frontiercloud:preprod-source-authority:v1", AuthorityKind: "ssh-collector-v1", SourceSSHHostKeySHA256: strings.Repeat("a", 64), SourceTLSOrigin: "https://source.test", SourceTLSSPKISHA256: strings.Repeat("b", 64), SourceNode: projection.Mappings[0].SourceID, SourceKeyID: projection.PremasterKeyID, SourcePublic: collector.Public().(ed25519.PublicKey), TargetNode: identity.ID, TargetMasterPublic: ed25519.NewKeyFromSeed(masterSeed).Public().(ed25519.PublicKey), TargetX25519: receiver.PublicKey().Bytes(), Generation: generation}
	pin.ImportScope = syntheticImportScope(projection)
	for _, m := range projection.Mappings {
		pin.SourceOwners = append(pin.SourceOwners, sourceOwnerPin{NodeID: m.SourceID, SSHHostKeySHA256: pin.SourceSSHHostKeySHA256})
	}
	if e = provisionSourceAuthority(ctx, master, masterVault, pin); e != nil {
		t.Fatal("pin provisioning", e)
	}
	source := syntheticSourceForComplete(complete)
	now := time.Now().UTC().Truncate(time.Second)
	challenge := strings.Repeat("1", 64)
	source.Version = 1
	source.AuthorityKind = pin.AuthorityKind
	source.SourceSSHHostKeySHA256 = pin.SourceSSHHostKeySHA256
	source.SourceNode = pin.SourceNode
	source.SourcePublic = protocol.Encode(pin.SourcePublic)
	source.TargetNode = pin.TargetNode
	source.TargetReceiver = pin.TargetX25519
	source.Challenge = challenge
	source.IssuedUnix = now.Unix()
	source.ExpiresUnix = now.Add(3 * time.Minute).Unix()
	raw, e := json.Marshal(source)
	if e != nil {
		t.Fatal(e)
	}
	hash := sha256.Sum256(raw)
	clear(raw)
	signature, e := protocol.Sign(collectorPrivate, map[string]any{"kind": "frontiercloud-preprod-media-source-v1", "sha256": hex.EncodeToString(hash[:]), "source_node": source.SourceNode, "target_node": source.TargetNode, "challenge": challenge})
	if e != nil {
		t.Fatal(e)
	}
	envelope, e := snapshotcrypt.Seal(store.SignedMediaSourceSnapshot{Snapshot: source, Signature: signature}, receiver.PublicKey().Bytes())
	if e != nil {
		t.Fatal(e)
	}
	_, sourceDigest, e := authenticateCompleteSource(envelope, receiver, pin, challenge, now, complete)
	if e != nil {
		t.Fatal("source authentication", e)
	}
	dir := t.TempDir()
	if e = os.Chmod(dir, 0700); e != nil {
		t.Fatal(e)
	}
	dbPath := filepath.Join(dir, "source-vault.sqlite")
	file, e := os.OpenFile(dbPath, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if e != nil {
		t.Fatal(e)
	}
	if e = file.Close(); e != nil {
		t.Fatal(e)
	}
	evidence, e := sql.Open("sqlite", dbPath)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = evidence.Close() })
	evidence.SetMaxOpenConns(1)
	for _, q := range []string{"PRAGMA journal_mode=WAL", "PRAGMA synchronous=FULL", "CREATE TABLE preprod_source_evidence(evidence_tag TEXT PRIMARY KEY,salt BLOB NOT NULL UNIQUE,nonce BLOB NOT NULL,cipher BLOB NOT NULL,challenge_tag TEXT NOT NULL UNIQUE)", "CREATE TABLE preprod_object_evidence(evidence_tag TEXT PRIMARY KEY,salt BLOB NOT NULL UNIQUE,nonce BLOB NOT NULL,cipher BLOB NOT NULL,challenge_tag TEXT NOT NULL UNIQUE)", "CREATE TABLE legacy_key_vault_meta(singleton INTEGER PRIMARY KEY,verifier TEXT NOT NULL)"} {
		if _, e = evidence.Exec(q); e != nil {
			t.Fatal(e)
		}
	}
	root := bytes.Repeat([]byte{12}, 32)
	if _, e = evidence.Exec("INSERT INTO legacy_key_vault_meta VALUES(1,?)", legacyVaultTag(root, "verifier", pin.TargetNode)); e != nil {
		t.Fatal(e)
	}
	ref, e := saveSourceEvidence(ctx, evidence, root, receiver, pin, envelope, challenge, complete, now, func(c context.Context) error { return c.Err() })
	if e != nil {
		t.Fatal("source evidence", e)
	}
	return fixtureSignedSource{Complete: complete, Pin: pin, Envelope: envelope, Receiver: receiver, Challenge: challenge, SourceDigest: sourceDigest, Source: source, CollectorPrivate: collectorPrivate, EvidenceDB: evidence, EvidencePath: dbPath, EvidenceRoot: root, EvidenceRef: ref, Media: selected}
}

// objectProof binds a signed synthetic owner observation to the exact target
// pending locator. Its device/inode values are fixture facts, not an SSH read.
func (f fixtureSignedSource) objectProof(t *testing.T, scope objectProofScope) store.EncryptedMediaSourceSnapshot {
	t.Helper()
	facts, e := sourceObjectFactsDigest(f.Source, f.Media)
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now().UTC().Truncate(time.Second)
	proof := sshObjectProof{Version: 1, SourceNode: f.Pin.SourceNode, SourceOwnerID: f.Media.SourceID, OwnerSSHHostKeySHA256: f.Pin.SourceSSHHostKeySHA256, SourceSnapshotDigest: f.SourceDigest, BeforeFactsSHA256: facts, AfterFactsSHA256: facts, MediaID: f.Media.MediaID, SourceObjectID: f.Media.ObjectID, Path: f.Media.Path, SHA256: f.Media.SHA256, Size: f.Media.Size, Device: 1, Inode: 2, MtimeNS: 3, CtimeNS: 4, TargetNode: f.Pin.TargetNode, TargetOwnerID: scope.TargetOwnerID, TargetBlobID: scope.TargetBlobID, TargetReadAlias: scope.TargetReadAlias, Challenge: scope.Challenge, IssuedUnix: now.Unix(), ExpiresUnix: now.Add(2 * time.Minute).Unix()}
	raw, e := json.Marshal(proof)
	if e != nil {
		t.Fatal(e)
	}
	hash := sha256.Sum256(raw)
	clear(raw)
	sig, e := protocol.Sign(f.CollectorPrivate, map[string]any{"kind": "frontiercloud-preprod-ssh-object-proof-v1", "sha256": hex.EncodeToString(hash[:])})
	if e != nil {
		t.Fatal(e)
	}
	raw, e = json.Marshal(signedSSHObjectProof{Proof: proof, Signature: sig})
	if e != nil {
		t.Fatal(e)
	}
	defer clear(raw)
	envelope, e := snapshotcrypt.SealObjectProof(raw, f.Receiver.PublicKey().Bytes())
	if e != nil {
		t.Fatal(e)
	}
	return envelope
}
