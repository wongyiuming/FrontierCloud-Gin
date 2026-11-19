package recovery_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/recovery"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store/sqlite"
	"github.com/wongyiuming/FrontierCloud-Gin/migrations"
)

// This is an offline physical SQLite archive test. It does not restore the
// independent S3 provider object or establish provider ownership.
func TestSQLiteArchiveRestorePreservesS3MetadataProof(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	data := filepath.Join(root, "source-data")
	secrets := filepath.Join(root, "source-secrets")
	db, err := sqlite.Open(filepath.Join(data, "frontiercloud.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err = db.Initialize(ctx); err != nil {
		t.Fatal(err)
	}
	identity, err := node.Initialize(ctx, db.Nodes(), secrets)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Nodes().PromoteIdentity(ctx, store.NodePromotion{Role: "Master", Endpoint: "https://master.test", Allocation: 20 * store.GiB, PhysicalFree: 5 * store.GiB}, store.NodeAudit{}); err != nil {
		t.Fatal(err)
	}
	repo := db.Pool().(store.S3Repository)
	sealed := "fixture-sealed-credentials"
	config := store.S3MemberConfiguration{Name: "fixture", Location: store.S3Location{Endpoint: "https://s3.us-east-1.amazonaws.com", Bucket: "fc-fixture", Region: "us-east-1", Prefix: "tenant", Style: "path"}, Quota: 20 * store.GiB, SealedCredentials: &sealed}
	member, err := repo.S3AddMember(ctx, config, store.NodeAudit{})
	if err != nil {
		t.Fatal(err)
	}
	probe, err := repo.S3StartProbe(ctx, member.ID, member.Revision, store.NodeAudit{})
	if err != nil {
		t.Fatal(err)
	}
	member, err = repo.S3FinishProbe(ctx, probe.ID, probe.Revision, store.S3ProbeResult{Key: probe.Key, ProviderUploadID: "probe-upload", VersionID: "probe-version", ETag: "probe-etag", ChecksPassed: true, CleanupSettled: true}, store.NodeAudit{})
	if err != nil {
		t.Fatal(err)
	}
	config.SealedCredentials = nil
	config.Enabled = true
	member, err = repo.S3ConfigureMember(ctx, member.ID, member.Revision, config, store.NodeAudit{})
	if err != nil {
		t.Fatal(err)
	}
	reservation, err := db.Pool().(store.EncryptionRepository).ReserveEncryptedUpload(ctx, "music/Fixture/private.mp3", "s3", 7, 0, store.AdminAudit{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	upload, err := repo.S3Upload(ctx, reservation.ID)
	if err != nil {
		t.Fatal(err)
	}
	upload, err = repo.S3StartCreate(ctx, upload.Reservation.ID, upload.Revision)
	if err != nil {
		t.Fatal(err)
	}
	upload, err = repo.S3FinishCreate(ctx, upload.Reservation.ID, upload.Revision, "fixture-provider-upload", "created", "")
	if err != nil {
		t.Fatal(err)
	}
	partHash := sha256.Sum256([]byte("synthetic"))
	checksum := base64.StdEncoding.EncodeToString(partHash[:])
	part, err := repo.S3IssuePart(ctx, upload.Reservation.ID, 1, checksum, upload.Reservation.ExpectedBytes)
	if err != nil {
		t.Fatal(err)
	}
	part.ETag = "fixture-part-etag"
	upload, err = repo.S3ConfirmPart(ctx, upload.Reservation.ID, part)
	if err != nil {
		t.Fatal(err)
	}
	upload, err = repo.S3StartComplete(ctx, upload.Reservation.ID, upload.Revision)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(partHash[:])
	proof := store.S3ObjectProof{MetadataFormat: upload.Proof.MetadataFormat, MetadataOwner: upload.Proof.MetadataOwner, Key: upload.Key, SessionID: upload.Reservation.ID, ObjectID: upload.ObjectID, MemberID: upload.Reservation.MemberID, MediaID: upload.Reservation.MediaID, Bytes: upload.Reservation.ExpectedBytes, ETag: "fixture-object-etag", VersionID: "fixture-version", CompositeSHA256: base64.StdEncoding.EncodeToString(sum[:]) + "-1"}
	if proof.MetadataFormat != store.S3OpaqueMetadata {
		t.Fatal("new upload lacked metadata format")
	}
	media, err := repo.S3FinalizeUpload(ctx, upload.Reservation.ID, upload.Revision, proof, store.AdminAudit{})
	if err != nil {
		t.Fatal(err)
	}
	before, err := repo.S3Object(ctx, media.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before.Proof, proof) {
		t.Fatal("source proof mismatch")
	}
	var sourceGeneration int
	if err = db.Database().QueryRow("SELECT generation FROM frontiercloud_schema WHERE singleton=1").Scan(&sourceGeneration); err != nil || sourceGeneration != migrations.Generation {
		t.Fatal("source schema generation", sourceGeneration, err)
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	manifest := recovery.Manifest{NodeID: identity.ID, Role: "Master", Revision: strings.Repeat("b", 40), Database: "sqlite", Consistency: "native-offline-and-deployment-writers-stopped", KeyReferences: []string{"runtime_secrets/node-vault.key"}}
	archive := filepath.Join(root, "state.tar")
	created, err := recovery.Create(ctx, archive, manifest, []recovery.Root{{Class: "data", Directory: data}, {Class: "runtime_secrets", Directory: secrets}})
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "restored")
	if _, err = recovery.Apply(ctx, archive, target, created.SHA256, identity.ID); err != nil {
		t.Fatal(err)
	}
	restored, err := sqlite.OpenReadOnly(ctx, filepath.Join(target, "data", "frontiercloud.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	restoredIdentity, err := node.OpenExisting(ctx, restored.Nodes(), filepath.Join(target, "runtime_secrets"))
	if err != nil || restoredIdentity.ID != identity.ID {
		t.Fatal("restored identity", err)
	}
	var restoredGeneration int
	if err = restored.Database().QueryRow("SELECT generation FROM frontiercloud_schema WHERE singleton=1").Scan(&restoredGeneration); err != nil || restoredGeneration != sourceGeneration {
		t.Fatal("restored schema generation", restoredGeneration, err)
	}
	after, err := restored.Pool().(store.S3Repository).S3Object(ctx, media.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(after.Proof, before.Proof) || after.Media.ID != before.Media.ID || after.Media.MemberID != member.ID {
		t.Fatal("restored S3 proof or identity changed")
	}
}
