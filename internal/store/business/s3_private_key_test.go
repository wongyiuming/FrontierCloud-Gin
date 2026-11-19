package business_test

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"regexp"
	"strings"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store/business"
)

func TestS3NewKeyIsIndependentAndLegacyKeysRemainRecoverable(t *testing.T) {
	f := newS3SQL(t, true)
	f.add(t, "tenant", true)
	first := f.reserve(t, "music/PrivateArtist/PrivateSong.mp3", 1024, nil)
	second := f.reserve(t, "music/PrivateArtist/AnotherSong.mp3", 1024, nil)
	shape := regexp.MustCompile(`^objects/([0-9a-f]{2})/([0-9a-f]{2})/([0-9a-f]{64})\.blob$`)
	for _, upload := range []store.S3Upload{first, second} {
		match := shape.FindStringSubmatch(upload.Key)
		if match == nil || match[1] != match[3][:2] || match[2] != match[3][2:4] {
			t.Fatalf("unexpected opaque key %q", upload.Key)
		}
		if strings.Contains(upload.Key, upload.Reservation.ID) || strings.Contains(upload.Key, upload.Reservation.MediaID) || strings.Contains(upload.Key, "Private") {
			t.Fatal("physical key contains upload, media or path")
		}
		if !store.ValidS3MetadataBinding(upload.Proof.MetadataFormat, upload.Key, upload.Proof.MetadataOwner) || strings.Contains(upload.Key, upload.Proof.MetadataOwner) || upload.Proof.MetadataOwner == upload.Reservation.MediaID {
			t.Fatal("provider ownership marker is not independently random")
		}
		// The provider observes both values in metadata. The old identity
		// construction allowed offline verification of each guessed path.
		old := sha256.Sum256([]byte(upload.Reservation.ID + ":" + upload.Reservation.Path))
		if upload.Reservation.MediaID == hex.EncodeToString(old[:]) {
			t.Fatal("media identity is derivable from provider metadata and a guessed path")
		}
		again, err := business.New(f.raw, f.db.Backend()).S3Upload(f.ctx, upload.Reservation.ID)
		if err != nil || again.Key != upload.Key || again.Reservation.MediaID != upload.Reservation.MediaID || again.Proof.MetadataOwner != upload.Proof.MetadataOwner {
			t.Fatalf("restart changed durable upload intent: %#v %v", again, err)
		}
	}
	if first.Key == second.Key || first.Reservation.MediaID == second.Reservation.MediaID {
		t.Fatal("distinct uploads shared random identities")
	}
	first, proof := f.completing(t, first)
	wrongFormat := proof
	wrongFormat.MetadataFormat = ""
	if _, err := f.repo.S3FinalizeUpload(f.ctx, first.Reservation.ID, first.Revision, wrongFormat, store.AdminAudit{}); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("provider metadata format downgrade accepted", err)
	}
	wrongOwner := proof
	wrongOwner.MetadataOwner = strings.Repeat("f", 64)
	if _, err := f.repo.S3FinalizeUpload(f.ctx, first.Reservation.ID, first.Revision, wrongOwner, store.AdminAudit{}); !errors.Is(err, store.ErrNodeState) {
		t.Fatal("provider ownership marker substitution accepted", err)
	}
	object, err := f.repo.S3FinalizeUpload(f.ctx, first.Reservation.ID, first.Revision, proof, store.AdminAudit{})
	if err != nil {
		t.Fatal(err)
	}
	stored, err := f.repo.S3Object(f.ctx, object.ID)
	if err != nil || stored.Proof.Key != first.Key {
		t.Fatal("completed object lost its reserved key", err)
	}
	if _, err := f.repo.S3FinalizeUpload(f.ctx, first.Reservation.ID, first.Revision, proof, store.AdminAudit{}); err != nil {
		t.Fatal("completion retry changed", err)
	}

	// Historical sessions retain their original provider names and proofs.
	legacyDigest := sha256.Sum256([]byte(second.Reservation.ID + ":" + second.Reservation.Path))
	legacyID := hex.EncodeToString(legacyDigest[:])
	legacyKey := "objects/" + legacyID + "/" + second.Reservation.ID
	if _, err := f.raw.Exec("UPDATE cluster_upload_sessions SET media_id=? WHERE upload_id=?", legacyID, second.Reservation.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.raw.Exec("UPDATE s3_uploads SET object_key=?,object_id=?,proof_json='{}' WHERE upload_id=?", legacyKey, legacyID, second.Reservation.ID); err != nil {
		t.Fatal(err)
	}
	legacy, err := business.New(f.raw, f.db.Backend()).S3Upload(f.ctx, second.Reservation.ID)
	if err != nil || legacy.Key != legacyKey {
		t.Fatal("historical upload key was changed", err)
	}
	legacy, legacyProof := f.completing(t, legacy)
	legacyObject, err := f.repo.S3FinalizeUpload(f.ctx, legacy.Reservation.ID, legacy.Revision, legacyProof, store.AdminAudit{})
	if err != nil {
		t.Fatal(err)
	}
	stored, err = f.repo.S3Object(f.ctx, legacyObject.ID)
	if err != nil || stored.Proof.Key != legacyKey {
		t.Fatal("historical object key was changed during completion", err)
	}
}
