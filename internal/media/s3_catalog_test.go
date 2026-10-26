package media

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	sqlitestore "github.com/wongyiuming/FrontierCloud-Gin/internal/store/sqlite"
)

// This fixture exercises real authoritative SQL transitions with synthetic
// control-plane observations. It creates no provider or native storage peer.
func s3CatalogFixture(t *testing.T) (string, *sqlitestore.Store, *Service, store.S3Member) {
	t.Helper()
	root, db, service := masterFixture(t)
	ctx := context.Background()
	repository := db.Pool().(store.S3Repository)
	sealed := "sealed-catalog-fixture-credential"
	config := store.S3MemberConfiguration{Name: "Catalog object store", Location: store.S3Location{Endpoint: "https://object-store.example.test", Bucket: "catalog-fixture", Region: "us-east-1", Prefix: "private-prefix", Style: "path"}, Quota: store.GiB, SealedCredentials: &sealed}
	member, err := repository.S3AddMember(ctx, config, store.NodeAudit{})
	if err != nil {
		t.Fatal(err)
	}
	probe, err := repository.S3StartProbe(ctx, member.ID, member.Revision, store.NodeAudit{})
	if err != nil {
		t.Fatal(err)
	}
	member, err = repository.S3FinishProbe(ctx, probe.ID, probe.Revision, store.S3ProbeResult{Key: probe.Key, ProviderUploadID: "probe-upload", VersionID: "probe-version", ETag: "probe-etag", ChecksPassed: true, CleanupSettled: true}, store.NodeAudit{})
	if err != nil {
		t.Fatal(err)
	}
	config.SealedCredentials, config.Enabled = nil, true
	member, err = repository.S3ConfigureMember(ctx, member.ID, member.Revision, config, store.NodeAudit{})
	if err != nil {
		t.Fatal(err)
	}
	return root, db, service, member
}

func publishS3CatalogObject(t *testing.T, db *sqlitestore.Store, name string, metadata *mediacrypto.Metadata) store.GlobalMedia {
	t.Helper()
	ctx := context.Background()
	repository := db.Pool().(store.S3Repository)
	size := int64(128)
	if metadata != nil {
		size = metadata.CiphertextSize
	}
	reservation, err := db.Pool().(store.EncryptionRepository).ReserveEncryptedUpload(ctx, name, "s3", size, 0, store.AdminAudit{}, metadata)
	if err != nil {
		t.Fatal(err)
	}
	upload, err := repository.S3Upload(ctx, reservation.ID)
	if err != nil {
		t.Fatal(err)
	}
	upload, err = repository.S3StartCreate(ctx, reservation.ID, upload.Revision)
	if err != nil {
		t.Fatal(err)
	}
	upload, err = repository.S3FinishCreate(ctx, reservation.ID, upload.Revision, "provider-upload", "created", "")
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("fixture-part-observation"))
	part, err := repository.S3IssuePart(ctx, reservation.ID, 1, base64.StdEncoding.EncodeToString(digest[:]), size)
	if err != nil {
		t.Fatal(err)
	}
	part.ETag = "part-etag"
	upload, err = repository.S3ConfirmPart(ctx, reservation.ID, part)
	if err != nil {
		t.Fatal(err)
	}
	upload, err = repository.S3StartComplete(ctx, reservation.ID, upload.Revision)
	if err != nil {
		t.Fatal(err)
	}
	composite := sha256.Sum256(digest[:])
	proof := store.S3ObjectProof{Key: upload.Key, SessionID: reservation.ID, ObjectID: upload.ObjectID, MemberID: reservation.MemberID, MediaID: reservation.MediaID, Bytes: size, ETag: "provider-object-etag", VersionID: "provider-object-version", CompositeSHA256: base64.StdEncoding.EncodeToString(composite[:]) + "-1"}
	media, err := repository.S3FinalizeUpload(ctx, reservation.ID, upload.Revision, proof, store.AdminAudit{})
	if err != nil {
		t.Fatal(err)
	}
	return media
}

func TestS3CatalogAndArtworkExposeBrowserIdentityWithoutProviderAccess(t *testing.T) {
	_, db, service, member := s3CatalogFixture(t)
	ctx := context.Background()
	media := publishS3CatalogObject(t, db, "music/S3Catalog/plain.MP3", nil)
	before, err := db.Pool().(store.S3Repository).S3Object(ctx, media.ID)
	if err != nil {
		t.Fatal(err)
	}
	tracks, err := service.Catalog(ctx, "music", "music/S3Catalog", "", false)
	if err != nil || len(tracks) != 1 {
		t.Fatal(tracks, err)
	}
	service.DecorateMusicTracks(ctx, tracks)
	track := tracks[0]
	if track.Transport != "S3" || track.ObjectID != media.ObjectID || track.SizeBytes != media.Bytes || track.NativeMetadata || !track.BrowserMetadata || track.ResourceID != media.ID || !strings.HasPrefix(track.URL, "/api/v1/media/stream?") {
		t.Fatal("incomplete browser catalog identity", track)
	}
	encoded, err := json.Marshal(track)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{member.ID, member.SealedCredentials, member.Location.Endpoint, member.Location.Bucket, member.Location.Prefix, "storage_member_id", "node_id"} {
		if strings.Contains(string(encoded), secret) {
			t.Fatal("catalog exposed resource configuration", secret, string(encoded))
		}
	}
	artwork, err := service.DirectoryArtwork(ctx, "music/S3Catalog", false)
	if err != nil || len(artwork.MetadataTracks) != 1 || !artwork.MetadataTracks[0].BrowserMetadata || artwork.MetadataTracks[0].NativeMetadata || len(service.tagsCache) != 0 {
		t.Fatal("artwork requested native metadata", artwork, err)
	}
	object, err := db.Pool().(store.S3Repository).S3Object(ctx, media.ID)
	if err != nil || object.GrantUntil != before.GrantUntil {
		t.Fatal("catalog issued a provider read grant", object.GrantUntil, err)
	}
}

func TestS3MusicMetadataIgnoresLocalShadowAndKaraokeKeepsBrowserContext(t *testing.T) {
	root, db, service, _ := s3CatalogFixture(t)
	ctx := context.Background()
	media := publishS3CatalogObject(t, db, "music/S3Context/song.mp3", nil)
	before, err := db.Pool().(store.S3Repository).S3Object(ctx, media.ID)
	if err != nil {
		t.Fatal(err)
	}
	shadow := filepath.Join(root, media.Path)
	if err := os.MkdirAll(filepath.Dir(shadow), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(shadow, tagFixture(3, tagFrame(3, "TIT2", []byte("\x03Local shadow must not be read"))), 0600); err != nil {
		t.Fatal(err)
	}
	tags, err := service.MusicMetadata(ctx, media.Path, media.ID)
	if err != nil || tags.Title != "" || tags.Artist != "" || len(tags.Picture) != 0 || len(service.tagsCache) != 0 {
		t.Fatal("S3 metadata fell back to local payload", tags, err)
	}
	handle, err := service.identity.KaraokeHandle(media.ID, true)
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := service.ResolveKaraoke(ctx, handle)
	if err != nil || resolved.Transport != "S3" || resolved.ObjectID != media.ObjectID || resolved.SizeBytes != media.Bytes || resolved.Path != media.Path || resolved.ID != media.ID || resolved.Type != "audio" {
		t.Fatal("S3 karaoke context lost ownership identity", resolved, err)
	}
	metadata, err := service.KaraokeMetadata(ctx, handle)
	if err != nil || metadata.Title != "song" {
		t.Fatal("S3 karaoke metadata read payload", metadata, err)
	}
	object, err := db.Pool().(store.S3Repository).S3Object(ctx, media.ID)
	if err != nil || object.GrantUntil != before.GrantUntil {
		t.Fatal("context issued a provider read grant", object.GrantUntil, err)
	}
}

func TestS3EncryptedCatalogKeepsDescriptorAndCiphertextSize(t *testing.T) {
	_, db, service, _ := s3CatalogFixture(t)
	ctx := context.Background()
	metadata, err := mediacrypto.NewMetadata(128)
	if err != nil {
		t.Fatal(err)
	}
	media := publishS3CatalogObject(t, db, "music/S3Encrypted/song.mp3", &metadata)
	tracks, err := service.Catalog(ctx, "music", "music/S3Encrypted", "", false)
	if err != nil || len(tracks) != 1 {
		t.Fatal(tracks, err)
	}
	descriptors, err := service.Encryptions(ctx, []string{media.ID})
	if err != nil {
		t.Fatal(err)
	}
	tracks[0].Encryption = descriptors[media.ID]
	service.DecorateMusicTracks(ctx, tracks)
	if tracks[0].Encryption == nil || *tracks[0].Encryption != metadata || tracks[0].SizeBytes != metadata.CiphertextSize || tracks[0].NativeMetadata || tracks[0].BrowserMetadata {
		t.Fatal("encrypted S3 catalog crossed metadata boundary", tracks[0])
	}
	object, err := service.CryptoObject(ctx, media.Path, media.ID, false)
	if err != nil || object.Encryption == nil || *object.Encryption != metadata {
		t.Fatal("S3 crypto context used a local object", object, err)
	}
	if tags, err := service.MusicMetadata(ctx, media.Path, media.ID); err != nil || tags.Title != "" || len(service.tagsCache) != 0 {
		t.Fatal("encrypted S3 metadata attempted a payload read", tags, err)
	}
}

func TestS3AdminTreePreservesSizeAndOpaqueObjectIdentity(t *testing.T) {
	_, db, service, _ := s3CatalogFixture(t)
	ctx := context.Background()
	media := publishS3CatalogObject(t, db, "music/S3Tree/song.mp3", nil)
	tree, err := service.Tree(ctx, "music/S3Tree")
	if err != nil || len(tree.Items) != 1 {
		t.Fatal(tree, err)
	}
	item := tree.Items[0]
	if item.Transport != "S3" || item.MediaID != media.ID || item.ObjectID != media.ObjectID || item.Size == nil || item.SizeBytes == nil || *item.Size != media.Bytes || *item.SizeBytes != media.Bytes || item.StorageAddress != nil || item.StorageAddressLocal {
		t.Fatal("S3 tree borrowed a local/peer address", item)
	}
	encoded, err := json.Marshal(item)
	if err != nil || !strings.Contains(string(encoded), `"object_id":"`+media.ObjectID+`"`) || !strings.Contains(string(encoded), `"size_bytes":128`) {
		t.Fatal("admin DTO omitted browser identity", string(encoded), err)
	}
}

func TestS3BrowserMetadataFlagsPreserveNativeAndEncryptedBoundaries(t *testing.T) {
	_, _, service := deleteFixture(t)
	tracks := []Track{{Type: "audio", MediaPath: "music/plain/a.mp3", Transport: "S3", NativeMetadata: true}, {Type: "audio", MediaPath: "music/encrypted/a.mp3", Transport: "S3", Encryption: &mediacrypto.Metadata{}, BrowserMetadata: true}, {Type: "audio", MediaPath: "music/other/a.flac", Transport: "S3", BrowserMetadata: true}, {Type: "video", MediaPath: "vido/film/a.mp4", Transport: "S3", BrowserMetadata: true}, {Type: "audio", MediaPath: "music/local/a.mp3", Transport: "Local"}, {Type: "audio", MediaPath: "music/native/a.mp3", Transport: "Direct"}, {Type: "audio", MediaPath: "music/legacy/a.mp3"}}
	service.DecorateMusicTracks(context.Background(), tracks)
	for index, track := range tracks {
		if track.BrowserMetadata != (index == 0) || track.NativeMetadata != (index >= 4) {
			t.Fatal("metadata crossed browser/native boundary", index, track)
		}
	}
}

func TestS3ResolveRechecksProofAndReadAuthorityWithoutNativeFallback(t *testing.T) {
	for _, mode := range []string{"unchecked-probe", "cleanup-only", "foreign-relationship", "foreign-proof", "stopped-placement"} {
		t.Run(mode, func(t *testing.T) {
			_, db, service, member := s3CatalogFixture(t)
			ctx := context.Background()
			media := publishS3CatalogObject(t, db, "music/S3Authority/song.mp3", nil)
			var err error
			switch mode {
			case "unchecked-probe":
				_, err = db.Database().Exec("UPDATE s3_members SET probe_revision=0 WHERE member_id=?", member.ID)
			case "cleanup-only":
				_, err = db.Database().Exec("UPDATE s3_members SET cleanup_only=1 WHERE member_id=?", member.ID)
			case "foreign-relationship":
				_, err = db.Database().Exec("UPDATE cluster_storage_members SET relationship_id=? WHERE member_id=?", strings.Repeat("f", 32), member.ID)
			case "foreign-proof":
				object, e := db.Pool().(store.S3Repository).S3Object(ctx, media.ID)
				if e != nil {
					t.Fatal(e)
				}
				object.Proof.MemberID = strings.Repeat("f", 32)
				raw, e := json.Marshal(object.Proof)
				if e != nil {
					t.Fatal(e)
				}
				_, err = db.Database().Exec("UPDATE s3_objects SET proof_json=? WHERE media_id=?", string(raw), media.ID)
			case "stopped-placement":
				_, err = db.Pool().(store.S3Repository).S3ConfigureMember(ctx, member.ID, member.Revision, store.S3MemberConfiguration{Name: member.Name, Location: member.Location, Quota: member.Allocation, Enabled: false}, store.NodeAudit{})
			}
			if err != nil {
				t.Fatal(err)
			}
			_, _, err = service.resolveGlobal(ctx, media.ID, media.Path)
			if mode == "stopped-placement" {
				if err != nil {
					t.Fatal("read authority depended on new placement enablement", err)
				}
				return
			}
			if !errors.Is(err, ErrUnavailable) && !errors.Is(err, os.ErrNotExist) {
				t.Fatal("S3 authority failure admitted or attempted native fallback", mode, err)
			}
		})
	}
}
