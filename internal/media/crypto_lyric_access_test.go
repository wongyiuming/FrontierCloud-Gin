package media

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func publishCryptoLyric(t *testing.T, svc *Service, filename string) (string, []byte) {
	t.Helper()
	meta, ciphertext := encryptedFixtureBytes(t, "[00:01.00] private lyrics\n")
	stage, err := svc.Stage(context.Background(), bytes.NewReader(ciphertext), meta.CiphertextSize)
	if err != nil {
		t.Fatal(err)
	}
	defer stage.Close()
	name, err := svc.PublishEncrypted(context.Background(), stage, filename, "", "", true, 255, store.AdminAudit{}, &meta)
	if err != nil {
		t.Fatal(err)
	}
	return name, ciphertext
}

// Both issuance and every later ciphertext open must use current permissions;
// retaining a valid browser session or an earlier descriptor grants no access.
func checkCryptoLyricAccess(t *testing.T, svc *Service, name string, ciphertext []byte, denied error) {
	t.Helper()
	object, keyErr := svc.CryptoObject(context.Background(), name, "", false)
	f, info, bytesErr := svc.OpenCryptoLyric(context.Background(), name)
	if f != nil {
		defer f.Close()
	}
	if denied != nil {
		if !errors.Is(keyErr, denied) || !errors.Is(bytesErr, denied) || f != nil {
			t.Fatalf("public key/bytes should be denied: %v / %v", keyErr, bytesErr)
		}
		return
	}
	if keyErr != nil || bytesErr != nil || object.Kind != "lyric" || object.Encryption == nil || info.Size() != int64(len(ciphertext)) {
		t.Fatalf("public lyric key/bytes: %+v / %v / %v", object, keyErr, bytesErr)
	}
	actual, err := io.ReadAll(f)
	if err != nil || !bytes.Equal(actual, ciphertext) {
		t.Fatal("lyric ciphertext changed", err)
	}
}

func TestPublicEncryptedLyricRequiresCurrentVisibleAudioRelation(t *testing.T) {
	for _, master := range []bool{false, true} {
		label := "Standalone"
		if master {
			label = "Master"
		}
		t.Run(label, func(t *testing.T) {
			fixture := deleteFixture
			if master {
				fixture = masterFixture
			}
			_, _, svc := fixture(t)
			ctx := context.Background()
			lyric, ciphertext := publishCryptoLyric(t, svc, "shared.lrc")
			replacement, replacementCipher := publishCryptoLyric(t, svc, "replacement.lrc")
			bind := func(track string, names ...string) {
				t.Helper()
				if _, err := svc.ReplaceLyrics(ctx, "track", track, names, store.AdminAudit{}); err != nil {
					t.Fatal(err)
				}
			}
			hide := func(dir string, value bool) {
				t.Helper()
				if err := svc.Hide(ctx, []string{dir}, value, store.AdminAudit{}); err != nil {
					t.Fatal(err)
				}
			}
			checkCryptoLyricAccess(t, svc, lyric, ciphertext, os.ErrNotExist)
			if object, err := svc.CryptoObject(ctx, lyric, "", true); err != nil || object.Encryption == nil {
				t.Fatal("admin lost orphan lyric management", err)
			}
			bind("music/artist/song.mp3", lyric)
			checkCryptoLyricAccess(t, svc, lyric, ciphertext, nil)
			sourceTrack, err := svc.CryptoObject(ctx, "music/artist/song.mp3", "", false)
			if err != nil {
				t.Fatal(err)
			}
			source, err := svc.EncryptedLyric(ctx, "music/artist/song.mp3", "")
			if err != nil || source.Path != lyric || source.Encryption == nil {
				t.Fatal("visible source lost its lyric", source, err)
			}
			hide("music/artist", true)
			checkCryptoLyricAccess(t, svc, lyric, ciphertext, os.ErrNotExist)
			bind("music/other/song.mp3", lyric)
			checkCryptoLyricAccess(t, svc, lyric, ciphertext, nil)
			if _, err := svc.EncryptedLyric(ctx, "music/artist/song.mp3", ""); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("shared visible source authorized a hidden source request", err)
			}
			hide("music/other", true)
			checkCryptoLyricAccess(t, svc, lyric, ciphertext, os.ErrNotExist)
			hide("music/artist", false)
			checkCryptoLyricAccess(t, svc, lyric, ciphertext, nil)
			bind("music/artist/song.mp3", replacement)
			checkCryptoLyricAccess(t, svc, lyric, ciphertext, os.ErrNotExist)
			checkCryptoLyricAccess(t, svc, replacement, replacementCipher, nil)
			hide("music/other", false)
			checkCryptoLyricAccess(t, svc, lyric, ciphertext, nil)
			bind("music/other/song.mp3")
			checkCryptoLyricAccess(t, svc, lyric, ciphertext, os.ErrNotExist)
			// A visible track linked to a different lyric cannot authorize an
			// orphan path, even though it shares the same media directory tree.
			if _, err := svc.CryptoObject(ctx, lyric, sourceTrack.ID, false); !errors.Is(err, ErrPath) {
				t.Fatal("track resource identity accepted for a lyric path", err)
			}
			if master {
				if _, err := svc.EncryptedLyric(ctx, "music/other/song.mp3", sourceTrack.ID); !errors.Is(err, ErrLyrics) {
					t.Fatal("resource ID authorized a different source path", err)
				}
			}
			bind("music/artist/song.mp3", lyric)
			var deleteErr error
			if master {
				_, deleteErr = svc.DeleteGlobal(ctx, []string{"music/artist/song.mp3"}, store.AdminAudit{})
			} else {
				_, deleteErr = svc.Delete(ctx, []string{"music/artist/song.mp3"}, store.AdminAudit{})
			}
			if deleteErr != nil {
				t.Fatal(deleteErr)
			}
			checkCryptoLyricAccess(t, svc, lyric, ciphertext, os.ErrNotExist)
			if object, err := svc.CryptoObject(ctx, lyric, "", true); err != nil || object.Encryption == nil {
				t.Fatal("source deletion removed admin access to retained lyric", err)
			}
		})
	}
}

func TestPublicEncryptedLyricRejectsMissingStandaloneAudio(t *testing.T) {
	root, _, svc := deleteFixture(t)
	name, ciphertext := publishCryptoLyric(t, svc, "missing-source.lrc")
	if _, err := svc.ReplaceLyrics(context.Background(), "track", "music/artist/song.mp3", []string{name}, store.AdminAudit{}); err != nil {
		t.Fatal(err)
	}
	checkCryptoLyricAccess(t, svc, name, ciphertext, nil)
	// The durable JOIN still contains a valid audio row; current physical
	// availability must be checked rather than relying only on that metadata.
	if err := os.Remove(filepath.Join(root, "music/artist/song.mp3")); err != nil {
		t.Fatal(err)
	}
	checkCryptoLyricAccess(t, svc, name, ciphertext, os.ErrNotExist)
}

func TestPublicEncryptedLyricMasterRemoteHealthAndLogicalRelation(t *testing.T) {
	_, db, svc := masterFixture(t)
	ctx := context.Background()
	name, ciphertext := publishCryptoLyric(t, svc, "remote-source.lrc")
	relation := store.Relationship{ID: strings.Repeat("8", 32), PeerID: strings.Repeat("6", 32), Endpoint: "https://lyric-follower.test", PublicKey: strings.Repeat("A", 43), Credential: "sealed-fixture", Direction: "downstream", Mode: "Relay", State: "pending", Protocol: 2, CreatedAt: time.Now().Unix()}
	if err := db.Nodes().PrepareRelationship(ctx, relation, store.NodeAudit{}); err != nil {
		t.Fatal(err)
	}
	if err := db.Nodes().ActivateRelationship(ctx, relation.ID, store.NodeAudit{}); err != nil {
		t.Fatal(err)
	}
	configuration := store.ResourceConfiguration{}
	configuration.Storage.Enabled, configuration.Storage.Allocation = true, 10*store.GiB
	if err := db.Pool().ConfigureMember(ctx, relation.PeerID, configuration, store.NodeAudit{}); err != nil {
		t.Fatal(err)
	}
	status := map[string]any{"storage": map[string]any{"physical_free_bytes": 20 * store.GiB}}
	if err := db.Nodes().RecordHeartbeat(ctx, relation.ID, true, 1, status, time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	ticket, err := db.Pool().ReserveUpload(ctx, "music/remote/song.mp3", "relay", 10, 10*store.GiB, store.AdminAudit{})
	if err != nil {
		t.Fatal(err)
	}
	row, err := db.Pool().FinalizeUpload(ctx, ticket.ID, ticket.MediaID, 10, `"cipher-fixture"`, store.AdminAudit{})
	if err != nil {
		t.Fatal(err)
	}
	if local, err := db.Media().ObjectByID(ctx, row.ID); err != nil || local != nil {
		t.Fatal("remote logical resource manufactured a local object", err)
	}
	if _, err := svc.ReplaceLyrics(ctx, "track", row.Path, []string{name}, store.AdminAudit{}); err != nil {
		t.Fatal(err)
	}
	checkCryptoLyricAccess(t, svc, name, ciphertext, nil)
	if object, err := svc.EncryptedLyric(ctx, "", row.ID); err != nil || object.Path != name {
		t.Fatal("logical resource ID lost its lyric", err)
	}
	if err := db.Nodes().RecordHeartbeat(ctx, relation.ID, false, 0, nil, time.Now().Unix()+121); err != nil {
		t.Fatal(err)
	}
	checkCryptoLyricAccess(t, svc, name, ciphertext, ErrUnavailable)
	// Another healthy local source still authorizes this shared lyric; the
	// offline source-specific entry point must continue to fail.
	if _, err := svc.ReplaceLyrics(ctx, "track", "music/artist/song.mp3", []string{name}, store.AdminAudit{}); err != nil {
		t.Fatal(err)
	}
	checkCryptoLyricAccess(t, svc, name, ciphertext, nil)
	if _, err := svc.EncryptedLyric(ctx, "", row.ID); !errors.Is(err, ErrUnavailable) {
		t.Fatal("offline resource was authorized by another source", err)
	}
	if err := svc.Hide(ctx, []string{"music/artist"}, true, store.AdminAudit{}); err != nil {
		t.Fatal(err)
	}
	checkCryptoLyricAccess(t, svc, name, ciphertext, ErrUnavailable)
	// Real global lifecycle transition removes the stale remote relation from
	// public authorization, even before physical remote deletion is completed.
	if _, err := db.Pool().PrepareGlobalDelete(ctx, []store.DeleteItem{{Path: row.Path}}, store.AdminAudit{}); err != nil {
		t.Fatal(err)
	}
	checkCryptoLyricAccess(t, svc, name, ciphertext, os.ErrNotExist)
}

type lyricAccessRepository struct {
	store.MediaRepository
	store.EncryptionRepository
	onLyricPath     func()
	onRelations     func(string, string)
	relationFailure error
}

func (r *lyricAccessRepository) LyricPath(ctx context.Context, id string) (string, error) {
	if r.onLyricPath != nil {
		r.onLyricPath()
	}
	return r.MediaRepository.LyricPath(ctx, id)
}

func (r *lyricAccessRepository) LyricRelations(ctx context.Context, track, lyric string) ([]store.LyricRelation, error) {
	if r.onRelations != nil {
		r.onRelations(track, lyric)
	}
	if r.relationFailure != nil {
		return nil, r.relationFailure
	}
	return r.MediaRepository.LyricRelations(ctx, track, lyric)
}

func TestPublicEncryptedLyricScopedChecksHoldLeaseAndFailClosed(t *testing.T) {
	_, _, svc := masterFixture(t)
	ctx := context.Background()
	lyric, _ := publishCryptoLyric(t, svc, "lease-source.lrc")
	if _, err := svc.ReplaceLyrics(ctx, "track", "music/artist/song.mp3", []string{lyric}, store.AdminAudit{}); err != nil {
		t.Fatal(err)
	}
	track, err := svc.CryptoObject(ctx, "music/artist/song.mp3", "", false)
	if err != nil {
		t.Fatal(err)
	}
	token, err := svc.identity.KaraokeHandle(track.ID, true)
	if err != nil {
		t.Fatal(err)
	}
	repository := &lyricAccessRepository{MediaRepository: svc.repository, EncryptionRepository: svc.repository.(store.EncryptionRepository)}
	svc.repository = repository
	checks := 0
	assertLease := func() {
		t.Helper()
		checks++
		if svc.mutation.TryLock() {
			svc.mutation.Unlock()
			t.Error("lyric relation lookup escaped the source's shared mutation lease")
		}
	}
	repository.onLyricPath = assertLease
	repository.onRelations = func(trackScope, lyricScope string) {
		assertLease()
		if trackScope != "" || lyricScope != lyric {
			t.Errorf("public authorization queried beyond exact lyric: %q / %q", trackScope, lyricScope)
		}
	}
	if _, err := svc.EncryptedLyric(ctx, "", track.ID); err != nil {
		t.Fatal(err)
	}
	if metadata, fileID, err := svc.RecordingLyricSource(ctx, token); err != nil || metadata.EncryptedLyricPath != lyric || fileID == "" {
		t.Fatal("recording source authorization", err)
	}
	if checks != 4 {
		t.Fatal("source/relation checks were bypassed", checks)
	}
	repository.relationFailure = errors.New("lyric permission repository unavailable")
	if _, err := svc.CryptoObject(ctx, lyric, "", false); !errors.Is(err, repository.relationFailure) {
		t.Fatal("key authorization ignored relation lookup failure", err)
	}
	if file, _, err := svc.OpenCryptoLyric(ctx, lyric); !errors.Is(err, repository.relationFailure) || file != nil {
		if file != nil {
			file.Close()
		}
		t.Fatal("cipher bytes ignored relation lookup failure", err)
	}
}
