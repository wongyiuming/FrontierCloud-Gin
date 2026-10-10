package httpapi

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/media"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/network"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func TestLocalEncryptedAccelSelectsCipherAliasAndPreservesPlainPolicy(t *testing.T) {
	for _, role := range []string{"Standalone", "Master"} {
		t.Run(role, func(t *testing.T) {
			ctx := context.Background()
			transport := &clusterHTTP{routers: map[string]*gin.Engine{}}
			router, _, _, public, control := clusterFixture(t, "https://master.test", transport, false)
			public.settings.NginxMedia = true
			if role == "Master" {
				if _, err := control.Promote(ctx, role, "https://master.test", 10*store.GiB, store.NodeAudit{}); err != nil {
					t.Fatal(err)
				}
			}
			metadata, err := mediacrypto.NewMetadata(10)
			if err != nil {
				t.Fatal(err)
			}
			// These opaque bytes only exercise HTTP routing policy. The real
			// compiled-browser cluster test authenticates actual AES-GCM bytes.
			ciphertext := bytes.Repeat([]byte{'x'}, int(metadata.CiphertextSize))
			name := "music/artist/密文.mp3"
			if role == "Master" {
				ticket, err := public.media.ReserveMasterEncryptedUpload(ctx, "密文.mp3", "music/artist", "", "primary", metadata.CiphertextSize, 255, store.AdminAudit{}, &metadata)
				if err != nil {
					t.Fatal(err)
				}
				if _, err = public.media.UploadMasterBytes(ctx, ticket.ID, bytes.NewReader(ciphertext), store.AdminAudit{}); err != nil {
					t.Fatal(err)
				}
			} else {
				stage, err := public.media.Stage(ctx, bytes.NewReader(ciphertext), metadata.CiphertextSize)
				if err != nil {
					t.Fatal(err)
				}
				defer stage.Close()
				if _, err = public.media.PublishEncrypted(ctx, stage, "密文.mp3", "music/artist", "", false, 255, store.AdminAudit{}, &metadata); err != nil {
					t.Fatal(err)
				}
			}
			for _, method := range []string{http.MethodGet, http.MethodHead} {
				w := request(router, method, "/api/v1/media/stream?"+url.Values{"file_path": {name}}.Encode(), "")
				if w.Code != 200 || w.Header().Get("X-Accel-Redirect") != "/_protected_cipher/"+media.QuotePath(name) || w.Header().Get("Content-Type") != "application/octet-stream" || !strings.Contains(w.Header().Get("Cache-Control"), "no-store") || w.Body.Len() != 0 {
					t.Fatal("encrypted edge route lost policy", w.Code, w.Header())
				}
				plain := request(router, method, "/api/v1/media/stream?file_path=music/artist/song.mp3", "")
				if plain.Code != 200 || plain.Header().Get("X-Accel-Redirect") != "/_protected_media/music/artist/song.mp3" || plain.Header().Get("Content-Type") != "audio/mpeg" || plain.Header().Get("Cache-Control") != "public, max-age=86400" {
					t.Fatal("plaintext policy changed", plain.Code, plain.Header())
				}
			}
		})
	}
}

func TestFollowerEncryptedAccelSelectsCipherAliasAndRetainsRelationshipCORS(t *testing.T) {
	ctx := context.Background()
	transport := &clusterHTTP{routers: map[string]*gin.Engine{}}
	_, db, _, public, master := clusterFixture(t, "https://master.test", transport, false)
	_, _, _, storagePublic, follower := clusterFixture(t, "https://follower.test", transport, true)
	if _, err := master.Promote(ctx, "Master", "https://master.test", 10*store.GiB, store.NodeAudit{}); err != nil {
		t.Fatal(err)
	}
	if _, err := follower.Promote(ctx, "Follower", "https://follower.test", 0, store.NodeAudit{}); err != nil {
		t.Fatal(err)
	}
	pair, err := follower.CreatePair(ctx, store.NodeAudit{})
	if err != nil {
		t.Fatal(err)
	}
	relationshipID, err := master.ImportPair(ctx, pair, store.NodeAudit{})
	if err != nil {
		t.Fatal(err)
	}
	relationship, _ := db.Nodes().Relationship(ctx, relationshipID)
	configuration := store.ResourceConfiguration{}
	configuration.Storage.Enabled, configuration.Storage.Allocation = true, 5*store.GiB
	if err = db.Pool().ConfigureMember(ctx, relationship.PeerID, configuration, store.NodeAudit{}); err != nil {
		t.Fatal(err)
	}
	if err = master.Tick(ctx, relationship); err != nil {
		t.Fatal(err)
	}
	if err = db.Nodes().SetRelationshipMode(ctx, relationshipID, "Direct", false, store.NodeAudit{}); err != nil {
		t.Fatal(err)
	}
	settings := storagePublic.settings
	settings.NginxMedia = true
	resolver, _ := network.New(nil)
	edge := New(pass, pass)
	RegisterNodeMedia(edge, settings, resolver, follower, storagePublic.media)
	for _, encrypted := range []bool{false, true} {
		filename, payload := "plain.mp3", []byte("ID3payload")
		var metadata *mediacrypto.Metadata
		if encrypted {
			filename = "cipher.mp3"
			value, err := mediacrypto.NewMetadata(10)
			if err != nil {
				t.Fatal(err)
			}
			metadata, payload = &value, bytes.Repeat([]byte{'x'}, int(value.CiphertextSize))
		}
		ticket, err := public.media.ReserveMasterEncryptedUpload(ctx, filename, "music/StorageCipher", "", "direct", int64(len(payload)), 255, store.AdminAudit{}, metadata)
		if err != nil {
			t.Fatal(err)
		}
		reservation, err := db.Pool().Upload(ctx, ticket.ID)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = master.UploadStorage(ctx, reservation, bytes.NewReader(payload)); err != nil {
			t.Fatal(err)
		}
		if _, err = public.media.FinalizeMasterUpload(ctx, ticket.ID, store.AdminAudit{}); err != nil {
			t.Fatal(err)
		}
		token, err := master.MediaCapability(ctx, relationshipID, ticket.MemberID, ticket.MediaID, ticket.MediaID, "", "")
		if err != nil {
			t.Fatal(err)
		}
		for _, method := range []string{http.MethodGet, http.MethodHead} {
			r := httptest.NewRequest(method, "https://follower.test/internal/v1/media/"+ticket.MediaID+"?"+url.Values{"token": {token}}.Encode(), nil)
			r.Header.Set("Origin", "https://master.test")
			w := httptest.NewRecorder()
			edge.ServeHTTP(w, r)
			prefix, contentType := "/_protected_media/", "audio/mpeg"
			if encrypted {
				prefix, contentType = "/_protected_cipher/", "application/octet-stream"
			}
			if w.Code != 200 || w.Header().Get("X-Accel-Redirect") != prefix+media.QuotePath(ticket.Path) || w.Header().Get("Content-Type") != contentType || w.Header().Get("Access-Control-Allow-Origin") != "https://master.test" || !strings.Contains(w.Header().Get("Access-Control-Expose-Headers"), "Content-Range") || w.Header().Get("Vary") != "Origin" || w.Body.Len() != 0 {
				t.Fatal("storage edge metadata policy changed", encrypted, w.Code, w.Header())
			}
			if encrypted && !strings.Contains(w.Header().Get("Cache-Control"), "no-store") {
				t.Fatal("storage cipher cache policy missing", w.Header())
			}
		}
	}
}
