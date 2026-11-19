package nativeacceptance

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/media"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func fleetPrepareHiddenDirectory(t *testing.T, ctx context.Context, master *fleetSite) {
	t.Helper()
	const route = "/api/v1/media/admin/upload/selected/hidden-directory"
	body := []byte(`{"path":"music/private-fleet-hidden"}`)
	request := func(client *http.Client, origin string) int {
		t.Helper()
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, master.origin+route, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", origin)
		response, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return response.StatusCode
	}
	if code := request(&http.Client{Transport: master.client.Transport}, master.origin); code == http.StatusOK {
		t.Fatal("hidden directory accepted without session")
	}
	if code := request(master.client, master.origin); code == http.StatusOK {
		t.Fatal("hidden directory accepted without CSRF")
	}
	code, _, err := master.request(ctx, "POST", route, map[string]any{"path": "music/private-fleet-hidden"}, map[string]string{"Origin": "https://untrusted.invalid"})
	if err != nil || code != http.StatusForbidden {
		t.Fatal("hidden directory accepted wrong origin", code, err)
	}
	fleetJSON(t, ctx, master, "POST", route, map[string]any{"path": "music/private-fleet-hidden"})
	fleetJSON(t, ctx, master, "POST", route, map[string]any{"path": "music/private-fleet-hidden"})
	code, _, err = master.request(ctx, "POST", route, map[string]any{"path": "music/private-fleet"}, map[string]string{"Origin": master.origin})
	if err != nil || code != http.StatusConflict {
		t.Fatal("visible existing directory accepted", code, err)
	}
}

func fleetCheckHiddenDirectory(t *testing.T, ctx context.Context, peer *fleetSite, hidden fleetEncryptedUpload) {
	t.Helper()
	const directory = "music/private-fleet-hidden"
	if !strings.HasPrefix(hidden.path, directory+"/") {
		t.Fatal("invalid hidden fixture")
	}
	// Create a separate public browser with no Admin credentials in its jar.
	browser := *peer
	client := *peer.client
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client.Jar = jar
	browser.client = &client
	const categoriesRoute = "/api/v1/media/catalog/categories?media_type=music"
	listed := func(route string) bool {
		t.Helper()
		var listing struct {
			Entries []media.Category `json:"entries"`
		}
		sealedFleetDecode(t, fleetJSON(t, ctx, &browser, "GET", route, nil), &listing)
		for _, entry := range listing.Entries {
			if entry.Name == "private-fleet-hidden" {
				return true
			}
		}
		return false
	}
	if listed(categoriesRoute) || !listed(categoriesRoute+"&include_hidden=true") {
		t.Fatal("hidden directory did not follow its catalog discovery setting")
	}
	const playbackSession = "45a265cb-9c29-44a5-aa51-a4ae57b88882"
	mediaRoute := "/api/v1/media/catalog/media?media_type=music&path=" + url.QueryEscape(directory) + "&playback_session_id=" + playbackSession
	readTrack := func(route string) media.Track {
		t.Helper()
		var listing struct {
			Entries []media.Track `json:"entries"`
		}
		sealedFleetDecode(t, fleetJSON(t, ctx, &browser, "GET", route, nil), &listing)
		if len(listing.Entries) != 1 || listing.Entries[0].MediaPath != hidden.path || listing.Entries[0].ResourceID == "" || listing.Entries[0].ObjectID == "" || listing.Entries[0].Encryption == nil {
			t.Fatal("exact hidden directory catalog missing its encrypted track")
		}
		return listing.Entries[0]
	}
	known, revealed := readTrack(mediaRoute), readTrack(mediaRoute+"&include_hidden=true")
	if known.ResourceID != revealed.ResourceID || known.ObjectID != revealed.ObjectID || *known.Encryption != *revealed.Encryption {
		t.Fatal("known and revealed directories resolved different media")
	}
	source := fleetCheckEncryptedTrack(t, ctx, &browser, hidden, known, "Local")
	report := map[string]any{"media_path": hidden.path, "resource_id": known.ResourceID, "playback_session_id": playbackSession, "played_seconds": 60, "duration": 90}
	var first, again store.PlaybackResult
	sealedFleetDecode(t, fleetJSON(t, ctx, &browser, "POST", "/api/v1/media/playback", report), &first)
	sealedFleetDecode(t, fleetJSON(t, ctx, &browser, "POST", "/api/v1/media/playback", report), &again)
	if first.MediaID != known.ResourceID || first.PlayScore < 1 || again.MediaID != first.MediaID || again.PlayScore != first.PlayScore || again.Counted {
		t.Fatal("hidden media playback reporting did not deduplicate")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, source, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Range", "bytes=0-15")
	anonymous := *peer.client
	anonymous.Jar = nil
	anonymous.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := anonymous.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 4096))
	response.Body.Close()
	if err != nil || response.StatusCode != http.StatusUnauthorized || bytes.Equal(body, hidden.ciphertext) {
		t.Fatal("hidden ciphertext accepted without capability", response.StatusCode, err)
	}
}
