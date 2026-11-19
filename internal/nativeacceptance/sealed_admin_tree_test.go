package nativeacceptance

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/media"
)

func fleetCheckAdminTree(t *testing.T, ctx context.Context, master *fleetSite, ownerID string, hidden fleetEncryptedUpload) {
	t.Helper()
	path := "/api/v1/media/admin/tree?path=" + url.QueryEscape("music/private-fleet-hidden")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, master.origin+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := (&http.Client{Transport: master.client.Transport}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode == http.StatusOK {
		t.Fatal("unauthenticated Admin tree accepted")
	}
	code, _, err := master.request(ctx, http.MethodGet, path, nil, map[string]string{"Origin": "https://untrusted.invalid"})
	if err != nil || code != http.StatusForbidden {
		t.Fatal("Admin tree accepted wrong origin", code, err)
	}
	raw := fleetJSON(t, ctx, master, http.MethodGet, path, nil)
	var tree media.Tree
	sealedFleetDecode(t, raw, &tree)
	if len(tree.Items) != 1 || tree.Items[0].Path != hidden.path || !tree.Items[0].Hidden || tree.Items[0].HiddenDirect || tree.Items[0].MemberID != ownerID || tree.Items[0].SizeBytes == nil || *tree.Items[0].SizeBytes != int64(len(hidden.ciphertext)) {
		t.Fatal("Admin hidden tree view missing or inconsistent")
	}
	raw = fleetJSON(t, ctx, master, http.MethodGet, "/api/v1/media/admin/tree?path=music", nil)
	sealedFleetDecode(t, raw, &tree)
	found := false
	for _, item := range tree.Items {
		if item.Path == "music/private-fleet-hidden" {
			found = item.Hidden && item.HiddenDirect
		}
	}
	if !found {
		t.Fatal("Admin direct hidden directory missing")
	}
	raw = fleetJSON(t, ctx, master, http.MethodGet, "/api/v1/media/admin/tree/search?q=hidden-song&path=music", nil)
	var result media.SearchResult
	sealedFleetDecode(t, raw, &result)
	if len(result.Items) != 1 || result.Items[0].Path != hidden.path || !result.Items[0].Hidden || result.Items[0].HiddenDirect {
		t.Fatal("Admin search lost hidden file")
	}
}
