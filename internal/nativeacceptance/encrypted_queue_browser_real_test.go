package nativeacceptance

import (
	"context"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Chromium exercises the normal upload, catalog, encryption and MSE surfaces
// against a fresh native fleet. No production data or identities are mounted.
func fleetEncryptedQueueBrowserGate(t *testing.T, ctx context.Context, e *Engine, sites []*fleetSite) {
	t.Helper()
	hosts := map[string]string{}
	for i, site := range sites {
		container := site.web
		if i == 0 {
			container = site.project + "-edge"
		}
		var inspected struct {
			NetworkSettings struct {
				Networks map[string]struct{ IPAddress string }
			}
		}
		if err := e.call(ctx, "GET", "/containers/"+container+"/json", nil, &inspected); err != nil {
			t.Fatal("encrypted queue browser network inventory", err)
		}
		u, err := url.Parse(site.origin)
		address := inspected.NetworkSettings.Networks[site.project].IPAddress
		if err != nil || address == "" {
			t.Fatal("encrypted queue browser endpoint unavailable")
		}
		hosts[u.Hostname()] = address
	}
	root := filepath.Dir(sites[0].root)
	fixture := map[string]any{"origin": sites[0].origin, "hosts": hosts,
		"admin_key_file": filepath.Join(sites[0].root, "secrets", "admin_key")}
	raw, err := json.Marshal(fixture)
	if err != nil || os.WriteFile(filepath.Join(root, "encrypted-queue-fixture.json"), raw, 0600) != nil {
		t.Fatal("encrypted queue browser handoff failed")
	}
	t.Log("native fleet awaits encrypted queue Chromium acceptance", root)
	timer := time.NewTimer(8 * time.Minute)
	defer timer.Stop()
	for {
		raw, err = os.ReadFile(filepath.Join(root, "encrypted-queue-result.json"))
		if err == nil {
			var result struct {
				Passed    bool `json:"passed"`
				Relay     bool `json:"relay_verified"`
				Manual    bool `json:"manual_mse_verified"`
				Automatic bool `json:"automatic_mse_verified"`
				Pictures  bool `json:"own_original_pictures_verified"`
				Cache     bool `json:"cipher_cache_reuse_verified"`
			}
			if json.Unmarshal(raw, &result) != nil || !result.Passed || !result.Relay || !result.Manual || !result.Automatic || !result.Pictures || !result.Cache {
				t.Fatal("encrypted queue Chromium acceptance failed; private evidence retained")
			}
			return
		}
		if !os.IsNotExist(err) {
			t.Fatal("encrypted queue Chromium result unreadable")
		}
		select {
		case <-ctx.Done():
			t.Fatal("encrypted queue Chromium acceptance interrupted")
		case <-timer.C:
			t.Fatal("encrypted queue Chromium acceptance timed out")
		case <-time.After(time.Second):
		}
	}
}
