package nativeacceptance

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// This is an additional handoff, not a replacement profile: the caller must
// continue every default fleet check, including both databases and idle CPU.
func fleetMediaBrowserGate(t *testing.T, ctx context.Context, e *Engine, project string, sites []*fleetSite, perform func(*fleetSite, string, string, any) map[string]any) {
	t.Helper()
	root := filepath.Dir(sites[0].root)
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	token := hex.EncodeToString(nonce)
	hosts, owners := map[string]string{}, map[string]string{}
	byMember := map[string]*fleetSite{}
	for i, site := range sites {
		web, err := e.Inspect(ctx, site.web)
		if err != nil || web.label("com.docker.compose.project") != project {
			t.Fatal("native browser Web ownership missing")
		}
		cpu, cpuOK := web.HostConfig["NanoCpus"].(json.Number)
		memory, memoryOK := web.HostConfig["Memory"].(json.Number)
		swap, swapOK := web.HostConfig["MemorySwap"].(json.Number)
		if !cpuOK || cpu.String() != "1000000000" || !memoryOK || memory.String() != "536870912" || !swapOK || swap.String() != "536870912" {
			t.Fatal("native browser Web cgroup budget differs from default fleet")
		}
		id, _ := perform(site, "GET", "/nodes", nil)["node_id"].(string)
		if len(id) != 32 {
			t.Fatal("native browser owner identity missing")
		}
		owners[id], byMember[id] = site.origin, site
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
			t.Fatal("native browser endpoint inspect", err)
		}
		endpoint, err := url.Parse(site.origin)
		address := inspected.NetworkSettings.Networks[site.project].IPAddress
		if err != nil || address == "" {
			t.Fatal("native browser endpoint unavailable")
		}
		hosts[endpoint.Hostname()] = address
	}
	write := func(name string, value any) {
		t.Helper()
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal("native browser handoff encoding")
		}
		file, err := os.CreateTemp(root, ".media-browser-*")
		if err != nil {
			t.Fatal("native browser handoff create")
		}
		nameToRemove := file.Name()
		defer os.Remove(nameToRemove)
		if err := file.Chmod(0600); err != nil {
			file.Close()
			t.Fatal(err)
		}
		_, err = file.Write(data)
		closeErr := file.Close()
		if err != nil || closeErr != nil || os.Rename(nameToRemove, filepath.Join(root, name)) != nil {
			t.Fatal("native browser handoff write")
		}
	}
	read := func(name string, value any) bool {
		t.Helper()
		path := filepath.Join(root, name)
		info, err := os.Lstat(path)
		if os.IsNotExist(err) {
			return false
		}
		if err != nil || !info.Mode().IsRegular() || info.Size() > 2<<20 {
			t.Fatal("native browser handoff is not a bounded regular file")
		}
		data, err := os.ReadFile(path)
		if err != nil || json.Unmarshal(data, value) != nil {
			t.Fatal("native browser handoff invalid")
		}
		return true
	}
	write("media-browser-fixture.json", map[string]any{
		"format": "frontiercloud-gin-native-media-browser-v1", "nonce": token,
		"database": filepath.Base(root), "origin": sites[0].origin, "hosts": hosts, "owners": owners,
		"admin_key_file": filepath.Join(sites[0].root, "secrets", "admin_key"),
		"ca_file":        filepath.Join(root, "certs", "ca.pem"),
		"web_cpu_limit":  1, "web_memory_bytes": 512 << 20,
	})
	t.Log("additional normal-TLS media browser handoff", filepath.Join(root, "media-browser-fixture.json"))
	var stopped *fleetSite
	restored := false
	defer func() {
		if stopped != nil && !restored {
			recovery, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if err := e.Start(recovery, stopped.web); err != nil {
				t.Error("owned browser outage recovery failed", err)
			}
		}
	}()
	timer := time.NewTimer(15 * time.Minute)
	defer timer.Stop()
	for {
		if stopped == nil {
			var request struct {
				Nonce  string `json:"nonce"`
				Member string `json:"member_id"`
			}
			if read("media-browser-offline-request.json", &request) {
				site := byMember[request.Member]
				if request.Nonce != token || site == nil || site == sites[0] {
					t.Fatal("owned browser outage request invalid")
				}
				observed, err := e.Inspect(ctx, site.web)
				if err != nil || observed.ID != site.web || observed.label("com.docker.compose.project") != project {
					// The project is supplied by the matrix, not by Chromium.
					t.Fatal("native browser outage ownership check failed")
				}
				if err := e.Stop(ctx, site.web); err != nil {
					t.Fatal("owned browser outage failed", err)
				}
				stopped = site
				write("media-browser-offline-ready.json", map[string]any{"nonce": token, "member_id": request.Member, "stopped": true})
			}
		}
		if stopped != nil && !restored {
			var result struct {
				Nonce  string `json:"nonce"`
				Passed bool   `json:"passed"`
			}
			if read("media-browser-offline-result.json", &result) {
				if result.Nonce != token || !result.Passed {
					t.Fatal("native browser offline address verification failed")
				}
				if err := e.Start(ctx, stopped.web); err != nil {
					t.Fatal("owned browser restart failed", err)
				}
				if err := e.Healthy(ctx, stopped.web); err != nil {
					t.Fatal("owned browser restart not healthy", err)
				}
				restored = true
				write("media-browser-online-ready.json", map[string]any{"nonce": token, "restored": true})
			}
		}
		var result struct {
			Nonce      string `json:"nonce"`
			Passed     bool   `json:"passed"`
			TLSIgnored bool   `json:"tls_errors_ignored"`
			Cases      []struct {
				Site      string `json:"site_type"`
				Mode      string `json:"storage_mode"`
				Manual    bool   `json:"manual_mse"`
				Automatic bool   `json:"automatic_mse"`
				Long      bool   `json:"above_128mib"`
				Metadata  bool   `json:"visible_metadata"`
				Pictures  bool   `json:"original_pictures"`
				Address   bool   `json:"admin_address"`
				Range     bool   `json:"plaintext_range"`
			} `json:"playback"`
			Lyrics  bool `json:"shared_lyrics_verified"`
			Karaoke bool `json:"karaoke_readiness_verified"`
			Offline bool `json:"offline_address_verified"`
			Cleanup bool `json:"managed_fixture_cleanup_verified"`
		}
		if read("media-browser-result.json", &result) {
			if result.Nonce != token || !result.Passed || result.TLSIgnored || !result.Lyrics || !result.Karaoke || !result.Offline || !restored || !result.Cleanup || len(result.Cases) != 6 {
				t.Fatal("native normal-TLS browser acceptance failed; private evidence retained")
			}
			seen := map[string]bool{}
			for _, c := range result.Cases {
				key := c.Site + "/" + c.Mode
				validSite := c.Site == "primary" || c.Site == "direct" || c.Site == "relay"
				if !validSite || (c.Mode != "plain" && c.Mode != "encrypted") || seen[key] || !c.Manual || !c.Automatic || !c.Long || !c.Metadata || !c.Pictures || !c.Address || !c.Range {
					t.Fatal("native browser six-case proof incomplete")
				}
				seen[key] = true
			}
			t.Log("normal-TLS browser six-case gate passed; continuing full default native matrix", filepath.Base(root))
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal("native media browser interrupted")
		case <-timer.C:
			t.Fatal("native media browser bounded handoff expired")
		case <-time.After(time.Second):
		}
	}
}
