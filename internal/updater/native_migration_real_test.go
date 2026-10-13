package updater

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/media"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/migrationdata"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/noderetirement"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/resourcemigration"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func fleetDecode(t *testing.T, value any, out any) {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil || json.Unmarshal(raw, out) != nil {
		t.Fatal("invalid native response shape")
	}
}

func fleetRequireRetirementClear(t *testing.T, value map[string]any) {
	t.Helper()
	var report noderetirement.Report
	fleetDecode(t, value, &report)
	if !report.ObservationComplete || !report.Master.DatabaseClear || !report.Peer.DatabaseClear || len(report.Concerns) != 0 || report.ExpectedItems != 0 {
		t.Fatal("empty native follower retirement remains blocked", report.Master.Blockers, report.Peer.Blockers, report.Concerns)
	}
}

// Each case owns a fresh five-node fleet. The normal one-hour source retention
// is never shortened by SQL edits, an environment override or a test clock.
// This gate proves cutover and retained-source safety; a selected long run can
// additionally wait for real cleanup. Neither mode changes hosted CI budgets.
func TestRealNativeMatrixFleetMigrations(t *testing.T) {
	base, prefix := os.Getenv("FRONTIERCLOUD_TEST_NATIVE_MATRIX_WORKSPACE"), os.Getenv("FRONTIERCLOUD_TEST_NATIVE_MATRIX_PREFIX")
	if base == "" {
		t.Skip("isolated native migration matrix not selected")
	}
	info, err := os.Lstat(base)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || !filepath.IsAbs(base) || !strings.HasPrefix(filepath.Base(base), "fc-native-matrix-") || !dockerName.MatchString(prefix) || !strings.HasPrefix(prefix, "fc-matrix-") {
		t.Fatal("new owned native workspace required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Hour)
	defer cancel()
	e, err := NewEngine(ctx, os.Getenv("FRONTIERCLOUD_TEST_DOCKER_SOCKET"))
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	driver, err := e.Inspect(ctx, prefix+"-driver")
	if err != nil || driver.label("frontiercloud.acceptance") != prefix {
		t.Fatal("private driver ownership required")
	}
	selected := os.Getenv("FRONTIERCLOUD_TEST_NATIVE_MATRIX_MASTER")
	combination := os.Getenv("FRONTIERCLOUD_TEST_NATIVE_MIGRATION_CASE")
	if selected != "" && selected != "go-sqlite" && selected != "go-mysql" {
		t.Fatal("unknown database selection")
	}
	if combination != "" && combination != "dd" && combination != "dr" && combination != "rd" && combination != "rr" {
		t.Fatal("unknown migration selection")
	}
	for _, kind := range []string{"go-sqlite", "go-mysql"} {
		if selected != "" && selected != kind {
			continue
		}
		for _, pair := range []string{"dd", "dr", "rd", "rr"} {
			if combination != "" && combination != pair {
				continue
			}
			t.Run(kind+"-"+pair, func(t *testing.T) {
				caseBase := filepath.Join(base, kind+"-"+pair)
				if err := os.Mkdir(caseBase, 0755); err != nil {
					t.Fatal(err)
				}
				if err := os.Link(filepath.Join(base, "certificate.test"), filepath.Join(caseBase, "certificate.test")); err != nil {
					t.Fatal("private certificate controller fixture", err)
				}
				testFleetControl(t, ctx, e, caseBase, prefix+"-"+pair, driver.ID, kind, pair)
			})
		}
	}
}

type fleetMigrationFixture struct {
	path, id, sourcePath, targetPath, sha string
	bytes                                 int64
	payload                               []byte
}

func fleetMigrationScenario(t *testing.T, ctx context.Context, e *Engine, sites []*fleetSite, relations []string, perform func(*fleetSite, string, string, any) map[string]any, pair string) {
	t.Helper()
	master := sites[0]
	sourceIndex, targetIndex := 1, 2
	if pair[0] == 'r' {
		sourceIndex = 3
	}
	if pair[1] == 'r' {
		targetIndex = 4
	}
	siteType := "direct"
	if sourceIndex == 3 {
		siteType = "relay"
	}
	sourceID, _ := perform(sites[sourceIndex], "GET", "/nodes", nil)["node_id"].(string)
	targetID, _ := perform(sites[targetIndex], "GET", "/nodes", nil)["node_id"].(string)
	for i, relation := range relations {
		perform(master, "POST", "/nodes/"+relation+"/resources", map[string]any{"storage_enabled": i+1 == sourceIndex, "storage_capacity_gib": 1, "backup_enabled": false})
	}
	var fixtures []fleetMigrationFixture
	upload := func(path string, reader io.Reader, length int64, extra map[string]any, sample []byte, digest string) {
		t.Helper()
		last := strings.LastIndex(path, "/")
		parent, name := path[:last], path[last+1:]
		body := map[string]any{"storage_mode": "plain", "site_type": siteType, "target_dir": parent, "filename": name, "size_bytes": length}
		for k, v := range extra {
			body[k] = v
		}
		ticket := perform(master, "POST", "/upload/session", body)
		if ticket["member_id"] != sourceID {
			t.Fatal("site-type fixture did not select only eligible source")
		}
		location, _ := ticket["upload_url"].(string)
		uploadSite := master
		if strings.HasPrefix(location, "https://") {
			u, err := url.Parse(location)
			if err != nil || u.Scheme+"://"+u.Host != sites[sourceIndex].origin {
				t.Fatal("upload escaped private source")
			}
			uploadSite = sites[sourceIndex]
			location = u.RequestURI()
		}
		r, err := http.NewRequestWithContext(ctx, "PUT", uploadSite.origin+location, reader)
		if err != nil {
			t.Fatal(err)
		}
		r.ContentLength = length
		r.Header.Set("Content-Type", "application/octet-stream")
		r.Header.Set("Origin", master.origin)
		// Relay uploads use the authenticated Master Admin route, including its
		// normal CSRF cookie/header contract. Direct tickets remain source-bound.
		origin, _ := url.Parse(uploadSite.origin)
		for _, cookie := range uploadSite.client.Jar.Cookies(origin) {
			if cookie.Name == "__Host-admin-csrf" {
				r.Header.Set("X-CSRF-Token", cookie.Value)
			}
		}
		client := *uploadSite.client
		client.Timeout = 3 * time.Minute
		response, err := client.Do(r)
		if err != nil {
			t.Fatal("native upload transport failed")
		}
		_, readErr := io.Copy(io.Discard, io.LimitReader(response.Body, 1<<20))
		response.Body.Close()
		if readErr != nil || response.StatusCode != 200 {
			t.Fatal("native upload failed", response.StatusCode, readErr)
		}
		if siteType == "direct" {
			id, _ := ticket["upload_id"].(string)
			perform(master, "POST", "/upload/session/"+id+"/finalize", nil)
		}
		id, _ := ticket["media_id"].(string)
		fixtures = append(fixtures, fleetMigrationFixture{path: path, id: id, bytes: length, payload: sample, sha: digest})
	}
	actualAudio := os.Getenv("FRONTIERCLOUD_TEST_NATIVE_MIGRATION_AUDIO") == "1"
	var shortAudio, longAudio []byte
	if actualAudio {
		readAudio := func(name string) []byte {
			dir := filepath.Join(os.Getenv("FRONTIERCLOUD_TEST_NATIVE_MATRIX_WORKSPACE"), "audio-fixtures")
			info, err := os.Lstat(filepath.Join(dir, name))
			if err != nil || !info.Mode().IsRegular() || info.Size() < 1024 || info.Size() > 2<<20 {
				t.Fatal("bounded private generated MP3 required")
			}
			raw, err := os.ReadFile(filepath.Join(dir, name))
			if err != nil || !bytes.HasPrefix(raw, []byte("ID3")) {
				t.Fatal("private generated MP3 bytes unavailable")
			}
			return raw
		}
		shortAudio, longAudio = readAudio("short.mp3"), readAudio("long.mp3")
		if len(longAudio) <= 1048620 {
			t.Fatal("generated encrypted MP3 does not cross crypto chunk boundary")
		}
	}
	for i := 0; i < 48; i++ {
		payload := []byte(fmt.Sprintf("ID3native migration %04d exact plaintext payload", i))
		if actualAudio {
			payload = shortAudio
		}
		digest := sha256.Sum256(payload)
		upload(fmt.Sprintf("music/migrate/parent%d/track-%03d.mp3", i/16, i), bytes.NewReader(payload), int64(len(payload)), nil, payload, hex.EncodeToString(digest[:]))
	}
	crypto := newFleetBrowserCrypto(t, ctx, master)
	plain := bytes.Repeat([]byte("ID3native opaque encrypted migration"), 40000)
	if actualAudio {
		plain = longAudio
	}
	prepared, ciphertext := crypto.prepare(t, ctx, master, plain)
	cryptoPath := "music/migrate/encrypted/opaque.mp3"
	digest := sha256.Sum256(ciphertext)
	upload(cryptoPath, bytes.NewReader(ciphertext), int64(len(ciphertext)), map[string]any{"storage_mode": "encrypted", "encryption": prepared.Encryption, "preparation_token": prepared.Preparation}, ciphertext, hex.EncodeToString(digest[:]))
	// The driver creates this fixture with a fixed buffer. Product processes
	// have 512 MiB/no-swap cgroup limits even for this 128 MiB object.
	large, err := os.CreateTemp(filepath.Dir(sites[0].root), "migration-bytes-*")
	if err != nil {
		t.Fatal(err)
	}
	defer large.Close()
	defer os.Remove(large.Name())
	block := make([]byte, 64<<10)
	for i := range block {
		block[i] = byte(i % 251)
	}
	copy(block, "ID3")
	hash := sha256.New()
	writer := io.MultiWriter(large, hash)
	for i := 0; i < 2048; i++ {
		if _, err = writer.Write(block); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = large.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	upload("music/migrate/large/bounded.mp3", large, 128<<20, nil, block, hex.EncodeToString(hash.Sum(nil)))
	if actualAudio {
		fleetMigrationLyricFixture(t, ctx, master, perform, []string{fixtures[16].path, cryptoPath})
	}
	hidden := fixtures[0].path[:strings.LastIndex(fixtures[0].path, "/")]
	perform(master, "POST", "/hide", map[string]any{"paths": []string{hidden}, "hidden": true})
	perform(master, "POST", "/media-priority", map[string]any{"media_path": fixtures[1].path, "value": 4})
	perform(master, "POST", "/nodes/"+relations[targetIndex-1]+"/resources", map[string]any{"storage_enabled": true, "storage_capacity_gib": 1, "backup_enabled": false})
	var plan resourcemigration.PlanView
	requestID := make([]byte, 16)
	if _, err = rand.Read(requestID); err != nil {
		t.Fatal(err)
	}
	fleetDecode(t, perform(master, "POST", "/nodes/migration-plans", map[string]any{"request_id": hex.EncodeToString(requestID), "source_id": sourceID, "target_id": targetID}), &plan)
	waitPlan := func(want string) {
		deadline := time.Now().Add(5 * time.Minute)
		for plan.State != want {
			if plan.State == "blocked" || plan.State == "failed" || plan.State == "expired" || time.Now().After(deadline) {
				t.Fatal("native migration plan did not reach", want, plan.State, plan.ErrorCode, plan.ErrorStage, plan.Blockers)
			}
			time.Sleep(200 * time.Millisecond)
			fleetDecode(t, perform(master, "GET", "/nodes/migration-plans/"+plan.ID, nil), &plan)
		}
	}
	waitPlan("ready")
	if plan.ObjectCount != int64(len(fixtures)) {
		t.Fatal("whole-node plan omitted managed or hidden files", plan.ObjectCount, len(fixtures))
	}
	objects := map[string]store.MigrationObject{}
	page := plan
	for {
		for _, object := range page.Objects {
			if _, ok := objects[object.ID]; ok {
				t.Fatal("duplicate object across plan pages")
			}
			objects[object.ID] = object
		}
		if page.Complete {
			break
		}
		if page.Next == page.After {
			t.Fatal("stalled plan cursor")
		}
		fleetDecode(t, perform(master, "GET", "/nodes/migration-plans/"+plan.ID+"?after="+page.Next, nil), &page)
	}
	for i := range fixtures {
		object, ok := objects[fixtures[i].id]
		if !ok || object.Bytes != fixtures[i].bytes {
			t.Fatal("plan identity/length mismatch")
		}
		fixtures[i].sourcePath = object.Path
		fixtures[i].targetPath = object.TargetPath
	}
	networkBefore := map[string][2]uint64{}
	for _, site := range []*fleetSite{master, sites[sourceIndex], sites[targetIndex]} {
		networkBefore[site.web] = fleetMigrationNetworkBytes(t, ctx, e, site.web)
	}
	fleetDecode(t, perform(master, "POST", "/nodes/migration-plans/"+plan.ID+"/start", map[string]any{"review_sha256": plan.ReviewSHA, "confirm_source_id": sourceID, "confirm_target_id": targetID}), &plan)
	waitPlan("started")
	if os.Getenv("FRONTIERCLOUD_TEST_MIGRATION_NO_DIRECT") == "1" {
		fleetMigrationDirectRefusal(t, ctx, master, sites[targetIndex], perform, plan.ID, sourceID, fixtures)
		return
	}
	if os.Getenv("FRONTIERCLOUD_TEST_NATIVE_MIGRATION_DURING") == "1" {
		deadline := time.Now().Add(3 * time.Minute)
		for {
			var live store.MigrationStatus
			fleetDecode(t, perform(master, "GET", "/nodes/migrations/"+plan.ID, nil), &live)
			if live.Execution != nil && live.Execution.ObjectID == fixtures[49].id && live.Execution.CurrentBytes >= 1<<20 && live.Execution.CurrentBytes < fixtures[49].bytes/2 {
				break
			}
			if live.Task.State == "failed" || live.Task.State == "cleanup_pending" || time.Now().After(deadline) {
				t.Fatal("during-copy browser missed the native transfer", live.Task.State, live.Task.ErrorCode)
			}
			time.Sleep(200 * time.Millisecond)
		}
		fleetMigrationBrowserGatePhase(t, ctx, e, sites, plan.ID, sourceID, targetID, cryptoPath, prepared.Encryption.FileID, plain, "during")
	}
	if os.Getenv("FRONTIERCLOUD_TEST_NATIVE_MIGRATION_TRAFFIC") == "1" {
		fleetMigrationTrafficGate(t, ctx, master, sites[sourceIndex], sites[targetIndex], perform, plan.ID, sourceID, targetID, fixtures[49])
	}
	var status store.MigrationStatus
	deadline := time.Now().Add(6 * time.Minute)
	peak := map[string]uint64{}
	for {
		fleetDecode(t, perform(master, "GET", "/nodes/migrations/"+plan.ID, nil), &status)
		for _, site := range []*fleetSite{master, sites[sourceIndex], sites[targetIndex]} {
			var stats struct {
				Memory struct{ Usage, Limit uint64 } `json:"memory_stats"`
			}
			if err = e.call(ctx, "GET", "/containers/"+site.web+"/stats?stream=false", nil, &stats); err != nil {
				t.Fatal("native memory sample failed", err)
			}
			if stats.Memory.Limit > 512<<20 || stats.Memory.Usage >= 512<<20 {
				t.Fatal("migration memory exceeded product budget", stats.Memory)
			}
			if stats.Memory.Usage > peak[site.web] {
				peak[site.web] = stats.Memory.Usage
			}
		}
		if status.Task.State == "cleanup_pending" {
			break
		}
		if status.Task.State == "failed" || time.Now().After(deadline) {
			t.Fatal("native transfer did not commit", status.Task.State, status.Task.ErrorCode)
		}
		started := time.Now()
		perform(master, "GET", "/nodes", nil)
		if time.Since(started) > 3*time.Second {
			t.Fatal("copy blocked node control")
		}
		time.Sleep(300 * time.Millisecond)
	}
	if status.Task.CommittedBytes != status.Task.TotalBytes || status.RetirementReady {
		t.Fatal("cutover accounting or grace status invalid")
	}
	networkAfter := map[string][2]uint64{}
	for _, site := range []*fleetSite{master, sites[sourceIndex], sites[targetIndex]} {
		networkAfter[site.web] = fleetMigrationNetworkBytes(t, ctx, e, site.web)
		before, after := networkBefore[site.web], networkAfter[site.web]
		if after[0] < before[0] || after[1] < before[1] {
			t.Fatal("native network counters reset during copy")
		}
	}
	masterBytes := networkAfter[master.web][0] - networkBefore[master.web][0] + networkAfter[master.web][1] - networkBefore[master.web][1]
	sourceTx := networkAfter[sites[sourceIndex].web][1] - networkBefore[sites[sourceIndex].web][1]
	targetRx := networkAfter[sites[targetIndex].web][0] - networkBefore[sites[targetIndex].web][0]
	if masterBytes >= uint64(status.Task.TotalBytes)/4 || sourceTx < uint64(status.Task.TotalBytes) || targetRx < uint64(status.Task.TotalBytes) {
		t.Fatal("migration payload was not confined to peer data path", masterBytes, sourceTx, targetRx, status.Task.TotalBytes)
	}
	t.Logf("direct-only native network proof: master total=%d source tx=%d target rx=%d payload=%d", masterBytes, sourceTx, targetRx, status.Task.TotalBytes)
	checkedParents := map[string]bool{}
	owned := map[string]media.TreeItem{}
	for _, fixture := range fixtures {
		parent := fixture.path[:strings.LastIndex(fixture.path, "/")]
		if checkedParents[parent] {
			continue
		}
		checkedParents[parent] = true
		var tree media.Tree
		fleetDecode(t, perform(master, "GET", "/tree?"+url.Values{"path": {parent}}.Encode(), nil), &tree)
		for _, item := range tree.Items {
			if item.Media {
				owned[item.MediaID] = item
			}
		}
	}
	for _, fixture := range fixtures {
		item, ok := owned[fixture.id]
		if !ok || item.MemberID != targetID || item.Path != fixture.path || item.Hidden != strings.HasPrefix(fixture.path, hidden+"/") {
			t.Fatal("cutover changed logical path, visibility or authoritative owner")
		}
	}
	var priority media.PriorityResult
	fleetDecode(t, perform(master, "GET", "/media-priority?"+url.Values{"path": {"music/migrate/parent0"}}.Encode(), nil), &priority)
	priorityPreserved := false
	for _, item := range priority.Items {
		if item.MediaID == fixtures[1].id && item.MediaPath == fixtures[1].path && item.Preference == 4 {
			priorityPreserved = true
		}
	}
	if !priorityPreserved {
		t.Fatal("migration changed logical media priority")
	}
	// Inspect exact fixture bytes without editing runtime state. A source copy
	// is retained during grace; the target bytes must already match the plan.
	for _, fixture := range fixtures {
		for _, location := range []struct {
			site *fleetSite
			path string
		}{{sites[sourceIndex], fixture.sourcePath}, {sites[targetIndex], fixture.targetPath}} {
			file, err := os.Open(filepath.Join(location.site.root, "data", "media", filepath.FromSlash(location.path)))
			if err != nil {
				t.Fatal("native source retention or target publication missing", err)
			}
			hash := sha256.New()
			count, err := io.CopyBuffer(hash, file, make([]byte, 64<<10))
			file.Close()
			if err != nil || count != fixture.bytes || hex.EncodeToString(hash.Sum(nil)) != fixture.sha {
				t.Fatal("actual native published bytes differ from original")
			}
		}
	}
	for _, fixture := range []fleetMigrationFixture{fixtures[16], fixtures[48], fixtures[49]} {
		parent := fixture.path[:strings.LastIndex(fixture.path, "/")]
		code, catalog, err := master.request(ctx, "GET", "/api/v1/media/catalog/media?"+url.Values{"media_type": {"music"}, "path": {parent}, "playback_session_id": {"migration-fleet-session"}}.Encode(), nil)
		if code != 200 || err != nil {
			t.Fatal("post-migration business catalog failed", code, err)
		}
		entries, _ := catalog["entries"].([]any)
		found := false
		for _, raw := range entries {
			track := raw.(map[string]any)
			if track["resource_id"] != fixture.id {
				continue
			}
			found = true
			stream, _ := track["url"].(string)
			fleetRange(t, ctx, sites, stream, fixture.id, fixture.payload, fixture.bytes)
			if fixture.path == cryptoPath {
				actual := fleetPreparedCrypto{}
				fleetCryptoDecode(t, map[string]any{"encryption": track["encryption"]}, &actual)
				if actual.Encryption != prepared.Encryption {
					t.Fatal("migration changed encryption descriptor")
				}
				aead := crypto.decryptGrant(t, ctx, master, cryptoPath, prepared.Encryption)
				fleetDecryptCiphertext(t, ctx, sites, stream, prepared.Encryption, aead, plain)
			}
		}
		if !found {
			t.Fatal("migration changed logical media identity")
		}
	}
	// Restart all three participants without changing stored task facts. The
	// one-hour cleanup window and target authority must survive the restart.
	for _, site := range []*fleetSite{master, sites[sourceIndex], sites[targetIndex]} {
		if err = e.Stop(ctx, site.web); err != nil {
			t.Fatal(err)
		}
		if err = e.Start(ctx, site.web); err != nil {
			t.Fatal(err)
		}
		if err = e.Healthy(ctx, site.web); err != nil {
			t.Fatal(err)
		}
	}
	fleetDecode(t, perform(master, "GET", "/nodes/migrations/"+plan.ID, nil), &status)
	if status.Task.State != "cleanup_pending" || status.Task.CommittedBytes != status.Task.TotalBytes {
		t.Fatal("restart lost committed ownership or grace")
	}
	check := perform(master, "POST", "/nodes/"+relations[sourceIndex-1]+"/retire/check", map[string]any{"member_id": sourceID})
	var report noderetirement.Report
	fleetDecode(t, check, &report)
	if report.Master.DatabaseClear && report.Peer.DatabaseClear && len(report.Concerns) == 0 {
		t.Fatal("retirement ignored pending source cleanup")
	}
	t.Log("native migration committed real bytes, kept IDs/encryption and grace copies across restart", pair, "objects", len(fixtures), "bytes", status.Task.TotalBytes, "peak cgroup bytes", peak)
	if os.Getenv("FRONTIERCLOUD_TEST_NATIVE_MIGRATION_BROWSER") == "1" {
		fleetMigrationBrowserGate(t, ctx, e, sites, plan.ID, sourceID, targetID, cryptoPath, prepared.Encryption.FileID, plain)
	}
	if os.Getenv("FRONTIERCLOUD_TEST_NATIVE_MIGRATION_WAIT_CLEANUP") != "1" {
		t.Log("real one-hour cleanup not awaited in this cutover run")
		return
	}
	deadline = time.Now().Add(70 * time.Minute)
	for status.Task.State != "completed" {
		if time.Now().After(deadline) || status.Task.State == "failed" {
			t.Fatal("real grace cleanup did not complete", status.Task.State, status.Task.ErrorCode)
		}
		time.Sleep(10 * time.Second)
		fleetDecode(t, perform(master, "GET", "/nodes/migrations/"+plan.ID, nil), &status)
	}
	for _, fixture := range fixtures {
		if _, err = os.Lstat(filepath.Join(sites[sourceIndex].root, "data", "media", filepath.FromSlash(fixture.sourcePath))); !os.IsNotExist(err) {
			t.Fatal("completed task retained source object", err)
		}
	}
	t.Log("actual one-hour source grace elapsed and native managed cleanup completed", pair)
	// Retirement after a real migration has durable task/journal history, unlike
	// the empty-node pairing gate. Recheck that history through the normal APIs.
	fleetRequireRetirementClear(t, perform(master, "POST", "/nodes/"+relations[sourceIndex-1]+"/retire/check", map[string]any{"member_id": sourceID}))
	perform(master, "POST", "/nodes/"+relations[sourceIndex-1]+"/retire/apply", map[string]any{"member_id": sourceID, "confirm_member_id": sourceID})
	for _, site := range []*fleetSite{master, sites[sourceIndex]} {
		state := perform(site, "GET", "/nodes", nil)
		if site == sites[sourceIndex] && state["node_id"] != sourceID {
			t.Fatal("post-migration retirement replaced source identity")
		}
		rows, _ := state["relationships"].([]any)
		for _, raw := range rows {
			row := raw.(map[string]any)
			if row["relationship_id"] == relations[sourceIndex-1] && row["state"] != "revoked" {
				t.Fatal("post-migration retirement retained active old relationship")
			}
		}
		container, err := e.Inspect(ctx, site.web)
		if err != nil || container.State.Status != "running" {
			t.Fatal("business retirement stopped native containers", err)
		}
		if info, err := os.Stat(filepath.Join(site.root, "data")); err != nil || !info.IsDir() {
			t.Fatal("business retirement removed retained native data")
		}
	}
	t.Log("independent post-migration native retirement revoked the old relationship, retained NodeID/history and left containers/data intact")
}

func fleetMigrationNetworkBytes(t *testing.T, ctx context.Context, e *Engine, id string) [2]uint64 {
	t.Helper()
	var stats struct {
		Networks map[string]struct {
			Rx uint64 `json:"rx_bytes"`
			Tx uint64 `json:"tx_bytes"`
		} `json:"networks"`
	}
	if err := e.call(ctx, "GET", "/containers/"+id+"/stats?stream=false", nil, &stats); err != nil || len(stats.Networks) == 0 {
		t.Fatal("native data-path counters unavailable", err)
	}
	var totals [2]uint64
	for _, network := range stats.Networks {
		totals[0] += network.Rx
		totals[1] += network.Tx
	}
	return totals
}

func fleetMigrationLyricFixture(t *testing.T, ctx context.Context, master *fleetSite, perform func(*fleetSite, string, string, any) map[string]any, tracks []string) {
	t.Helper()
	var body bytes.Buffer
	form := multipart.NewWriter(&body)
	if form.WriteField("storage_mode", "plain") != nil || form.WriteField("relative_path", "migration/tone.lrc") != nil {
		t.Fatal("private lyric form unavailable")
	}
	file, err := form.CreateFormFile("file", "tone.lrc")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = io.WriteString(file, "[00:00.00]Native migration tone lyric\n[00:01.00]Original business relation retained\n"); err != nil || form.Close() != nil {
		t.Fatal("private lyric fixture unavailable")
	}
	code, result, err := master.request(ctx, "POST", "/api/v1/media/admin/upload/lyric", body.Bytes(), map[string]string{"Content-Type": form.FormDataContentType()})
	if err != nil || code != 200 || result["path"] != "lyrics/migration/tone.lrc" {
		t.Fatal("native Master lyric upload failed", code)
	}
	for _, track := range tracks {
		perform(master, "POST", "/lyrics/relations", map[string]any{"origin_kind": "track", "origin_path": track, "linked_paths": []string{"lyrics/migration/tone.lrc"}})
	}
}

func fleetMigrationDirectRefusal(t *testing.T, ctx context.Context, master, target *fleetSite, perform func(*fleetSite, string, string, any) map[string]any, task, sourceID string, fixtures []fleetMigrationFixture) {
	t.Helper()
	var status store.MigrationStatus
	for deadline := time.Now().Add(2 * time.Minute); ; {
		fleetDecode(t, perform(master, "GET", "/nodes/migrations/"+task, nil), &status)
		if status.Task.State == "failed" {
			break
		}
		if status.Task.CommittedBytes != 0 || time.Now().After(deadline) {
			t.Fatal("unreachable native peers did not stop safely", status.Task.State, status.Task.ErrorCode)
		}
		time.Sleep(300 * time.Millisecond)
	}
	if status.Task.ErrorCode != "direct_peer_transfer" || status.Task.CommittedBytes != 0 || status.RetirementReady {
		t.Fatal("unreachable peer used another path or lost safe state")
	}
	checked := map[string]bool{}
	for _, fixture := range fixtures {
		parent := fixture.path[:strings.LastIndex(fixture.path, "/")]
		if !checked[parent] {
			checked[parent] = true
			var tree media.Tree
			fleetDecode(t, perform(master, "GET", "/tree?"+url.Values{"path": {parent}}.Encode(), nil), &tree)
			for _, item := range tree.Items {
				if item.Media && item.MemberID != sourceID {
					t.Fatal("unreachable peers changed native authoritative owner")
				}
			}
		}
		sum := sha256.Sum256([]byte("media:" + fixture.id))
		journal := filepath.Join(target.root, "data", "media", ".migration-data-"+task+"-"+hex.EncodeToString(sum[:])+".json")
		raw, err := os.ReadFile(journal)
		if os.IsNotExist(err) {
			continue
		}
		var checkpoint migrationdata.Checkpoint
		if err != nil || len(raw) > 16<<10 || json.Unmarshal(raw, &checkpoint) != nil || checkpoint.Spec.TaskID != task || checkpoint.Spec.LogicalID != fixture.id || checkpoint.Offset != 0 {
			t.Fatal("unreachable peer wrote target payload")
		}
	}
	t.Log("native peers are mutually unreachable: direct_peer_transfer failure, zero copied/committed bytes, source ownership retained, no Master relay fallback")
}

// The public download is real business traffic through the native media route.
// Product clocks, counters, SQL and receiver journals are never changed by this
// acceptance. The bounded driver reads slowly to keep the response in flight.
func fleetMigrationTrafficGate(t *testing.T, ctx context.Context, master, source, target *fleetSite, perform func(*fleetSite, string, string, any) map[string]any, task, sourceID, targetID string, fixture fleetMigrationFixture) {
	t.Helper()
	readStatus := func() store.MigrationStatus {
		var status store.MigrationStatus
		fleetDecode(t, perform(master, "GET", "/nodes/migrations/"+task, nil), &status)
		if status.Task.State == "failed" {
			t.Fatal("traffic acceptance failed task", status.Task.ErrorCode)
		}
		return status
	}
	wait := func(label string, timeout time.Duration, accept func(store.MigrationStatus) bool) store.MigrationStatus {
		deadline := time.Now().Add(timeout)
		for {
			status := readStatus()
			if accept(status) {
				return status
			}
			if time.Now().After(deadline) {
				t.Fatal("native traffic gate timed out", label, status.Task.State, status.Task.ErrorCode)
			}
			time.Sleep(200 * time.Millisecond)
		}
	}
	wait("initial large-object checkpoint", 2*time.Minute, func(s store.MigrationStatus) bool {
		return s.Execution != nil && s.Execution.ObjectID == fixture.id && s.Execution.CurrentBytes >= 1<<20 && s.Execution.CurrentBytes < fixture.bytes/2
	})
	parent := fixture.path[:strings.LastIndex(fixture.path, "/")]
	code, catalog, err := master.request(ctx, "GET", "/api/v1/media/catalog/media?"+url.Values{"media_type": {"music"}, "path": {parent}, "playback_session_id": {"migration-traffic-session"}}.Encode(), nil)
	if code != 200 || err != nil {
		t.Fatal("native traffic catalog unavailable")
	}
	location := ""
	entries, _ := catalog["entries"].([]any)
	for _, raw := range entries {
		entry := raw.(map[string]any)
		if entry["resource_id"] == fixture.id {
			location, _ = entry["url"].(string)
		}
	}
	if strings.HasPrefix(location, "/") {
		location = master.origin + location
	}
	loadCtx, stopLoad := context.WithCancel(ctx)
	defer stopLoad()
	var response *http.Response
	for redirects := 0; redirects < 2; redirects++ {
		u, err := url.Parse(location)
		if err != nil {
			t.Fatal("invalid private traffic URL")
		}
		site := master
		if u.Scheme+"://"+u.Host == source.origin {
			site = source
		} else if u.Scheme+"://"+u.Host != master.origin {
			t.Fatal("business load escaped private source/master")
		}
		r, err := http.NewRequestWithContext(loadCtx, "GET", location, nil)
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Origin", master.origin)
		client := *site.client
		client.Timeout = 2 * time.Minute
		response, err = client.Do(r)
		if err != nil {
			t.Fatal("actual business stream unavailable")
		}
		if response.StatusCode == 307 && redirects == 0 {
			location = response.Header.Get("Location")
			response.Body.Close()
			continue
		}
		if response.StatusCode != 200 {
			response.Body.Close()
			t.Fatal("actual business stream failed", response.StatusCode)
		}
		break
	}
	if response == nil || response.StatusCode != 200 {
		t.Fatal("business load did not reach media bytes")
	}
	done := make(chan error, 1)
	go func() {
		defer response.Body.Close()
		buffer := make([]byte, 64<<10)
		for {
			_, err := io.ReadFull(response.Body, buffer)
			if err != nil {
				done <- err
				return
			}
			timer := time.NewTimer(60 * time.Millisecond)
			select {
			case <-loadCtx.Done():
				timer.Stop()
				done <- loadCtx.Err()
				return
			case <-timer.C:
			}
		}
	}()
	stopped := false
	stop := func() {
		if !stopped {
			stopped = true
			stopLoad()
			response.Body.Close()
			<-done
		}
	}
	defer stop()
	busy := wait("actual HTTP peak wait", 20*time.Second, func(s store.MigrationStatus) bool {
		return s.Task.ErrorCode == "waiting_business_traffic" && s.Execution != nil && s.Execution.State == "waiting_traffic"
	})
	seenSource := false
	for _, peer := range busy.Execution.Traffic {
		if peer.NodeID == sourceID && !peer.View.CanRun && (peer.View.Ingress+peer.View.Egress >= peer.View.High || peer.View.Recent >= peer.View.High) {
			seenSource = true
		}
	}
	if !seenSource {
		t.Fatal("source HTTP bytes did not explain native wait")
	}
	sum := sha256.Sum256([]byte("media:" + fixture.id))
	journal := filepath.Join(target.root, "data", "media", ".migration-data-"+task+"-"+hex.EncodeToString(sum[:])+".json")
	checkpoint := func() int64 {
		raw, err := os.ReadFile(journal)
		var cp migrationdata.Checkpoint
		if err != nil || len(raw) > 16<<10 || json.Unmarshal(raw, &cp) != nil || cp.Spec.TaskID != task || cp.Spec.LogicalID != fixture.id {
			t.Fatal("actual native receiver checkpoint unavailable")
		}
		return cp.Offset
	}
	// Allow the single already admitted chunk to finish, then require the actual
	// on-disk offset to stay fixed throughout sustained peak traffic.
	time.Sleep(time.Second)
	offset := checkpoint()
	if offset < 1<<20 || offset >= fixture.bytes {
		t.Fatal("traffic load missed in-flight native copy", offset)
	}
	time.Sleep(4 * time.Second)
	if checkpoint() != offset || readStatus().Task.ErrorCode != "waiting_business_traffic" {
		t.Fatal("peak traffic advanced persisted copy checkpoint")
	}
	stop()
	released := time.Now()
	resumed := wait("continuous low-traffic resume", 50*time.Second, func(s store.MigrationStatus) bool {
		return s.Execution != nil && s.Execution.ObjectID == fixture.id && s.Execution.CurrentBytes > offset
	})
	if time.Since(released) < 29*time.Second {
		t.Fatal("native resumed before sustained low interval")
	}
	perform(master, "POST", "/nodes/migrations/"+task+"/control", map[string]any{"action": "pause", "revision": resumed.Task.Revision, "confirm_source_id": sourceID, "confirm_target_id": targetID})
	time.Sleep(2 * time.Second)
	pausedOffset := checkpoint()
	for deadline := time.Now().Add(32 * time.Second); time.Now().Before(deadline); {
		status := readStatus()
		if status.Task.State != "paused" || status.Execution != nil || checkpoint() != pausedOffset {
			t.Fatal("manual pause resumed or changed checkpoint while idle")
		}
		time.Sleep(time.Second)
	}
	paused := readStatus()
	perform(master, "POST", "/nodes/migrations/"+task+"/control", map[string]any{"action": "resume", "revision": paused.Task.Revision, "confirm_source_id": sourceID, "confirm_target_id": targetID})
	wait("explicit manual resume", 30*time.Second, func(s store.MigrationStatus) bool {
		return s.Execution != nil && s.Execution.ObjectID == fixture.id && s.Execution.CurrentBytes > pausedOffset
	})
	t.Logf("actual HTTP peak held native checkpoint=%d; sustained quiet auto-resumed; manual pause retained checkpoint=%d for 32s and explicit resume succeeded", offset, pausedOffset)
}

// The host's isolated Chromium driver reads this private handoff after native
// cutover and restart. Only fixture metadata and file locations are written;
// credentials and signed URLs never enter the test transcript.
func fleetMigrationBrowserGate(t *testing.T, ctx context.Context, e *Engine, sites []*fleetSite, task, source, target, encryptedPath, fileID string, plaintext []byte) {
	fleetMigrationBrowserGatePhase(t, ctx, e, sites, task, source, target, encryptedPath, fileID, plaintext, "after")
}

func fleetMigrationBrowserGatePhase(t *testing.T, ctx context.Context, e *Engine, sites []*fleetSite, task, source, target, encryptedPath, fileID string, plaintext []byte, phase string) {
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
			t.Fatal("private browser network inventory", err)
		}
		u, err := url.Parse(site.origin)
		address := inspected.NetworkSettings.Networks[site.project].IPAddress
		if err != nil || address == "" {
			t.Fatal("private browser endpoint unavailable")
		}
		hosts[u.Hostname()] = address
	}
	digest := sha256.Sum256(plaintext)
	rangeDigest := sha256.Sum256(plaintext[1048541:1048620])
	root := filepath.Dir(sites[0].root)
	fixture := map[string]any{"origin": sites[0].origin, "hosts": hosts,
		"phase":          phase,
		"admin_key_file": filepath.Join(sites[0].root, "secrets", "admin_key"),
		"task_id":        task, "source_id": source, "target_id": target,
		"encrypted": map[string]any{"path": encryptedPath, "file_id": fileID,
			"plaintext_sha256": hex.EncodeToString(digest[:]), "plaintext_bytes": len(plaintext),
			"range_start": 1048541, "range_end": 1048619, "range_sha256": hex.EncodeToString(rangeDigest[:])}}
	if os.Getenv("FRONTIERCLOUD_TEST_NATIVE_MIGRATION_AUDIO") == "1" {
		fixture["audio"] = map[string]any{"plain_directory": "music/migrate/parent1", "plain_first_path": "music/migrate/parent1/track-016.mp3", "plain_second_path": "music/migrate/parent1/track-017.mp3", "lyric_path": "lyrics/migration/tone.lrc"}
	}
	raw, err := json.Marshal(fixture)
	fixtureName, resultName := "browser-fixture.json", "browser-result.json"
	if phase == "during" {
		fixtureName, resultName = "browser-during-fixture.json", "browser-during-result.json"
	}
	if err != nil || os.WriteFile(filepath.Join(root, fixtureName), raw, 0600) != nil {
		t.Fatal("private browser handoff could not be saved")
	}
	t.Log("native fixture awaits isolated Chromium result", phase, filepath.Join(root, fixtureName))
	deadline := time.Now().Add(5 * time.Minute)
	for {
		raw, err := os.ReadFile(filepath.Join(root, resultName))
		if err == nil {
			var result struct {
				Passed     bool `json:"passed"`
				RealServer bool `json:"real_server"`
				Decrypted  bool `json:"decrypted"`
				Decoded    bool `json:"decoded_playback_verified"`
				Encrypted  bool `json:"encrypted_playback_verified"`
				Continuous bool `json:"continuous_playback_verified"`
				Lyrics     bool `json:"lyric_relation_verified"`
			}
			if json.Unmarshal(raw, &result) != nil || !result.Passed || !result.RealServer || !result.Decrypted {
				t.Fatal("actual Chromium migration verification failed; private result retained")
			}
			if os.Getenv("FRONTIERCLOUD_TEST_NATIVE_MIGRATION_AUDIO") == "1" && (!result.Decoded || !result.Encrypted || !result.Continuous || !result.Lyrics) {
				t.Fatal("generated MP3 playback/continuation/lyric proof is incomplete")
			}
			t.Log("actual Chromium Admin task rendering and post-restart encrypted native byte/Range verification passed")
			return
		}
		if !os.IsNotExist(err) || time.Now().After(deadline) {
			t.Fatal("actual Chromium result unavailable")
		}
		select {
		case <-ctx.Done():
			t.Fatal("native browser gate interrupted")
		case <-time.After(time.Second):
		}
	}
}

// Give every Storage its own native Docker network, reachable by the Master
// and the private test driver. Storage nodes share no network with each other;
// a migration transfer must therefore stop without relaying through Master. No host firewall
// or global Docker network configuration is changed.
func fleetSeparateStorageNetworks(t *testing.T, ctx context.Context, e *Engine, sites []*fleetSite) {
	t.Helper()
	master := sites[0]
	driver, err := e.Inspect(ctx, os.Getenv("FRONTIERCLOUD_TEST_NATIVE_MATRIX_PREFIX")+"-driver")
	if err != nil {
		t.Fatal("private migration driver unavailable", err)
	}
	edge, err := e.Inspect(ctx, master.project+"-edge")
	if err != nil {
		t.Fatal("private migration edge unavailable", err)
	}
	shared := strings.TrimSuffix(master.project, "-site0") + "-plane"
	for _, site := range sites[1:] {
		for _, id := range []string{driver.ID, master.web, edge.ID} {
			body := map[string]any{"Container": id}
			if id == edge.ID {
				body["EndpointConfig"] = map[string]any{"Aliases": []string{"site0.fleet.invalid"}}
			}
			if err := e.call(ctx, "POST", "/networks/"+site.project+"/connect", body, nil); err != nil {
				t.Fatal("private migration network connection", err)
			}
		}
		if err := e.call(ctx, "POST", "/networks/"+shared+"/disconnect", map[string]any{"Container": site.web, "Force": false}, nil); err != nil {
			t.Fatal("private storage isolation failed", err)
		}
		site.client.CloseIdleConnections()
	}
	master.client.CloseIdleConnections()
	for _, site := range sites[1:] {
		var inspected struct {
			NetworkSettings struct{ Networks map[string]any }
		}
		if err := e.call(ctx, "GET", "/containers/"+site.web+"/json", nil, &inspected); err != nil {
			t.Fatal(err)
		}
		if len(inspected.NetworkSettings.Networks) != 1 || inspected.NetworkSettings.Networks[site.project] == nil {
			t.Fatal("Storage still shares an unintended network")
		}
	}
	t.Log("all four Storage processes have separate native networks; migration relay is prohibited")
}
