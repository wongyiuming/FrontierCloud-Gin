//go:build linux

package operator

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/backup"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/release"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/runtimefacts"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sitecontrol"
	"github.com/wongyiuming/FrontierCloud-Gin/migrations"
)

func TestBusinessImportRequiresProtectedExactArtifact(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "business.backup")
	payload := []byte("pinned business backup")
	digest := sha256.Sum256(payload)
	expected := backup.Expectation{Generation: 9, Checksum: hex.EncodeToString(digest[:]), Bytes: int64(len(payload))}
	if err := os.WriteFile(file, payload, 0600); err != nil {
		t.Fatal(err)
	}
	f, err := openBusinessImport(t.Context(), file, expected)
	if err != nil {
		t.Fatal(err)
	}
	read, err := io.ReadAll(f)
	f.Close()
	if err != nil || !bytes.Equal(read, payload) {
		t.Fatalf("verified file is not rewound: %q, %v", read, err)
	}
	wrong := expected
	wrong.Checksum = strings.Repeat("0", 64)
	if f, err := openBusinessImport(t.Context(), file, wrong); err == nil {
		f.Close()
		t.Fatal("accepted wrong artifact digest")
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(file, link); err != nil {
		t.Fatal(err)
	}
	if f, err := openBusinessImport(t.Context(), link, expected); err == nil {
		f.Close()
		t.Fatal("accepted artifact symlink")
	}
	if err := os.Chmod(file, 0644); err != nil {
		t.Fatal(err)
	}
	if f, err := openBusinessImport(t.Context(), file, expected); err == nil {
		f.Close()
		t.Fatal("accepted publicly readable artifact")
	}
}

type businessImportTestInput struct {
	bytes.Buffer
	closed bool
}

func (in *businessImportTestInput) Close() error { in.closed = true; return nil }

func TestBusinessImportBindsCompleteNativeReport(t *testing.T) {
	master := strings.Repeat("a", 32)
	source := "fixture"
	expected := backup.Expectation{Generation: 9, Checksum: strings.Repeat("c", 64), Bytes: int64(len(source))}
	proof := backup.BusinessStateReport{TargetMasterID: master, SourceGeneration: expected.Generation, SourceSHA256: expected.Checksum, ImportedRows: map[string]int64{
		"ip_security_audit_log": 1, "ip_security_summary": 1, "ip_auto_ban_events": 0, "ip_permanent_whitelist": 1,
		"webrtc_observation_events": 1, "webrtc_observation_summary": 1, "karaoke_users": 1, "karaoke_registration_daily": 0, "karaoke_audit_log": 0,
	}}
	data, err := json.Marshal(proof)
	if err != nil {
		t.Fatal(err)
	}
	record := string(data) + "\n"
	exchange := func(ctx context.Context, input, output string) (backup.BusinessStateReport, *businessImportTestInput, error) {
		writer := new(businessImportTestInput)
		report, err := exchangeBusinessImport(ctx, strings.NewReader(input), expected, master, writer, bufio.NewReader(strings.NewReader(output)))
		return report, writer, err
	}
	result, writer, err := exchange(t.Context(), source, record)
	if err != nil || !result.MatchesImport(expected, master) || !writer.closed || writer.String() != source {
		t.Fatalf("exact exchange: %+v, %v", result, err)
	}
	for _, candidate := range []string{
		strings.TrimSuffix(record, "\n"), strings.Replace(record, master, strings.Repeat("b", 32), 1),
		strings.Replace(record, `,"restore_ready":false`, "", 1), strings.Replace(record, `"restore_ready":false`, `"restore_ready":true`, 1),
		strings.Replace(record, `,"karaoke_users":1`, "", 1), strings.Replace(record, `,"karaoke_users":1`, `,"karaoke_users":1,"karaoke_users":1`, 1),
	} {
		if _, _, err := exchange(t.Context(), source, candidate); err == nil {
			t.Errorf("accepted malformed report %s", candidate)
		}
	}
	for _, candidate := range []string{source + "x", source[:len(source)-1]} {
		if _, _, err := exchange(t.Context(), candidate, record); err == nil {
			t.Error("accepted changed artifact length")
		}
	}
}

func TestBusinessPreparationBindsFencedMasterReport(t *testing.T) {
	master := strings.Repeat("a", 32)
	valid := `{"target_master_id":"` + master + `","prepared":true,"restore_ready":false}` + "\n"
	read := func(raw string) error {
		report, err := readBusinessPreparationReport(bufio.NewReader(strings.NewReader(raw)), master)
		if err == nil && (report.TargetMasterID != master || !report.Prepared || report.RestoreReady) {
			t.Fatalf("unexpected preparation report: %+v", report)
		}
		return err
	}
	if err := read(valid); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{
		strings.Replace(valid, master, strings.Repeat("b", 32), 1),
		strings.Replace(valid, `"restore_ready":false`, `"restore_ready":true`, 1),
		strings.Replace(valid, `,"restore_ready":false`, "", 1),
		strings.Replace(valid, `"prepared":true`, `"prepared":true,"prepared":true`, 1),
		strings.TrimSuffix(valid, "\n"),
	} {
		if err := read(raw); err == nil {
			t.Error("accepted an unbound or incomplete preparation report")
		}
	}
}

func TestBusinessImportReceiptBindsTargetAndMounts(t *testing.T) {
	target := stoppedBusinessState{deployment: &Deployment{Directory: t.TempDir()}, id: strings.Repeat("a", 32)}
	target.mounts.proof[0].Inode = 10
	source := backup.Expectation{Generation: 9, Checksum: strings.Repeat("c", 64), Bytes: 42}
	report := backup.BusinessStateReport{TargetMasterID: target.id, SourceGeneration: source.Generation, SourceSHA256: source.Checksum, ImportedRows: map[string]int64{
		"ip_security_audit_log": 1, "ip_security_summary": 1, "ip_auto_ban_events": 0, "ip_permanent_whitelist": 1,
		"webrtc_observation_events": 1, "webrtc_observation_summary": 1, "karaoke_users": 1, "karaoke_registration_daily": 0, "karaoke_audit_log": 0,
	}}
	if _, err := target.businessImportReceipt(); !os.IsNotExist(err) {
		t.Fatalf("initial receipt: %v", err)
	}
	if err := target.recordBusinessImport(source, report, businessImportReceipt{}); err != nil {
		t.Fatal(err)
	}
	recorded, err := target.businessImportReceipt()
	if err != nil || recorded.Source != source || recorded.Report.TargetMasterID != target.id {
		t.Fatalf("recorded receipt: %+v, %v", recorded, err)
	}
	report.AlreadyApplied = true
	if err := target.recordBusinessImport(source, report, recorded); err != nil {
		t.Fatal(err)
	}
	report.ImportedRows["karaoke_users"]++
	if err := target.recordBusinessImport(source, report, recorded); err == nil {
		t.Fatal("accepted changed report for the same artifact")
	}
	foreign := target
	foreign.mounts.proof[0].Inode++
	if _, err := foreign.businessImportReceipt(); err == nil {
		t.Fatal("accepted import receipt for another data mount")
	}
	foreign = target
	foreign.receipt.Revision = strings.Repeat("b", 40)
	if _, err := foreign.businessImportReceipt(); err == nil {
		t.Fatal("accepted import receipt from another deployment")
	}
}

func TestBusinessActivationRequiresRealManualMarker(t *testing.T) {
	directory := t.TempDir()
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	owner := runtimefacts.TreeBackupMount{UID: uint32(os.Geteuid()), GID: uint32(os.Getegid())}
	requireInvalid := func() {
		t.Helper()
		if _, err := businessManualMarker(root, owner); !errors.Is(err, sitecontrol.ErrState) {
			t.Fatalf("unexpected manual marker result: %v", err)
		}
	}
	requireInvalid()
	site, err := sitecontrol.Open(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer site.Close()
	if _, err := site.Set(t.Context(), true); err != nil {
		t.Fatal(err)
	}
	marker, err := businessManualMarker(root, owner)
	named, statErr := root.Lstat(sitecontrol.Manual)
	if err != nil || statErr != nil || marker.Ino != named.Sys().(*syscall.Stat_t).Ino {
		t.Fatalf("expected original marker: %v, %v", err, statErr)
	}
	if err := root.Chmod(sitecontrol.Manual, 0664); err != nil {
		t.Fatal(err)
	}
	requireInvalid()
	if err := root.Chmod(sitecontrol.Manual, 0644); err != nil {
		t.Fatal(err)
	}
	if err := root.WriteFile(sitecontrol.ForceOpen, []byte("release-failure-override\n"), 0600); err != nil {
		t.Fatal(err)
	}
	requireInvalid()
	if err := root.Remove(sitecontrol.ForceOpen); err != nil {
		t.Fatal(err)
	}
	if err := root.Rename(sitecontrol.Manual, "other"); err != nil {
		t.Fatal(err)
	}
	if err := root.Symlink("other", sitecontrol.Manual); err != nil {
		t.Fatal(err)
	}
	requireInvalid()
}

func TestBusinessActivationChecksComposeDefaultsAndRejectsEdgeOverrides(t *testing.T) {
	source := t.TempDir()
	image := release.ImageProof{
		Image:    "ghcr.io/wongyiuming/frontiercloud-gin-nginx@sha256:" + strings.Repeat("a", 64),
		Revision: strings.Repeat("b", 40), ConfigDigest: "sha256:" + strings.Repeat("c", 64),
		Platform: "linux/amd64", Generation: migrations.Generation,
	}
	runner := &fakeRunner{}
	target := stoppedBusinessState{
		deployment: &Deployment{Runner: runner},
		receipt:    Receipt{Revision: image.Revision, Images: map[string]release.ImageProof{"nginx": image}},
		cfg: Config{Services: map[string]Service{
			"certificate-agent": {Image: "web"},
			"redis":             {Image: "redis"},
			"web": {Image: "web", Environment: map[string]string{"TLS_ENABLED": "true", "SERVER_NAME": "master.test"},
				Execution: map[string]json.RawMessage{"command": json.RawMessage(`["serve"]`), "entrypoint": json.RawMessage("null")}},
			"nginx": {Image: image.Image, Environment: map[string]string{"TLS_ENABLED": "true", "SERVER_NAME": "master.test", "NGINX_ENVSUBST_OUTPUT_DIR": "/etc/nginx"},
				Execution: map[string]json.RawMessage{"command": json.RawMessage("null"), "entrypoint": json.RawMessage("null")},
				Volumes:   []Mount{{Type: "bind", Source: source, Target: "/app/data", ReadOnly: true}}},
		}},
		mounts: businessImportMounts{data: source, proof: [2]runtimefacts.TreeBackupMount{{Mode: 0750, GID: 10001}}},
	}
	// The fake cannot attest a Docker engine. Reaching it proves the same null
	// command and entrypoint emitted by Compose passed the edge checks.
	_ = target.checkActivationEdge(t.Context())
	if len(runner.calls) == 0 || !strings.Contains(runner.calls[0], "context inspect") {
		t.Fatal("Compose defaults prevented local image verification")
	}
	runner.calls = nil
	target.cfg.Services["nginx"].Execution["command"] = json.RawMessage(`["sh"]`)
	if err := target.checkActivationEdge(t.Context()); err == nil || len(runner.calls) != 0 {
		t.Fatal("custom edge command reached local image verification")
	}
}
