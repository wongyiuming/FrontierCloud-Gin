//go:build linux

package operator

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/backup"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/release"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/runtimefacts"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sitecontrol"
	"github.com/wongyiuming/FrontierCloud-Gin/migrations"
)

const businessImportReceiptFile = ".fc-business-import.json"

type businessImportReceipt struct {
	Version       int                             `json:"version"`
	DeploymentSHA string                          `json:"deployment_sha256"`
	Mounts        [2]runtimefacts.TreeBackupMount `json:"mounts"`
	Source        backup.Expectation              `json:"source"`
	Report        backup.BusinessStateReport      `json:"report"`
}

func (t *stoppedBusinessState) businessImportReceipt() (businessImportReceipt, error) {
	var value businessImportReceipt
	path := filepath.Join(t.deployment.Directory, businessImportReceiptFile)
	info, err := os.Lstat(path)
	if err != nil {
		return value, err
	}
	invalid := errors.New("invalid or foreign business import receipt")
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || info.Mode() != 0600 || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 {
		return value, invalid
	}
	raw, err := readRegular(path, 4096)
	if err != nil {
		return value, err
	}
	current, err := os.Lstat(path)
	if err != nil || !sameTreeRuntimeFile(info, current) {
		return value, invalid
	}
	if _, err = protocol.ParseStrictJSON(raw, 4096); err != nil {
		return value, invalid
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&value) != nil || value.Version != 1 || value.DeploymentSHA != upgradeHash(t.receipt) || value.Mounts != t.mounts.proof ||
		!validRetainedTreeDigest(value.Source.Checksum) || value.Source.Generation <= 0 || value.Source.Bytes <= 0 || value.Source.Bytes > backup.MaxBusinessStateBytes ||
		value.Report.AlreadyApplied || !value.Report.MatchesImport(value.Source, t.id) {
		return businessImportReceipt{}, invalid
	}
	return value, nil
}

func (t *stoppedBusinessState) recordBusinessImport(source backup.Expectation, report backup.BusinessStateReport, previous businessImportReceipt) error {
	report.AlreadyApplied = false
	value := businessImportReceipt{Version: 1, DeploymentSHA: upgradeHash(t.receipt), Mounts: t.mounts.proof, Source: source, Report: report}
	if previous.Version != 0 {
		if !reflect.DeepEqual(previous, value) {
			return errors.New("business import report changed on retry")
		}
		return nil
	}
	return exclusiveJSON(filepath.Join(t.deployment.Directory, businessImportReceiptFile), value)
}

// ActivateBusinessState resumes only the prepared target behind its existing
// manual public maintenance fence. It does not open the site.
func (d *Deployment) ActivateBusinessState(ctx context.Context, r Receipt, targetMasterID, sourceSHA string) (runtimefacts.BusinessActivationReport, error) {
	var report runtimefacts.BusinessActivationReport
	if ctx == nil || !validRetainedTreeDigest(sourceSHA) {
		return report, backup.ErrBusinessStateTarget
	}
	ctx, cancel := context.WithTimeout(ctx, 4*time.Minute)
	defer cancel()
	err := d.withStoppedBusinessState(ctx, r, targetMasterID, func(t *stoppedBusinessState) (activationErr error) {
		imported, err := t.businessImportReceipt()
		if err != nil || imported.Source.Checksum != sourceSHA {
			return errors.New("activation requires a completed import of the exact source on this Master")
		}
		for _, marker := range []string{RecoverySetMarker, treeRetainedJournal} {
			if _, err := os.Lstat(filepath.Join(d.Directory, marker)); !os.IsNotExist(err) {
				return errors.New("activation refuses a separate recovery operation")
			}
		}
		if err := t.checkActivationEdge(ctx); err != nil {
			return err
		}
		root, err := os.OpenRoot(t.mounts.data)
		if err != nil {
			return err
		}
		defer root.Close()
		rootInfo, err := root.Stat(".")
		if err != nil || !os.SameFile(rootInfo, t.mounts.dataInfo) {
			return sitecontrol.ErrState
		}
		releaseSite, err := sitecontrol.Lease(ctx, root, true)
		if err != nil {
			return err
		}
		marker, err := businessManualMarker(root, t.mounts.proof[0])
		releaseSite()
		if err != nil {
			return err
		}
		defer func() {
			if activationErr != nil && !d.fenceUpgradeFailure(ctx, t.cfg) {
				activationErr = errors.Join(activationErr, errors.New("native maintenance and stopped writers could not be reconfirmed"))
			}
		}()
		if err := t.runChild(ctx, []string{resumeBusinessState, "--manual-proof", fmt.Sprintf("%d:%d", marker.Dev, marker.Ino)}, func(in io.WriteCloser, out *bufio.Reader) error {
			if err := in.Close(); err != nil {
				return err
			}
			_, fields, err := readBusinessStateReport(out)
			if err != nil || len(fields) != 3 || fields["target_master_id"] != t.id || fields["resumed"] != true || fields["restore_ready"] != false {
				return errors.New("private resume report does not match the selected Master")
			}
			return nil
		}); err != nil {
			return err
		}
		if err := t.check(ctx, false); err != nil {
			return err
		}
		releaseSite, err = sitecontrol.Lease(ctx, root, true)
		if err != nil {
			return err
		}
		defer releaseSite()
		checkMarker := func() error {
			current, err := businessManualMarker(root, t.mounts.proof[0])
			if err != nil || current.Dev != marker.Dev || current.Ino != marker.Ino || current.Ctim != marker.Ctim {
				return sitecontrol.ErrState
			}
			return nil
		}
		if err := checkMarker(); err != nil {
			return err
		}
		_, err = d.Compose(ctx, true, "up", "-d", "--no-build", "--pull", "never", "--no-deps", "--wait", "--wait-timeout", "120",
			"certificate-agent", "redis", "web", "nginx")
		if err != nil {
			return err
		}
		certCtx, cancel := context.WithTimeout(ctx, 40*time.Second)
		defer cancel()
		if err := d.installCertificateReady(certCtx, t.cfg); err != nil {
			return err
		}
		raw, err := d.Compose(ctx, true, "exec", "-T", "web", "/app/frontiercloud", "operator-status")
		if err != nil {
			return err
		}
		var fact RuntimeFact
		if json.Unmarshal(raw, &fact) != nil || fact.NodeID != t.id || fact.Role != "Master" || !fact.Maintenance || fact.NativeMaintenance ||
			fact.Database.Role != "Master" || fact.Database.SchemaGeneration != migrations.Generation || len(fact.Nodes) != 0 ||
			fact.Database.Pending["sealed_tree_unrecoverable"] != 1 {
			return errors.New("the resumed Master did not confirm private recovery mode")
		}
		for name, count := range fact.Database.Pending {
			if name != "sealed_tree_unrecoverable" && count != 0 {
				return errors.New("resumed Master has unexpected pending work")
			}
		}
		if err := checkMarker(); err != nil {
			return err
		}
		report = runtimefacts.BusinessActivationReport{TargetMasterID: t.id, SourceSHA256: sourceSHA, ServicesStarted: true, ManualMaintenance: true}
		return nil
	})
	if err != nil {
		return runtimefacts.BusinessActivationReport{}, err
	}
	return report, nil
}

func (t *stoppedBusinessState) checkActivationEdge(ctx context.Context) error {
	invalid := errors.New("activation requires the pinned HTTPS edge and its read-only native data bind")
	hasOverride := func(raw json.RawMessage) bool {
		// Compose emits JSON null for unset command and entrypoint fields.
		return len(raw) != 0 && string(raw) != "null"
	}
	for _, name := range []string{"certificate-agent", "redis", "web", "nginx"} {
		service := t.cfg.Services[name]
		if service.Image == "" || hasOverride(service.Execution["network_mode"]) ||
			(name != "nginx" && len(service.Ports) != 0) {
			return invalid
		}
	}
	web, edge := t.cfg.Services["web"], t.cfg.Services["nginx"]
	if web.Environment["TLS_ENABLED"] != "true" || edge.Environment["TLS_ENABLED"] != "true" ||
		web.Environment["SERVER_NAME"] == "" || edge.Environment["SERVER_NAME"] != web.Environment["SERVER_NAME"] {
		return invalid
	}
	var command []string
	if json.Unmarshal(web.Execution["command"], &command) != nil || len(command) != 1 || command[0] != "serve" ||
		hasOverride(web.Execution["entrypoint"]) || hasOverride(edge.Execution["entrypoint"]) || hasOverride(edge.Execution["command"]) ||
		edge.Environment["NGINX_ENVSUBST_OUTPUT_DIR"] != "/etc/nginx" ||
		edge.Environment["NGINX_ENVSUBST_TEMPLATE_DIR"] != "" || edge.Environment["NGINX_ENVSUBST_TEMPLATE_SUFFIX"] != "" ||
		edge.Environment["NGINX_ENVSUBST_FILTER"] != "" {
		return invalid
	}
	// The reviewed edge workers run in group 10001. They must be able to
	// traverse the mounted data directory to see the maintenance flag.
	owner := t.mounts.proof[0]
	if owner.Mode&0001 == 0 && (owner.GID != 10001 || owner.Mode&0010 == 0) {
		return invalid
	}
	found := false
	for _, mount := range edge.Volumes {
		target := filepath.Clean(mount.Target)
		switch {
		case target == "/app/data":
			if found || mount.Type != "bind" || mount.Source != t.mounts.data || !mount.ReadOnly {
				return invalid
			}
			found = true
		case target == "/run/frontiercloud-tls":
			if mount.Type != "volume" || !mount.ReadOnly {
				return invalid
			}
		case target == "/run/frontiercloud-traffic":
			if mount.Type != "volume" || mount.ReadOnly {
				return invalid
			}
		default:
			// A custom trust root is acceptable, but it cannot replace the
			// reviewed edge entrypoint, server configuration, or public files.
			if mount.Type == "bind" && mount.ReadOnly && target == edge.Environment["SSL_CERT_FILE"] &&
				strings.HasPrefix(target, "/run/") && filepath.Dir(target) == "/run" &&
				strings.HasSuffix(target, ".pem") && !strings.HasPrefix(target, "/run/frontiercloud-tls") {
				continue
			}
			return invalid
		}
	}
	proof := t.receipt.Images["nginx"]
	repository, err := release.ImageRepository("nginx")
	if err != nil || !found || proof.Image != edge.Image || proof.Revision != t.receipt.Revision ||
		!strings.HasPrefix(proof.Image, repository+"@sha256:") {
		return invalid
	}
	return t.deployment.verifyLocalReleaseImage(ctx, "nginx", proof)
}

func businessManualMarker(root *os.Root, owner runtimefacts.TreeBackupMount) (syscall.Stat_t, error) {
	const contents = "manual\n"
	var invalid syscall.Stat_t
	f, err := root.OpenFile(sitecontrol.Manual, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return invalid, sitecontrol.ErrState
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !sitecontrol.ValidManualMode(info.Mode()) || info.Size() != int64(len(contents)) {
		return invalid, sitecontrol.ErrState
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != owner.UID || stat.Gid != owner.GID || stat.Nlink != 1 {
		return invalid, sitecontrol.ErrState
	}
	var raw [len(contents)]byte
	if _, err := io.ReadFull(f, raw[:]); err != nil || string(raw[:]) != contents {
		return invalid, sitecontrol.ErrState
	}
	named, err := root.Lstat(sitecontrol.Manual)
	if err != nil || !sameTreeRuntimeFile(info, named) {
		return invalid, sitecontrol.ErrState
	}
	if _, err := root.Lstat(sitecontrol.ForceOpen); !os.IsNotExist(err) {
		return invalid, sitecontrol.ErrState
	}
	return *stat, nil
}
