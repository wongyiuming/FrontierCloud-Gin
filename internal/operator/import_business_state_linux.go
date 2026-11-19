//go:build linux

package operator

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/backup"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/maintenance"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/node"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/release"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/runtimefacts"
)

const prepareBusinessState = "prepare-business-state"
const resumeBusinessState = "resume-business-state"

// ImportBusinessState runs the new release's native importer against the
// selected, already prepared and fenced Master. It never starts the site or
// takes a dependency on the previous deployment's database schema.
func (d *Deployment) ImportBusinessState(ctx context.Context, r Receipt, input string, expected backup.Expectation, targetMasterID string) (report backup.BusinessStateReport, err error) {
	if ctx == nil {
		return report, backup.ErrBusinessStateTarget
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()
	file, err := openBusinessImport(ctx, input, expected)
	if err != nil {
		return report, err
	}
	defer file.Close()
	command := []string{"import-business-state", "--generation", strconv.FormatInt(expected.Generation, 10),
		"--sha256", expected.Checksum, "--bytes", strconv.FormatInt(expected.Bytes, 10)}
	if err = d.withStoppedBusinessState(ctx, r, targetMasterID, func(target *stoppedBusinessState) error {
		previous, err := target.businessImportReceipt()
		if err != nil && !os.IsNotExist(err) {
			return err
		}
		if err == nil && previous.Source != expected {
			return errors.New("a different business artifact was already imported on this target")
		}
		if err := target.runChild(ctx, command, func(in io.WriteCloser, out *bufio.Reader) error {
			var exchangeErr error
			report, exchangeErr = exchangeBusinessImport(ctx, file, expected, targetMasterID, in, out)
			return exchangeErr
		}); err != nil {
			return err
		}
		if err := target.check(ctx, true); err != nil {
			return err
		}
		return target.recordBusinessImport(expected, report, previous)
	}); err != nil {
		return backup.BusinessStateReport{}, err
	}
	return report, nil
}

// PrepareBusinessState prepares encrypted storage on the selected empty,
// already stopped Master and leaves it in native maintenance.
func (d *Deployment) PrepareBusinessState(ctx context.Context, r Receipt, targetMasterID string) (report runtimefacts.BusinessPreparationReport, err error) {
	if ctx == nil {
		return report, backup.ErrBusinessStateTarget
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	if err = d.withStoppedBusinessState(ctx, r, targetMasterID, func(target *stoppedBusinessState) error {
		if err := target.runChild(ctx, []string{prepareBusinessState}, func(in io.WriteCloser, out *bufio.Reader) error {
			if err := in.Close(); err != nil {
				return err
			}
			var exchangeErr error
			report, exchangeErr = readBusinessPreparationReport(out, targetMasterID)
			return exchangeErr
		}); err != nil {
			return err
		}
		return target.check(ctx, true)
	}); err != nil {
		return runtimefacts.BusinessPreparationReport{}, err
	}
	return report, nil
}

type stoppedBusinessState struct {
	deployment *Deployment
	receipt    Receipt
	id         string
	cfg        Config
	mounts     businessImportMounts
	stream     treeDuplexRunner
}

// Hold the host operation lock across child execution and its completion check.
func (d *Deployment) withStoppedBusinessState(ctx context.Context, r Receipt, targetMasterID string, run func(*stoppedBusinessState) error) (operationErr error) {
	if d.Role != "master" || r.Role != "master" || r.Database != "sqlite" || r.Recovered ||
		(r.State != "ready" && r.State != "prepared") || !node.ValidIdentifier(targetMasterID) {
		return backup.ErrBusinessStateTarget
	}
	stream, ok := d.Runner.(treeDuplexRunner)
	if !ok {
		return errors.New("business state recovery requires an isolated duplex runtime")
	}
	done, err := d.AcquireOperation()
	if err != nil {
		return err
	}
	defer func() { operationErr = errors.Join(operationErr, done()) }()
	if err = d.requireTreeLocalDocker(ctx); err != nil {
		return err
	}
	cfg, err := d.ValidateReceipt(ctx, r)
	if err != nil {
		return err
	}
	web := cfg.Services["web"]
	image := r.Images["web"]
	repository, err := release.ImageRepository("web")
	if err != nil || image.Image != web.Image || image.Revision != r.Revision || !strings.HasPrefix(image.Image, repository+"@sha256:") {
		return errors.New("business state recovery web image differs from the selected release")
	}
	if err = d.verifyLocalReleaseImage(ctx, "web", image); err != nil {
		return err
	}
	mounts, err := d.businessImportMounts(ctx, cfg)
	if err != nil {
		return err
	}
	target := stoppedBusinessState{deployment: d, receipt: r, id: targetMasterID, cfg: cfg, mounts: mounts, stream: stream}
	if err = target.check(ctx, true); err != nil {
		return err
	}
	return run(&target)
}

func (t *stoppedBusinessState) check(ctx context.Context, offline bool) error {
	d, r := t.deployment, t.receipt
	_, currentReceipt, err := Open(d.Directory)
	if err != nil || upgradeHash(currentReceipt) != upgradeHash(r) {
		return backup.ErrBusinessStateTarget
	}
	if pending, _, err := d.PendingUpgradeRouting(r); err != nil || pending != "" {
		return errors.New("business state recovery refuses a pending or unverified upgrade")
	}
	current, err := d.ValidateReceipt(ctx, r)
	if err != nil {
		return err
	}
	currentMounts, err := d.businessImportMounts(ctx, current)
	if err != nil || t.mounts.data != currentMounts.data || t.mounts.secrets != currentMounts.secrets ||
		!sameTreeRuntimeDirectory(t.mounts.dataInfo, currentMounts.dataInfo) || !sameTreeRuntimeDirectory(t.mounts.secretInfo, currentMounts.secretInfo) {
		return backup.ErrBusinessStateTarget
	}
	if err = d.stoppedWriters(ctx); err != nil {
		return err
	}
	gate, err := maintenance.OpenExisting(t.mounts.data)
	if err != nil {
		return err
	}
	defer gate.Close()
	if enabled, err := gate.Enabled(); err != nil || enabled != offline {
		return errors.New("business state recovery found an unexpected native maintenance state")
	}
	return d.validateBackupAdmission(ctx, current, r, RuntimeFact{NodeID: t.id})
}

// Only preparation can write a tree key into the secrets volume.
func (t *stoppedBusinessState) runChild(ctx context.Context, command []string, exchange func(io.WriteCloser, *bufio.Reader) error) (operationErr error) {
	d, mounts := t.deployment, t.mounts
	web := t.cfg.Services["web"]
	image := t.receipt.Images["web"]
	preparing := command[0] == prepareBusinessState
	if preparing && !mounts.secretsWritable {
		return errors.New("business state preparation needs the recorded writable secrets volume")
	}
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	key := hex.EncodeToString(nonce[:])
	label, name := "frontiercloud.business-state-import", "fc-business-import-"+key
	if preparing {
		label, name = "frontiercloud.business-state-prepare", "fc-business-prepare-"+key
	} else if command[0] == resumeBusinessState {
		label, name = "frontiercloud.business-state-resume", "fc-business-resume-"+key
	}
	mountProof, err := json.Marshal(mounts.proof)
	if err != nil {
		return err
	}
	command = append(command, "--target-master-id", t.id, "--mount-proof", string(mountProof))
	inspect := func(ctx context.Context) (treeCaptureChild, error) {
		return d.treeRuntimeContainer(ctx, image.Image, name, key, label, command...)
	}
	removed := false
	defer func() {
		if removed {
			return
		}
		cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
		defer stop()
		child, err := inspect(cleanup)
		if err == nil && child.ID != "" {
			_, err = d.Runner.Run(cleanup, "docker", "container", "rm", "--force", child.ID)
		}
		operationErr = errors.Join(operationErr, err)
	}()
	secretsMount := "type=bind,src=" + mounts.secrets + ",dst=" + web.Environment["SECRETS_DIR"]
	if !preparing {
		secretsMount += ",readonly"
	}
	args := []string{"container", "create", "--interactive", "--name", name, "--label", label + "=" + key,
		"--pull=never", "--network=none", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--pids-limit=32",
		"--memory=768m", "--memory-swap=768m", "--cpus=0.50", "--user", mounts.user,
		"--mount", "type=bind,src=" + mounts.data + ",dst=" + web.Environment["DATA_ROOT"],
		"--mount", secretsMount}
	for _, name := range []string{"DEPLOYMENT_MODE", "DB_TYPE", "DATA_ROOT", "SQLITE_PATH", "SECRETS_DIR", "SERVER_NAME", "TLS_ENABLED"} {
		args = append(args, "--env", name+"="+web.Environment[name])
	}
	args = append(args, "--entrypoint=/app/frontiercloud", image.Image)
	raw, err := d.Runner.Run(ctx, "docker", append(args, command...)...)
	if err != nil {
		return err
	}
	id := strings.TrimSpace(string(raw))
	child, err := inspect(ctx)
	if err != nil || id == "" || child.ID != id || child.Status != "created" {
		return errors.New("private business state child identity is unverified")
	}
	if err = t.check(ctx, true); err != nil {
		return err
	}
	if err = t.stream.RunDuplex(ctx, "docker", []string{"container", "start", "--attach", "--interactive", id}, exchange); err != nil {
		return err
	}
	child, err = inspect(ctx)
	if err != nil || child.ID != id || child.Status != "exited" || child.ExitCode != 0 {
		return errors.New("private business state child completion is unverified")
	}
	if _, err = d.Runner.Run(ctx, "docker", "container", "rm", id); err != nil {
		return err
	}
	removed = true
	return nil
}

type businessImportMounts struct {
	data, secrets, user  string
	dataInfo, secretInfo os.FileInfo
	proof                [2]runtimefacts.TreeBackupMount
	secretsWritable      bool
}

func (d *Deployment) businessImportMounts(ctx context.Context, cfg Config) (mounts businessImportMounts, err error) {
	web := cfg.Services["web"]
	data, secrets, database := web.Environment["DATA_ROOT"], web.Environment["SECRETS_DIR"], web.Environment["SQLITE_PATH"]
	if !validBusinessImportPath(data) || !validBusinessImportPath(secrets) || !validBusinessImportPath(database) ||
		!strings.HasPrefix(database, data+"/") || data == secrets || strings.HasPrefix(secrets, data+"/") || strings.HasPrefix(data, secrets+"/") {
		return mounts, backup.ErrBusinessStateTarget
	}
	if mounts.data, err = upgradeDataRoot(cfg); err != nil {
		return mounts, err
	}
	dataMounts := 0
	for _, mount := range web.Volumes {
		switch mount.Target {
		case data:
			dataMounts++
		case secrets:
			volume, exists := cfg.Volumes[mount.Source]
			if mounts.secrets != "" || mount.Type != "volume" || !exists || volume.External || volume.Name == "" {
				return mounts, backup.ErrBusinessStateTarget
			}
			mounts.secrets, err = d.volumeRoot(ctx, volume.Name)
			if err != nil {
				return mounts, err
			}
			mounts.secretsWritable = !mount.ReadOnly
		default:
			target := filepath.Clean(mount.Target)
			if target == "/" || target == data || target == secrets || strings.HasPrefix(target, data+"/") || strings.HasPrefix(target, secrets+"/") ||
				strings.HasPrefix(data, target+"/") || strings.HasPrefix(secrets, target+"/") {
				return mounts, backup.ErrBusinessStateTarget
			}
		}
	}
	if dataMounts != 1 {
		return mounts, backup.ErrBusinessStateTarget
	}
	for _, root := range []string{mounts.data, mounts.secrets} {
		resolved, err := filepath.EvalSymlinks(root)
		if err != nil || !validBusinessImportPath(root) || resolved != root {
			return mounts, backup.ErrBusinessStateTarget
		}
	}
	if mounts.data == mounts.secrets || strings.HasPrefix(mounts.secrets, mounts.data+"/") || strings.HasPrefix(mounts.data, mounts.secrets+"/") {
		return mounts, backup.ErrBusinessStateTarget
	}
	mounts.dataInfo, err = os.Lstat(mounts.data)
	if err != nil {
		return mounts, err
	}
	mounts.secretInfo, err = os.Lstat(mounts.secrets)
	if err != nil {
		return mounts, err
	}
	a, first := treeRuntimeMount(mounts.dataInfo)
	b, second := treeRuntimeMount(mounts.secretInfo)
	if first != nil || second != nil || os.SameFile(mounts.dataInfo, mounts.secretInfo) || a.UID == 0 || a.UID != b.UID || a.GID != b.GID || mounts.secretInfo.Mode().Perm() != 0700 ||
		json.Unmarshal(web.Execution["user"], &mounts.user) != nil || mounts.user != strconv.FormatUint(uint64(a.UID), 10)+":"+strconv.FormatUint(uint64(a.GID), 10) {
		return mounts, backup.ErrBusinessStateTarget
	}
	mounts.proof = [2]runtimefacts.TreeBackupMount{a, b}
	return mounts, nil
}

func validBusinessImportPath(path string) bool {
	return filepath.IsAbs(path) && path != "/" && filepath.Clean(path) == path && !strings.ContainsAny(path, ",\r\n\x00")
}

func openBusinessImport(ctx context.Context, input string, expected backup.Expectation) (*os.File, error) {
	invalid := errors.New("business state import requires an exact protected source file, length and SHA-256")
	if !validBusinessImportPath(input) || !validRetainedTreeDigest(expected.Checksum) || expected.Generation <= 0 || expected.Bytes <= 0 || expected.Bytes > backup.MaxBusinessStateBytes {
		return nil, invalid
	}
	resolved, err := filepath.EvalSymlinks(input)
	if err != nil || resolved != input {
		return nil, invalid
	}
	f, err := os.OpenFile(input, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, invalid
	}
	before, err := f.Stat()
	if err != nil || !before.Mode().IsRegular() || before.Mode().Perm()&0077 != 0 || before.Size() != expected.Bytes {
		f.Close()
		return nil, invalid
	}
	if st, ok := before.Sys().(*syscall.Stat_t); !ok || st.Nlink != 1 || st.Uid != uint32(os.Geteuid()) {
		f.Close()
		return nil, invalid
	}
	hash := sha256.New()
	n, err := io.Copy(hash, io.LimitReader(treeRuntimeReader{ctx: ctx, reader: f}, expected.Bytes+1))
	after, statErr := os.Lstat(input)
	if err != nil || statErr != nil || !sameTreeRuntimeFile(before, after) || n != expected.Bytes || hex.EncodeToString(hash.Sum(nil)) != expected.Checksum {
		f.Close()
		return nil, invalid
	}
	if _, err = f.Seek(0, io.SeekStart); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

func exchangeBusinessImport(ctx context.Context, file io.Reader, expected backup.Expectation, masterID string, input io.WriteCloser, output *bufio.Reader) (report backup.BusinessStateReport, err error) {
	n, err := io.Copy(input, io.LimitReader(treeRuntimeReader{ctx: ctx, reader: file}, expected.Bytes+1))
	if closeErr := input.Close(); err != nil || closeErr != nil || n != expected.Bytes {
		return report, errors.New("private source stream ended before exact input was sent")
	}
	raw, fields, err := readBusinessStateReport(output)
	if err != nil || len(fields) != 8 {
		return report, errors.New("private business state import report is malformed")
	}
	if _, ok := fields["already_applied"].(bool); !ok || fields["restore_ready"] != false {
		return report, errors.New("private business state import report is malformed")
	}
	rows, ok := fields["imported_rows"].(map[string]any)
	if !ok {
		return report, errors.New("private business state import report is malformed")
	}
	for _, count := range rows {
		if _, ok = count.(json.Number); !ok {
			return report, errors.New("private business state import report is malformed")
		}
	}
	for _, name := range []string{"source_generation", "archived_recordings", "archived_usage_bytes"} {
		if _, ok = fields[name].(json.Number); !ok {
			return report, errors.New("private business state import report is malformed")
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&report) != nil || !report.MatchesImport(expected, masterID) {
		return backup.BusinessStateReport{}, errors.New("private business state import report does not match the selected target and source")
	}
	return report, nil
}

func readBusinessPreparationReport(output *bufio.Reader, masterID string) (runtimefacts.BusinessPreparationReport, error) {
	_, fields, err := readBusinessStateReport(output)
	if err != nil || len(fields) != 3 || fields["target_master_id"] != masterID || fields["prepared"] != true || fields["restore_ready"] != false {
		return runtimefacts.BusinessPreparationReport{}, errors.New("private preparation report does not match the selected fenced Master")
	}
	return runtimefacts.BusinessPreparationReport{TargetMasterID: masterID, Prepared: true}, nil
}

// Each child writes exactly one bounded newline-terminated JSON object.
// The duplex runner verifies EOF and successful completion separately.
func readBusinessStateReport(output *bufio.Reader) ([]byte, map[string]any, error) {
	raw, err := output.ReadSlice('\n')
	if err != nil {
		return nil, nil, err
	}
	value, err := protocol.ParseStrictJSON(raw, 4096)
	fields, ok := value.(map[string]any)
	if err != nil || !ok {
		return nil, nil, errors.New("private business state report is malformed")
	}
	return raw, fields, nil
}
