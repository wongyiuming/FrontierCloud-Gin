//go:build linux

package operator

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/recovery"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/release"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/runtimefacts"
	"github.com/wongyiuming/FrontierCloud-Gin/migrations"
)

const treeRetainedRuntimeCommand = "tree-retained-recovery"
const treeRetainedRuntimeLabel = "frontiercloud.tree-retained-recovery"

func (d *Deployment) treeRetainedDockerRuntime(ctx context.Context, cfg Config, helper release.ImageProof, roots map[string]string, recheck func(context.Context) error) (retainedTreeRuntime, error) {
	var runtime retainedTreeRuntime
	stream, ok := d.Runner.(treeDuplexRunner)
	if !ok {
		return runtime, errors.New("retained tree recovery requires an isolated duplex runtime")
	}
	if err := d.requireTreeLocalDocker(ctx); err != nil {
		return runtime, err
	}
	data, secrets := roots["data"], roots["runtime_secrets"]
	for _, name := range []string{data, secrets} {
		if name == "" || strings.ContainsAny(name, ",\r\n\x00") {
			return runtime, recovery.ErrUnsafe
		}
	}
	web := cfg.Services["web"]
	if err := d.verifyLocalReleaseImage(ctx, "web", helper); err != nil {
		return runtime, err
	}
	image := helper.Image
	dataInfo, err := os.Lstat(data)
	if err != nil {
		return runtime, err
	}
	dataProof, err := treeRuntimeMount(dataInfo)
	if err != nil {
		return runtime, err
	}
	secretInfo, err := os.Lstat(secrets)
	if err != nil {
		return runtime, err
	}
	secretProof, err := treeRuntimeMount(secretInfo)
	if err != nil {
		return runtime, err
	}
	user := strconv.FormatUint(uint64(dataProof.UID), 10) + ":" + strconv.FormatUint(uint64(dataProof.GID), 10)
	var configuredUser string
	if dataProof.UID == 0 || dataProof.UID != secretProof.UID || dataProof.GID != secretProof.GID || json.Unmarshal(web.Execution["user"], &configuredUser) != nil || configuredUser != user {
		return runtime, errors.New("retained tree mounts differ from the recorded runtime identity")
	}
	expected := runtimefacts.TreeRetainedRecoveryMounts{UID: dataProof.UID, GID: dataProof.GID, Data: dataProof, Secrets: secretProof}
	run := func(c context.Context, request runtimefacts.TreeRetainedRecoveryRequest, local *runtimefacts.TreeRetainedLocalProof) (operationErr error) {
		c, cancel := context.WithTimeout(c, 30*time.Minute)
		defer cancel()
		if err := recheck(c); err != nil {
			return err
		}
		var nonce [32]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			return err
		}
		request.Nonce = hex.EncodeToString(nonce[:])
		name := "fc-tree-retained-" + request.Nonce
		inspect := func(c context.Context) (treeCaptureChild, error) {
			return d.treeRuntimeContainer(c, image, name, request.Nonce, treeRetainedRuntimeLabel, treeRetainedRuntimeCommand)
		}
		removed := false
		defer func() {
			if removed {
				return
			}
			cleanup, stop := context.WithTimeout(context.WithoutCancel(c), 15*time.Second)
			defer stop()
			child, err := inspect(cleanup)
			if err == nil && child.ID != "" {
				_, err = d.Runner.Run(cleanup, "docker", "container", "rm", "--force", child.ID)
			}
			operationErr = errors.Join(operationErr, err)
		}()
		raw, err := d.Runner.Run(c, "docker", "container", "create", "--interactive", "--name", name, "--label", treeRetainedRuntimeLabel+"="+request.Nonce,
			"--pull=never", "--network=none", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--pids-limit=32",
			"--memory=128m", "--memory-swap=128m", "--cpus=0.10", "--user", user,
			"--mount", "type=bind,src="+data+",dst=/fc-tree-data",
			"--mount", "type=bind,src="+secrets+",dst=/fc-tree-secrets,readonly", "--entrypoint=/app/frontiercloud", image, treeRetainedRuntimeCommand)
		if err != nil {
			return err
		}
		id := strings.TrimSpace(string(raw))
		child, err := inspect(c)
		if err != nil || id == "" || child.ID != id || child.Status != "created" {
			return errors.New("retained tree recovery child identity unavailable")
		}
		if err = stream.RunDuplex(c, "docker", []string{"container", "start", "--attach", "--interactive", id}, func(input io.WriteCloser, output *bufio.Reader) error {
			return exchangeRetainedTreeRuntime(c, input, output, request, expected, recheck, local)
		}); err != nil {
			return err
		}
		child, err = inspect(c)
		if err != nil || child.ID != id || child.Status != "exited" || child.ExitCode != 0 {
			return errors.New("retained tree recovery child completion is unverified")
		}
		if _, err = d.Runner.Run(c, "docker", "container", "rm", id); err != nil {
			return err
		}
		removed = true
		return recheck(c)
	}
	runtime.hold = func(c context.Context, binding, dataRoot string) error {
		if dataRoot != data {
			return recovery.ErrUnsafe
		}
		return run(c, runtimefacts.TreeRetainedRecoveryRequest{Action: "hold", BindingSHA256: binding}, nil)
	}
	runtime.rebind = func(c context.Context, binding, archiveSHA string, manifest recovery.Manifest, dataRoot, secretRoot, database string) error {
		if dataRoot != data || secretRoot != secrets {
			return recovery.ErrUnsafe
		}
		return run(c, runtimefacts.TreeRetainedRecoveryRequest{Action: "rebind", BindingSHA256: binding, ArchiveSHA256: archiveSHA,
			DatabaseRelative: database, NodeID: manifest.NodeID, Manifest: &manifest}, nil)
	}
	runtime.local = func(c context.Context, binding, archiveSHA string, manifest recovery.Manifest, database string) (runtimefacts.TreeRetainedLocalProof, error) {
		var proof runtimefacts.TreeRetainedLocalProof
		err := run(c, runtimefacts.TreeRetainedRecoveryRequest{Action: "verify-local", BindingSHA256: binding, ArchiveSHA256: archiveSHA,
			DatabaseRelative: database, NodeID: manifest.NodeID, Manifest: &manifest}, &proof)
		if err != nil {
			return runtimefacts.TreeRetainedLocalProof{}, err
		}
		return proof, nil
	}
	return runtime, nil
}

func (d *Deployment) verifyLocalReleaseImage(ctx context.Context, component string, helper release.ImageProof) error {
	bad := errors.New("local release image differs from its reviewed image proof")
	i := strings.LastIndex(helper.Image, "@sha256:")
	config, ok := strings.CutPrefix(helper.ConfigDigest, "sha256:")
	arch, linux := strings.CutPrefix(helper.Platform, "linux/")
	if i <= 0 || !validRetainedTreeDigest(helper.Image[i+8:]) || !ok || !validRetainedTreeDigest(config) || !release.ValidSHA(helper.Revision) ||
		!linux || arch != "amd64" && arch != "arm64" || helper.Generation != migrations.Generation {
		return bad
	}
	if err := d.localUpgradeEngine(ctx, arch); err != nil {
		return err
	}
	raw, err := d.Runner.Run(ctx, "docker", "image", "inspect", helper.Image)
	var images []struct {
		ID           string `json:"Id"`
		OS           string
		Architecture string
		RepoDigests  []string
		Descriptor   struct{ Digest string }
		Config       struct{ Labels map[string]string }
	}
	if err != nil || json.Unmarshal(raw, &images) != nil || len(images) != 1 {
		return bad
	}
	image := images[0]
	manifest := helper.Image[i+1:]
	if image.OS != "linux" || image.Architecture != arch || !slices.Contains(image.RepoDigests, helper.Image) ||
		image.ID != helper.ConfigDigest && !(image.ID == manifest && image.Descriptor.Digest == manifest) ||
		image.Config.Labels["frontiercloud.revision"] != helper.Revision || image.Config.Labels["frontiercloud.component"] != component ||
		image.Config.Labels["frontiercloud.schema-generation"] != strconv.Itoa(helper.Generation) {
		return bad
	}
	return nil
}

func validRetainedTreeDigest(s string) bool {
	b, err := hex.DecodeString(s)
	return err == nil && len(b) == 32 && hex.EncodeToString(b) == s
}

func exchangeRetainedTreeRuntime(ctx context.Context, input io.WriteCloser, output *bufio.Reader, request runtimefacts.TreeRetainedRecoveryRequest, expected runtimefacts.TreeRetainedRecoveryMounts, recheck func(context.Context) error, local *runtimefacts.TreeRetainedLocalProof) error {
	if (local != nil) != (request.Action == "verify-local") {
		return recovery.ErrUnsafe
	}
	encoder := json.NewEncoder(input)
	if err := encoder.Encode(request); err != nil {
		return err
	}
	var proof *runtimefacts.TreeRetainedLocalProof
	read := func(phase string) error {
		var reply runtimefacts.TreeRetainedRecoveryReply
		if err := readTreeCaptureReply(ctx, output, 8192, &reply); err != nil {
			return err
		}
		mounts := reply.Mounts
		if !treeIdentityUIDMap(mounts.UIDMap) {
			return recovery.ErrUnsafe
		}
		mounts.UIDMap = ""
		if reply.Phase != phase || reply.Action != request.Action || reply.Nonce != request.Nonce || reply.BindingSHA256 != request.BindingSHA256 || mounts != expected ||
			(reply.Already != nil) != (phase == "complete" && request.Action == "rebind") ||
			(reply.Local != nil) != (phase == "complete" && request.Action == "verify-local") || reply.Local != nil && !reply.Local.Valid() {
			return errors.New("retained tree runtime reply differs from the admitted action")
		}
		proof = reply.Local
		return recheck(ctx)
	}
	if err := read("ready"); err != nil {
		return err
	}
	if err := encoder.Encode(runtimefacts.TreeRetainedRecoveryCommit{Nonce: request.Nonce, BindingSHA256: request.BindingSHA256}); err != nil {
		return err
	}
	if err := input.Close(); err != nil {
		return err
	}
	if err := read("complete"); err != nil {
		return err
	}
	if _, err := output.ReadByte(); err != io.EOF {
		return errors.New("unexpected retained tree runtime output after completion")
	}
	if local != nil {
		*local = *proof
	}
	return nil
}
