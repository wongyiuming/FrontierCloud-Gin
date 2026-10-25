package operator

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/recovery"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/release"
)

const ComposeRegistration = ".foc-compose-registration.json"

func focHostInstaller(name string, service Service) bool {
	if name != "foc-host-init" || service.Environment["FOC_COMPOSE_INSTALL"] != "1" || service.Environment["FOC_AUTOMATIC_PROJECT"] != "1" {
		return false
	}
	var entry, command, caps []string
	var network, user string
	var readonly, privileged bool
	_ = json.Unmarshal(service.Execution["entrypoint"], &entry)
	_ = json.Unmarshal(service.Execution["command"], &command)
	_ = json.Unmarshal(service.Execution["cap_drop"], &caps)
	_ = json.Unmarshal(service.Execution["network_mode"], &network)
	_ = json.Unmarshal(service.Execution["user"], &user)
	_ = json.Unmarshal(service.Execution["read_only"], &readonly)
	_ = json.Unmarshal(service.Execution["privileged"], &privileged)
	var added, security []string
	var pid string
	_ = json.Unmarshal(service.Execution["cap_add"], &added)
	_ = json.Unmarshal(service.Execution["security_opt"], &security)
	_ = json.Unmarshal(service.Execution["pid"], &pid)
	if len(added) != 0 || !equalStrings(security, []string{"no-new-privileges:true"}) || pid != "" {
		return false
	}
	if !equalStrings(entry, []string{"/bin/sh", "/app/operator/install-foc.sh"}) || !equalStrings(command, []string{"auto"}) || !equalStrings(caps, []string{"ALL"}) || network != "none" || user != "0:0" || !readonly || privileged {
		return false
	}
	expected := map[string]Mount{
		"/host/usr":                    {Type: "bind", Source: "/usr", Target: "/host/usr", ReadOnly: true},
		"/host/etc":                    {Type: "bind", Source: "/etc", Target: "/host/etc", ReadOnly: true},
		"/usr/local/bin":               {Type: "bind", Source: "/usr/local/bin", Target: "/usr/local/bin"},
		"/usr/local/lib/frontiercloud": {Type: "bind", Source: "/usr/local/lib/frontiercloud", Target: "/usr/local/lib/frontiercloud"},
		"/etc/frontiercloud":           {Type: "bind", Source: "/etc/frontiercloud", Target: "/etc/frontiercloud"},
	}
	if len(service.Volumes) != len(expected) {
		return false
	}
	for _, mount := range service.Volumes {
		want, ok := expected[mount.Target]
		if !ok || mount != want {
			return false
		}
		delete(expected, mount.Target)
	}
	return len(expected) == 0
}

// Host-executable installer bytes have an independent published release pin.
// Verify it before any install pull or initializer, without treating host paths
// as empty business mounts or mixing it into the application's image revision.
func proveHostInstaller(ctx context.Context, service Service, arch string, evidence Evidence, images Images) (release.ImageProof, error) {
	revision := service.Environment["FOC_OPERATOR_REVISION"]
	if !release.ValidSHA(revision) {
		return release.ImageProof{}, release.ErrImageIntegrity
	}
	proof, err := evidence.Artifact(ctx, revision)
	if err != nil || proof["publishable"] != true || proof["sha"] != revision || !release.ValidSHA(fmtString(proof["ci_sha"])) {
		return release.ImageProof{}, release.ErrImageIntegrity
	}
	image, err := images.Prove(ctx, revision, "web", arch)
	if err != nil {
		return release.ImageProof{}, err
	}
	if image.Image != service.Image || image.Revision != revision || image.Platform != "linux/"+arch {
		return release.ImageProof{}, release.ErrImageIntegrity
	}
	return image, nil
}

type registrationContainer struct {
	ID       string `json:"ID"`
	Service  string `json:"Service"`
	State    string `json:"State"`
	Health   string `json:"Health"`
	ExitCode int    `json:"ExitCode"`
}

func (d *Deployment) registrationContainers(ctx context.Context, cfg Config) (map[string]registrationContainer, error) {
	raw, e := d.Compose(ctx, false, "ps", "--all", "--format", "json")
	if e != nil || len(raw) > 1<<20 {
		return nil, errors.New("Compose registration container inventory unavailable")
	}
	var rows []registrationContainer
	if json.Unmarshal(raw, &rows) != nil {
		decoder := json.NewDecoder(strings.NewReader(string(raw)))
		for decoder.More() {
			var row registrationContainer
			if e = decoder.Decode(&row); e != nil {
				return nil, e
			}
			rows = append(rows, row)
		}
	}
	result := map[string]registrationContainer{}
	for _, row := range rows {
		if _, ok := cfg.Services[row.Service]; !ok || row.ID == "" {
			return nil, errors.New("unexpected Compose registration container")
		}
		if _, ok := result[row.Service]; ok {
			return nil, errors.New("scaled Compose registration is unsupported")
		}
		if strings.HasSuffix(row.Service, "-init") {
			if row.State != "exited" || row.ExitCode != 0 {
				return nil, errors.New("Compose initialization has not completed")
			}
		} else if row.State != "running" || row.Health != "" && row.Health != "healthy" {
			return nil, errors.New("Compose services are not ready for registration")
		}
		result[row.Service] = row
	}
	for name, service := range cfg.Services {
		if _, present := result[name]; !present && !focHostInstaller(name, service) {
			return nil, errors.New("Compose registration requires the complete selected service set")
		}
	}
	return result, nil
}

type registrationIntent struct {
	Receipt  Receipt           `json:"receipt"`
	NodeID   string            `json:"node_id"`
	ImageIDs map[string]string `json:"image_ids"`
}

// RegisterCompose records verified running public images; it never initializes
// or freezes data, pulls images, restarts containers or grants host permissions.
func (d *Deployment) RegisterCompose(ctx context.Context, arch string, evidence Evidence, images Images) (result Receipt, operationErr error) {
	done, e := d.AcquireOperation()
	if e != nil {
		return result, e
	}
	defer func() { operationErr = errors.Join(operationErr, done()) }()
	if _, e = os.Lstat(filepath.Join(d.Directory, ReceiptFile)); e == nil {
		opened, r, err := Open(d.Directory)
		if err != nil {
			return result, err
		}
		opened.Runner = d.Runner
		_, err = opened.ValidateReceipt(ctx, r)
		return r, err
	} else if !os.IsNotExist(e) {
		return result, e
	}
	if e = d.localUpgradeEngine(ctx, arch); e != nil {
		return result, e
	}
	cfg, e := d.Config(ctx, false)
	if e != nil {
		return result, e
	}
	if installer, present := cfg.Services["foc-host-init"]; present && !focHostInstaller("foc-host-init", installer) {
		return result, errors.New("Compose foc installer differs from its bounded installation contract")
	}
	containers, e := d.registrationContainers(ctx, cfg)
	if e != nil {
		return result, e
	}
	labelsRaw, e := d.Runner.Run(ctx, "docker", "inspect", "--format", "{{json .Config.Labels}}", containers["web"].ID)
	var labels map[string]string
	if e != nil || json.Unmarshal(labelsRaw, &labels) != nil || labels["com.docker.compose.service"] != "web" || !strings.EqualFold(labels["com.docker.compose.oneoff"], "false") || labels["frontiercloud.runtime"] != "go" || labels["frontiercloud.component"] != "web" || labels["com.docker.compose.project"] != cfg.Name || !filepath.IsAbs(labels["com.docker.compose.project.working_dir"]) || filepath.Clean(labels["com.docker.compose.project.working_dir"]) != d.Directory {
		return result, errors.New("Compose Web identity does not match the host deployment")
	}
	var actualFiles []string
	for _, file := range strings.Split(labels["com.docker.compose.project.config_files"], ",") {
		actualFiles = append(actualFiles, filepath.Clean(file))
	}
	var expectedFiles []string
	for _, file := range d.Files {
		expectedFiles = append(expectedFiles, filepath.Join(d.Directory, file))
	}
	if !equalStrings(actualFiles, expectedFiles) {
		return result, errors.New("automatic registration requires the selected standard Compose files")
	}
	imageIDs := map[string]string{}
	for name, container := range containers {
		raw, err := d.Runner.Run(ctx, "docker", "inspect", "--format", "{{json .Image}}", container.ID)
		var id string
		if err != nil || json.Unmarshal(raw, &id) != nil || !strings.HasPrefix(id, "sha256:") || len(id) != 71 {
			return result, errors.New("running image identity unavailable")
		}
		imageIDs[name] = id
	}
	raw, e := d.Runner.Run(ctx, "docker", "image", "inspect", "--format", "{{json .Config.Labels}}", imageIDs["web"])
	var sourceLabels map[string]string
	if e != nil || json.Unmarshal(raw, &sourceLabels) != nil || !release.ValidSHA(sourceLabels["frontiercloud.revision"]) {
		return result, release.ErrImageIntegrity
	}
	revision := sourceLabels["frontiercloud.revision"]
	proof, e := evidence.Artifact(ctx, revision)
	if e != nil || proof["publishable"] != true || proof["sha"] != revision || !release.ValidSHA(fmtString(proof["ci_sha"])) {
		return result, errors.New("running Compose images lack reviewed main and exact-source CI proof")
	}
	r := Receipt{Version: ConfigurationVersion, Role: d.Role, Project: cfg.Name, Database: cfg.Services["web"].Environment["DB_TYPE"], Revision: revision, SourceSHA: fmtString(proof["ci_sha"]), CreatedAt: time.Now().UTC().Format(time.RFC3339), SelectionHash: selectionHash(cfg), Images: map[string]release.ImageProof{}, ServiceImages: map[string]string{}, Files: append([]string(nil), d.Files...), State: "ready"}
	if r.Database != "sqlite" && r.Database != "mysql" || d.Role == "storage" && r.Database != "sqlite" {
		return result, errors.New("unsupported Compose database selection")
	}
	for name, service := range cfg.Services {
		if name == "foc-host-init" {
			// A --rm installation is allowed to leave no container. The
			// configured host executable bundle still needs its independent
			// reviewed public pin, and any retained container must match it.
			installer, err := proveHostInstaller(ctx, service, arch, evidence, images)
			if err != nil || imageIDs[name] != "" && installer.ConfigDigest != imageIDs[name] {
				return result, release.ErrImageIntegrity
			}
			r.ServiceImages[name] = installer.Image
			continue
		}
		component := ""
		for _, candidate := range []string{"web", "nginx"} {
			repository, _ := release.ImageRepository(candidate)
			if strings.HasPrefix(service.Image, repository+":") || strings.HasPrefix(service.Image, repository+"@") {
				component = candidate
			}
		}
		if name == "web" && component != "web" || name == "nginx" && component != "nginx" || name == "foc-host-init" && component != "web" {
			return result, release.ErrImageIntegrity
		}
		if component != "" {
			p, ok := r.Images[component]
			if !ok {
				p, e = images.Prove(ctx, revision, component, arch)
				if e != nil {
					return result, e
				}
				r.Images[component] = p
			}
			if p.Revision != revision || p.Platform != "linux/"+arch || p.ConfigDigest != imageIDs[name] {
				return result, release.ErrImageIntegrity
			}
			r.ServiceImages[name] = p.Image
		} else {
			raw, e = d.Runner.Run(ctx, "docker", "image", "inspect", "--format", "{{json .RepoDigests}}", imageIDs[name])
			var digests []string
			if e != nil || json.Unmarshal(raw, &digests) != nil {
				return result, errors.New("infrastructure image digest unavailable")
			}
			repository := strings.Split(strings.Split(service.Image, "@")[0], ":")[0]
			for _, digest := range digests {
				normalized := strings.TrimPrefix(digest, "docker.io/library/")
				if strings.HasPrefix(normalized, repository+"@sha256:") && len(strings.Split(normalized, "@sha256:")[1]) == 64 {
					r.ServiceImages[name] = digest
					break
				}
			}
			if r.ServiceImages[name] == "" {
				return result, errors.New("infrastructure image cannot be fixed to its running digest")
			}
		}
	}
	raw, e = d.Compose(ctx, false, "exec", "-T", "web", "/app/frontiercloud", "operator-status")
	var fact RuntimeFact
	if e != nil || json.Unmarshal(raw, &fact) != nil || len(fact.NodeID) != 32 || fact.NativeMaintenance || !fact.Database.LogicalIdle || fact.Database.SchemaGeneration != r.Images["web"].Generation || !recovery.SupportedSchemaGeneration(fact.Database.SchemaGeneration) {
		return result, errors.New("running native identity and database are not ready for registration")
	}
	if d.Role == "storage" && fact.Role != "Follower" || d.Role == "master" && fact.Role != "Master" && fact.Role != "Standalone" {
		return result, errors.New("running node role conflicts with Compose registration")
	}
	// Probe the existing application; registration never launches a new writer.
	if _, e = d.Compose(ctx, false, "exec", "-T", "web", "/app/frontiercloud", "healthcheck"); e != nil {
		return result, errors.New("running application is not ready")
	}
	after, e := d.Config(ctx, false)
	if e != nil || selectionHash(after) != r.SelectionHash {
		return result, errors.New("Compose configuration changed during registration")
	}
	current, e := d.registrationContainers(ctx, cfg)
	if e != nil || !reflect.DeepEqual(current, containers) {
		return result, errors.New("Compose containers changed during registration")
	}
	intent := registrationIntent{r, fact.NodeID, imageIDs}
	intentPath := filepath.Join(d.Directory, ComposeRegistration)
	if existing, err := readRegular(intentPath, 1<<20); err == nil {
		var recorded registrationIntent
		if json.Unmarshal(existing, &recorded) != nil {
			return result, errors.New("invalid Compose registration intent")
		}
		intent.Receipt.CreatedAt = recorded.Receipt.CreatedAt
		if !reflect.DeepEqual(intent, recorded) {
			return result, errors.New("Compose registration intent no longer matches running state")
		}
		r = intent.Receipt
	} else if !os.IsNotExist(err) {
		return result, err
	} else {
		if _, err = os.Lstat(filepath.Join(d.Directory, ImagesFile)); !os.IsNotExist(err) {
			return result, errors.New("unowned image lock prevents automatic registration")
		}
		if e = exclusiveJSON(intentPath, intent); e != nil {
			return result, e
		}
	}
	lock := map[string]map[string]string{}
	for name, image := range r.ServiceImages {
		lock[name] = map[string]string{"image": image}
	}
	if e = exclusiveJSONOrSame(filepath.Join(d.Directory, ImagesFile), map[string]any{"services": lock}); e != nil {
		return result, e
	}
	if e = exclusiveJSONOrSame(filepath.Join(d.Directory, ReceiptFile), r); e != nil {
		return result, e
	}
	if _, e = d.ValidateReceipt(ctx, r); e != nil {
		return result, e
	}
	return r, nil
}
