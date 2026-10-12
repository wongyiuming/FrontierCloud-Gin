// Package operator is a short-lived host-side Compose client. It is never
// linked into the business service and requires no Docker socket in Web.
package operator

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/fsutil"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/release"
)

const ReceiptFile = ".fc-deployment.json"
const ImagesFile = ".fc-images.json"
const ConfigurationVersion = 1

type Runner interface {
	Run(context.Context, string, ...string) ([]byte, error)
}

type Mount struct {
	Type     string `json:"type"`
	Source   string `json:"source"`
	Target   string `json:"target"`
	ReadOnly bool   `json:"read_only"`
}
type Port struct {
	Target    int    `json:"target"`
	Published string `json:"published"`
	HostIP    string `json:"host_ip"`
	Protocol  string `json:"protocol"`
}
type Service struct {
	Image       string            `json:"image"`
	Environment map[string]string `json:"environment"`
	Volumes     []Mount           `json:"volumes"`
	Ports       []Port            `json:"ports"`
	Build       json.RawMessage   `json:"build"`
}
type Config struct {
	Name     string             `json:"name"`
	Services map[string]Service `json:"services"`
	Volumes  map[string]struct {
		Name     string `json:"name"`
		External bool   `json:"external"`
	} `json:"volumes"`
}
type Receipt struct {
	Version       int                           `json:"configuration_version"`
	Role          string                        `json:"role"`
	Project       string                        `json:"project"`
	Database      string                        `json:"database"`
	Revision      string                        `json:"revision"`
	SourceSHA     string                        `json:"reviewed_source_sha"`
	CreatedAt     string                        `json:"created_at"`
	SelectionHash string                        `json:"selection_sha256"`
	Images        map[string]release.ImageProof `json:"images"`
	ServiceImages map[string]string             `json:"service_images"`
	Files         []string                      `json:"compose_files"`
	State         string                        `json:"state"`
}
type Deployment struct {
	Directory      string
	Role           string
	Files          []string
	Runner         Runner
	ImageInspector Images
}

func New(directory, role, database string) (*Deployment, error) {
	root, err := filepath.Abs(directory)
	if err != nil {
		return nil, err
	}
	file := "docker-compose.yaml"
	if role == "storage" {
		file = "docker-compose.storage.yaml"
	} else if role != "master" {
		return nil, errors.New("role must be master or storage")
	}
	files := []string{file}
	if database == "mysql" {
		if role != "master" {
			return nil, errors.New("Storage requires embedded SQLite")
		}
		files = append(files, "docker-compose.gin-mysql.yaml")
	} else if database != "sqlite" {
		return nil, errors.New("database must be sqlite or mysql")
	}
	return &Deployment{Directory: root, Role: role, Files: files}, nil
}
func Open(directory string) (*Deployment, Receipt, error) {
	root, err := filepath.Abs(directory)
	if err != nil {
		return nil, Receipt{}, err
	}
	raw, err := readRegular(filepath.Join(root, ReceiptFile), 1<<20)
	if err != nil {
		return nil, Receipt{}, errors.New("deployment receipt missing; use the documented existing-deployment takeover procedure")
	}
	var receipt Receipt
	if _, err = protocol.ParseStrictJSON(raw, 1<<20); err != nil {
		return nil, receipt, err
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&receipt) != nil || receipt.Version != ConfigurationVersion || !release.ValidSHA(receipt.Revision) || receipt.Project == "" {
		return nil, receipt, errors.New("invalid deployment receipt")
	}
	dep, err := New(root, receipt.Role, receipt.Database)
	if err != nil {
		return nil, receipt, err
	}
	if !equalStrings(dep.Files, receipt.Files) {
		return nil, receipt, errors.New("unexpected Compose file selection")
	}
	return dep, receipt, nil
}
func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
func (d *Deployment) composeArgs(pinned bool) []string {
	args := []string{"compose", "--project-directory", d.Directory}
	for _, file := range d.Files {
		args = append(args, "-f", filepath.Join(d.Directory, file))
	}
	if pinned {
		args = append(args, "-f", filepath.Join(d.Directory, ImagesFile))
	}
	return args
}
func (d *Deployment) Compose(ctx context.Context, pinned bool, args ...string) ([]byte, error) {
	return d.Runner.Run(ctx, "docker", append(d.composeArgs(pinned), args...)...)
}
func (d *Deployment) Config(ctx context.Context, pinned bool) (Config, error) {
	var cfg Config
	raw, err := d.Compose(ctx, pinned, "config", "--format", "json")
	if err != nil {
		return cfg, errors.New("Compose configuration rejected; check domain, role, mounts and required parameters")
	}
	if json.Unmarshal(raw, &cfg) != nil || cfg.Name == "" || cfg.Services["web"].Image == "" {
		return cfg, errors.New("invalid Compose configuration")
	}
	for _, s := range cfg.Services {
		if len(s.Build) > 0 && string(s.Build) != "null" {
			return cfg, errors.New("ordinary installation forbids build definitions")
		}
	}
	return cfg, nil
}

// selectionHash excludes secrets and image versions, but binds all mounts,
// database endpoints, role/network settings and project identity.
func selectionHash(cfg Config) string {
	values := map[string]any{"project": cfg.Name, "volumes": cfg.Volumes}
	services := map[string]any{}
	for name, s := range cfg.Services {
		env := map[string]string{}
		for _, key := range []string{"DEPLOYMENT_MODE", "DB_TYPE", "SQLITE_PATH", "DATA_ROOT", "SECRETS_DIR", "MYSQL_HOST", "MYSQL_PORT", "MYSQL_DATABASE", "SERVER_NAME", "TLS_ENABLED", "STORAGE_TRANSPORT", "STORAGE_ENDPOINT", "STORAGE_PORT"} {
			if v, ok := s.Environment[key]; ok {
				env[key] = v
			}
		}
		services[name] = map[string]any{"environment": env, "mounts": s.Volumes, "ports": s.Ports}
	}
	values["services"] = services
	raw, _ := json.Marshal(values)
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:])
}
func readRegular(path string, limit int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > limit {
		return nil, errors.New("expected bounded regular file")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, errors.New("file changed while opening")
	}
	return io.ReadAll(io.LimitReader(f, limit+1))
}
func exclusiveJSON(path string, value any) error {
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, err = f.Write(append(raw, '\n'))
	if err == nil {
		err = f.Sync()
	}
	if err = errors.Join(err, f.Close()); err != nil {
		return err
	}
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer root.Close()
	return fsutil.SyncDirectory(root, ".")
}
func (d *Deployment) ValidateReceipt(ctx context.Context, r Receipt) (Config, error) {
	cfg, err := d.Config(ctx, true)
	if err != nil {
		return cfg, err
	}
	if cfg.Name != r.Project || selectionHash(cfg) != r.SelectionHash {
		return cfg, errors.New("project, role, database or mounts changed; configuration edits are not a migration")
	}
	if len(cfg.Services) != len(r.ServiceImages) {
		return cfg, errors.New("service selection changed")
	}
	for name, s := range cfg.Services {
		if r.ServiceImages[name] != s.Image {
			return cfg, errors.New("image lock changed; use an explicitly approved upgrade")
		}
	}
	return cfg, nil
}
func (d *Deployment) Empty(ctx context.Context, cfg Config) error {
	// A changed project/mount selection must not hide an older deployment in
	// this bundle directory. This check includes stopped Compose containers.
	prior, e := d.Runner.Run(ctx, "docker", "ps", "--all", "--filter", "label=com.docker.compose.project.working_dir="+d.Directory, "--format", "{{.ID}}")
	if e != nil {
		return e
	}
	if strings.TrimSpace(string(prior)) != "" {
		return errors.New("this directory belongs to an existing Compose deployment; changing project name is not takeover")
	}
	for _, name := range []string{"data", "storage-data"} {
		directory := filepath.Join(d.Directory, name)
		if info, e := os.Lstat(directory); e == nil {
			if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
				return errors.New("existing default state path is unsafe; fresh initialization refused")
			}
			entries, e := os.ReadDir(directory)
			if e != nil {
				return e
			}
			if len(entries) > 0 {
				return errors.New("existing default data or identity remains in this bundle; changing mounts is not migration")
			}
		} else if !os.IsNotExist(e) {
			return e
		}
	}
	for _, name := range []string{ReceiptFile, ImagesFile} {
		if _, err := os.Lstat(filepath.Join(d.Directory, name)); err == nil {
			return errors.New("existing installation receipt or image lock; use status, takeover or recovery")
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	raw, err := d.Compose(ctx, false, "ps", "--all", "--quiet")
	if err != nil {
		return err
	}
	if strings.TrimSpace(string(raw)) != "" {
		return errors.New("Compose project already has containers; fresh install refused")
	}
	raw, err = d.Runner.Run(ctx, "docker", "volume", "ls", "--format", "{{.Name}}")
	if err != nil {
		return err
	}
	volumes := map[string]bool{}
	for _, name := range strings.Fields(string(raw)) {
		volumes[name] = true
	}
	for _, v := range cfg.Volumes {
		if volumes[v.Name] || v.External {
			return errors.New("existing or external volume; fresh install refused; use takeover or restore")
		}
	}
	seen := map[string]bool{}
	for _, s := range cfg.Services {
		for _, m := range s.Volumes {
			if m.Type != "bind" || m.ReadOnly || seen[m.Source] {
				continue
			}
			seen[m.Source] = true
			info, e := os.Lstat(m.Source)
			if errors.Is(e, os.ErrNotExist) {
				continue
			}
			if e != nil {
				return e
			}
			if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
				return errors.New("unsafe or non-directory data mount")
			}
			entries, e := os.ReadDir(m.Source)
			if e != nil {
				return e
			}
			if len(entries) > 0 {
				return errors.New("data mount is not empty; existing identity, media or database must be taken over or restored")
			}
		}
	}
	return nil
}

type Evidence interface {
	Artifact(context.Context, string) (map[string]any, error)
}
type Images interface {
	Prove(context.Context, string, string, string) (release.ImageProof, error)
}

func (d *Deployment) Install(ctx context.Context, target, architecture string, evidence Evidence, images Images) (Receipt, error) {
	var r Receipt
	// Explicit installation is a write operation. This lock never appears in
	// doctor. A crash leaves it for operator review, never automatic takeover.
	done, err := d.AcquireOperation()
	if err != nil {
		return r, err
	}
	defer done()
	cfg, err := d.Config(ctx, false)
	if err != nil {
		return r, err
	}
	if err = d.Empty(ctx, cfg); err != nil {
		return r, err
	}
	if target == "" {
		target = "latest"
	}
	web, err := images.Prove(ctx, target, "web", architecture)
	if err != nil {
		return r, err
	}
	target = web.Revision
	proof, err := evidence.Artifact(ctx, target)
	if err != nil || proof["publishable"] != true || proof["sha"] != target {
		return r, errors.New("release is not backed by reviewed main and successful exact-source CI")
	}
	r = Receipt{Version: ConfigurationVersion, Role: d.Role, Project: cfg.Name, Database: cfg.Services["web"].Environment["DB_TYPE"], Revision: target, SourceSHA: fmt.Sprint(proof["ci_sha"]), CreatedAt: time.Now().UTC().Format(time.RFC3339), SelectionHash: selectionHash(cfg), Images: map[string]release.ImageProof{"web": web}, ServiceImages: map[string]string{}, Files: append([]string(nil), d.Files...), State: "prepared"}
	override := map[string]map[string]string{}
	// Fetch every component from the SAME immutable revision before pulling or
	// initializing anything. Infrastructure images are pinned after pull too.
	names := make([]string, 0, len(cfg.Services))
	for name := range cfg.Services {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		s := cfg.Services[name]
		component := ""
		for _, c := range []string{"web", "nginx", "updater"} {
			repo, _ := release.ImageRepository(c)
			if strings.HasPrefix(s.Image, repo+":") {
				component = c
			}
		}
		if component != "" {
			p, ok := r.Images[component]
			if !ok {
				p, err = images.Prove(ctx, target, component, architecture)
				if err != nil {
					return r, err
				}
				r.Images[component] = p
			}
			if p.Revision != target || p.Platform != "linux/"+architecture {
				return r, release.ErrImageIntegrity
			}
			r.ServiceImages[name] = p.Image
		} else {
			r.ServiceImages[name] = s.Image
		}
	}
	for _, name := range names {
		image := r.ServiceImages[name]
		if _, err = d.Runner.Run(ctx, "docker", "pull", image); err != nil {
			return r, errors.New("image pull failed after verification; fix network/permissions; local build is never automatic")
		}
		if !strings.Contains(image, "@sha256:") {
			raw, e := d.Runner.Run(ctx, "docker", "image", "inspect", "--format", "{{json .RepoDigests}}", image)
			if e != nil {
				return r, e
			}
			var digests []string
			if json.Unmarshal(raw, &digests) != nil {
				return r, errors.New("infrastructure digest inspection failed")
			}
			repo := strings.Split(image, ":")[0]
			pinned := ""
			for _, digest := range digests {
				if strings.HasPrefix(digest, repo+"@sha256:") || strings.HasPrefix(digest, "docker.io/library/"+repo+"@sha256:") {
					pinned = digest
				}
			}
			if pinned == "" {
				return r, errors.New("infrastructure image has no matching immutable digest")
			}
			r.ServiceImages[name] = pinned
		}
		override[name] = map[string]string{"image": r.ServiceImages[name]}
	}
	// Repeat the nonempty-target guard after slow network work.
	if err = d.Empty(ctx, cfg); err != nil {
		return r, err
	}
	if err = exclusiveJSON(filepath.Join(d.Directory, ImagesFile), map[string]any{"services": override}); err != nil {
		return r, err
	}
	if err = exclusiveJSON(filepath.Join(d.Directory, ReceiptFile), r); err != nil {
		return r, err
	}
	if _, err = d.ValidateReceipt(ctx, r); err != nil {
		return r, err
	}
	_, err = d.Compose(ctx, true, "up", "-d", "--no-build", "--pull", "never", "--wait", "--wait-timeout", "600")
	if err != nil {
		return r, errors.New("installation has not passed readiness; preserve its receipt and volumes; inspect status and automatic TLS")
	}
	r.State = "ready"
	if err = replaceJSON(filepath.Join(d.Directory, ReceiptFile), r); err != nil {
		return r, errors.New("services started but the ready receipt could not be persisted; preserve state and inspect status")
	}
	return r, nil
}

func replaceJSON(path string, value any) error {
	temporary := path + ".next"
	if err := exclusiveJSON(temporary, value); err != nil {
		return err
	}
	defer os.Remove(temporary)
	if err := os.Rename(temporary, path); err != nil {
		return err
	}
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer root.Close()
	return fsutil.SyncDirectory(root, ".")
}
