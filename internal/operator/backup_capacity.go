package operator

import (
	"archive/tar"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/recovery"
)

type BackupCapacity struct {
	ReadOnly              bool   `json:"read_only"`
	Output                string `json:"output"`
	DataBytes             uint64 `json:"source_bytes"`
	Files                 int    `json:"files"`
	Directories           int    `json:"directories"`
	ArchiveBytes          uint64 `json:"archive_upper_bound_bytes"`
	ScratchBytes          uint64 `json:"scratch_bytes"`
	SafetyBytes           uint64 `json:"safety_bytes"`
	RequiredBytes         uint64 `json:"required_free_bytes"`
	FreeBytes             uint64 `json:"free_bytes"`
	Fits                  bool   `json:"fits"`
	Snapshot              string `json:"snapshot"`
	ManifestBytes         uint64 `json:"manifest_upper_bound_bytes"`
	Scope                 string `json:"scope"`
	BusinessFilesIncluded bool   `json:"business_files_included"`
}

type byteCounter struct{ bytes uint64 }

func (c *byteCounter) Write(p []byte) (int, error) {
	if uint64(len(p)) > 10*1024*1024*1024*1024-c.bytes {
		return 0, recovery.ErrUnsafe
	}
	c.bytes += uint64(len(p))
	return len(p), nil
}

// BackupCapacity inspects metadata and, for MySQL, counts a read-only logical dump.
// It creates no files/locks, pulls no images and does not freeze any writer.
func (d *Deployment) BackupCapacity(ctx context.Context, receipt Receipt, output string) (BackupCapacity, error) {
	return d.backupCapacity(ctx, receipt, output, "")
}

func generatedBackupDirectories(database string) int {
	if database == "mysql" {
		return 2
	}
	return 1
}
func (p *BackupCapacity) addSourceDirectory() error {
	p.Directories++
	if p.Directories > recovery.MaxFiles {
		return recovery.ErrUnsafe
	}
	return nil
}
func (p *BackupCapacity) addManifestMetadata(value any) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	p.ManifestBytes += uint64(len(raw) + 1)
	if p.ManifestBytes > recovery.MaxManifest {
		return errors.New("recovery manifest metadata exceeds archive format limit")
	}
	return nil
}

func (d *Deployment) capacityFact(ctx context.Context) (RuntimeFact, error) {
	raw, err := d.Compose(ctx, true, "exec", "-T", "web", "/app/frontiercloud", "operator-status")
	var fact RuntimeFact
	if err == nil && json.Unmarshal(raw, &fact) == nil && fact.NodeID != "" {
		return fact, nil
	}
	raw, err = d.Compose(ctx, true, "run", "--rm", "--no-deps", "--pull", "never", "-T", "web", "operator-status")
	if err != nil || json.Unmarshal(raw, &fact) != nil || fact.NodeID == "" {
		return fact, errors.New("read-only runtime metadata inspection failed")
	}
	return fact, nil
}

// setParent is used only for a new recovery-set directory on an existing parent.
func (d *Deployment) backupCapacity(ctx context.Context, receipt Receipt, output, setParent string) (BackupCapacity, error) {
	return d.backupCapacityScope(ctx, receipt, output, setParent, "deployment")
}
func (d *Deployment) backupCapacityScope(ctx context.Context, receipt Receipt, output, setParent, scope string) (BackupCapacity, error) {
	p := BackupCapacity{ReadOnly: true, Snapshot: "live estimate; repeated before freeze and under the offline lease"}
	p.Scope = scope
	p.BusinessFilesIncluded = scope != "upgrade-state"
	p.Directories = generatedBackupDirectories(receipt.Database)
	if output == "" {
		return p, errors.New("new backup output required")
	}
	cfg, err := d.ValidateReceipt(ctx, receipt)
	if err != nil {
		return p, err
	}
	output, err = filepath.Abs(output)
	if err != nil || output == "" {
		return p, errors.New("absolute new backup output required")
	}
	p.Output = output
	if _, err = os.Lstat(output); !os.IsNotExist(err) {
		return p, errors.New("backup output already exists or cannot be inspected")
	}
	parent := filepath.Dir(output)
	if setParent != "" {
		parent = setParent
	}
	info, err := os.Lstat(parent)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return p, errors.New("backup parent must exist and be a real directory")
	}
	raw, err := d.Runner.Run(ctx, "docker", "context", "inspect", "--format", "{{json .Endpoints.docker.Host}}")
	var endpoint string
	if err != nil || json.Unmarshal(raw, &endpoint) != nil || !strings.HasPrefix(endpoint, "unix://") || os.Getenv("DOCKER_HOST") != "" && !strings.HasPrefix(os.Getenv("DOCKER_HOST"), "unix://") {
		return p, errors.New("backup capacity requires the local Unix-socket Docker engine")
	}
	data, err := upgradeDataRoot(cfg)
	if err != nil {
		return p, err
	}
	var selection []string
	if scope == recovery.UpgradeStateScope {
		selection, err = upgradeDataSelection(cfg, receipt)
		if err != nil {
			return p, err
		}
	}
	roots := map[string]string{"data": data}
	mounted := map[string]bool{}
	for name, service := range cfg.Services {
		if focHostInstaller(name, service) {
			continue
		}
		for _, mount := range service.Volumes {
			if mount.Type == "volume" {
				mounted[mount.Source] = true
			}
			if mount.Type != "bind" || mount.Source == data && mount.Target == cfg.Services["web"].Environment["DATA_ROOT"] {
				continue
			}
			class := recoveredMountClass(name, mount.Target)
			if !receipt.Recovered || class == "" || filepath.Clean(mount.Source) != filepath.Join(filepath.Dir(d.Directory), class) {
				return p, errors.New("unclassified state bind prevents complete capacity proof")
			}
			if prior, ok := roots[class]; ok && prior != mount.Source {
				return p, errors.New("multiple roots claim one recovery class")
			}
			roots[class] = mount.Source
		}
	}
	classes := map[string]string{"runtime_secrets": "runtime_secrets", "storage_secrets": "runtime_secrets", "certificate_state": "certificate_state", "certificate_published": "certificate_published", "redis_data": "redis_data"}
	for logical, volume := range cfg.Volumes {
		if receipt.Recovered && !mounted[logical] {
			continue
		}
		class, ok := classes[logical]
		if !ok {
			if logical != "web_tmp" && logical != "certificate_runtime" && logical != "traffic_runtime" && logical != "mysql_data" {
				return p, errors.New("unclassified state volume prevents complete capacity proof")
			}
			continue
		}
		if _, ok = roots[class]; ok {
			return p, errors.New("multiple roots claim one recovery class")
		}
		root, e := d.volumeRoot(ctx, volume.Name)
		if e != nil {
			return p, e
		}
		roots[class] = root
	}
	fact, err := d.capacityFact(ctx)
	if err != nil {
		return p, err
	}
	if scope == recovery.UpgradeStateScope {
		if err = d.validateBackupAdmission(ctx, cfg, receipt, fact); err != nil {
			return p, err
		}
	}
	header := recovery.Manifest{Format: recovery.Format, Version: 1, Scope: scope, NodeID: fact.NodeID, Role: fact.Role, Revision: receipt.Revision, Database: receipt.Database, SchemaGeneration: fact.Database.SchemaGeneration, ConfigurationVersion: receipt.Version, CreatedAt: "9999-12-31T23:59:59.999999999Z", Consistency: "native-offline-and-deployment-writers-stopped", Bytes: 10 * 1024 * 1024 * 1024 * 1024, RecoverySet: strings.Repeat("f", 32), KeyReferences: []string{"runtime_secrets/node-vault.key", "runtime_secrets/media-premaster.key"}, Classes: []string{"deployment"}}
	if scope == recovery.UpgradeStateScope {
		header.Missing = []string{recovery.ExcludedBusinessFiles}
	}
	for class := range roots {
		header.Classes = append(header.Classes, class)
	}
	if receipt.Database == "mysql" {
		header.Classes = append(header.Classes, "mysql_dump")
	}
	for _, n := range fact.Nodes {
		if n.State != "revoked" {
			header.Missing = append(header.Missing, "matching recovery state for related node "+n.NodeID+" is not included")
			header.Relations = append(header.Relations, recovery.Relation{NodeID: n.NodeID, Direction: n.Direction, State: n.State, Protocol: n.Protocol})
		}
	}
	// Reserve fixed/header growth and use longest numeric ownership values for
	// generated scratch. Existing entries use their actual escaped JSON metadata.
	p.ManifestBytes = 1024
	if err = p.addManifestMetadata(header); err != nil {
		return p, err
	}
	for _, class := range []string{"deployment", "mysql_dump"} {
		if class == "mysql_dump" && receipt.Database != "mysql" {
			continue
		}
		if err = p.addManifestMetadata(recovery.Directory{Path: class, Mode: 0700, UID: 1<<31 - 1, GID: 1<<31 - 1}); err != nil {
			return p, err
		}
	}
	for class, directory := range roots {
		relative, e := filepath.Rel(directory, output)
		if e != nil || relative == "." || relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return p, errors.New("backup output must be outside every captured state root")
		}
		info, e := os.Lstat(directory)
		if e != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return p, errors.New("unsafe recovery root")
		}
		root, e := os.OpenRoot(directory)
		if e != nil {
			return p, e
		}
		e = fs.WalkDir(root.FS(), ".", func(name string, item fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if e := ctx.Err(); e != nil {
				return e
			}
			if class == "data" && !recovery.SelectedPath(selection, name, item.IsDir()) {
				if item.IsDir() {
					return fs.SkipDir
				}
				return nil
			}
			if name != "." && (len(class)+1+len(name) > 4096 || strings.ContainsAny(name, "\\\x00\r\n")) {
				return recovery.ErrUnsafe
			}
			info, e := root.Lstat(name)
			if e != nil {
				return e
			}
			if info.IsDir() {
				if e = p.addSourceDirectory(); e != nil {
					return e
				}
				h, e := tar.FileInfoHeader(info, "")
				if e != nil {
					return e
				}
				path := class
				if name != "." {
					path += "/" + name
				}
				return p.addManifestMetadata(recovery.Directory{Path: path, Mode: h.Mode & 0777, UID: h.Uid, GID: h.Gid})
			}
			if !info.Mode().IsRegular() || info.Size() < 0 || p.Files >= recovery.MaxFiles {
				return recovery.ErrUnsafe
			}
			p.Files++
			h, e := tar.FileInfoHeader(info, "")
			if e != nil {
				return e
			}
			if e = p.addManifestMetadata(recovery.Entry{Path: class + "/" + name, Bytes: info.Size(), SHA256: strings.Repeat("0", 64), Mode: h.Mode & 0777, UID: h.Uid, GID: h.Gid}); e != nil {
				return e
			}
			p.DataBytes += uint64(info.Size())
			if p.DataBytes > 10*1024*1024*1024*1024 {
				return recovery.ErrUnsafe
			}
			return nil
		})
		root.Close()
		if e != nil {
			return p, e
		}
	}
	for _, name := range append([]string{ReceiptFile, ImagesFile, ".env"}, d.Files...) {
		raw, e := readRegular(filepath.Join(d.Directory, name), 1<<20)
		if os.IsNotExist(e) && name == ".env" {
			continue
		}
		if e != nil {
			return p, e
		}
		p.DataBytes += uint64(len(raw))
		p.ScratchBytes += uint64(len(raw))
		p.Files++
		if err = p.addManifestMetadata(recovery.Entry{Path: "deployment/" + name, Bytes: int64(len(raw)), SHA256: strings.Repeat("0", 64), Mode: 0600, UID: 1<<31 - 1, GID: 1<<31 - 1}); err != nil {
			return p, err
		}
	}
	if receipt.Database == "mysql" {
		if !validSQLName(cfg.Services["mysql"].Environment["MYSQL_DATABASE"]) {
			return p, errors.New("invalid scoped MySQL database name")
		}
		stream, ok := d.Runner.(StreamRunner)
		if !ok {
			return p, errors.New("logical dump capacity inspection unavailable")
		}
		count := &byteCounter{}
		args := append(d.composeArgs(true), "exec", "-T", "mysql", "sh", "-c", `MYSQL_PWD=$(cat /run/frontiercloud-secrets/mysql_root_password) exec mysqldump --single-transaction --quick --skip-lock-tables --hex-blob --routines --events --triggers --no-tablespaces -u root --databases "$MYSQL_DATABASE"`)
		if err = stream.RunTo(ctx, count, "docker", args...); err != nil {
			return p, errors.New("logical dump capacity inspection failed")
		}
		if count.bytes > 10*1024*1024*1024*1024 {
			return p, recovery.ErrUnsafe
		}
		p.DataBytes += count.bytes
		p.ScratchBytes += count.bytes
		p.Files++
		if err = p.addManifestMetadata(recovery.Entry{Path: "mysql_dump/database.sql", Bytes: int64(count.bytes), SHA256: strings.Repeat("0", 64), Mode: 0600, UID: 1<<31 - 1, GID: 1<<31 - 1}); err != nil {
			return p, err
		}
	}
	if p.Files > recovery.MaxFiles || p.DataBytes > 10*1024*1024*1024*1024 {
		return p, recovery.ErrUnsafe
	}
	// Include maximum manifest, tar padding and PAX records for long names.
	p.ArchiveBytes = p.DataBytes + uint64(p.Files)*9216 + recovery.MaxManifest + 10240
	p.SafetyBytes = (p.ArchiveBytes+p.ScratchBytes)/10 + (64 << 20)
	p.RequiredBytes = p.ArchiveBytes + p.ScratchBytes + p.SafetyBytes + (512 << 20)
	p.FreeBytes, err = diskFree(parent)
	if err != nil {
		return p, err
	}
	p.Fits = p.FreeBytes >= p.RequiredBytes
	return p, nil
}

func validSQLName(name string) bool {
	if len(name) < 1 || len(name) > 64 {
		return false
	}
	for _, c := range name {
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_') {
			return false
		}
	}
	return true
}
func (d *Deployment) requireBackupCapacity(ctx context.Context, r Receipt, output string) error {
	p, err := d.BackupCapacity(ctx, r, output)
	if err != nil {
		return err
	}
	if !p.Fits {
		return fmt.Errorf("backup capacity insufficient: need %d bytes including archive, scratch and reserve; %d bytes free", p.RequiredBytes, p.FreeBytes)
	}
	return nil
}
