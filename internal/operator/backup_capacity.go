package operator

import (
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
	ReadOnly      bool   `json:"read_only"`
	Output        string `json:"output"`
	DataBytes     uint64 `json:"source_bytes"`
	Files         int    `json:"files"`
	Directories   int    `json:"directories"`
	ArchiveBytes  uint64 `json:"archive_upper_bound_bytes"`
	ScratchBytes  uint64 `json:"scratch_bytes"`
	SafetyBytes   uint64 `json:"safety_bytes"`
	RequiredBytes uint64 `json:"required_free_bytes"`
	FreeBytes     uint64 `json:"free_bytes"`
	Fits          bool   `json:"fits"`
	Snapshot      string `json:"snapshot"`
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

// setParent is used only for a new recovery-set directory on an existing parent.
func (d *Deployment) backupCapacity(ctx context.Context, receipt Receipt, output, setParent string) (BackupCapacity, error) {
	p := BackupCapacity{ReadOnly: true, Snapshot: "live estimate; repeated before freeze and under the offline lease"}
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
	roots := map[string]string{"data": data}
	mounted := map[string]bool{}
	for name, service := range cfg.Services {
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
			if name != "." && (len(class)+1+len(name) > 4096 || strings.ContainsAny(name, "\\\x00\r\n")) {
				return recovery.ErrUnsafe
			}
			info, e := root.Lstat(name)
			if e != nil {
				return e
			}
			if info.IsDir() {
				return p.addSourceDirectory()
			}
			if !info.Mode().IsRegular() || info.Size() < 0 || p.Files >= recovery.MaxFiles {
				return recovery.ErrUnsafe
			}
			p.Files++
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
