package operator

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/maintenance"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/recovery"
	"github.com/wongyiuming/FrontierCloud-Gin/migrations"
)

type StreamRunner interface {
	RunTo(context.Context, io.Writer, string, ...string) error
}

func (d *Deployment) runtimeFact(ctx context.Context) (RuntimeFact, error) {
	var fact RuntimeFact
	// This short-lived read-only command does not initialize identity, start
	// services or acquire the native offline writer lease.
	raw, e := d.Compose(ctx, true, "run", "--rm", "--no-deps", "-T", "web", "operator-status")
	if e != nil {
		return fact, e
	}
	if json.Unmarshal(raw, &fact) != nil || fact.NodeID == "" {
		return fact, errors.New("read-only runtime inspection failed")
	}
	return fact, nil
}
func (d *Deployment) stoppedWriters(ctx context.Context) error {
	raw, e := d.Compose(ctx, true, "ps", "--all", "--format", "json")
	if e != nil {
		return e
	}
	type state struct {
		Service string `json:"Service"`
		State   string `json:"State"`
	}
	var states []state
	if json.Unmarshal(raw, &states) != nil {
		decoder := json.NewDecoder(strings.NewReader(string(raw)))
		for decoder.More() {
			var value state
			if decoder.Decode(&value) != nil {
				return errors.New("invalid writer-state inventory")
			}
			states = append(states, value)
		}
	}
	for _, value := range states {
		if value.Service != "mysql" && value.State != "exited" && value.State != "created" && value.State != "dead" {
			return errors.New("deployment writers are not stopped; use explicit --freeze before backup")
		}
	}
	return nil
}
func (d *Deployment) volumeRoot(ctx context.Context, name string) (string, error) {
	raw, e := d.Runner.Run(ctx, "docker", "volume", "inspect", "--format", "{{json .Mountpoint}}", name)
	if e != nil {
		return "", e
	}
	var directory string
	if json.Unmarshal(raw, &directory) != nil || !filepath.IsAbs(directory) {
		return "", errors.New("local volume mountpoint unavailable")
	}
	return directory, nil
}

// Backup creates one deployment recovery point, with a held native lifecycle
// lease and all its filesystem writers stopped. It never copies a hot MySQL
// directory, reopens traffic or claims to include another node's media/state.
func (d *Deployment) Backup(ctx context.Context, receipt Receipt, output string, freeze, externalWritersStopped bool) (recovery.Report, error) {
	var empty recovery.Report
	done, e := d.AcquireOperation()
	if e != nil {
		return empty, e
	}
	defer done()
	cfg, e := d.ValidateReceipt(ctx, receipt)
	if e != nil {
		return empty, e
	}
	if output == "" {
		return empty, errors.New("backup output required")
	}
	output, e = filepath.Abs(output)
	if e != nil {
		return empty, e
	}
	if _, e = os.Lstat(output); !errors.Is(e, os.ErrNotExist) {
		return empty, errors.New("backup output already exists or cannot be inspected")
	}
	// Inspect the effective Docker endpoint rather than assuming local paths
	// belong to a remote engine. Only a Unix socket on this Linux host is allowed.
	raw, e := d.Runner.Run(ctx, "docker", "context", "inspect", "--format", "{{json .Endpoints.docker.Host}}")
	if e != nil {
		return empty, e
	}
	var endpoint string
	if json.Unmarshal(raw, &endpoint) != nil || !strings.HasPrefix(endpoint, "unix://") || os.Getenv("DOCKER_HOST") != "" && !strings.HasPrefix(os.Getenv("DOCKER_HOST"), "unix://") {
		return empty, errors.New("offline recovery requires a local Unix-socket Docker engine")
	}
	if receipt.Database == "mysql" && !externalWritersStopped {
		return empty, errors.New("MySQL backup requires explicit confirmation that external database writers are stopped")
	}
	data := ""
	for _, mount := range cfg.Services["web"].Volumes {
		if mount.Target == cfg.Services["web"].Environment["DATA_ROOT"] && mount.Type == "bind" {
			data = mount.Source
		}
	}
	if data == "" {
		return empty, errors.New("offline backup requires the recorded local DATA_ROOT bind")
	}
	if freeze {
		if _, e = d.Compose(ctx, true, "run", "--rm", "--no-deps", "-T", "web", "maintenance", "enter", "--wait-seconds", "120"); e != nil {
			return empty, errors.New("native freeze failed; preserve maintenance and inspect unfinished transactions")
		}
		var names []string
		for name := range cfg.Services {
			if name != "mysql" {
				names = append(names, name)
			}
		}
		sort.Strings(names)
		if _, e = d.Compose(ctx, true, append([]string{"stop"}, names...)...); e != nil {
			return empty, errors.New("not all deployment services stopped; site remains fenced")
		}
	}
	if e = d.stoppedWriters(ctx); e != nil {
		return empty, e
	}
	gate, e := maintenance.Open(data)
	if e != nil {
		return empty, e
	}
	defer gate.Close()
	var report recovery.Report
	e = gate.Inspect(ctx, func(ctx context.Context) error {
		// Repeat Docker state under the native lease. The native lifecycle fence
		// blocks concurrent initializer/migration/resume writers for this root.
		if e := d.stoppedWriters(ctx); e != nil {
			return e
		}
		fact, e := d.runtimeFact(ctx)
		if e != nil {
			return e
		}
		if !fact.NativeMaintenance || !fact.Database.LogicalIdle || fact.Database.SchemaGeneration != migrations.Generation {
			return errors.New("backup requires matching operator/schema generation, native maintenance and no unfinished resource transactions")
		}
		workspace, e := os.MkdirTemp(filepath.Dir(output), ".fc-backup-")
		if e != nil {
			return e
		}
		// Private scratch is retained on failure for diagnosis. No recursive
		// cleanup command can accidentally erase a source or old recovery point.
		deployment := filepath.Join(workspace, "deployment")
		if e = os.Mkdir(deployment, 0700); e != nil {
			return e
		}
		for _, name := range append([]string{ReceiptFile, ImagesFile, ".env"}, d.Files...) {
			content, e := readRegular(filepath.Join(d.Directory, name), 1<<20)
			if os.IsNotExist(e) && name == ".env" {
				continue
			}
			if e != nil {
				return e
			}
			if e = os.WriteFile(filepath.Join(deployment, name), content, 0600); e != nil {
				return e
			}
		}
		sources := []recovery.Root{{Class: "data", Directory: data}, {Class: "deployment", Directory: deployment}}
		m := recovery.Manifest{NodeID: fact.NodeID, Role: fact.Role, Revision: receipt.Revision, Database: receipt.Database, Consistency: "native-offline-and-deployment-writers-stopped", Missing: []string{}, KeyReferences: []string{"runtime_secrets/node-vault.key"}}
		for _, n := range fact.Nodes {
			if n.State != "revoked" {
				m.Missing = append(m.Missing, "matching recovery state for related node "+n.NodeID+" is not included")
			}
		}
		m.CompleteCluster = len(m.Missing) == 0
		classes := map[string]string{"runtime_secrets": "runtime_secrets", "storage_secrets": "runtime_secrets", "certificate_state": "certificate_state", "certificate_published": "certificate_published", "redis_data": "redis_data"}
		seen := map[string]bool{}
		for logical, volume := range cfg.Volumes {
			class, ok := classes[logical]
			if !ok {
				if logical != "web_tmp" && logical != "certificate_runtime" && logical != "mysql_data" {
					m.Missing = append(m.Missing, "unclassified volume "+logical)
				}
				continue
			}
			if seen[class] {
				return errors.New("multiple volumes claim one recovery state class")
			}
			seen[class] = true
			root, e := d.volumeRoot(ctx, volume.Name)
			if e != nil {
				return e
			}
			sources = append(sources, recovery.Root{Class: class, Directory: root})
			if class == "runtime_secrets" {
				if _, e := os.Lstat(filepath.Join(root, "media-premaster.key")); e == nil {
					m.KeyReferences = append(m.KeyReferences, "runtime_secrets/media-premaster.key")
				} else if !os.IsNotExist(e) {
					return e
				}
			}
		}
		if receipt.Database == "mysql" {
			if !regexp.MustCompile(`^[A-Za-z0-9_]{1,64}$`).MatchString(cfg.Services["mysql"].Environment["MYSQL_DATABASE"]) {
				return errors.New("invalid scoped MySQL database name")
			}
			stream, ok := d.Runner.(StreamRunner)
			if !ok {
				return errors.New("bounded MySQL dump streaming unavailable")
			}
			dumpRoot := filepath.Join(workspace, "mysql_dump")
			if e = os.Mkdir(dumpRoot, 0700); e != nil {
				return e
			}
			dump, e := os.OpenFile(filepath.Join(dumpRoot, "database.sql"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
			if e != nil {
				return e
			}
			// Password comes from the existing private mounted file, never an
			// argv value. mysqldump provides one consistent InnoDB logical snapshot.
			args := append(d.composeArgs(true), "exec", "-T", "mysql", "sh", "-c", `MYSQL_PWD=$(cat /run/frontiercloud-secrets/mysql_root_password) exec mysqldump --single-transaction --quick --skip-lock-tables --hex-blob --routines --events --triggers --no-tablespaces -u root --databases "$MYSQL_DATABASE"`)
			e = stream.RunTo(ctx, dump, "docker", args...)
			if e == nil {
				e = dump.Sync()
			}
			e = errors.Join(e, dump.Close())
			if e != nil {
				return errors.New("consistent MySQL export failed; source and maintenance remain intact")
			}
			sources = append(sources, recovery.Root{Class: "mysql_dump", Directory: dumpRoot})
		}
		m.CompleteCluster = len(m.Missing) == 0
		report, e = recovery.Create(ctx, output, m, sources)
		return e
	})
	return report, e
}
