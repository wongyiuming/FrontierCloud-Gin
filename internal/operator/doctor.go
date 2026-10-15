package operator

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/release"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type Check struct {
	Item   string `json:"item"`
	State  string `json:"state"`
	Reason string `json:"reason"`
	Next   string `json:"next"`
}
type Report struct {
	Operation string  `json:"operation"`
	State     string  `json:"state"`
	ReadOnly  bool    `json:"read_only"`
	Checks    []Check `json:"checks"`
}

func (r *Report) Add(item, state, reason, next string) {
	r.Checks = append(r.Checks, Check{item, state, reason, next})
	if state == "blocked" {
		r.State = "needs_attention"
	} else if (state == "warning" || state == "unverified") && r.State == "available" {
		r.State = "degraded"
	}
}
func (r Report) ExitCode() int {
	warning := false
	for _, c := range r.Checks {
		if c.State == "blocked" {
			return 2
		}
		if c.State == "warning" || c.State == "unverified" {
			warning = true
		}
	}
	if warning {
		return 3
	}
	return 0
}
func (r Report) Human() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s: %s (read_only=%t)\n", r.Operation, r.State, r.ReadOnly)
	for _, c := range r.Checks {
		fmt.Fprintf(&b, "[%s] %s: %s; next: %s\n", c.State, c.Item, c.Reason, c.Next)
	}
	return b.String()
}

// Doctor never initializes data, creates a lock, probes writes or pulls images.
func (d *Deployment) Doctor(ctx context.Context) Report {
	r := Report{Operation: "doctor", State: "available", ReadOnly: true}
	raw, err := d.Runner.Run(ctx, "docker", "info", "--format", "{{json .}}")
	if err != nil {
		r.Add("docker", "blocked", "Docker daemon is unavailable or access denied", "start Docker or grant this operator scoped daemon access")
		return r
	}
	var info struct {
		OSType        string `json:"OSType"`
		Architecture  string `json:"Architecture"`
		ServerVersion string `json:"ServerVersion"`
	}
	if json.Unmarshal(raw, &info) != nil || info.OSType != "linux" {
		r.Add("engine", "blocked", "Linux Docker engine required", "select a Linux engine")
	} else {
		r.Add("engine", "pass", "Linux Docker engine available", "none")
	}
	arch := Architecture(info.Architecture)
	engineMajor, _ := strconv.Atoi(strings.Split(info.ServerVersion, ".")[0])
	if engineMajor < 24 {
		r.Add("docker_version", "blocked", "Docker Engine >= 24 required", "upgrade Docker through the host's approved package procedure")
	} else {
		r.Add("docker_version", "pass", "Docker Engine version "+info.ServerVersion, "none")
	}
	if arch == "" {
		r.Add("architecture", "blocked", "architecture is unsupported by the operator bundle", "use a published supported platform")
	} else {
		r.Add("architecture", "pass", "engine architecture: "+arch, "verify the selected release publishes this platform")
	}
	raw, err = d.Runner.Run(ctx, "docker", "compose", "version", "--short")
	if err != nil || !ComposeVersion(string(raw)) {
		r.Add("compose", "blocked", "Compose >= 2.24 required for optional env_file and waiting", "install a compatible Docker Compose plugin")
	} else {
		r.Add("compose", "pass", "compatible Compose plugin", "none")
	}
	cfg, err := d.Config(ctx, false)
	if err != nil {
		r.Add("configuration", "blocked", err.Error(), "check the selected role, database and required domain settings")
		return r
	}
	r.Add("configuration", "pass", "project: "+cfg.Name+"; role: "+d.Role+"; database: "+cfg.Services["web"].Environment["DB_TYPE"], "configuration changes do not move data")
	if _, e := os.Lstat(filepath.Join(d.Directory, OperationLock)); e == nil {
		r.Add("host_operation", "blocked", "host operation lock exists", "inspect the active/interrupted operation; do not auto-clear the lock")
	} else if !os.IsNotExist(e) {
		r.Add("host_operation", "blocked", "host operation lock cannot be inspected", "check deployment directory access")
	}
	web := cfg.Services["web"]
	if d.Role == "storage" && (web.Environment["DB_TYPE"] != "sqlite" || web.Environment["DEPLOYMENT_MODE"] != "only_stroge") || d.Role == "master" && web.Environment["DEPLOYMENT_MODE"] == "only_stroge" {
		r.Add("role", "blocked", "role/database configuration conflicts with selected deployment", "use the appropriate role and takeover workflow")
	}
	host := web.Environment["SERVER_NAME"]
	if web.Environment["TLS_ENABLED"] == "true" {
		if host == "" || host == "localhost" || net.ParseIP(host) != nil || strings.ContainsAny(host, " /:@") {
			r.Add("dns", "blocked", "HTTPS requires a valid public DNS hostname", "set SERVER_NAME and the corresponding storage endpoint")
		} else if _, e := net.DefaultResolver.LookupIPAddr(ctx, host); e != nil {
			r.Add("dns", "blocked", "hostname does not resolve from this host", "correct public A/AAAA records")
		} else {
			r.Add("dns", "pass", "hostname resolves from the operator host", "check all A/AAAA destinations and NAT forwarding")
		}
		r.Add("inbound_http01", "unverified", "local DNS/outbound access does not prove public TCP 80 reaches this host", "verify public reachability independently before certificate issuance")
		r.Add("inbound_https", "unverified", "public TCP reachability cannot be established locally", "verify 443 for Direct/Master or the configured Relay port from an external host")
	} else {
		r.Add("tls", "warning", "automatic HTTPS is disabled", "enable HTTPS before using fixed Master/Storage roles")
	}
	if err = d.Empty(ctx, cfg); err != nil {
		r.Add("fresh_target", "warning", err.Error(), "fresh install will refuse; use status, takeover or restore")
	} else {
		r.Add("fresh_target", "pass", "no declared existing containers, data or volumes", "installation rechecks before initialization")
	}
	var boundReceipt *Receipt
	receiptPresent := false
	if _, e := os.Lstat(filepath.Join(d.Directory, ReceiptFile)); e == nil {
		receiptPresent = true
		dep, receipt, e := Open(d.Directory)
		if e == nil {
			dep.Runner = d.Runner
			_, e = dep.ValidateReceipt(ctx, receipt)
		}
		if e != nil {
			r.Add("deployment_binding", "blocked", "deployment selection differs from its durable receipt", "restore the recorded project, role, mounts, database and image lock")
		} else {
			boundReceipt = &receipt
			r.Add("deployment_binding", "pass", "recorded deployment selection and image digests match", "none")
		}
	}
	seen := map[string]bool{}
	for _, s := range cfg.Services {
		for _, m := range s.Volumes {
			if m.Type != "bind" || seen[m.Source] {
				continue
			}
			seen[m.Source] = true
			path := m.Source
			info, e := os.Lstat(path)
			if e != nil && !os.IsNotExist(e) {
				r.Add("mount", "blocked", "cannot inspect a declared mount", "check access and mount configuration")
				continue
			}
			if e == nil && (!info.IsDir() || info.Mode()&os.ModeSymlink != 0) {
				r.Add("mount", "blocked", "declared data mount is not a real directory", "correct the mount; do not initialize over old state")
				continue
			}
			for os.IsNotExist(e) {
				parent := filepath.Dir(path)
				if parent == path {
					break
				}
				path = parent
				info, e = os.Stat(path)
			}
			if e == nil {
				free, e := diskFree(path)
				if e != nil {
					r.Add("disk_free", "unverified", "physical free space cannot be read on this platform", "check the actual data filesystem")
				} else if free < 2<<30 {
					r.Add("disk_free", "blocked", "less than 2 GiB free on the data filesystem", "free space or select another empty target")
				} else {
					r.Add("disk_free", "pass", fmt.Sprintf("%d bytes free on the data filesystem", free), "backup and migration need additional reserved space")
				}
			}
			r.Add("write_permissions", "unverified", "read-only inspection cannot prove the runtime UID can create and sync files", "verify ownership/ACL for UID 10001; no write probe was executed")
		}
	}
	ports, err := listeningPorts()
	if err != nil {
		r.Add("ports", "unverified", "local socket inventory unavailable", "inspect TCP/UDP listeners and configured bind addresses")
	} else {
		var occupied []string
		if web.Environment["TLS_ENABLED"] == "true" && ports["tcp:80"] {
			occupied = append(occupied, "tcp:80 (HTTP-01)")
		}
		for _, s := range cfg.Services {
			for _, p := range s.Ports {
				key := p.Protocol + ":" + p.Published
				if ports[key] {
					occupied = append(occupied, key)
				}
			}
		}
		if len(occupied) > 0 {
			r.Add("ports", "warning", "listeners exist on configured ports: "+strings.Join(occupied, ", "), "identify their owner; fresh installation must not replace another deployment")
		} else {
			r.Add("ports", "pass", "configured TCP/UDP ports have no observed listeners", "recheck immediately before starting; this does not prove inbound access")
		}
	}
	if d.ImageInspector == nil {
		r.Add("registry", "unverified", "registry image inspection unavailable", "install verifies provenance/digests and refuses failed pulls")
	} else if receiptPresent && boundReceipt == nil {
		r.Add("registry", "blocked", "deployment receipt cannot bind image verification", "restore the recorded deployment before verifying its images")
	} else if arch != "" {
		repo, _ := release.ImageRepository("web")
		target := strings.TrimPrefix(web.Image, repo+":")
		if boundReceipt != nil {
			target = boundReceipt.Revision
		}
		proof, e := d.ImageInspector.Prove(ctx, target, "web", arch)
		if e == nil && boundReceipt != nil && (proof.Revision != target || proof.Image != boundReceipt.ServiceImages["web"]) {
			e = release.ErrImageIntegrity
		}
		if e != nil {
			r.Add("registry", "blocked", e.Error(), "correct package access/network/platform; do not fall back to compilation")
		} else {
			verifyNginx := d.Role == "master"
			if boundReceipt != nil {
				verifyNginx = boundReceipt.Role == "master"
			}
			if verifyNginx {
				var nginx release.ImageProof
				nginx, e = d.ImageInspector.Prove(ctx, proof.Revision, "nginx", arch)
				if e == nil && boundReceipt != nil && (nginx.Revision != target || nginx.Image != boundReceipt.ServiceImages["nginx"]) {
					e = release.ErrImageIntegrity
				}
			}
			if e != nil {
				r.Add("registry", "blocked", e.Error(), "wait for the complete matching release; never mix aliases")
			} else {
				r.Add("registry", "pass", "published component manifest/config hashes and platform verified at "+proof.Revision, "installation rechecks; no image was pulled or run")
			}
		}
	}
	r.Add("database_generation", "unverified", "existing database was not opened by the host doctor", "use status on a running instance or the read-only restore compatibility check")
	return r
}
func Architecture(v string) string {
	switch strings.TrimSpace(v) {
	case "amd64", "x86_64":
		return "amd64"
	case "arm64", "aarch64":
		return "arm64"
	}
	return ""
}
func ComposeVersion(v string) bool {
	parts := strings.Split(strings.TrimPrefix(strings.TrimSpace(v), "v"), ".")
	if len(parts) < 2 {
		return false
	}
	major, e := strconv.Atoi(parts[0])
	minor, f := strconv.Atoi(parts[1])
	return e == nil && f == nil && (major > 2 || major == 2 && minor >= 24)
}
func listeningPorts() (map[string]bool, error) {
	result := map[string]bool{}
	for _, file := range []string{"tcp", "tcp6", "udp", "udp6"} {
		raw, err := os.ReadFile("/proc/net/" + file)
		if err != nil {
			return nil, err
		}
		for _, line := range strings.Split(string(raw), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 4 || file[0] == 't' && fields[3] != "0A" {
				continue
			}
			pair := strings.Split(fields[1], ":")
			if len(pair) != 2 {
				continue
			}
			port, e := strconv.ParseInt(pair[1], 16, 32)
			if e == nil {
				protocol := "udp"
				if file[0] == 't' {
					protocol = "tcp"
				}
				result[protocol+":"+strconv.FormatInt(port, 10)] = true
			}
		}
	}
	return result, nil
}

func (d *Deployment) Status(ctx context.Context, receipt Receipt) Report {
	r := Report{Operation: "status", State: "available", ReadOnly: true}
	if _, err := d.ValidateReceipt(ctx, receipt); err != nil {
		r.Add("deployment_binding", "blocked", err.Error(), "restore recorded configuration; do not reinitialize")
		return r
	}
	r.Add("version", "pass", "source "+receipt.Revision+"; images fixed by digest", "upgrade requires an explicit target release")
	raw, err := d.Compose(ctx, true, "ps", "--all", "--format", "json")
	if err != nil {
		r.Add("containers", "blocked", "container status unavailable", "check Docker/project permissions")
		return r
	}
	var containers []struct {
		Service  string `json:"Service"`
		State    string `json:"State"`
		Health   string `json:"Health"`
		ExitCode int    `json:"ExitCode"`
	}
	// Compose versions emit either a JSON array or JSON lines.
	if json.Unmarshal(raw, &containers) != nil {
		decoder := json.NewDecoder(strings.NewReader(string(raw)))
		for decoder.More() {
			var c struct {
				Service  string `json:"Service"`
				State    string `json:"State"`
				Health   string `json:"Health"`
				ExitCode int    `json:"ExitCode"`
			}
			if decoder.Decode(&c) != nil {
				r.Add("containers", "blocked", "invalid container status", "check Compose compatibility")
				return r
			}
			containers = append(containers, c)
		}
	}
	if len(containers) == 0 {
		r.Add("containers", "blocked", "no deployment containers found", "inspect interrupted installation receipt and target data")
		return r
	}
	for _, c := range containers {
		state := "pass"
		if strings.HasSuffix(c.Service, "-init") && c.State == "exited" && c.ExitCode == 0 {
			continue
		}
		if c.State != "running" || c.Health != "" && c.Health != "healthy" {
			state = "blocked"
		}
		r.Add("container:"+c.Service, state, c.State+" "+c.Health, "inspect scoped diagnostics if not healthy")
	}
	present := map[string]bool{}
	for _, c := range containers {
		present[c.Service] = true
	}
	for name := range receipt.ServiceImages {
		if !strings.HasSuffix(name, "-init") && !present[name] {
			r.Add("container:"+name, "blocked", "expected resident service is missing", "inspect interrupted installation and selected project")
		}
	}
	if _, err = d.Compose(ctx, true, "exec", "-T", "web", "/app/frontiercloud", "healthcheck"); err != nil {
		r.Add("application_database", "blocked", "application readiness probe failed", "inspect database, maintenance fence and TLS state")
	} else {
		r.Add("application_database", "pass", "application readiness probe passed", "this does not replace playback/Range acceptance")
	}
	// Query from the existing Web cgroup through its read-only socket mount.
	// Starting full CLI processes in the 0.05 CPU controller can exhaust its
	// small PID budget and starve the observation being measured.
	raw, err = d.Compose(ctx, true, "exec", "-T", "web", "/app/frontiercloud", "certificate-status")
	if err != nil {
		r.Add("certificate", "blocked", "certificate controller status unavailable", "inspect controller service and persistent certificate volumes")
	} else {
		var v struct {
			Enabled           bool   `json:"enabled"`
			HTTPSReady        bool   `json:"https_ready"`
			ServingMatches    bool   `json:"serving_matches"`
			ControllerRunning bool   `json:"controller_running"`
			LastError         string `json:"last_error"`
		}
		if json.Unmarshal(raw, &v) != nil {
			r.Add("certificate", "blocked", "invalid certificate status", "check controller compatibility")
		} else if !v.ControllerRunning || v.Enabled && (!v.HTTPSReady || !v.ServingMatches) {
			reason := "automatic HTTPS is not ready or serving bytes differ"
			switch v.LastError {
			case "serving_probe_timeout", "serving_dns", "serving_connection", "serving_tls_verification", "serving_tls_handshake", "serving_certificate_mismatch":
				reason = "automatic HTTPS serving check: " + v.LastError
			}
			r.Add("certificate", "blocked", reason, "check DNS, HTTP-01 and certificate controller")
		} else {
			r.Add("certificate", "pass", "certificate controller ready", "none")
		}
	}
	raw, err = d.Compose(ctx, true, "exec", "-T", "web", "/app/frontiercloud", "operator-status")
	if err != nil {
		r.Add("runtime_facts", "unverified", "read-only runtime inspection unavailable; release may predate this command", "check authenticated Admin nodes and database compatibility")
	} else {
		var fact RuntimeFact
		if json.Unmarshal(raw, &fact) != nil {
			r.Add("runtime_facts", "blocked", "invalid runtime facts", "check release compatibility")
		} else {
			r.Add("database_generation", "pass", fmt.Sprintf("generation %d; role %s; node %s", fact.Database.SchemaGeneration, fact.Role, fact.NodeID), "retain matching recovery images")
			if d.Role == "storage" && fact.Role != "Follower" || d.Role == "master" && fact.Role != "Standalone" && fact.Role != "Master" {
				r.Add("runtime_role", "blocked", "runtime role differs from deployment receipt", "use takeover or recovery; never reinitialize")
			}
			if fact.Maintenance {
				r.Add("maintenance", "warning", "site is in maintenance; native fence="+strconv.FormatBool(fact.NativeMaintenance), "preserve this state until an approved recovery or upgrade finishes")
				if r.State != "needs_attention" {
					r.State = "maintenance"
				}
			}
			if !fact.Database.LogicalIdle {
				r.Add("resource_transactions", "warning", "resource reservations or unfinished transactions exist", "inspect uploads, file journals and background tasks")
			}
			for _, n := range fact.Nodes {
				state := "pass"
				if n.State != "active" || n.Health != "online" || n.LastHeartbeat < time.Now().Unix()-90 || n.Protocol != 2 {
					state = "warning"
				}
				r.Add("node:"+n.NodeID, state, n.State+" "+n.Health, "check node connectivity and authenticated health")
			}
		}
	}
	r.Add("business_read", "unverified", "playback and managed Range reads have not been exercised", "test a representative authorized managed Range read")
	return r
}
