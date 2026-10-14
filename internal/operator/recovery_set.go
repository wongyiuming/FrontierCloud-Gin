package operator

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/maintenance"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/recovery"
)

type RecoveryDeployment struct {
	Deployment *Deployment
	Receipt    Receipt
}

// BackupSet coordinates explicit local-engine deployments. All host-operation
// and native lifecycle leases remain held for the entire multi-node capture.
// No matching interval is inferred from separately captured backup timestamps.
func BackupSet(ctx context.Context, deployments []RecoveryDeployment, output, master string, freeze, external bool) (operationResult recovery.SetReport, operationErr error) {
	var empty recovery.SetReport
	if !freeze || len(deployments) < 2 || len(deployments) > recovery.MaxSetMembers || output == "" {
		return empty, errors.New("cluster backup requires explicit --freeze-all, complete member directories and a new output directory")
	}
	if _, e := os.Lstat(output); !os.IsNotExist(e) {
		return empty, errors.New("recovery-set output must not exist")
	}
	items := append([]RecoveryDeployment(nil), deployments...)
	for _, item := range items {
		if item.Deployment == nil || item.Deployment.Runner == nil {
			return empty, errors.New("invalid explicit deployment")
		}
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Deployment.Directory < items[j].Deployment.Directory })
	var releases []func() error
	defer func() {
		for i := len(releases) - 1; i >= 0; i-- {
			operationErr = errors.Join(operationErr, releases[i]())
		}
	}()
	seen := map[string]bool{}
	projects := map[string]bool{}
	roots := map[string]string{}
	facts := map[string]RuntimeFact{}
	for _, item := range items {
		d := item.Deployment
		if seen[d.Directory] {
			return empty, errors.New("duplicate deployment directory")
		}
		seen[d.Directory] = true
		done, e := d.AcquireOperation()
		if e != nil {
			return empty, e
		}
		releases = append(releases, done)
		cfg, e := d.ValidateReceipt(ctx, item.Receipt)
		if e != nil {
			return empty, e
		}
		if projects[cfg.Name] {
			return empty, errors.New("duplicate Compose project cannot represent independent nodes")
		}
		projects[cfg.Name] = true
		data, e := upgradeDataRoot(cfg)
		if e != nil {
			return empty, e
		}
		for _, other := range roots {
			if sameOrInside(data, other) || sameOrInside(other, data) {
				return empty, errors.New("cluster member state roots must not overlap")
			}
		}
		if sameOrInside(data, output) {
			return empty, errors.New("recovery-set output must be outside member state")
		}
		arch, e := d.Runner.Run(ctx, "docker", "info", "--format", "{{.Architecture}}")
		if e != nil {
			return empty, e
		}
		if e = d.localUpgradeEngine(ctx, Architecture(string(arch))); e != nil {
			return empty, e
		}
		if item.Receipt.Database == "mysql" && !external {
			return empty, errors.New("external MySQL writers must be explicitly confirmed stopped")
		}
		fact, e := d.runtimeFact(ctx)
		if e != nil {
			return empty, e
		}
		if !recovery.SupportedSchemaGeneration(fact.Database.SchemaGeneration) {
			return empty, errors.New("operator and member schema generations differ")
		}
		if item.Receipt.Role == "master" && fact.Role != "Master" || item.Receipt.Role == "storage" && fact.Role != "Follower" {
			return empty, errors.New("deployment and runtime cluster roles disagree")
		}
		roots[d.Directory] = data
		facts[d.Directory] = fact
	}
	id := make([]byte, 16)
	if _, e := rand.Read(id); e != nil {
		return empty, e
	}
	m := recovery.SetManifest{Format: "frontiercloud-recovery-set", Version: 1, ID: hex.EncodeToString(id), MasterID: master, Consistency: "all-listed-local-native-leases-held-and-deployment-writers-stopped"}
	for _, item := range items {
		fact := facts[item.Deployment.Directory]
		m.Members = append(m.Members, setMemberFact(item.Receipt, fact))
	}
	if recovery.ValidateSetGraph(m) != nil {
		return empty, errors.New("directories do not cover exactly one Master and every mutually paired Storage member")
	}
	if e := preflightRecoverySetCapacity(ctx, items, output, facts); e != nil {
		return empty, e
	}
	// Freeze the Master first so no new remote mutation is issued while the
	// remaining members drain. Any failure leaves all acquired fences closed.
	sort.SliceStable(items, func(i, j int) bool {
		return facts[items[i].Deployment.Directory].NodeID == master && facts[items[j].Deployment.Directory].NodeID != master
	})
	for _, item := range items {
		d := item.Deployment
		if _, e := d.Compose(ctx, true, "run", "--rm", "--no-deps", "-T", "web", "maintenance", "enter", "--wait-seconds", "120"); e != nil {
			return empty, errors.New("member freeze failed; acquired fences remain closed")
		}
		var services []string
		for _, name := range sortedServices(item.Receipt.ServiceImages) {
			if name != "mysql" {
				services = append(services, name)
			}
		}
		if _, e := d.Compose(ctx, true, append([]string{"stop"}, services...)...); e != nil {
			return empty, errors.New("member writers did not stop; no complete recovery set was produced")
		}
	}
	var gates []*maintenance.Gate
	defer func() {
		for _, gate := range gates {
			_ = gate.Close()
		}
	}()
	for _, item := range items {
		gate, e := maintenance.Open(roots[item.Deployment.Directory])
		if e != nil {
			return empty, e
		}
		gates = append(gates, gate)
	}
	var result recovery.SetReport
	var capture func(int) error
	capture = func(index int) error {
		if index < len(gates) {
			return gates[index].Inspect(ctx, func(context.Context) error { return capture(index + 1) })
		}
		// The final root lease closes the common interval. Recheck every member
		// now, before reading any archive payload or claiming completeness.
		m.Members = nil
		for _, item := range items {
			d := item.Deployment
			if _, e := d.ValidateReceipt(ctx, item.Receipt); e != nil {
				return e
			}
			if e := d.stoppedWriters(ctx); e != nil {
				return e
			}
			fact, e := d.runtimeFact(ctx)
			if e != nil || fact.NodeID != facts[d.Directory].NodeID || !fact.NativeMaintenance || !fact.Database.LogicalIdle || fact.Database.SchemaGeneration != facts[d.Directory].Database.SchemaGeneration {
				return errors.New("member identity, native fence or transaction state is not quiescent")
			}
			m.Members = append(m.Members, setMemberFact(item.Receipt, fact))
		}
		if recovery.ValidateSetGraph(m) != nil {
			return errors.New("cluster roster changed while draining")
		}
		if e := os.Mkdir(output, 0700); e != nil {
			return e
		}
		warnings := map[string]recovery.ScratchWarning{}
		for index, item := range items {
			member := &m.Members[index]
			member.Archive = member.NodeID + ".tar"
			r, e := item.Deployment.backupSetLocked(ctx, item.Receipt, filepath.Join(output, member.Archive), false, external, m.ID, true)
			if e != nil {
				return e
			}
			member.SHA256 = r.SHA256
			member.Bytes = r.Manifest.Bytes
			if r.CleanupWarning != "" {
				warnings[member.NodeID] = recovery.ScratchWarning{Warning: r.CleanupWarning, RetainedScratch: r.RetainedScratch}
			}
		}
		var e error
		result, e = recovery.PublishSet(ctx, output, m)
		result.CleanupWarnings = warnings
		return e
	}
	if e := capture(0); e != nil {
		return result, e
	}
	return result, nil
}

// All member archives share the new output directory's filesystem. Sum their
// complete upper bounds before freezing anyone; keep one final filesystem reserve.
func preflightRecoverySetCapacity(ctx context.Context, items []RecoveryDeployment, output string, facts map[string]RuntimeFact) error {
	parent, err := filepath.Abs(filepath.Dir(output))
	if err != nil {
		return err
	}
	required := uint64((512 << 20) + recovery.MaxManifest)
	var free uint64
	for _, item := range items {
		p, e := item.Deployment.backupCapacity(ctx, item.Receipt, filepath.Join(output, facts[item.Deployment.Directory].NodeID+".tar"), parent)
		if e != nil {
			return e
		}
		free = p.FreeBytes
		required += p.RequiredBytes - (512 << 20)
	}
	if free < required {
		return errors.New("recovery-set backup capacity insufficient before member freeze")
	}
	return nil
}

func sameOrInside(parent, child string) bool {
	rel, e := filepath.Rel(parent, child)
	return e == nil && (rel == "." || rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)))
}
func setMemberFact(receipt Receipt, fact RuntimeFact) recovery.SetMember {
	m := recovery.SetMember{NodeID: fact.NodeID, Role: fact.Role, Database: receipt.Database, Revision: receipt.Revision, Relations: []recovery.Relation{}}
	m.Generation = fact.Database.SchemaGeneration
	for _, node := range fact.Nodes {
		if node.State != "revoked" {
			m.Relations = append(m.Relations, recovery.Relation{NodeID: node.NodeID, Direction: node.Direction, State: node.State, Protocol: node.Protocol})
		}
	}
	return m
}

func RestoreSetCheck(ctx context.Context, input, target, expected string) (recovery.SetReport, error) {
	r, e := recovery.CheckSet(ctx, input, expected)
	if e != nil {
		return r, e
	}
	if target == "" {
		return r, errors.New("absent restoration target required")
	}
	if _, e = os.Lstat(target); !os.IsNotExist(e) {
		return r, errors.New("restoration target must not exist")
	}
	parent, e := filepath.Abs(filepath.Dir(target))
	if e != nil {
		return r, e
	}
	if info, err := os.Lstat(parent); err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return r, errors.New("existing real restoration parent required")
	}
	free, e := diskFree(parent)
	if e != nil {
		return r, e
	}
	required := uint64(1 << 30)
	for _, member := range r.Manifest.Members {
		required += uint64(member.Bytes)
		if member.Database == "mysql" {
			required += 2 * uint64(member.Bytes)
		}
	}
	if free < required {
		return r, errors.New("restoration filesystem lacks space for every member, staging and database imports")
	}
	return r, nil
}
