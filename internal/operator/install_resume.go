package operator

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"time"
)

// ResumeInstall only finalizes already initialized, pinned prepared state.
// It never reselects latest, pulls replacements or repeats fresh initializers.
func (d *Deployment) ResumeInstall(ctx context.Context, receipt Receipt) (Receipt, error) {
	done, e := d.AcquireOperation()
	if e != nil {
		return receipt, e
	}
	defer done()
	cfg, e := d.ValidateReceipt(ctx, receipt)
	if e != nil {
		return receipt, e
	}
	if receipt.Recovered || (receipt.State != "prepared" && receipt.State != "ready") {
		return receipt, errors.New("installation resume requires its original prepared receipt")
	}
	if receipt.State == "ready" {
		return receipt, nil
	}
	before, e := d.runtimeFact(ctx)
	if e != nil || before.NodeID == "" || before.NativeMaintenance || !before.Database.LogicalIdle || before.Database.SchemaGeneration != receipt.Images["web"].Generation {
		return receipt, errors.New("prepared installation lacks verified existing identity/database; preserve state and repair initialization separately")
	}
	var resident []string
	for _, name := range sortedServices(receipt.ServiceImages) {
		if !strings.HasSuffix(name, "-init") {
			resident = append(resident, name)
		}
	}
	readyCtx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	if _, e = d.Compose(readyCtx, true, append([]string{"up", "-d", "--no-build", "--pull", "never", "--no-deps", "--wait", "--wait-timeout", "600"}, resident...)...); e != nil {
		return receipt, errors.New("prepared installation still fails readiness; identity and pinned state retained")
	}
	if e = d.installCertificateReady(readyCtx, cfg); e != nil {
		return receipt, e
	}
	after, e := d.runtimeFact(readyCtx)
	if e != nil || after.NodeID != before.NodeID || after.NativeMaintenance || !after.Database.LogicalIdle || after.Database.SchemaGeneration != before.Database.SchemaGeneration {
		return receipt, errors.New("prepared installation identity/database changed during readiness")
	}
	receipt.State = "ready"
	if e = replaceJSON(filepath.Join(d.Directory, ReceiptFile), receipt); e != nil {
		return receipt, errors.New("ready installation receipt could not be persisted; repeat the same resume")
	}
	return receipt, nil
}
