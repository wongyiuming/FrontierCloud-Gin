package operator

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ResumeInstall uses only the recorded fresh-install pins. An initializing
// intent may replay idempotent initializers; prepared state never does.
func (d *Deployment) ResumeInstall(ctx context.Context, receipt Receipt) (Receipt, error) {
	done, e := d.AcquireOperation()
	if e != nil {
		return receipt, e
	}
	defer done()
	if receipt.State == "initializing" {
		if _, err := os.Lstat(filepath.Join(d.Directory, ImagesFile)); os.IsNotExist(err) {
			bare, err := d.Config(ctx, false)
			if err != nil || bare.Name != receipt.Project || selectionHash(bare) != receipt.SelectionHash {
				return receipt, errors.New("initializing configuration changed before image-lock recovery")
			}
			lock := map[string]map[string]string{}
			for name, image := range receipt.ServiceImages {
				lock[name] = map[string]string{"image": image}
			}
			if e = exclusiveJSON(filepath.Join(d.Directory, ImagesFile), map[string]any{"services": lock}); e != nil {
				return receipt, e
			}
		} else if err != nil {
			return receipt, err
		}
	}
	cfg, e := d.ValidateReceipt(ctx, receipt)
	if e != nil {
		return receipt, e
	}
	if receipt.Recovered || (receipt.State != "initializing" && receipt.State != "prepared" && receipt.State != "ready") {
		return receipt, errors.New("installation resume requires its original prepared receipt")
	}
	if receipt.State == "ready" {
		return receipt, nil
	}
	before, e := d.runtimeFact(ctx)
	if receipt.State == "initializing" {
		originalID := before.NodeID
		if e == nil && (before.NativeMaintenance || !before.Database.LogicalIdle || before.Database.SchemaGeneration != receipt.Images["web"].Generation) {
			return receipt, errors.New("initialization retry refuses changed or independently fenced state")
		}
		readyCtx, cancel := context.WithTimeout(ctx, 10*time.Minute)
		defer cancel()
		if _, e = d.Compose(readyCtx, true, "up", "-d", "--no-build", "--pull", "never", "--wait", "--wait-timeout", "600"); e != nil {
			return receipt, errors.New("pinned fresh initialization remains incomplete; preserve its recorded intent and material")
		}
		before, e = d.runtimeFact(readyCtx)
		if e == nil && originalID != "" && before.NodeID != originalID {
			return receipt, errors.New("initialization retry changed its existing identity")
		}
	}
	if e != nil || before.NodeID == "" || before.NativeMaintenance || !before.Database.LogicalIdle || before.Database.SchemaGeneration != receipt.Images["web"].Generation {
		return receipt, errors.New("prepared installation lacks verified existing identity/database; preserve state and repair initialization separately")
	}
	if receipt.State == "initializing" {
		receipt.State = "prepared"
		if e = replaceJSON(filepath.Join(d.Directory, ReceiptFile), receipt); e != nil {
			return receipt, e
		}
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
