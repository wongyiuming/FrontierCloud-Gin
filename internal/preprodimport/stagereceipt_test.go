package preprodimport

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestSyntheticStageReceiptAuthenticatesOpaqueExactSet(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("native stage lock and private ACL unavailable")
	}
	base := t.TempDir()
	if err := os.Chmod(base, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{"direct", "direct/objects", "direct/partial"} {
		if err := os.Mkdir(filepath.Join(base, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(base, "direct/.lock"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	id := strings.Repeat("a", 64)
	data := []byte("synthetic stage payload")
	file := filepath.Join(base, "direct/objects", id+".blob")
	if err := os.WriteFile(file, data, 0o600); err != nil {
		t.Fatal(err)
	}
	req := stageReceiptRequest{Version: 1, Role: "direct", OwnerID: strings.Repeat("1", 32), MasterID: strings.Repeat("2", 32), Generation: strings.Repeat("3", 64), PlanDigest: strings.Repeat("4", 64), Challenge: strings.Repeat("5", 64), Items: []stageReceiptItem{{StageID: id, Size: int64(len(data)), SHA256: digest(data)}}}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(2000000000, 0)
	opts := Options{MaxBytesPerSecond: 4 * 1024 * 1024, Progress: func(Event) error { return nil }}
	receipt, err := signStageReceipt(context.Background(), base, req, priv, opts, now)
	if err != nil {
		t.Fatal(err)
	}
	if err = verifyStageReceipt(receipt, req, pub, now); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*stageReceiptRequest){"owner": func(v *stageReceiptRequest) { v.OwnerID = strings.Repeat("6", 32) }, "generation": func(v *stageReceiptRequest) { v.Generation = strings.Repeat("6", 64) }, "plan": func(v *stageReceiptRequest) { v.PlanDigest = strings.Repeat("6", 64) }, "challenge": func(v *stageReceiptRequest) { v.Challenge = strings.Repeat("6", 64) }, "stage id": func(v *stageReceiptRequest) { v.Items[0].StageID = strings.Repeat("6", 64) }} {
		t.Run(name, func(t *testing.T) {
			changed := req
			changed.Items = append([]stageReceiptItem(nil), req.Items...)
			mutate(&changed)
			if err := verifyStageReceipt(receipt, changed, pub, now); err == nil {
				t.Fatal("changed expected receipt accepted")
			}
		})
	}
	wrong, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err = verifyStageReceipt(receipt, req, wrong, now); err == nil {
		t.Fatal("wrong owner pin accepted")
	}
	if err = verifyStageReceipt(receipt, req, pub, now.Add(5*time.Minute)); err == nil {
		t.Fatal("expired receipt accepted")
	}
	raw, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "synthetic stage payload") {
		t.Fatal("receipt leaked payload")
	}
	partial := filepath.Join(base, "direct/partial", strings.Repeat("b", 64)+".part")
	if err = os.WriteFile(partial, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err = signStageReceipt(context.Background(), base, req, priv, opts, now); err == nil {
		t.Fatal("partial stage signed")
	}
	if err = os.Remove(partial); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(base, "direct/objects", strings.Repeat("c", 64)+".blob"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err = signStageReceipt(context.Background(), base, req, priv, opts, now); err == nil {
		t.Fatal("extra stage object signed")
	}
	if err = os.Remove(filepath.Join(base, "direct/objects", strings.Repeat("c", 64)+".blob")); err != nil {
		t.Fatal(err)
	}
	cancelled, stop := context.WithCancel(context.Background())
	stop()
	if _, err = signStageReceipt(cancelled, base, req, priv, opts, now); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation ignored: %v", err)
	}
	mutating := opts
	mutating.Progress = func(Event) error {
		if err := os.Remove(file); err != nil {
			return err
		}
		return os.WriteFile(file, data, 0o600)
	}
	if _, err = signStageReceipt(context.Background(), base, req, priv, mutating, now); err == nil {
		t.Fatal("replaced object signed")
	}
	mutating.Progress = func(Event) error {
		objects := filepath.Join(base, "direct/objects")
		if err := os.Rename(objects, objects+"-old"); err != nil {
			return err
		}
		if err := os.Mkdir(objects, 0o700); err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(objects, id+".blob"), data, 0o600)
	}
	if _, err = signStageReceipt(context.Background(), base, req, priv, mutating, now); err == nil {
		t.Fatal("replaced object directory signed")
	}
}
