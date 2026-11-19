//go:build linux

package recovery

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/maintenance"
)

type treeStageItem struct {
	name     string
	kind     byte
	mode     int64
	uid, gid int
	content  string
}

func treeStageTar(t *testing.T, items []treeStageItem) []byte {
	t.Helper()
	var b bytes.Buffer
	w := tar.NewWriter(&b)
	for _, it := range items {
		h := &tar.Header{Name: it.name, Typeflag: it.kind, Mode: it.mode, Uid: it.uid, Gid: it.gid, Size: int64(len(it.content))}
		if err := w.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(w, it.content); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}
func TestTreeStagingPreservesOriginalMetadataUnderLease(t *testing.T) {
	base := t.TempDir()
	data, keys, stageDir, outDir := filepath.Join(base, "data"), filepath.Join(base, "keys"), filepath.Join(base, "stage"), filepath.Join(base, "out")
	for _, dir := range []string{data, keys, stageDir, outDir} {
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	db := filepath.Join(data, "db.sqlite")
	if err := os.WriteFile(db, []byte("sqlite-fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	for name, raw := range map[string][]byte{"tree-master.key": bytes.Repeat([]byte{1}, 32), "node-vault.key": []byte("vault")} {
		if err := os.WriteFile(filepath.Join(keys, name), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	gate, err := maintenance.Open(data)
	if err != nil {
		t.Fatal(err)
	}
	defer gate.Close()
	if err = gate.Enter(context.Background(), func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	stage, err := os.OpenRoot(stageDir)
	if err != nil {
		t.Fatal(err)
	}
	defer stage.Close()
	stream := treeStageTar(t, []treeStageItem{{"deployment", tar.TypeDir, 0750, 111, 222, ""}, {"deployment/.env", tar.TypeReg, 0640, 333, 444, "fixture"}, {"redis_data", tar.TypeDir, 0700, 999, 999, ""}, {"redis_data/dump.rdb", tar.TypeReg, 0600, 999, 999, "data"}})
	manifest := Manifest{NodeID: strings.Repeat("a", 32), Role: "Master", Revision: strings.Repeat("b", 40), Database: "sqlite", Consistency: "native-offline-and-deployment-writers-stopped", Missing: []string{}, KeyReferences: []string{"runtime_secrets/node-vault.key", "runtime_secrets/tree-master.key"}}
	began, ended := false, false
	begin := func(_ context.Context, check func() error) (func(Manifest) (json.RawMessage, error), func() error, error) {
		began = true
		return func(Manifest) (json.RawMessage, error) { return json.RawMessage(`{"fixture":true}`), check() }, func() error { ended = true; return check() }, nil
	}
	receive := func(ctx context.Context, check func() error) ([]Root, error) {
		if !began || check() != nil {
			t.Fatal("staging ran outside capture lease")
		}
		roots, e := ReceiveTreeBackupClasses(ctx, bytes.NewReader(stream), stage, []string{"deployment", "redis_data"}, 1<<20)
		if e != nil {
			return nil, e
		}
		return append([]Root{{Class: "data", Directory: data}, {Class: "runtime_secrets", Directory: keys}}, roots...), nil
	}
	output := filepath.Join(outDir, "full.tar")
	report, err := CreateTreeArchiveStaged(context.Background(), gate, data, db, output, manifest, receive, begin)
	if err != nil || !ended {
		t.Fatal("staged archive", err, ended)
	}
	var fileOK, dirOK bool
	for _, f := range report.Manifest.Files {
		if f.Path == "deployment/.env" {
			fileOK = f.UID == 333 && f.GID == 444 && f.Mode == 0640
		}
	}
	for _, d := range report.Manifest.Directories {
		if d.Path == "deployment" {
			dirOK = d.UID == 111 && d.GID == 222 && d.Mode == 0750
		}
	}
	if !fileOK || !dirOK {
		t.Fatal("source metadata lost")
	}
	info, err := os.Stat(filepath.Join(stageDir, "deployment", ".env"))
	if err != nil {
		t.Fatal(err)
	}
	st := info.Sys().(*syscall.Stat_t)
	if st.Uid != uint32(os.Geteuid()) || info.Mode().Perm() != 0600 {
		t.Fatal("stage permissions were changed to source metadata")
	}
	if _, err = CheckTreeArchive(context.Background(), output, report.SHA256); err != nil {
		t.Fatal(err)
	}
}
func TestTreeStagingRejectsLinksTraversalDuplicatesAndOverflow(t *testing.T) {
	cases := map[string][]treeStageItem{
		"link":             {{"deployment", tar.TypeDir, 0700, 1, 1, ""}, {"deployment/link", tar.TypeSymlink, 0600, 1, 1, ""}},
		"traversal":        {{"deployment", tar.TypeDir, 0700, 1, 1, ""}, {"deployment/../outside", tar.TypeReg, 0600, 1, 1, "x"}},
		"duplicate":        {{"deployment", tar.TypeDir, 0700, 1, 1, ""}, {"deployment/a", tar.TypeReg, 0600, 1, 1, "x"}, {"deployment/a", tar.TypeReg, 0600, 1, 1, "y"}},
		"missing-parent":   {{"deployment", tar.TypeDir, 0700, 1, 1, ""}, {"deployment/dir/a", tar.TypeReg, 0600, 1, 1, "x"}},
		"unselected-class": {{"deployment", tar.TypeDir, 0700, 1, 1, ""}, {"data", tar.TypeDir, 0700, 1, 1, ""}},
		"overflow":         {{"deployment", tar.TypeDir, 0700, 1, 1, ""}, {"deployment/a", tar.TypeReg, 0600, 1, 1, "123456"}},
	}
	for name, items := range cases {
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "stage")
			if err := os.Mkdir(dir, 0700); err != nil {
				t.Fatal(err)
			}
			root, err := os.OpenRoot(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			if _, err = ReceiveTreeBackupClasses(context.Background(), bytes.NewReader(treeStageTar(t, items)), root, []string{"deployment"}, 5); err == nil {
				t.Fatal("invalid input accepted")
			}
		})
	}
	t.Run("trailing-data", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "stage")
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
		root, err := os.OpenRoot(dir)
		if err != nil {
			t.Fatal(err)
		}
		defer root.Close()
		stream := treeStageTar(t, []treeStageItem{{"deployment", tar.TypeDir, 0700, 1, 1, ""}})
		stream = append(stream, []byte("nonzero")...)
		if _, err = ReceiveTreeBackupClasses(context.Background(), bytes.NewReader(stream), root, []string{"deployment"}, 5); err == nil {
			t.Fatal("trailing data accepted")
		}
	})
	t.Run("canceled", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "stage")
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
		root, err := os.OpenRoot(dir)
		if err != nil {
			t.Fatal(err)
		}
		defer root.Close()
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		stream := treeStageTar(t, []treeStageItem{{"deployment", tar.TypeDir, 0700, 1, 1, ""}})
		if _, err = ReceiveTreeBackupClasses(ctx, bytes.NewReader(stream), root, []string{"deployment"}, 5); err == nil {
			t.Fatal("canceled stream accepted")
		}
		entries, e := os.ReadDir(dir)
		if e != nil || len(entries) != 0 {
			t.Fatal("canceled stream modified staging", e)
		}
	})

}

type treeStageMutatingWriter struct {
	bytes.Buffer
	target  string
	changed bool
	err     error
}

func (w *treeStageMutatingWriter) Write(p []byte) (int, error) {
	n, e := w.Buffer.Write(p)
	if !w.changed && w.Len() > 128*1024 {
		w.changed = true
		before, x := os.Stat(w.target)
		if x == nil {
			w.err = os.WriteFile(w.target, []byte("late!"), 0600)
			if w.err == nil {
				w.err = os.Chtimes(w.target, before.ModTime(), before.ModTime())
			}
		} else {
			w.err = x
		}
	}
	return n, e
}
func TestCommittedTreeStageStreamFailsClosedOnAbortAndMutation(t *testing.T) {
	base := t.TempDir()
	src := filepath.Join(base, "deployment")
	if err := os.Mkdir(src, 0700); err != nil {
		t.Fatal(err)
	}
	first := filepath.Join(src, "a")
	if err := os.WriteFile(first, []byte("first"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "z"), make([]byte, 1024*1024), 0600); err != nil {
		t.Fatal(err)
	}
	nonce := strings.Repeat("ab", 32)
	sources := []Root{{Class: "deployment", Directory: src}}
	check := func() error { return nil }
	var good bytes.Buffer
	if err := WriteCommittedTreeBackupClasses(context.Background(), &good, sources, 2<<20, nonce, check); err != nil {
		t.Fatal(err)
	}
	receive := func(data []byte, actualNonce string) error {
		dir, err := os.MkdirTemp(base, "stage-")
		if err != nil {
			return err
		}
		root, err := os.OpenRoot(dir)
		if err != nil {
			return err
		}
		defer root.Close()
		_, err = ReceiveCommittedTreeBackupClasses(context.Background(), bytes.NewReader(data), root, []string{"deployment"}, 2<<20, actualNonce)
		return err
	}
	if err := receive(good.Bytes(), nonce); err != nil {
		t.Fatal("valid stream", err)
	}
	if err := receive(good.Bytes()[:len(good.Bytes())-1], nonce); err == nil {
		t.Fatal("truncated commit accepted")
	}
	if err := receive(good.Bytes(), strings.Repeat("cd", 32)); err == nil {
		t.Fatal("wrong nonce accepted")
	}
	tampered := append([]byte(nil), good.Bytes()...)
	tampered[len(tampered)-64] ^= 1
	if err := receive(tampered, nonce); err == nil {
		t.Fatal("wrong digest accepted")
	}
	trailing := append(append([]byte(nil), good.Bytes()...), 1)
	if err := receive(trailing, nonce); err == nil {
		t.Fatal("trailing data accepted")
	}
	changed := &treeStageMutatingWriter{target: first}
	if err := WriteCommittedTreeBackupClasses(context.Background(), changed, sources, 2<<20, nonce, check); err == nil || !changed.changed || changed.err != nil {
		t.Fatal("changed source committed", err, changed.err)
	}
	if got, err := os.ReadFile(first); err != nil || string(got) != "late!" {
		t.Fatal("source mutation not preserved", err)
	}
	if err := receive(changed.Bytes(), nonce); err == nil {
		t.Fatal("aborted source stream accepted")
	}
}
