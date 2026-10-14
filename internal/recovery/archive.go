// Package recovery implements bounded, uncompressed offline recovery archives.
// Callers must hold the native offline lease and stop every deployment writer
// for the entire capture. This is per-deployment recovery, never a live replica.
package recovery

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/fsutil"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/release"
	"github.com/wongyiuming/FrontierCloud-Gin/migrations"
)

const Format = "frontiercloud-deployment-recovery"
const MaxManifest = 16 << 20
const MaxFiles = 100000
const UpgradeStateScope = "upgrade-state"
const ExcludedBusinessFiles = "media, lyric and recording files are excluded; original business file mounts must be retained"
const legacyExcludedBusinessFiles = "media and lyric files are excluded; original business file mounts must be retained"

var hashPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
var nodePattern = regexp.MustCompile(`^[a-f0-9]{32}$`)
var ErrUnsafe = errors.New("unsafe, incomplete or incompatible recovery archive")

type Entry struct {
	Path   string `json:"path"`
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
	Mode   int64  `json:"mode"`
	UID    int    `json:"uid"`
	GID    int    `json:"gid"`
}
type Directory struct {
	Path string `json:"path"`
	Mode int64  `json:"mode"`
	UID  int    `json:"uid"`
	GID  int    `json:"gid"`
}
type Manifest struct {
	Format               string      `json:"format"`
	Version              int         `json:"version"`
	Scope                string      `json:"scope"`
	NodeID               string      `json:"node_id"`
	Role                 string      `json:"role"`
	Revision             string      `json:"revision"`
	Database             string      `json:"database"`
	MySQLRestoreBytes    uint64      `json:"mysql_restore_storage_budget_bytes,omitempty"`
	SchemaGeneration     int         `json:"schema_generation"`
	ConfigurationVersion int         `json:"configuration_version"`
	CreatedAt            string      `json:"created_at"`
	Consistency          string      `json:"consistency"`
	CompleteCluster      bool        `json:"complete_cluster"`
	Missing              []string    `json:"missing_items"`
	KeyReferences        []string    `json:"key_references"`
	Classes              []string    `json:"state_classes"`
	Bytes                int64       `json:"bytes"`
	Files                []Entry     `json:"files"`
	Directories          []Directory `json:"directories"`
	RecoverySet          string      `json:"recovery_set,omitempty"`
	Relations            []Relation  `json:"relations,omitempty"`
}
type Report struct {
	Manifest         Manifest `json:"manifest"`
	SHA256           string   `json:"sha256"`
	Verified         bool     `json:"integrity_verified"`
	RestoreReady     bool     `json:"restore_ready"`
	BusinessVerified bool     `json:"restored_business_verified"`
	CleanupWarning   string   `json:"cleanup_warning,omitempty"`
	RetainedScratch  string   `json:"retained_scratch,omitempty"`
}
type Root struct {
	Class        string
	Directory    string
	IncludePaths []string
}

// SelectedPath prunes unselected subtrees without reading or copying their files.
// A nil selection retains the explicit complete-recovery behavior.
func SelectedPath(paths []string, name string, directory bool) bool {
	if paths == nil || name == "." {
		return true
	}
	for _, selected := range paths {
		if name == selected || directory && strings.HasPrefix(selected, name+"/") {
			return true
		}
	}
	return false
}

func validClass(v string) bool {
	switch v {
	case "data", "runtime_secrets", "certificate_state", "certificate_published", "redis_data", "mysql_dump", "deployment":
		return true
	}
	return false
}
func validPath(v string) bool {
	return len(v) <= 4096 && fs.ValidPath(v) && path.Clean(v) == v && !strings.ContainsAny(v, "\\\x00\r\n") && strings.Contains(v, "/") && validClass(strings.SplitN(v, "/", 2)[0])
}

type contextReader struct {
	ctx context.Context
	r   io.Reader
}

func (r contextReader) Read(p []byte) (int, error) {
	if e := r.ctx.Err(); e != nil {
		return 0, e
	}
	return r.r.Read(p)
}
func hashFile(ctx context.Context, r *os.Root, name string) (Entry, error) {
	var entry Entry
	info, e := r.Lstat(name)
	if e != nil || !info.Mode().IsRegular() {
		return entry, ErrUnsafe
	}
	f, e := r.Open(name)
	if e != nil {
		return entry, e
	}
	defer f.Close()
	opened, e := f.Stat()
	if e != nil || !os.SameFile(info, opened) {
		return entry, ErrUnsafe
	}
	h := sha256.New()
	size, e := io.CopyBuffer(h, contextReader{ctx, f}, make([]byte, 64<<10))
	if e != nil || size != info.Size() {
		return entry, ErrUnsafe
	}
	end, e := f.Stat()
	if e != nil || end.Size() != info.Size() || !end.ModTime().Equal(info.ModTime()) {
		return entry, ErrUnsafe
	}
	header, e := tar.FileInfoHeader(info, "")
	if e != nil {
		return entry, e
	}
	return Entry{Path: name, Bytes: size, SHA256: hex.EncodeToString(h.Sum(nil)), Mode: header.Mode & 0777, UID: header.Uid, GID: header.Gid}, nil
}

// Create is write-only to a new private archive, not a writer-freeze primitive.
// SQLite data includes its WAL/SHM under the held native offline boundary.
// MySQL roots must include a consistent logical dump, never its data directory.
func Create(ctx context.Context, output string, m Manifest, sources []Root) (Report, error) {
	var report Report
	if !nodePattern.MatchString(m.NodeID) || !release.ValidSHA(m.Revision) || m.Database != "sqlite" && m.Database != "mysql" || m.Role != "Standalone" && m.Role != "Master" && m.Role != "Follower" || m.Consistency != "native-offline-and-deployment-writers-stopped" {
		return report, ErrUnsafe
	}
	m.Format = Format
	m.Version = 1
	if m.Scope == "" {
		m.Scope = "deployment"
	}
	if m.Scope == UpgradeStateScope {
		m.CompleteCluster = false
		m.Missing = append(m.Missing, ExcludedBusinessFiles)
	}
	if m.SchemaGeneration == 0 {
		m.SchemaGeneration = migrations.Generation
	}
	m.ConfigurationVersion = 1
	m.CreatedAt = time.Now().UTC().Format(time.RFC3339)
	m.Files = []Entry{}
	m.Classes = []string{}
	m.Bytes = 0
	roots := map[string]*os.Root{}
	defer func() {
		for _, r := range roots {
			r.Close()
		}
	}()
	for _, source := range sources {
		if m.Scope == UpgradeStateScope && source.Class == "data" && source.IncludePaths == nil {
			return report, ErrUnsafe
		}
		if !validClass(source.Class) || roots[source.Class] != nil {
			return report, ErrUnsafe
		}
		info, e := os.Lstat(source.Directory)
		if e != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return report, ErrUnsafe
		}
		rel, e := filepath.Rel(source.Directory, output)
		if e != nil || rel == "." || rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return report, errors.New("backup output must be outside every captured state root")
		}
		r, e := os.OpenRoot(source.Directory)
		if e != nil {
			return report, e
		}
		roots[source.Class] = r
		m.Classes = append(m.Classes, source.Class)
		e = fs.WalkDir(r.FS(), ".", func(name string, item fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if e := ctx.Err(); e != nil {
				return e
			}
			if !SelectedPath(source.IncludePaths, name, item.IsDir()) {
				if item.IsDir() {
					return fs.SkipDir
				}
				return nil
			}
			if item.Type()&os.ModeSymlink != 0 {
				return ErrUnsafe
			}
			if item.IsDir() {
				info, e := item.Info()
				if e != nil {
					return e
				}
				header, e := tar.FileInfoHeader(info, "")
				if e != nil {
					return e
				}
				directory := source.Class
				if name != "." {
					directory += "/" + name
				}
				m.Directories = append(m.Directories, Directory{directory, header.Mode & 0777, header.Uid, header.Gid})
				if len(m.Directories) > MaxFiles {
					return ErrUnsafe
				}
				return nil
			}
			if len(m.Files) >= MaxFiles {
				return ErrUnsafe
			}
			entry, e := hashFile(ctx, r, name)
			if e != nil {
				return e
			}
			entry.Path = source.Class + "/" + name
			if !validPath(entry.Path) || entry.Bytes > 10*1024*1024*1024*1024 || m.Bytes > 10*1024*1024*1024*1024-entry.Bytes {
				return ErrUnsafe
			}
			m.Bytes += entry.Bytes
			m.Files = append(m.Files, entry)
			return nil
		})
		if e != nil {
			return report, e
		}
	}
	if roots["data"] == nil || roots["runtime_secrets"] == nil || m.Database == "mysql" && roots["mysql_dump"] == nil {
		return report, ErrUnsafe
	}
	sort.Strings(m.Classes)
	sort.Slice(m.Files, func(i, j int) bool { return m.Files[i].Path < m.Files[j].Path })
	sort.Slice(m.Directories, func(i, j int) bool { return m.Directories[i].Path < m.Directories[j].Path })
	if validateManifest(m) != nil {
		return report, ErrUnsafe
	}
	raw, e := json.Marshal(m)
	if e != nil || len(raw) > MaxManifest {
		return report, ErrUnsafe
	}
	f, e := os.CreateTemp(filepath.Dir(output), filepath.Base(output)+".next-")
	if e != nil {
		return report, e
	}
	temporary := f.Name()
	defer func() {
		f.Close()
		os.Remove(temporary)
	}()
	archiveHash := sha256.New()
	writer := tar.NewWriter(io.MultiWriter(f, archiveHash))
	if e = writer.WriteHeader(&tar.Header{Name: "manifest.json", Mode: 0600, Size: int64(len(raw)), Typeflag: tar.TypeReg}); e != nil {
		return report, e
	}
	if _, e = writer.Write(raw); e != nil {
		return report, e
	}
	for _, entry := range m.Files {
		if e = writer.WriteHeader(&tar.Header{Name: entry.Path, Mode: entry.Mode, Size: entry.Bytes, Uid: entry.UID, Gid: entry.GID, Typeflag: tar.TypeReg}); e != nil {
			return report, e
		}
		parts := strings.SplitN(entry.Path, "/", 2)
		source, e := roots[parts[0]].Open(parts[1])
		if e != nil {
			return report, e
		}
		h := sha256.New()
		size, copyErr := io.CopyBuffer(io.MultiWriter(writer, h), contextReader{ctx, io.LimitReader(source, entry.Bytes+1)}, make([]byte, 64<<10))
		source.Close()
		if copyErr != nil || size != entry.Bytes || hex.EncodeToString(h.Sum(nil)) != entry.SHA256 {
			return report, ErrUnsafe
		}
	}
	if e = writer.Close(); e != nil {
		return report, e
	}
	if e = f.Sync(); e != nil {
		return report, e
	}
	if e = f.Close(); e != nil {
		return report, e
	}
	if e = os.Link(temporary, output); e != nil {
		return report, e
	}
	parent, e := os.OpenRoot(filepath.Dir(output))
	if e != nil {
		return report, e
	}
	e = fsutil.SyncDirectory(parent, ".")
	parent.Close()
	if e != nil {
		return report, e
	}
	return Report{Manifest: m, SHA256: hex.EncodeToString(archiveHash.Sum(nil)), Verified: true}, nil
}

func validateManifest(m Manifest) error {
	if m.Format != Format || m.Version != 1 || m.Scope != "deployment" && m.Scope != UpgradeStateScope || !nodePattern.MatchString(m.NodeID) || !release.ValidSHA(m.Revision) || !SupportedSchemaGeneration(m.SchemaGeneration) || m.ConfigurationVersion != 1 || m.Database != "sqlite" && m.Database != "mysql" || m.Role != "Standalone" && m.Role != "Master" && m.Role != "Follower" || len(m.Files) > MaxFiles || m.Bytes < 0 || m.Consistency != "native-offline-and-deployment-writers-stopped" || m.CompleteCluster && len(m.Missing) != 0 {
		return ErrUnsafe
	}
	if m.Scope == UpgradeStateScope {
		found := false
		for _, item := range m.Missing {
			if item == ExcludedBusinessFiles || item == legacyExcludedBusinessFiles {
				found = true
			}
		}
		if !found || m.CompleteCluster || m.RecoverySet != "" {
			return ErrUnsafe
		}
	}
	if m.RecoverySet != "" && !nodePattern.MatchString(m.RecoverySet) || len(m.Relations) > MaxSetMembers {
		return ErrUnsafe
	}
	for _, relation := range m.Relations {
		if !nodePattern.MatchString(relation.NodeID) || relation.NodeID == m.NodeID || relation.Protocol != 2 || relation.State != "active" || relation.Direction != "upstream" && relation.Direction != "downstream" {
			return ErrUnsafe
		}
	}
	seen := map[string]bool{}
	var total int64
	for _, entry := range m.Files {
		if !validPath(entry.Path) || seen[entry.Path] || entry.Bytes < 0 || entry.Bytes > 10*1024*1024*1024*1024 || total > 10*1024*1024*1024*1024-entry.Bytes || !hashPattern.MatchString(entry.SHA256) || entry.Mode < 0 || entry.Mode > 0777 || entry.UID < 0 || entry.GID < 0 {
			return ErrUnsafe
		}
		seen[entry.Path] = true
		total += entry.Bytes
	}
	if total != m.Bytes || len(m.Directories) > MaxFiles {
		return ErrUnsafe
	}
	dirs := map[string]bool{}
	for _, directory := range m.Directories {
		if !(validClass(directory.Path) || validPath(directory.Path)) || dirs[directory.Path] || seen[directory.Path] || directory.Mode < 0 || directory.Mode > 0777 || directory.UID < 0 || directory.GID < 0 {
			return ErrUnsafe
		}
		dirs[directory.Path] = true
	}
	classes := map[string]bool{}
	for _, class := range m.Classes {
		if !validClass(class) || classes[class] || !dirs[class] {
			return ErrUnsafe
		}
		classes[class] = true
	}
	if !classes["data"] || !classes["runtime_secrets"] || m.Database == "mysql" && !classes["mysql_dump"] {
		return ErrUnsafe
	}
	for _, directory := range m.Directories {
		if !classes[strings.SplitN(directory.Path, "/", 2)[0]] || !validClass(directory.Path) && !dirs[path.Dir(directory.Path)] {
			return ErrUnsafe
		}
	}
	for _, entry := range m.Files {
		if !dirs[path.Dir(entry.Path)] || !classes[strings.SplitN(entry.Path, "/", 2)[0]] {
			return ErrUnsafe
		}
	}
	for _, ref := range m.KeyReferences {
		if !seen[ref] {
			return ErrUnsafe
		}
	}
	return nil
}

// walkArchive verifies actual bytes, not source declarations or file lengths.
// consume is called only for known regular files, never links or special nodes.
func walkArchive(ctx context.Context, file *os.File, consume func(Entry, io.Reader) error) (Report, error) {
	var report Report
	h := sha256.New()
	reader := tar.NewReader(io.TeeReader(contextReader{ctx, file}, h))
	header, e := reader.Next()
	if e != nil || header.Name != "manifest.json" || header.Typeflag != tar.TypeReg || header.Size < 1 || header.Size > MaxManifest {
		return report, ErrUnsafe
	}
	raw, e := io.ReadAll(io.LimitReader(reader, MaxManifest+1))
	if e != nil {
		return report, e
	}
	if _, e = protocol.ParseStrictJSON(raw, MaxManifest); e != nil {
		return report, ErrUnsafe
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&report.Manifest) != nil || validateManifest(report.Manifest) != nil {
		return report, ErrUnsafe
	}
	for _, entry := range report.Manifest.Files {
		header, e = reader.Next()
		if e != nil || header.Typeflag != tar.TypeReg || header.Name != entry.Path || header.Size != entry.Bytes || header.Mode != entry.Mode || header.Uid != entry.UID || header.Gid != entry.GID {
			return report, ErrUnsafe
		}
		digest := sha256.New()
		content := io.TeeReader(reader, digest)
		if consume == nil {
			_, e = io.CopyBuffer(io.Discard, content, make([]byte, 64<<10))
		} else {
			e = consume(entry, content)
		}
		if e != nil || hex.EncodeToString(digest.Sum(nil)) != entry.SHA256 {
			return report, ErrUnsafe
		}
	}
	if _, e = reader.Next(); e != io.EOF {
		return report, ErrUnsafe
	}
	// Only zero padding is permitted after the terminator; appended hidden
	// archives or arbitrary payloads cannot be silently omitted by tar.Reader.
	remaining, e := io.ReadAll(io.LimitReader(io.TeeReader(file, h), 10241))
	if e != nil || len(remaining) > 10240 {
		return report, ErrUnsafe
	}
	for _, b := range remaining {
		if b != 0 {
			return report, ErrUnsafe
		}
	}
	report.SHA256 = hex.EncodeToString(h.Sum(nil))
	report.Verified = true
	return report, nil
}
func openArchive(name string) (*os.File, error) {
	info, e := os.Lstat(name)
	if e != nil || !info.Mode().IsRegular() {
		return nil, ErrUnsafe
	}
	f, e := os.Open(name)
	if e != nil {
		return nil, e
	}
	opened, e := f.Stat()
	if e != nil || !os.SameFile(info, opened) {
		f.Close()
		return nil, ErrUnsafe
	}
	return f, nil
}
func Check(ctx context.Context, input, expected string) (Report, error) {
	f, e := openArchive(input)
	if e != nil {
		return Report{}, e
	}
	defer f.Close()
	report, e := walkArchive(ctx, f, nil)
	if e != nil {
		return report, e
	}
	if expected != "" && (!hashPattern.MatchString(expected) || report.SHA256 != expected) {
		return report, ErrUnsafe
	}
	return report, nil
}

// Apply publishes only into an absent target, retaining original identities and
// every offline flag. It never starts a service, initializes a database or
// asserts business validation. Partial extraction remains private on failure.
func Apply(ctx context.Context, input, target, expected, confirmation string) (Report, error) {
	return applySetMember(ctx, input, target, expected, confirmation, "")
}

// ExtractState publishes private state material only. It grants no fresh-node
// restoration authority; the caller must retain and fence the original mounts.
func ExtractState(ctx context.Context, input, target, expected, confirmation string) (Report, error) {
	return extractMaterial(ctx, input, target, expected, confirmation, "", true)
}

// ReadStateFile returns bounded verified metadata without extracting an archive.
func ReadStateFile(ctx context.Context, input, expected, name string) ([]byte, error) {
	f, e := openArchive(input)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	var raw []byte
	r, e := walkArchive(ctx, f, func(entry Entry, content io.Reader) error {
		if entry.Path == name {
			if entry.Bytes > 1<<20 {
				return ErrUnsafe
			}
			var err error
			raw, err = io.ReadAll(io.LimitReader(content, (1<<20)+1))
			return err
		}
		_, err := io.Copy(io.Discard, content)
		return err
	})
	if e != nil || r.SHA256 != expected || r.Manifest.Scope != UpgradeStateScope || raw == nil {
		return nil, ErrUnsafe
	}
	return raw, nil
}

// The nonempty set permission is available only after CheckSet verified every
// member and mutual relationship. Public single-archive Apply cannot grant it.
func applySetMember(ctx context.Context, input, target, expected, confirmation, set string) (Report, error) {
	return extractMaterial(ctx, input, target, expected, confirmation, set, false)
}
func extractMaterial(ctx context.Context, input, target, expected, confirmation, set string, stateOnly bool) (Report, error) {
	var report Report
	if !hashPattern.MatchString(expected) || !nodePattern.MatchString(confirmation) {
		return report, ErrUnsafe
	}
	if _, e := os.Lstat(target); !errors.Is(e, os.ErrNotExist) {
		return report, errors.New("restore target must not exist; nonempty or unknown target is never overwritten")
	}
	checked, e := Check(ctx, input, expected)
	if e != nil {
		return checked, e
	}
	if checked.Manifest.NodeID != confirmation || stateOnly && checked.Manifest.Scope != UpgradeStateScope || !stateOnly && len(checked.Manifest.Missing) != 0 && (set == "" || checked.Manifest.RecoverySet != set) {
		return checked, ErrUnsafe
	}
	stage, e := os.MkdirTemp(filepath.Dir(target), ".fc-restore-")
	if e != nil {
		return checked, e
	}
	root, e := os.OpenRoot(stage)
	if e != nil {
		return checked, e
	}
	defer root.Close()
	for _, directory := range checked.Manifest.Directories {
		if e = root.MkdirAll(directory.Path, 0700); e != nil {
			return checked, e
		}
	}
	f, e := openArchive(input)
	if e != nil {
		return checked, e
	}
	defer f.Close()
	report, e = walkArchive(ctx, f, func(entry Entry, content io.Reader) error {
		if e := root.MkdirAll(path.Dir(entry.Path), 0700); e != nil {
			return e
		}
		out, e := root.OpenFile(entry.Path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if e != nil {
			return e
		}
		size, e := io.CopyBuffer(out, contextReader{ctx, content}, make([]byte, 64<<10))
		if e == nil && size != entry.Bytes {
			e = ErrUnsafe
		}
		if e == nil {
			e = out.Chown(entry.UID, entry.GID)
		}
		if e == nil {
			e = out.Chmod(os.FileMode(entry.Mode))
		}
		if e == nil {
			e = out.Sync()
		}
		e = errors.Join(e, out.Close())
		return e
	})
	if e != nil || report.SHA256 != expected {
		return report, ErrUnsafe
	}
	for i := len(report.Manifest.Directories) - 1; i >= 0; i-- {
		directory := report.Manifest.Directories[i]
		if e = root.Chown(directory.Path, directory.UID, directory.GID); e != nil {
			return report, e
		}
		if e = root.Chmod(directory.Path, os.FileMode(directory.Mode)); e != nil {
			return report, e
		}
	}
	// Persist all directory entries before publishing the restored generation.
	e = fs.WalkDir(root.FS(), ".", func(name string, item fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if item.IsDir() {
			return fsutil.SyncDirectory(root, name)
		}
		return nil
	})
	if e != nil {
		return report, e
	}
	if _, e = os.Lstat(target); !errors.Is(e, os.ErrNotExist) {
		return report, ErrUnsafe
	}
	if e = root.Close(); e != nil {
		return report, e
	}
	if e = os.Rename(stage, target); e != nil {
		return report, e
	}
	parent, e := os.OpenRoot(filepath.Dir(target))
	if e != nil {
		return report, e
	}
	e = fsutil.SyncDirectory(parent, ".")
	parent.Close()
	if e != nil {
		return report, e
	}
	return report, nil
}
