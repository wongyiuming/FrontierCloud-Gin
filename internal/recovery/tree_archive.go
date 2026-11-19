package recovery

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"path/filepath"
	"strings"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/maintenance"
)

// TreeManifestDigest binds all archive fields and file hashes while excluding
// the embedded evidence itself. The final archive SHA remains independently
// checked by the existing report and does not occur inside the archive.
func TreeManifestDigest(m Manifest) (string, error) {
	m.TreeEvidence = nil
	raw, err := json.Marshal(m)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:]), nil
}

// CreateTreeArchive requires a guarded source session held through sealing and
// byte-copy verification. Neither recovery nor service activation is implied.
func CreateTreeArchive(ctx context.Context, gate *maintenance.Gate, dataRoot, databasePath, output string, m Manifest, sources []Root, begin func(context.Context, func() error) (func(Manifest) (json.RawMessage, error), func() error, error)) (Report, error) {
	return CreateTreeArchiveStaged(ctx, gate, dataRoot, databasePath, output, m, func(context.Context, func() error) ([]Root, error) { return sources, nil }, begin)
}

// CreateTreeArchiveStaged runs receive only after the source's SQLite and tree
// capture has begun, under the same native maintenance lease. receive must
// stop on context cancellation and return only private verified staging roots.
// This internal building block does not authorize a caller or open a site.
func CreateTreeArchiveStaged(ctx context.Context, gate *maintenance.Gate, dataRoot, databasePath, output string, m Manifest, receive func(context.Context, func() error) ([]Root, error), begin func(context.Context, func() error) (func(Manifest) (json.RawMessage, error), func() error, error)) (out Report, err error) {
	if ctx == nil || gate == nil || receive == nil || begin == nil || m.Role != "Master" || m.Database != "sqlite" || m.Scope != "" && m.Scope != "deployment" && m.Scope != UpgradeStateScope {
		return out, ErrUnsafe
	}
	absolute, e := filepath.Abs(dataRoot)
	if e != nil {
		return out, ErrUnsafe
	}
	database, e := filepath.Abs(databasePath)
	if e != nil {
		return out, ErrUnsafe
	}
	relative, e := filepath.Rel(absolute, database)
	if e != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || filepath.IsAbs(relative) {
		return out, ErrUnsafe
	}
	err = gate.InspectSQLite(ctx, absolute, database, func(c context.Context, checkSQLite func() error) error {
		check := func() error {
			if held, err := gate.TreeRecoveryHeld(); err != nil || held {
				return ErrUnsafe
			}
			return checkSQLite()
		}
		if check() != nil {
			return ErrUnsafe
		}
		seal, end, e := begin(c, check)
		if e != nil || seal == nil || end == nil {
			return ErrUnsafe
		}
		defer func() { _ = end() }()
		sources, e := receive(c, check)
		if e != nil {
			return e
		}
		if check() != nil {
			return ErrUnsafe
		}
		seenData := false
		for _, source := range sources {
			if source.Class == "data" {
				p, e := filepath.Abs(source.Directory)
				if e != nil || filepath.Clean(p) != filepath.Clean(absolute) || (m.Scope == UpgradeStateScope) != (source.IncludePaths != nil) {
					return ErrUnsafe
				}
				seenData = true
			}
		}
		if !seenData {
			return ErrUnsafe
		}
		report, e := createArchive(c, output, m, sources, true, seal)
		if e != nil {
			return e
		}
		required := "data/" + filepath.ToSlash(relative)
		found := false
		for _, entry := range report.Manifest.Files {
			if entry.Path == required {
				found = true
			}
		}
		if !found || !report.Verified || check() != nil {
			return ErrUnsafe
		}
		finish := end
		end = func() error { return nil }
		if e = finish(); e != nil {
			return e
		}
		if check() != nil {
			return ErrUnsafe
		}
		out = report
		return nil
	})
	if err != nil {
		return Report{}, err
	}
	return out, nil
}

// CheckTreeArchive requires an independently recorded exact checksum. It only
// validates archive bytes; tree/Owner recovery and activation remain separate.
func CheckTreeArchive(ctx context.Context, input, expected string) (Report, error) {
	if !hashPattern.MatchString(expected) {
		return Report{}, ErrUnsafe
	}
	return checkArchive(ctx, input, expected, true)
}

// ApplyTreeArchive extracts privately and keeps the original node identity and
// maintenance markers. It does not rebind tree fences or activate the service.
// Rebinding requires separately verified fence recovery evidence.
func ApplyTreeArchive(ctx context.Context, input, target, expected, confirmation string) (Report, error) {
	return extractMaterialVersion(ctx, input, target, expected, confirmation, "", false, true)
}

// ApplyTreeStateArchive extracts only an authenticated state-only archive to a
// new private target. It does not replace existing data, rebind fences, prove
// business files or authorize an upgrade or service restart.
func ApplyTreeStateArchive(ctx context.Context, input, target, expected, confirmation string) (Report, error) {
	if _, err := CheckTreeArchiveAuthenticated(ctx, input, expected); err != nil {
		return Report{}, err
	}
	return extractMaterialVersion(ctx, input, target, expected, confirmation, "", true, true)
}

// CheckTreeArchiveAuthenticated verifies the entire archive and its independently
// supplied checksum before using the bounded, private tree key to authenticate
// the embedded recovery evidence. It does not open SQLite or authorize restore.
func CheckTreeArchiveAuthenticated(ctx context.Context, input, expected string) (Report, error) {
	if !hashPattern.MatchString(expected) {
		return Report{}, ErrUnsafe
	}
	f, e := openArchive(input)
	if e != nil {
		return Report{}, e
	}
	defer f.Close()
	var key []byte
	defer func() { clear(key) }()
	report, e := walkArchiveVersion(ctx, f, func(entry Entry, r io.Reader) error {
		if entry.Path == unsupportedTreeRootReference {
			var err error
			key, err = io.ReadAll(io.LimitReader(r, 33))
			if err != nil || len(key) != 32 {
				return ErrUnsafe
			}
			return nil
		}
		_, err := io.Copy(io.Discard, r)
		return err
	}, true)
	if e != nil || report.SHA256 != expected || len(key) != 32 {
		return Report{}, ErrUnsafe
	}
	var ev struct {
		Version                                                  int `json:"version"`
		ManifestSHA, NodeID, RootVerifier, MasterBinding, OldTag string
		Device, Inode                                            uint64
		Generation                                               int64
		MAC, RecoveryMAC                                         string
	}
	dec := json.NewDecoder(bytes.NewReader(report.Manifest.TreeEvidence))
	dec.DisallowUnknownFields()
	digest, err := TreeManifestDigest(report.Manifest)
	if err != nil || dec.Decode(&ev) != nil || dec.Decode(new(any)) != io.EOF || ev.Version != 1 || ev.ManifestSHA != digest || ev.NodeID != report.Manifest.NodeID || ev.Inode == 0 || ev.Generation < 0 || !hashPattern.MatchString(ev.MAC) || !hashPattern.MatchString(ev.RecoveryMAC) {
		return Report{}, ErrUnsafe
	}
	outer := ev.RecoveryMAC
	ev.RecoveryMAC = ""
	raw, err := json.Marshal(ev)
	if err != nil {
		return Report{}, ErrUnsafe
	}
	defer clear(raw)
	h := hmac.New(sha256.New, key)
	h.Write([]byte("frontiercloud:tree-fence-recovery-outer:v1\x00"))
	h.Write(raw)
	if !hmac.Equal([]byte(outer), []byte(hex.EncodeToString(h.Sum(nil)))) {
		return Report{}, ErrUnsafe
	}
	return report, nil
}
