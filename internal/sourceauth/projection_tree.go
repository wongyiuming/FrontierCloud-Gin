package sourceauth

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/migrationpaths"
	"strings"
	"unicode/utf8"
)

func SnapshotProjectionDigest(s Snapshot) (string, Report, error) {
	var empty Report
	count := len(s.Media) + len(s.Lyrics) + len(s.Directories) + len(s.Links) + len(s.Visibility) + len(s.Preferences) + len(s.RetiredNonces)
	if count > 25000 {
		return "", empty, invalid("snapshot projection limit")
	}
	_, report, err := ValidateSnapshotShape(s)
	if err != nil {
		return "", empty, err
	}
	if err = ValidateProjectionTree(s); err != nil {
		return "", empty, err
	}
	raw, err := json.Marshal(s)
	if err != nil || len(raw) > 16*1024*1024 {
		return "", empty, invalid("snapshot projection size")
	}
	h := sha256.New()
	_, _ = h.Write([]byte("frontiercloud:preprod-media-projection:v1\x00"))
	_, _ = h.Write(raw)
	return hex.EncodeToString(h.Sum(nil)), report, nil
}

// ValidateProjectionTree checks the complete reconciled projection in trusted
// Master memory. Source file/directory spelling remains exact: sealedtree does
// not normalize or case-fold names. Visibility-only references do not assert
// that their leaf is a directory, but cannot descend through a known file.
func ValidateProjectionTree(s Snapshot) error {
	var paths migrationpaths.MigrationPathPreflight
	defer paths.Close()
	files := map[string]bool{}
	for _, m := range s.Media {
		if err := paths.Add(m.Path, false); err != nil {
			return invalid("projection tree conflict")
		}
		files[m.Path] = true
	}
	for _, l := range s.Lyrics {
		if err := paths.Add(l.Path, false); err != nil {
			return invalid("projection tree conflict")
		}
		files[l.Path] = true
	}
	for _, d := range s.Directories {
		if err := paths.Add(d.Path, true); err != nil {
			return invalid("projection tree conflict")
		}
	}
	for _, v := range s.Visibility {
		parts := strings.Split(v.Path, "/")
		prefix := ""
		for i, part := range parts {
			if !sourceFactPath(part) || !utf8.ValidString(part) || strings.ContainsAny(part, "/\\\x00") {
				return invalid("projection visibility component")
			}
			if prefix != "" {
				prefix += "/"
			}
			prefix += part
			if i < len(parts)-1 && files[prefix] {
				return invalid("projection visibility parent")
			}
		}
	}
	if _, err := paths.Counts(); err != nil {
		return invalid("projection tree conflict")
	}
	return nil
}
