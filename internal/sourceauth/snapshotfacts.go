package sourceauth

// These typed facts are sensitive Master-only input. Their presence or digest
// alone cannot establish a consistent, authenticated production snapshot.
import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"unicode/utf8"
)

type SourceObjectFact struct{ ID, Kind, Path, CreatedAt, UpdatedAt string }
type SourcePlacementFact struct {
	MediaID, ETag, State string
	CreatedAt, UpdatedAt int64
}
type SourceVisibilityFact struct {
	Path      string
	Hidden    int64
	UpdatedAt string
}
type SourcePlaybackFact struct {
	MediaID, Path        string
	Preference           int
	PlayScore            int64
	CreatedAt, UpdatedAt string
}
type SourceLyricLinkFact struct{ MediaID, MediaPath, LyricID, LyricPath, CreatedAt, UpdatedAt string }
type SourceEncryptionFact struct {
	Kind, ObjectID, FileID string
	CreatedAt              int64
}
type SourceCompleteFacts struct {
	DeclaredSections []string               `json:"declared_sections"`
	Objects          []SourceObjectFact     `json:"objects"`
	Placements       []SourcePlacementFact  `json:"placements"`
	Visibility       []SourceVisibilityFact `json:"visibility"`
	Playback         []SourcePlaybackFact   `json:"playback"`
	LyricLinks       []SourceLyricLinkFact  `json:"lyric_links"`
	Encryption       []SourceEncryptionFact `json:"encryption"`
}
type CompleteSnapshot struct {
	Projection Snapshot            `json:"projection"`
	Facts      SourceCompleteFacts `json:"facts"`
}

func sourceFactText(v string, max int) bool {
	return v != "" && len(v) <= max && utf8.ValidString(v) && !containsNUL(v)
}
func sourceFactPath(v string) bool {
	return v != "" && len(v) <= 4096 && utf8.ValidString(v) && utf8.RuneCountInString(v) <= 1024 && !containsNUL(v)
}
func containsNUL(v string) bool {
	for _, c := range v {
		if c == 0 {
			return true
		}
	}
	return false
}

// CompleteSnapshotDigest binds supplemental SQL facts, but is deliberately
// not a source reader or authorization. Rows/counts need a separately
// authenticated complete source transaction before a real import is allowed.
func CompleteSnapshotDigest(s CompleteSnapshot) (string, error) {
	if _, _, err := SnapshotProjectionDigest(s.Projection); err != nil {
		return "", err
	}
	f := s.Facts
	want := map[string]bool{"objects": false, "placements": false, "visibility": false, "playback": false, "lyric_links": false, "encryption": false}
	for _, section := range f.DeclaredSections {
		seen, ok := want[section]
		if !ok || seen {
			return "", invalid("source facts section")
		}
		want[section] = true
	}
	for _, seen := range want {
		if !seen {
			return "", invalid("source facts section absent")
		}
	}
	if len(f.Objects)+len(f.Placements)+len(f.Visibility)+len(f.Playback)+len(f.LyricLinks)+len(f.Encryption) > 25000 {
		return "", invalid("source facts limit")
	}
	objects := map[string]bool{}
	paths := map[string]bool{}
	knownObjects := map[string]SourceObjectFact{}
	for _, m := range s.Projection.Media {
		knownObjects[m.MediaID] = SourceObjectFact{Kind: m.Kind, Path: m.Path}
	}
	for _, l := range s.Projection.Lyrics {
		knownObjects[l.ID] = SourceObjectFact{Kind: "lyric", Path: l.Path}
	}
	for _, d := range s.Projection.Directories {
		knownObjects[d.ID] = SourceObjectFact{Kind: "directory", Path: d.Path}
	}
	for _, o := range f.Objects {
		validObjectPath := (o.Kind == "directory" && ValidVisibility(o.Path)) || (o.Kind != "directory" && ValidPath(o.Path, o.Kind))
		if !id64.MatchString(o.ID) || objects[o.ID] || paths[o.Path] || !sourceFactPath(o.Path) || !sourceFactText(o.CreatedAt, 128) || !sourceFactText(o.UpdatedAt, 128) || !validObjectPath {
			return "", invalid("source object fact")
		}
		if known, ok := knownObjects[o.ID]; ok && (known.Kind != o.Kind || known.Path != o.Path) {
			return "", invalid("source object conflict")
		}
		objects[o.ID] = true
		paths[o.Path] = true
	}
	media := map[string]bool{}
	for _, m := range s.Projection.Media {
		media[m.MediaID] = true
	}
	seenMedia := map[string]bool{}
	for _, p := range f.Placements {
		if !media[p.MediaID] || seenMedia[p.MediaID] || (p.State != "active" && p.State != "pending_delete" && p.State != "renaming") || len(p.ETag) > 512 || !utf8.ValidString(p.ETag) || containsNUL(p.ETag) || p.CreatedAt < 0 || p.UpdatedAt < 0 {
			return "", invalid("source placement fact")
		}
		seenMedia[p.MediaID] = true
	}
	if len(seenMedia) != len(media) {
		return "", invalid("source placement coverage")
	}
	visibility := map[string]bool{}
	for _, v := range s.Projection.Visibility {
		visibility[v.Path] = v.Hidden
	}
	seenPaths := map[string]bool{}
	for _, v := range f.Visibility {
		hidden, ok := visibility[v.Path]
		if !ok || (v.Hidden != 0 && v.Hidden != 1) || hidden != (v.Hidden == 1) || seenPaths[v.Path] || !sourceFactText(v.UpdatedAt, 128) {
			return "", invalid("source visibility fact")
		}
		seenPaths[v.Path] = true
	}
	if len(seenPaths) != len(visibility) {
		return "", invalid("source visibility coverage")
	}
	preferences := map[string]Preference{}
	for _, v := range s.Projection.Preferences {
		preferences[v.ID] = v
	}
	seenPrefs := map[string]bool{}
	for _, v := range f.Playback {
		p, ok := preferences[v.MediaID]
		if !ok || seenPrefs[v.MediaID] || p.Value != v.Preference || p.PlayScore != v.PlayScore || !sourceFactPath(v.Path) || !sourceFactText(v.CreatedAt, 128) || !sourceFactText(v.UpdatedAt, 128) {
			return "", invalid("source playback fact")
		}
		seenPrefs[v.MediaID] = true
	}
	if len(seenPrefs) != len(preferences) {
		return "", invalid("source playback coverage")
	}
	links := map[string]string{}
	for _, v := range s.Projection.Links {
		links[v.MediaID] = v.LyricID
	}
	seenLinks := map[string]bool{}
	for _, v := range f.LyricLinks {
		id, ok := links[v.MediaID]
		if !ok || id != v.LyricID || seenLinks[v.MediaID] || !sourceFactPath(v.MediaPath) || !sourceFactPath(v.LyricPath) || !sourceFactText(v.CreatedAt, 128) || !sourceFactText(v.UpdatedAt, 128) {
			return "", invalid("source lyric fact")
		}
		seenLinks[v.MediaID] = true
	}
	if len(seenLinks) != len(links) {
		return "", invalid("source lyric coverage")
	}
	encryption := map[string]string{}
	active := map[string]bool{}
	for _, m := range s.Projection.Media {
		if m.Encryption != nil {
			encryption[m.MediaID] = m.Encryption.FileID
			active[m.MediaID] = true
		}
	}
	for _, t := range s.Projection.RetiredNonces {
		encryption[t.ObjectID] = t.FileID
	}
	seenEncryption := map[string]bool{}
	for _, v := range f.Encryption {
		id, ok := encryption[v.ObjectID]
		if !ok || id != v.FileID || seenEncryption[v.ObjectID] || v.CreatedAt < 0 || (v.Kind != "media" && v.Kind != "recording_lyric") || (active[v.ObjectID] && v.Kind != "media") {
			return "", invalid("source encryption fact")
		}
		seenEncryption[v.ObjectID] = true
	}
	if len(seenEncryption) != len(encryption) {
		return "", invalid("source encryption coverage")
	}
	raw, err := json.Marshal(s)
	if err != nil || len(raw) > 16*1024*1024 {
		return "", invalid("source facts size")
	}
	h := sha256.New()
	_, _ = h.Write([]byte("frontiercloud:preprod-complete-snapshot:v2\x00"))
	_, _ = h.Write(raw)
	return hex.EncodeToString(h.Sum(nil)), nil
}

func SourceFactPath(v string) bool          { return sourceFactPath(v) }
func SourceFactText(v string, max int) bool { return sourceFactText(v, max) }
func ContainsNUL(v string) bool             { return containsNUL(v) }
