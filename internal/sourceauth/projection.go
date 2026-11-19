package sourceauth

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"regexp"
	"strings"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
)

var ErrProjectionInvalid = errors.New("invalid isolated media projection")

// DefaultLyricContent is the existing built-in plaintext fallback, not a
// user-managed lyric. Importers must verify the original bytes exactly.
const DefaultLyricContent = "[00:00.00]建设中，暂无歌词\n"

var id32 = regexp.MustCompile(`^[a-f0-9]{32}$`)
var id64 = regexp.MustCompile(`^[a-f0-9]{64}$`)

type Mapping struct {
	SourceID string `json:"source_id"`
	TargetID string `json:"target_id"`
	Role     string `json:"role"`
	Capacity int64  `json:"capacity"`
}
type Media struct {
	MediaID    string                `json:"media_id"`
	ObjectID   string                `json:"object_id"`
	SourceID   string                `json:"source_id"`
	Path       string                `json:"path"`
	Kind       string                `json:"kind"`
	Size       int64                 `json:"size"`
	SHA256     string                `json:"sha256"`
	Encryption *mediacrypto.Metadata `json:"encryption,omitempty"`
}
type Lyric struct {
	ID         string                `json:"id"`
	Path       string                `json:"path"`
	Size       int64                 `json:"size"`
	SHA256     string                `json:"sha256"`
	Builtin    bool                  `json:"builtin"`
	Encryption *mediacrypto.Metadata `json:"encryption,omitempty"`
}
type Link struct {
	MediaID string `json:"media_id"`
	LyricID string `json:"lyric_id"`
}
type Directory struct {
	ID   string `json:"id"`
	Path string `json:"path"`
}
type Visibility struct {
	Path   string `json:"path"`
	Hidden bool   `json:"hidden"`
}
type Preference struct {
	ID        string `json:"id"`
	Value     int    `json:"value"`
	PlayScore int64  `json:"play_score"`
}
type NonceTombstone struct {
	ObjectID string `json:"object_id"`
	FileID   string `json:"file_id"`
}
type Snapshot struct {
	Version                int              `json:"version"`
	SourceProjectionSHA256 string           `json:"source_projection_sha256"`
	DeclaredSections       []string         `json:"declared_sections"`
	PremasterKeyID         string           `json:"premaster_key_id"`
	Mappings               []Mapping        `json:"mappings"`
	ExcludedSourceIDs      []string         `json:"excluded_source_ids"`
	Media                  []Media          `json:"media"`
	Lyrics                 []Lyric          `json:"lyrics"`
	Directories            []Directory      `json:"directories"`
	Links                  []Link           `json:"links"`
	Visibility             []Visibility     `json:"visibility"`
	Preferences            []Preference     `json:"preferences"`
	RetiredNonces          []NonceTombstone `json:"retired_nonces"`
}
type Report struct {
	ProjectionSHA256    string           `json:"projection_sha256"`
	ScratchDirectory    string           `json:"scratch_directory,omitempty"`
	MediaCount          int              `json:"media_count"`
	LyricCount          int              `json:"lyric_count"`
	LinkCount           int              `json:"link_count"`
	BytesByRole         map[string]int64 `json:"bytes_by_role"`
	SourceAuthenticated bool             `json:"source_authenticated"`
	SnapshotConsistent  bool             `json:"snapshot_consistent"`
	RuntimeReady        bool             `json:"runtime_ready"`
}

func invalid(detail string) error { return fmt.Errorf("%w: %s", ErrProjectionInvalid, detail) }
func ValidPath(name, kind string) bool {
	if !sourceFactPath(name) || strings.ContainsAny(name, "\\\x00") || path.Clean(name) != name || strings.HasPrefix(name, "/") {
		return false
	}
	parts := strings.Split(name, "/")
	for _, p := range parts {
		if p == "" || p == "." || p == ".." || strings.HasPrefix(p, ".") || strings.Contains(p, ":") {
			return false
		}
	}
	if len(parts) < 2 {
		return false
	}
	switch kind {
	case "audio":
		ext := strings.ToLower(path.Ext(name))
		return parts[0] == "music" && len(parts) >= 3 && len(parts) <= 4 && (ext == ".mp3" || ext == ".m4a" || ext == ".flac" || ext == ".wav")
	case "video":
		ext := strings.ToLower(path.Ext(name))
		return parts[0] == "vido" && len(parts) >= 3 && len(parts) <= 4 && (ext == ".mp4" || ext == ".webm" || ext == ".mkv")
	case "lyric":
		return parts[0] == "lyrics" && len(parts) <= 4 && strings.HasSuffix(strings.ToLower(name), ".lrc")
	}
	return false
}

// Hidden paths remain meaningful even when their current directory is empty:
// a later same-name object must not become visible merely because import
// discarded an apparently orphaned security rule.
func ValidVisibility(name string) bool {
	if !sourceFactPath(name) || strings.ContainsAny(name, "\\\x00") || path.Clean(name) != name || strings.HasPrefix(name, "/") {
		return false
	}
	parts := strings.Split(name, "/")
	if len(parts) > 4 || !(parts[0] == "music" || parts[0] == "vido" || parts[0] == "lyrics") || name == "lyrics/default.lrc" {
		return false
	}
	for _, p := range parts {
		if p == "" || p == "." || p == ".." || strings.HasPrefix(p, ".") || strings.Contains(p, ":") {
			return false
		}
	}
	return true
}

// Validate checks only declared facts. The caller's source-projection digest is
// an opaque binding, not proof of provenance or cross-host consistency.
// Validate is the legacy synthetic source-side check. The premaster must never
// be transmitted to an isolated target merely to Validate a snapshot shape.
func Validate(s Snapshot, premaster []byte) (map[string]Mapping, Report, error) {
	return ValidateWithKeyID(s, func(id string) bool {
		manager, err := mediacrypto.New(premaster)
		return err == nil && id64.MatchString(id) && manager.KeyID() == id
	})
}

// ValidateSnapshotShape checks only structural consistency. It is not source
// authentication, a key proof, an immutable source snapshot, or permission to
// import; callers must independently authenticate the signed complete plan.
func ValidateSnapshotShape(s Snapshot) (map[string]Mapping, Report, error) {
	return ValidateWithKeyID(s, func(id string) bool { return id64.MatchString(id) })
}

func ValidateWithKeyID(s Snapshot, verifyKeyID func(string) bool) (map[string]Mapping, Report, error) {
	report := Report{BytesByRole: map[string]int64{}}
	if s.Version != 1 || !id64.MatchString(s.SourceProjectionSHA256) || len(s.Mappings) != 3 {
		return nil, report, invalid("version, source binding or mapping count")
	}
	required := map[string]bool{"media": false, "lyrics": false, "directories": false, "links": false, "visibility": false, "preferences": false, "encryption_nonces": false}
	for _, section := range s.DeclaredSections {
		if seen, ok := required[section]; !ok || seen {
			return nil, report, invalid("source sections")
		}
		required[section] = true
	}
	for _, seen := range required {
		if !seen {
			return nil, report, invalid("missing source section")
		}
	}
	bySource := map[string]Mapping{}
	sourceIDs := map[string]bool{}
	targetIDs := map[string]bool{}
	roles := map[string]bool{}
	for _, m := range s.Mappings {
		if !id32.MatchString(m.SourceID) || !id32.MatchString(m.TargetID) || m.SourceID == m.TargetID || m.Capacity < 0 || sourceIDs[m.SourceID] || targetIDs[m.TargetID] || roles[m.Role] || (m.Role != "master" && m.Role != "direct" && m.Role != "relay") {
			return nil, report, invalid("owner mapping")
		}
		bySource[m.SourceID] = m
		sourceIDs[m.SourceID] = true
		targetIDs[m.TargetID] = true
		roles[m.Role] = true
	}
	for id := range sourceIDs {
		if targetIDs[id] {
			return nil, report, invalid("source and target identity overlap")
		}
	}
	excluded := map[string]bool{}
	for _, id := range s.ExcludedSourceIDs {
		if !id32.MatchString(id) || sourceIDs[id] || targetIDs[id] || excluded[id] {
			return nil, report, invalid("exclusion")
		}
		excluded[id] = true
	}
	globalIDs := map[string]bool{}
	mediaKinds := map[string]string{}
	paths := map[string]bool{}
	ownerObjects := map[string]bool{}
	cryptoIDs := map[string]bool{}
	stageKeys := map[string]bool{}
	needKey := len(s.RetiredNonces) > 0
	emptySHA := sha256.Sum256(nil)
	emptyDigest := hex.EncodeToString(emptySHA[:])
	for _, m := range s.Media {
		owner, ok := bySource[m.SourceID]
		if !ok || excluded[m.SourceID] || !id64.MatchString(m.MediaID) || !id64.MatchString(m.ObjectID) || !id64.MatchString(m.SHA256) || !ValidPath(m.Path, m.Kind) || m.Size < 0 || m.Size > 10*1024*1024*1024 || m.Size == 0 && m.SHA256 != emptyDigest || globalIDs[m.MediaID] || paths[m.Path] || ownerObjects[m.SourceID+":"+m.ObjectID] {
			return nil, report, invalid("media fact")
		}
		stageKey := owner.Role + ":" + m.ObjectID
		if stageKeys[stageKey] {
			return nil, report, invalid("duplicate staged object")
		}
		stageKeys[stageKey] = true
		globalIDs[m.MediaID] = true
		mediaKinds[m.MediaID] = m.Kind
		paths[m.Path] = true
		ownerObjects[m.SourceID+":"+m.ObjectID] = true
		if report.BytesByRole[owner.Role] > int64(^uint64(0)>>1)-m.Size {
			return nil, report, invalid("capacity overflow")
		}
		report.BytesByRole[owner.Role] += m.Size
		if m.Encryption != nil {
			if err := m.Encryption.Validate(); err != nil || m.Encryption.CiphertextSize != m.Size || cryptoIDs[m.Encryption.FileID] {
				return nil, report, invalid("media encryption")
			}
			cryptoIDs[m.Encryption.FileID] = true
			needKey = true
		}
	}
	lyrics := map[string]bool{}
	for _, l := range s.Lyrics {
		if !id64.MatchString(l.ID) || !id64.MatchString(l.SHA256) || !ValidPath(l.Path, "lyric") || l.Size < 0 || l.Size > 5*1024*1024 || l.Size == 0 && l.SHA256 != emptyDigest || lyrics[l.ID] || globalIDs[l.ID] || paths[l.Path] || stageKeys["master:"+l.ID] {
			return nil, report, invalid("lyric fact")
		}
		if l.Path == "lyrics/default.lrc" {
			defaultBytes := []byte(DefaultLyricContent)
			sum := sha256.Sum256(defaultBytes)
			if !l.Builtin || l.Encryption != nil || l.Size != int64(len(defaultBytes)) || l.SHA256 != hex.EncodeToString(sum[:]) {
				return nil, report, invalid("builtin lyric")
			}
		} else if l.Builtin {
			return nil, report, invalid("builtin lyric path")
		}
		if l.Encryption != nil {
			if err := l.Encryption.Validate(); err != nil || l.Encryption.CiphertextSize != l.Size || cryptoIDs[l.Encryption.FileID] {
				return nil, report, invalid("lyric encryption")
			}
			cryptoIDs[l.Encryption.FileID] = true
			needKey = true
		}
		stageKeys["master:"+l.ID] = true
		lyrics[l.ID] = true
		paths[l.Path] = true
		report.BytesByRole["master"] += l.Size
	}
	directoryIDs := map[string]bool{}
	for _, d := range s.Directories {
		if !id64.MatchString(d.ID) || d.Path == "" || strings.ContainsAny(d.Path, "\\\x00") || path.Clean(d.Path) != d.Path || strings.HasPrefix(d.Path, "/") || !(d.Path == "music" || d.Path == "vido" || strings.HasPrefix(d.Path, "music/") || strings.HasPrefix(d.Path, "vido/")) || directoryIDs[d.ID] || globalIDs[d.ID] || lyrics[d.ID] || paths[d.Path] {
			return nil, report, invalid("directory fact")
		}
		parts := strings.Split(d.Path, "/")
		if len(parts) > 3 {
			return nil, report, invalid("directory depth")
		}
		for _, part := range parts {
			if part == "" || part == "." || part == ".." || strings.HasPrefix(part, ".") || strings.Contains(part, ":") {
				return nil, report, invalid("directory path")
			}
		}
		directoryIDs[d.ID] = true
		paths[d.Path] = true
	}
	visible := map[string]bool{}
	for _, v := range s.Visibility {
		if !ValidVisibility(v.Path) || visible[v.Path] {
			return nil, report, invalid("visibility fact")
		}
		visible[v.Path] = true
	}
	preferences := map[string]bool{}
	for _, p := range s.Preferences {
		if (!globalIDs[p.ID] && !directoryIDs[p.ID]) || preferences[p.ID] || p.Value < -7 || p.Value > 500000 || p.PlayScore < 0 {
			return nil, report, invalid("preference fact")
		}
		preferences[p.ID] = true
	}
	for _, m := range s.Mappings {
		if report.BytesByRole[m.Role] > m.Capacity {
			return nil, report, invalid("capacity")
		}
	}
	linked := map[string]bool{}
	for _, l := range s.Links {
		if mediaKinds[l.MediaID] != "audio" || !lyrics[l.LyricID] || linked[l.MediaID] {
			return nil, report, invalid("lyric relation")
		}
		linked[l.MediaID] = true
	}
	retiredIDs := map[string]bool{}
	for _, n := range s.RetiredNonces {
		if !id64.MatchString(n.ObjectID) || !id32.MatchString(n.FileID) || cryptoIDs[n.FileID] || globalIDs[n.ObjectID] || lyrics[n.ObjectID] || directoryIDs[n.ObjectID] || retiredIDs[n.ObjectID] {
			return nil, report, invalid("nonce tombstone")
		}
		cryptoIDs[n.FileID] = true
		retiredIDs[n.ObjectID] = true
	}
	if needKey {
		if verifyKeyID == nil || !verifyKeyID(s.PremasterKeyID) {
			return nil, report, invalid("premaster key proof")
		}
	}
	data, err := json.Marshal(s)
	if err != nil {
		return nil, report, err
	}
	sum := sha256.Sum256(data)
	report.ProjectionSHA256 = hex.EncodeToString(sum[:])
	report.MediaCount = len(s.Media)
	report.LyricCount = len(s.Lyrics)
	report.LinkCount = len(s.Links)
	return bySource, report, nil
}
