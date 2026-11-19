package preprodimport

// Verifies the source Master-signed database facts against an independently
// provisioned pin. This is not an object-byte proof or an import permit.
import (
	"crypto/ecdh"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"time"
	"unicode/utf8"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/snapshotcrypt"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func openMediaSourceSnapshot(envelope store.EncryptedMediaSourceSnapshot, receiver *ecdh.PrivateKey, pin sourceAuthorityPin, challenge string, now time.Time) (store.SignedMediaSourceSnapshot, string, error) {
	signed, err := snapshotcrypt.Open(envelope, receiver)
	if err != nil {
		return store.SignedMediaSourceSnapshot{}, "", invalid("source snapshot envelope")
	}
	digest, err := verifyMediaSourceSnapshot(signed, pin, challenge, now)
	if err != nil {
		return store.SignedMediaSourceSnapshot{}, "", err
	}
	return signed, digest, nil
}

var sourceSnapshotColumns = []struct {
	name string
	columns []string
}{
	{"objects", []string{"media_id", "object_kind", "media_path", "path_locator", "created_at", "updated_at"}},
	{"placements", []string{"media_id", "storage_member_id", "object_id", "media_path", "object_kind", "size_bytes", "etag", "state", "created_at", "updated_at"}},
	{"visibility", []string{"relative_path", "hidden", "updated_at"}},
	{"playback", []string{"media_id", "media_path", "preference", "play_score", "created_at", "updated_at"}},
	{"lyric_links", []string{"media_id", "media_path", "lyric_id", "lyric_path", "created_at", "updated_at"}},
	{"encryption", []string{"object_kind", "object_id", "file_id", "descriptor_json", "created_at"}},
	{"members", []string{"member_id", "relationship_id", "member_kind", "transport", "storage_enabled", "allocated_bytes", "used_bytes", "reserved_bytes", "physical_free_bytes", "health", "writable", "updated_at"}},
	{"relationships", []string{"relationship_id", "peer_id", "peer_endpoint", "peer_key", "direction", "mode", "state", "created_at"}},
	{"crypto_key_id", []string{"singleton", "key_id", "created_at"}},
}

func verifyMediaSourceSnapshot(signed store.SignedMediaSourceSnapshot, pin sourceAuthorityPin, challenge string, now time.Time) (string, error) {
	s := signed.Snapshot
	public, err := protocol.Decode(s.SourcePublic)
	if err != nil || !validSourceAuthority(pin) || s.Version != 1 || s.AuthorityKind != pin.AuthorityKind || s.SourceSSHHostKeySHA256 != pin.SourceSSHHostKeySHA256 || s.SourceNode != pin.SourceNode || s.TargetNode != pin.TargetNode || subtle.ConstantTimeCompare(public, pin.SourcePublic) != 1 || subtle.ConstantTimeCompare(s.TargetReceiver, pin.TargetX25519) != 1 || !id64.MatchString(challenge) || s.Challenge != challenge || s.IssuedUnix <= 0 || s.IssuedUnix > now.Unix() || s.ExpiresUnix <= now.Unix() || s.ExpiresUnix-s.IssuedUnix > 300 || len(s.Sections) != len(sourceSnapshotColumns) {
		return "", invalid("source snapshot identity")
	}
	count := 0
	for i, expected := range sourceSnapshotColumns {
		section := s.Sections[i]
		if section.Name != expected.name || len(section.Columns) != len(expected.columns) || section.Rows == nil {
			return "", invalid("source snapshot section")
		}
		for j, column := range expected.columns {
			if section.Columns[j] != column {
				return "", invalid("source snapshot columns")
			}
		}
		for _, row := range section.Rows {
			count++
			if count > 25000 || len(row) != len(expected.columns) {
				return "", invalid("source snapshot row")
			}
			for j, cell := range row {
				if cell == nil {
					if !(section.Name == "encryption" && expected.columns[j] == "descriptor_json") && !(section.Name == "members" && expected.columns[j] == "relationship_id") {
						return "", invalid("source snapshot null")
					}
				} else if !utf8.ValidString(*cell) || containsNUL(*cell) {
					return "", invalid("source snapshot text")
				}
			}
		}
	}
	keys := s.Sections[len(s.Sections)-1].Rows
	if len(keys) != 1 || keys[0][0] == nil || *keys[0][0] != "1" || keys[0][1] == nil || *keys[0][1] != pin.SourceKeyID {
		return "", invalid("source snapshot key id")
	}
	raw, err := json.Marshal(s)
	if err != nil || len(raw) > 16*1024*1024 {
		return "", invalid("source snapshot size")
	}
	digest := sha256.Sum256(raw)
	clear(raw)
	hexDigest := hex.EncodeToString(digest[:])
	payload := map[string]any{"kind": "frontiercloud-preprod-media-source-v1", "sha256": hexDigest, "source_node": s.SourceNode, "target_node": s.TargetNode, "challenge": s.Challenge}
	if protocol.Verify(s.SourcePublic, payload, signed.Signature) != nil {
		return "", invalid("source snapshot signature")
	}
	return hexDigest, nil
}
