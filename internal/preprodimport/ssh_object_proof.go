package preprodimport

// A collector observation is not a source-node signature or a cross-node
// atomic snapshot. It binds one pinned SSH owner's bounded file read to the
// independently pinned collector and to authenticated SQL facts.
import (
	"bytes"
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"strings"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/snapshotcrypt"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

type sourceObjectFacts struct {
	Object       []*string   `json:"object"`
	Placement    []*string   `json:"placement"`
	Encryption   []*string   `json:"encryption"`
	Member       []*string   `json:"member"`
	Relationship []*string   `json:"relationship"`
	Visibility   [][]*string `json:"visibility"`
}

// This scope covers plaintext media and lyrics as well as encrypted media; it
// deliberately does not contain a file-key grant or imply key availability.
type objectProofScope struct {
	TargetOwnerID   string
	TargetBlobID    string
	TargetReadAlias string
	Challenge       string
}

type sshObjectProof struct {
	Version               int    `json:"version"`
	SourceNode            string `json:"source_node"`
	SourceOwnerID         string `json:"source_owner_id"`
	OwnerSSHHostKeySHA256 string `json:"owner_ssh_host_key_sha256"`
	SourceSnapshotDigest  string `json:"source_snapshot_digest"`
	BeforeFactsSHA256     string `json:"before_facts_sha256"`
	AfterFactsSHA256      string `json:"after_facts_sha256"`
	MediaID               string `json:"media_id"`
	SourceObjectID        string `json:"source_object_id"`
	Path                  string `json:"path"`
	SHA256                string `json:"sha256"`
	Size                  int64  `json:"size"`
	Device                uint64 `json:"device"`
	Inode                 uint64 `json:"inode"`
	MtimeNS               int64  `json:"mtime_ns"`
	CtimeNS               int64  `json:"ctime_ns"`
	TargetNode            string `json:"target_node"`
	TargetOwnerID         string `json:"target_owner_id"`
	TargetBlobID          string `json:"target_blob_id"`
	TargetReadAlias       string `json:"target_read_alias"`
	Challenge             string `json:"challenge"`
	IssuedUnix            int64  `json:"issued_unix"`
	ExpiresUnix           int64  `json:"expires_unix"`
}

type signedSSHObjectProof struct {
	Proof     sshObjectProof `json:"proof"`
	Signature string         `json:"signature"`
}

func sourceObjectFactsDigest(s store.MediaSourceSnapshot, media Media) (string, error) {
	facts := sourceObjectFacts{Visibility: make([][]*string, 0)}
	for _, section := range s.Sections {
		for _, row := range section.Rows {
			if len(row) == 0 || row[0] == nil {
				return "", invalid("source object facts")
			}
			switch section.Name {
			case "objects":
				if *row[0] == media.MediaID {
					if facts.Object != nil {
						return "", invalid("source object facts")
					}
					facts.Object = row
				}
			case "placements":
				if *row[0] == media.MediaID {
					if facts.Placement != nil {
						return "", invalid("source object facts")
					}
					facts.Placement = row
				}
			case "encryption":
				if len(row) != 5 || row[1] == nil {
					return "", invalid("source object facts")
				}
				if *row[0] == "media" && *row[1] == media.MediaID {
					if facts.Encryption != nil {
						return "", invalid("source object facts")
					}
					facts.Encryption = row
				}
			case "members":
				if *row[0] == media.SourceID {
					if facts.Member != nil {
						return "", invalid("source object facts")
					}
					facts.Member = row
				}
			case "visibility":
				if media.Path == *row[0] || strings.HasPrefix(media.Path, *row[0]+"/") {
					facts.Visibility = append(facts.Visibility, row)
				}
			}
		}
	}
	if len(facts.Member) != 12 {
		return "", invalid("source object facts")
	}
	if facts.Member[0] == nil || *facts.Member[0] != media.SourceID || facts.Member[2] == nil || facts.Member[3] == nil {
		return "", invalid("source owner facts")
	}
	if *facts.Member[2] == "MasterLocal" {
		if media.SourceID != s.SourceNode || facts.Member[1] != nil || *facts.Member[3] != "Local" {
			return "", invalid("source local owner")
		}
	} else if *facts.Member[2] == "Follower" {
		if facts.Member[1] == nil || (*facts.Member[3] != "Direct" && *facts.Member[3] != "Relay") {
			return "", invalid("source follower owner")
		}
	} else {
		return "", invalid("source non-native owner")
	}
	if media.Kind == "lyric" {
		if media.SourceID != s.SourceNode || media.ObjectID != media.MediaID || len(facts.Object) != 6 || facts.Object[1] == nil || *facts.Object[1] != "lyric" || facts.Object[2] == nil || *facts.Object[2] != media.Path || facts.Placement != nil {
			return "", invalid("source lyric facts")
		}
	} else if facts.Placement == nil {
		return "", invalid("source object facts")
	}
	if media.Encryption != nil && facts.Encryption == nil || media.Encryption == nil && facts.Encryption != nil {
		return "", invalid("source encryption facts")
	}
	if facts.Member[1] != nil {
		for _, section := range s.Sections {
			if section.Name == "relationships" {
				for _, row := range section.Rows {
					if len(row) != 8 || row[0] == nil {
						return "", invalid("source object facts")
					}
					if *row[0] == *facts.Member[1] {
						if facts.Relationship != nil {
							return "", invalid("source object facts")
						}
						facts.Relationship = row
					}
				}
			}
		}
		if facts.Relationship == nil {
			return "", invalid("source object facts")
		}
		if facts.Relationship[1] == nil || *facts.Relationship[1] != media.SourceID || facts.Relationship[4] == nil || *facts.Relationship[4] != "downstream" || facts.Relationship[6] == nil || *facts.Relationship[6] != "active" {
			return "", invalid("source relation facts")
		}
	}
	raw, err := json.Marshal(facts)
	if err != nil || len(raw) > 1024*1024 {
		return "", invalid("source object facts")
	}
	digest := sha256.Sum256(raw)
	clear(raw)
	return hex.EncodeToString(digest[:]), nil
}

func verifySSHObjectProof(e store.EncryptedMediaSourceSnapshot, receiver *ecdh.PrivateKey, pin sourceAuthorityPin, s store.MediaSourceSnapshot, sourceDigest string, media Media, scope objectProofScope, now time.Time) error {
	if receiver == nil || !validSourceAuthority(pin) || pin.AuthorityKind != "ssh-collector-v1" || !id64.MatchString(sourceDigest) {
		return invalid("SSH object proof input")
	}
	raw, err := snapshotcrypt.OpenObjectProof(e, receiver)
	if err != nil {
		return invalid("SSH object proof envelope")
	}
	defer clear(raw)
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var signed signedSSHObjectProof
	if decoder.Decode(&signed) != nil {
		return invalid("SSH object proof format")
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return invalid("SSH object proof format")
	}
	p := signed.Proof
	ownerPin := ""
	for _, owner := range pin.SourceOwners {
		if owner.NodeID == media.SourceID {
			ownerPin = owner.SSHHostKeySHA256
		}
	}
	facts, err := sourceObjectFactsDigest(s, media)
	if p.Size < 0 || p.Size == 0 && p.SHA256 != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		return invalid("SSH object proof empty digest")
	}
	if err != nil || ownerPin == "" || p.Version != 1 || p.SourceNode != pin.SourceNode || p.SourceOwnerID != media.SourceID || p.OwnerSSHHostKeySHA256 != ownerPin || p.SourceSnapshotDigest != sourceDigest || p.BeforeFactsSHA256 != facts || p.AfterFactsSHA256 != facts || p.MediaID != media.MediaID || p.SourceObjectID != media.ObjectID || p.Path != media.Path || p.SHA256 != media.SHA256 || p.Size != media.Size || p.Inode == 0 || p.TargetNode != pin.TargetNode || p.TargetOwnerID != scope.TargetOwnerID || p.TargetBlobID != scope.TargetBlobID || p.TargetReadAlias != scope.TargetReadAlias || p.Challenge != scope.Challenge || p.IssuedUnix <= 0 || p.IssuedUnix > now.Unix() || p.ExpiresUnix <= now.Unix() || p.ExpiresUnix-p.IssuedUnix > 300 || p.ExpiresUnix > s.ExpiresUnix {
		return invalid("SSH object proof scope")
	}
	body, err := json.Marshal(p)
	if err != nil {
		return invalid("SSH object proof format")
	}
	digest := sha256.Sum256(body)
	clear(body)
	payload := map[string]any{"kind": "frontiercloud-preprod-ssh-object-proof-v1", "sha256": hex.EncodeToString(digest[:])}
	if protocol.Verify(protocol.Encode(pin.SourcePublic), payload, signed.Signature) != nil {
		return invalid("SSH object proof signature")
	}
	return nil
}
