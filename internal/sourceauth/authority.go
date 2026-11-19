package sourceauth

import (
	"bytes"
	"crypto/ed25519"
	"net/url"
)

type AuthorityPin struct {
	Version                int          `json:"version"`
	Purpose                string       `json:"purpose"`
	AuthorityKind          string       `json:"authority_kind"`
	SourceSSHHostKeySHA256 string       `json:"source_ssh_host_key_sha256"`
	SourceTLSOrigin        string       `json:"source_tls_origin"`
	SourceTLSSPKISHA256    string       `json:"source_tls_spki_sha256"`
	SourceOwners           []OwnerPin   `json:"source_owners"`
	SourceNode             string       `json:"source_node"`
	SourceKeyID            string       `json:"source_key_id"`
	SourcePublic           []byte       `json:"source_public"`
	TargetNode             string       `json:"target_node"`
	TargetMasterPublic     []byte       `json:"target_master_public"`
	TargetX25519           []byte       `json:"target_x25519"`
	Generation             string       `json:"generation"`
	ImportScope            *ImportScope `json:"import_scope,omitempty"`
}

// The scope is sealed with the independently provisioned target pin. The
// retired Tencent identity is a node ID confirmed outside the source snapshot;
// no S3 or other node may be implicitly added to the exclusion set.
type ImportScope struct {
	Version                 int       `json:"version"`
	Purpose                 string    `json:"purpose"`
	Mappings                []Mapping `json:"mappings"`
	ExcludedTencentSourceID string    `json:"excluded_tencent_source_id"`
}

func SourceScopeMatches(scope *ImportScope, projection Snapshot) bool {
	if scope == nil || scope.Version != 1 || scope.Purpose != "frontiercloud:preprod-approved-scope:v1" || !id32.MatchString(scope.ExcludedTencentSourceID) || len(projection.ExcludedSourceIDs) != 1 || projection.ExcludedSourceIDs[0] != scope.ExcludedTencentSourceID || len(scope.Mappings) == 0 || len(scope.Mappings) != len(projection.Mappings) {
		return false
	}
	approved := make(map[string]Mapping, len(scope.Mappings))
	for _, mapping := range scope.Mappings {
		if !id32.MatchString(mapping.SourceID) || !id32.MatchString(mapping.TargetID) || mapping.SourceID == scope.ExcludedTencentSourceID || mapping.TargetID == scope.ExcludedTencentSourceID {
			return false
		}
		if _, exists := approved[mapping.SourceID]; exists {
			return false
		}
		approved[mapping.SourceID] = mapping
	}
	for _, mapping := range projection.Mappings {
		if expected, exists := approved[mapping.SourceID]; !exists || expected != mapping {
			return false
		}
		delete(approved, mapping.SourceID)
	}
	return len(approved) == 0
}

type OwnerPin struct {
	NodeID           string `json:"node_id"`
	SSHHostKeySHA256 string `json:"ssh_host_key_sha256"`
}

func ValidSourceAuthority(p AuthorityPin) bool {
	u, err := url.Parse(p.SourceTLSOrigin)
	validTLS := err == nil && u.Scheme == "https" && u.Host != "" && u.User == nil && u.Path == "" && u.RawQuery == "" && u.Fragment == "" && u.Opaque == ""
	owners := map[string]bool{}
	masterPinned := false
	for _, owner := range p.SourceOwners {
		if !id32.MatchString(owner.NodeID) || !id64.MatchString(owner.SSHHostKeySHA256) || owners[owner.NodeID] {
			return false
		}
		owners[owner.NodeID] = true
		if owner.NodeID == p.SourceNode && owner.SSHHostKeySHA256 == p.SourceSSHHostKeySHA256 {
			masterPinned = true
		}
	}
	authority := p.AuthorityKind == "source-node-v1" && p.SourceSSHHostKeySHA256 == "" && p.SourceTLSOrigin == "" && p.SourceTLSSPKISHA256 == "" && len(p.SourceOwners) == 0 || p.AuthorityKind == "ssh-collector-v1" && id64.MatchString(p.SourceSSHHostKeySHA256) && id64.MatchString(p.SourceTLSSPKISHA256) && validTLS && masterPinned && len(p.SourceOwners) <= 64
	return authority && p.Version == 1 && p.Purpose == "frontiercloud:preprod-source-authority:v1" && id32.MatchString(p.SourceNode) && id32.MatchString(p.TargetNode) && p.SourceNode != p.TargetNode && id64.MatchString(p.SourceKeyID) && id64.MatchString(p.Generation) && len(p.SourcePublic) == ed25519.PublicKeySize && !bytes.Equal(p.SourcePublic, make([]byte, ed25519.PublicKeySize)) && len(p.TargetMasterPublic) == ed25519.PublicKeySize && !bytes.Equal(p.TargetMasterPublic, make([]byte, ed25519.PublicKeySize)) && len(p.TargetX25519) == 32 && !bytes.Equal(p.TargetX25519, make([]byte, 32))
}
