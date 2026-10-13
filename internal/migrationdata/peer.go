package migrationdata

import (
	"bytes"
	"encoding/json"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/businesstraffic"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
	"io"
)

// Signed contains public identity proofs only, never relationship credentials.
type Signed struct {
	Payload   map[string]any `json:"payload"`
	Signature string         `json:"signature"`
}

// Preserve integer signing bytes through intermediate control envelopes.
func (s *Signed) UnmarshalJSON(raw []byte) error {
	type wire Signed
	var value wire
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	d.DisallowUnknownFields()
	if e := d.Decode(&value); e != nil {
		return e
	}
	var tail any
	if d.Decode(&tail) != io.EOF {
		return ErrState
	}
	*s = Signed(value)
	return nil
}

const PeerReadRoute = "/internal/v1/resource-migration/peer-read"
const DirectGrantFormat = "frontiercloud-direct-migration-read-v1"

// A source issues this grant only in response to its authenticated Master.
// Both peers still recheck their durable task, object and lease on each chunk.
type DirectGrant struct {
	Format          string                    `json:"format"`
	Header          store.MigrationPeerHeader `json:"header"`
	Lease           store.MigrationLease      `json:"lease"`
	Spec            Spec                      `json:"binding"`
	SourceEndpoint  string                    `json:"source_endpoint"`
	TargetPublicKey string                    `json:"target_public_key"`
	ExpiresAt       int64                     `json:"expires_at"`
}

type DirectRead struct {
	Route  string `json:"route"`
	Grant  Signed `json:"grant"`
	Offset int64  `json:"offset"`
	Length int    `json:"length"`
	Nonce  string `json:"nonce"`
	Time   int64  `json:"time"`
}

type DirectChunk struct {
	Nonce   string                `json:"nonce"`
	Offset  int64                 `json:"offset"`
	Size    int                   `json:"size_bytes"`
	Data    []byte                `json:"data"`
	SHA     string                `json:"chunk_sha256"`
	Version string                `json:"source_version"`
	Waiting bool                  `json:"waiting_traffic,omitempty"`
	Traffic *businesstraffic.View `json:"traffic,omitempty"`
}
