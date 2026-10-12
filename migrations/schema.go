// Package migrations owns the physical schemas used by both runtime implementations.
package migrations

import (
	"embed"
	"encoding/json"
	"fmt"
)

const Generation = 6
const JournalName = "create-schema-migration-journal"
const JournalChecksum = "aee46be69d8c5b005cbee58ebfd37feb41d3431eb1fb23bb8339c9076147c03e"

const EncryptionName = "browser-media-encryption-descriptors"

// SHA256 of the two canonical SQLite generation-3 CREATE TABLE statements joined
// by one newline. MySQL applies equivalent DDL under the same migration identity.
const EncryptionChecksum = "e5cee839fd964c7146758c365abf72fbde94dab1e74c4a9f8dc20df8ea62176b"

const PriorityName = "priority-range-negative7-to-500000"
const PriorityMySQLAlter = "ALTER TABLE media_playback_stats DROP CHECK chk_media_preference, MODIFY COLUMN preference INT NOT NULL DEFAULT 0, ADD CONSTRAINT chk_media_preference CHECK (preference BETWEEN -7 AND 500000)"

//go:embed mysql/*.json sqlite/*.json
var assets embed.FS

func Statements(backend string) ([]string, error) {
	if backend != "mysql" && backend != "sqlite" {
		return nil, fmt.Errorf("unsupported schema backend %q", backend)
	}
	data, err := assets.ReadFile(fmt.Sprintf("%s/%04d-schema.json", backend, Generation))
	if err != nil {
		return nil, err
	}
	var document struct {
		Generation int      `json:"generation"`
		Statements []string `json:"statements"`
	}
	if err := json.Unmarshal(data, &document); err != nil {
		return nil, err
	}
	if document.Generation != Generation {
		return nil, fmt.Errorf("shared schema generation mismatch")
	}
	return document.Statements, nil
}

// SHA256 of SQLite CREATE plus the equivalent atomic MySQL ALTER.
const PriorityChecksum = "40ed2a2da3227bc3835f9196d5bd1cc81fc547bf1ada05f410cff929715487f1"

const ResourceMigrationName = "durable-storage-resource-migration"
const ResourceMigrationChecksum = "64e2817e07fd7a65dc651297425ce9a0ca26d6a8f4e7abb21d3154a359c3ce3c"

const PeerBindingsName = "immutable-peer-resource-bindings"
const PeerBindingsChecksum = "1fda21be7bc2c0b5f1b14bfc6f74e352a1bc070688c5409ad000d47ce555aed8"
