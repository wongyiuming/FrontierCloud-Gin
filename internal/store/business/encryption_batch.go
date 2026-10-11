package business

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
)

const encryptionBatchSize = 500 // Below SQLite's smallest supported 999-parameter limit.

func readEncryptions(ctx context.Context, q queryer, ids []string) (map[string]*mediacrypto.Metadata, error) {
	result := make(map[string]*mediacrypto.Metadata)
	unique := make([]string, 0, len(ids))
	seen := make(map[string]bool)
	for _, id := range ids {
		if !nodeHashPattern.MatchString(id) {
			return nil, mediacrypto.ErrMetadata
		}
		if !seen[id] {
			unique = append(unique, id)
			seen[id] = true
		}
	}
	for start := 0; start < len(unique); start += encryptionBatchSize {
		batch := unique[start:min(start+encryptionBatchSize, len(unique))]
		args := make([]any, len(batch))
		for i, id := range batch {
			args[i] = id
		}
		rows, err := q.QueryContext(ctx, "SELECT object_id,descriptor_json FROM media_encryption WHERE object_kind='media' AND object_id IN ("+strings.TrimSuffix(strings.Repeat("?,", len(batch)), ",")+")", args...)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var id string
			var raw sql.NullString
			if err = rows.Scan(&id, &raw); err != nil {
				rows.Close()
				return nil, err
			}
			if !raw.Valid {
				continue
			} // Retired identities never become active descriptors.
			var metadata mediacrypto.Metadata
			if json.Unmarshal([]byte(raw.String), &metadata) != nil || metadata.Validate() != nil {
				rows.Close()
				return nil, mediacrypto.ErrMetadata
			}
			result[id] = &metadata
		}
		err = rows.Err()
		closeErr := rows.Close()
		if err != nil {
			return nil, err
		}
		if closeErr != nil {
			return nil, closeErr
		}
	}
	return result, nil
}

func (r *Repository) Encryptions(ctx context.Context, ids []string) (map[string]*mediacrypto.Metadata, error) {
	return readEncryptions(ctx, r.db, ids)
}
