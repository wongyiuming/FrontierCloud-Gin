package business

import (
	"context"
	"database/sql"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// Large, malformed and unexamined mutation manifests remain explicit blockers.
// The diagnostic budget never converts an incomplete projection into clearance.
func retirementMasterFileTransactions(ctx context.Context, tx *sql.Tx, master, member string) ([]store.RetirementBlocker, error) {
	const limit = 8
	const manifestBytes = 64 << 10
	var total int64
	if e := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM media_delete_operations WHERE state<>'rename_done'").Scan(&total); e != nil {
		return nil, e
	}
	rows, e := tx.QueryContext(ctx, "SELECT operation_id,state,SUBSTR(manifest,1,?) FROM media_delete_operations WHERE state<>'rename_done' ORDER BY operation_id LIMIT ?", manifestBytes+1, limit)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	known := store.RetirementBlocker{Code: "file_transactions", SampleIDs: []string{}, NextStep: "finish_native_file_recovery"}
	unknown := store.RetirementBlocker{Code: "unverified_file_transactions", SampleIDs: []string{}, NextStep: "finish_native_file_recovery"}
	var observed int64
	for rows.Next() {
		var id, state string
		var raw []byte
		if e = rows.Scan(&id, &state, &raw); e != nil {
			return nil, e
		}
		observed++
		op, parse := decodeGlobalRename(id, state, raw)
		if len(raw) > manifestBytes || parse != nil || op.MasterID != master {
			unknown.Count++
			if len(unknown.SampleIDs) < 8 {
				unknown.SampleIDs = append(unknown.SampleIDs, id)
			}
			continue
		}
		for _, object := range op.Media {
			if object.MemberID == member {
				known.Count++
				known.SampleIDs = append(known.SampleIDs, id)
				break
			}
		}
	}
	if e = rows.Err(); e != nil {
		return nil, e
	}
	unknown.Count += total - observed
	result := []store.RetirementBlocker{}
	if known.Count > 0 {
		result = append(result, known)
	}
	if unknown.Count > 0 {
		result = append(result, unknown)
	}
	return result, nil
}
