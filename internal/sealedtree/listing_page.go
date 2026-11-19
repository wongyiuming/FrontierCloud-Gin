package sealedtree

import (
	"context"
	"crypto/hmac"
	"database/sql"
	"strings"
)

type listingPageRow struct {
	key, group, lookup, object, mac string
	count, revision                 int64
}

// CatalogItem is sensitive Master-only metadata. Placement is present for
// native files, S3Placement for S3 files; both are absent for directories.
// A listing is never an authorization to read either kind of object.
type CatalogItem struct {
	Entry             Entry
	EntryRevision     int64
	Facts             Facts
	FactsRevision     int64
	Placement         *Placement
	S3Placement       *S3Placement
	PlacementRevision int64
}

// readCatalogPage authenticates a bounded page with batched SQL. No returned
// item is authorized for byte access merely by its presence in the index.
func (s *SQLStore) readCatalogPage(ctx context.Context, tx treeQuery, parent string, page []listingPageRow, includeHidden bool) ([]CatalogItem, error) {
	if len(page) == 0 {
		return []CatalogItem{}, nil
	}
	if len(page) > 257 {
		return nil, ErrInvalid
	}
	parentIndex, err := s.tree.ParentIndex(parent)
	if err != nil {
		return nil, ErrInvalid
	}
	args := make([]any, 0, len(page))
	expected := make(map[string]listingPageRow, len(page))
	for _, item := range page {
		if _, exists := expected[item.object]; exists {
			return nil, ErrInvalid
		}
		expected[item.object] = item
		args = append(args, item.object)
	}
	marks := strings.TrimSuffix(strings.Repeat("?,", len(args)), ",")
	query := `SELECT r.object_index,r.parent_index,r.lookup_tag,r.revision,r.encryption_id,r.sealed,
 f.object_index,f.revision,f.encryption_id,f.sealed,
 CASE WHEN rn.encryption_id IS NULL THEN 0 ELSE 1 END,
 CASE WHEN fn.encryption_id IS NULL THEN 0 ELSE 1 END,
 CASE WHEN rv.operation_index IS NULL THEN 0 ELSE 1 END,
 p.object_index,p.blob_index,p.revision,p.encryption_id,p.sealed,
 CASE WHEN pn.encryption_id IS NULL THEN 0 ELSE 1 END,
 CASE WHEN pb.blob_index IS NULL THEN 0 ELSE 1 END,
 CASE WHEN sa.alias_index IS NULL THEN 0 ELSE 1 END
 FROM sealed_tree_records r JOIN sealed_tree_facts f ON f.object_index=r.object_index
 LEFT JOIN sealed_tree_encryption_ids rn ON rn.encryption_id=r.encryption_id
 LEFT JOIN sealed_tree_encryption_ids fn ON fn.encryption_id=f.encryption_id
 LEFT JOIN sealed_tree_revocations rv ON rv.object_index=r.object_index
 LEFT JOIN sealed_tree_placements p ON p.object_index=r.object_index
 LEFT JOIN sealed_tree_encryption_ids pn ON pn.encryption_id=p.encryption_id
 LEFT JOIN sealed_tree_blob_ids pb ON pb.blob_index=p.blob_index
 LEFT JOIN sealed_tree_aliases sa ON sa.object_index=r.object_index
 WHERE r.object_index IN (` + marks + `)`
	rows, err := tx.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, ErrInvalid
	}
	defer rows.Close()
	decoded := make(map[string]CatalogItem, len(page))
	ids := make(map[string]bool, len(page)*3)
	aliases := make(map[string]string, len(page))
	// Each facts record is fully authenticated and decoded synchronously.
	// The scratch area is wiped by openFactsWithScratch on every path; decoded
	// entries must never retain a reference to it.
	factsScratch := make([]byte, 0, factsPayloadBytes)
	defer clear(factsScratch[:cap(factsScratch)])
	for rows.Next() {
		var r Record
		var f FactsRecord
		var nameID, factsID string
		var nameReserved, factsReserved, pending int
		var pObject, pBlob, pID sql.NullString
		var pRevision sql.NullInt64
		// RawBytes is valid only until the next Scan/Next/Close. All three
		// records are authenticated and decoded in this iteration; no raw
		// driver memory is retained by CatalogItem. Avoiding database/sql's
		// additional clone matters for fixed-size encrypted facts pages.
		var nameSealed, factsSealed, pSealed sql.RawBytes
		var pReserved, blobReserved, aliasPresent int
		if rows.Scan(&r.ObjectIndex, &r.ParentIndex, &r.Lookup, &r.Revision, &nameID, &nameSealed,
			&f.ObjectIndex, &f.Revision, &factsID, &factsSealed, &nameReserved, &factsReserved, &pending,
			&pObject, &pBlob, &pRevision, &pID, &pSealed, &pReserved, &blobReserved, &aliasPresent) != nil {
			return nil, ErrInvalid
		}
		r.Sealed, f.Sealed = nameSealed, factsSealed
		item, ok := expected[r.ObjectIndex]
		if !ok || decoded[r.ObjectIndex].Entry.ObjectID != "" || r.ParentIndex != parentIndex || r.Lookup != item.lookup || f.ObjectIndex != r.ObjectIndex || nameReserved != 1 || factsReserved != 1 || (pending != 0 && pending != 1) || ids[nameID] || ids[factsID] || nameID == factsID {
			return nil, ErrInvalid
		}
		actualName, e := EncryptionID(r)
		if e != nil || !hmac.Equal([]byte(nameID), []byte(actualName)) {
			return nil, ErrInvalid
		}
		actualFacts, e := FactsEncryptionID(f)
		if e != nil || !hmac.Equal([]byte(factsID), []byte(actualFacts)) {
			return nil, ErrInvalid
		}
		entry, e := s.tree.Open(parent, r)
		if e != nil {
			return nil, ErrInvalid
		}
		facts, e := s.tree.openFactsWithScratch(f, factsScratch)
		visible := listingVisible(&facts)
		if e != nil || !factsCompatible(entry, facts) || facts.InternalPlaceholder || facts.S3Deletion != nil || (pending == 1) != (facts.Revocation != nil) || facts.Revocation != nil || (!includeHidden && !visible) || item.group != s.listingGroup(parent, visible) {
			return nil, ErrInvalid
		}
		ids[nameID], ids[factsID] = true, true
		result := CatalogItem{Entry: entry, EntryRevision: r.Revision, Facts: facts, FactsRevision: f.Revision}
		if entry.Kind == "directory" {
			if pObject.Valid || pBlob.Valid || pRevision.Valid || pID.Valid || pSealed != nil || pReserved != 0 || blobReserved != 0 || aliasPresent != 0 {
				return nil, ErrInvalid
			}
		} else {
			if !pObject.Valid || !pBlob.Valid || !pRevision.Valid || !pID.Valid || pObject.String != r.ObjectIndex || pReserved != 1 || blobReserved != 1 || ids[pID.String] {
				return nil, ErrInvalid
			}
			if len(pSealed) == 1+recordSaltBytes+nonceBytes+s3PlacementPayloadBytes+16 {
				if aliasPresent != 0 {
					return nil, ErrInvalid
				}
				s3record := S3PlacementRecord{ObjectIndex: pObject.String, Revision: pRevision.Int64, Sealed: pSealed}
				actualID, e := S3PlacementEncryptionID(s3record)
				if e != nil || !hmac.Equal([]byte(pID.String), []byte(actualID)) {
					return nil, ErrInvalid
				}
				s3placement, e := s.openIndexedS3Placement(ctx, tx, entry.ObjectID, pBlob.String, pObject.String, pRevision.Int64, pSealed)
				if e != nil {
					return nil, ErrInvalid
				}
				ids[pID.String] = true
				result.S3Placement, result.PlacementRevision = &s3placement, pRevision.Int64
				decoded[r.ObjectIndex] = result
				continue
			}
			placementRecord := PlacementRecord{ObjectIndex: pObject.String, BlobIndex: pBlob.String, Revision: pRevision.Int64, Sealed: pSealed}
			actualID, e := PlacementEncryptionID(placementRecord)
			if e != nil || !hmac.Equal([]byte(pID.String), []byte(actualID)) {
				return nil, ErrInvalid
			}
			placement, e := s.tree.OpenPlacement(placementRecord)
			if e != nil || placement.ObjectID != entry.ObjectID {
				return nil, ErrInvalid
			}
			alias, e := s.tree.BlobIndex(placement.ReadAlias)
			if e != nil || alias == pBlob.String || aliases[alias] != "" {
				return nil, ErrInvalid
			}
			aliases[alias] = r.ObjectIndex
			ids[pID.String] = true
			result.Placement, result.PlacementRevision = &placement, pRevision.Int64
		}
		decoded[r.ObjectIndex] = result
	}
	if rows.Err() != nil || rows.Close() != nil || len(decoded) != len(page) {
		return nil, ErrInvalid
	}
	if len(aliases) > 0 {
		aliasArgs := make([]any, 0, len(aliases))
		for alias := range aliases {
			aliasArgs = append(aliasArgs, alias)
		}
		aliasMarks := strings.TrimSuffix(strings.Repeat("?,", len(aliasArgs)), ",")
		aliasRows, e := tx.QueryContext(ctx, `SELECT a.alias_index,a.object_index FROM sealed_tree_aliases a JOIN sealed_tree_blob_ids b ON b.blob_index=a.alias_index WHERE a.alias_index IN (`+aliasMarks+`)`, aliasArgs...)
		if e != nil {
			return nil, ErrInvalid
		}
		seen := make(map[string]bool, len(aliases))
		for aliasRows.Next() {
			var alias, object string
			if aliasRows.Scan(&alias, &object) != nil || aliases[alias] != object || seen[alias] {
				aliasRows.Close()
				return nil, ErrInvalid
			}
			seen[alias] = true
		}
		e = aliasRows.Err()
		closeErr := aliasRows.Close()
		if e != nil || closeErr != nil || len(seen) != len(aliases) {
			return nil, ErrInvalid
		}
	}
	result := make([]CatalogItem, 0, len(page))
	for _, item := range page {
		result = append(result, decoded[item.object])
	}
	return result, nil
}
