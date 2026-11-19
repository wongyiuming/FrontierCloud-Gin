package sealedtree

import (
	"context"
	"crypto/hmac"
)

// CheckDirectParentOwnerTx checks the existing and reserved native objects in
// exactly one logical parent, using the coordinator's authoritative transaction
// while its tree mutation fence is held. It does not authorize an upload or
// enforce the separate category-versus-subdirectory layout rule. Unknown or S3
// placement fails closed. Callers must perform capacity reservation and pending
// creation on this same transaction, in the agreed Owner -> ingress -> tree
// lock order. The caller is responsible for an appropriately bounded context.
func (m *CoordinatedMutation) CheckDirectParentOwnerTx(ctx context.Context, tx treeQuery, parentID, ownerID string) error {
	if m == nil || ctx == nil || tx == nil || !hexID(parentID) || !lowerHex(ownerID, 32) {
		return ErrInvalid
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.store
	if !m.active || !s.valid() {
		return ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := s.lockIndexedWriter(ctx, tx); err != nil {
		return err
	}
	if err := s.verifyRoot(ctx, tx); err != nil {
		return err
	}
	if err := s.checkDirectory(ctx, tx, parentID, ""); err != nil {
		return err
	}
	return s.scanDirectEntriesTx(ctx, tx, parentID, func(entry Entry, index string, pending *Placement) error {
		if entry.Kind == "directory" {
			return nil
		}
		var placement Placement
		var err error
		if pending != nil {
			placement = *pending
		} else {
			placement, err = s.placementFor(ctx, tx, entry, index)
		}
		if err != nil {
			return ErrInvalid
		}
		if placement.OwnerID != ownerID {
			return ErrConflict
		}
		return nil
	})
}

// scanDirectEntriesTx authenticates listing counts, each record/facts pair, and
// each pending entry in bounded pages, under its caller's tree and SQL fence.
// visit runs with closed SQL row cursors, permitting nested same-tx inspection.
func (s *SQLStore) scanDirectEntriesTx(ctx context.Context, tx treeQuery, parentID string, visit func(Entry, string, *Placement) error) error {
	parentIndex, err := s.tree.ParentIndex(parentID)
	if err != nil {
		return err
	}
	var counts [3]int64
	var expected [3]int64
	for class := 0; class < len(expected); class++ {
		expected[class], _, err = s.listingSummary(ctx, tx, s.listingClassGroup(parentID, class))
		if err != nil {
			return err
		}
	}
	after := ""
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		rows, err := tx.QueryContext(ctx, `SELECT object_index,parent_index,lookup_tag,revision,encryption_id,sealed FROM sealed_tree_records WHERE parent_index=? AND lookup_tag>? ORDER BY lookup_tag LIMIT 128`, parentIndex, after)
		if err != nil {
			return err
		}
		var batch []Record
		for rows.Next() {
			r, e := scanRecord(rows)
			if e != nil || r.Lookup <= after {
				_ = rows.Close()
				return ErrInvalid
			}
			after = r.Lookup
			batch = append(batch, r)
		}
		if err = rows.Err(); err != nil {
			_ = rows.Close()
			return err
		}
		if err = rows.Close(); err != nil {
			return err
		}
		if err = verifyNameReservations(ctx, tx, batch); err != nil {
			return err
		}
		for _, r := range batch {
			entry, e := s.tree.Open(parentID, r)
			if e != nil {
				return ErrInvalid
			}
			facts, _, e := s.factsFor(ctx, tx, entry, r.ObjectIndex)
			if e != nil {
				return ErrInvalid
			}
			class := listingClass(&facts)
			group := s.listingClassGroup(parentID, class)
			var object, mac string
			var count, revision int64
			if tx.QueryRowContext(ctx, `SELECT object_index,entry_count,group_revision,mac FROM sealed_tree_listing WHERE index_key=? AND group_tag=? AND lookup_tag=?`, s.listingKey(group, r.Lookup), group, r.Lookup).Scan(&object, &count, &revision, &mac) != nil || object != r.ObjectIndex || count != -1 || revision != 0 || !hmac.Equal([]byte(mac), []byte(s.listingRowMAC(group, r.Lookup, object, count, revision))) {
				return ErrInvalid
			}
			counts[class]++
			if counts[class] > expected[class] {
				return ErrInvalid
			}
			if e := visit(entry, r.ObjectIndex, nil); e != nil {
				return e
			}
		}
		if len(batch) < 128 {
			break
		}
	}
	if counts != expected {
		return ErrInvalid
	}
	after = ""
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		rows, err := tx.QueryContext(ctx, `SELECT operation_id,lookup_tag FROM sealed_tree_pending_files WHERE parent_index=? AND lookup_tag>? ORDER BY lookup_tag LIMIT 128`, parentIndex, after)
		if err != nil {
			return err
		}
		var operations []string
		for rows.Next() {
			var op, lookup string
			if rows.Scan(&op, &lookup) != nil || !hexID(op) || !hexID(lookup) || lookup <= after {
				_ = rows.Close()
				return ErrInvalid
			}
			after = lookup
			operations = append(operations, op)
		}
		if err = rows.Err(); err != nil {
			_ = rows.Close()
			return err
		}
		if err = rows.Close(); err != nil {
			return err
		}
		for _, op := range operations {
			_, entry, placement, e := s.pending(ctx, tx, op)
			if e != nil || entry.ParentID != parentID {
				return ErrInvalid
			}
			if e := visit(entry, op, &placement); e != nil {
				return e
			}
		}
		if len(operations) < 128 {
			break
		}
	}
	return nil
}
