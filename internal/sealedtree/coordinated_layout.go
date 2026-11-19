package sealedtree

import "context"

// CheckMediaCategoryLayoutTx preserves the existing upload rule: a music or
// video category may contain direct media or media one directory deeper, but
// not both. Empty child directories do not determine the layout. Pending files
// count alongside committed files, regardless of expiry. The tree mutation
// fence and authoritative SQL transaction must be shared with the subsequent
// capacity reservation and pending creation. This does not authorize an upload.
func (m *CoordinatedMutation) CheckMediaCategoryLayoutTx(ctx context.Context, tx treeQuery, parentID string) error {
	return m.checkMediaCategoryLayoutTx(ctx, tx, parentID, "")
}

// CheckMediaCategoryAndOwnerTx performs the category layout and direct-parent
// owner checks together, under the same mutation fence and SQL transaction.
// It does not supply Admin authorization or capacity admission. Native S3 or
// unknown placement types fail closed. Callers still need a bounded context.
func (m *CoordinatedMutation) CheckMediaCategoryAndOwnerTx(ctx context.Context, tx treeQuery, parentID, ownerID string) error {
	if !lowerHex(ownerID, 32) {
		return ErrInvalid
	}
	return m.checkMediaCategoryLayoutTx(ctx, tx, parentID, ownerID)
}

func (m *CoordinatedMutation) checkMediaCategoryLayoutTx(ctx context.Context, tx treeQuery, parentID, ownerID string) error {
	if m == nil || ctx == nil || tx == nil || !hexID(parentID) {
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
	return s.checkMediaCategoryLayoutReadTx(ctx, tx, parentID, ownerID)
}

// checkMediaCategoryLayoutReadTx must run under a tree fence with every query
// on the same SQLite transaction; it never writes or grants authorization.
func (s *SQLStore) checkMediaCategoryLayoutReadTx(ctx context.Context, tx treeQuery, parentID, ownerID string) error {
	if err := s.verifyRoot(ctx, tx); err != nil {
		return err
	}
	if err := s.requireListingReady(ctx, tx); err != nil {
		return err
	}
	if err := s.checkDirectory(ctx, tx, parentID, ""); err != nil {
		return err
	}
	var chain []Entry
	for id := parentID; id != s.rootID; {
		if len(chain) >= 3 {
			return ErrInvalid
		}
		_, entry, err := s.recordByID(ctx, tx, id)
		if err != nil || entry.Kind != "directory" {
			return ErrInvalid
		}
		chain = append(chain, entry)
		id = entry.ParentID
	}
	if len(chain) == 0 {
		return ErrInvalid
	}
	top := chain[len(chain)-1]
	if top.Name == "lyrics" {
		if len(chain) > 3 {
			return ErrInvalid
		}
		return s.scanDirectEntriesTx(ctx, tx, parentID, func(entry Entry, index string, pending *Placement) error {
			if entry.Kind == "directory" {
				if pending != nil {
					return ErrInvalid
				}
				return nil
			}
			if entry.Kind != "lyric" {
				return ErrInvalid
			}
			if ownerID == "" {
				return nil
			}
			var placement Placement
			var e error
			if pending != nil {
				placement = *pending
			} else {
				placement, e = s.placementFor(ctx, tx, entry, index)
			}
			if e != nil {
				return ErrInvalid
			}
			if placement.OwnerID != ownerID {
				return ErrConflict
			}
			return nil
		})
	}
	if len(chain) != 2 && len(chain) != 3 {
		return ErrInvalid
	}
	if top.Name != "music" && top.Name != "vido" {
		return ErrInvalid
	}
	category := chain[len(chain)-2].ObjectID
	nested := len(chain) == 3
	checkOwner := func(entry Entry, index string, pending *Placement) error {
		if ownerID == "" || entry.ParentID != parentID {
			return nil
		}
		var placement Placement
		var err error
		if pending != nil {
			placement = *pending
		} else {
			isS3, e := s.checkIndexedS3(ctx, tx, entry, index)
			if e != nil {
				return ErrInvalid
			}
			if isS3 {
				var slot string
				var revision int64
				var sealed []byte
				if e = tx.QueryRowContext(ctx, `SELECT blob_index,revision,sealed FROM sealed_tree_placements WHERE object_index=?`, index).Scan(&slot, &revision, &sealed); e != nil {
					return ErrInvalid
				}
				s3, e := s.openIndexedS3Placement(ctx, tx, entry.ObjectID, slot, index, revision, sealed)
				if e != nil {
					return ErrInvalid
				}
				if s3.MemberID != ownerID {
					return ErrConflict
				}
				return nil
			}
			placement, err = s.placementFor(ctx, tx, entry, index)
		}
		if err != nil {
			return ErrInvalid
		}
		if placement.OwnerID != ownerID {
			return ErrConflict
		}
		return nil
	}
	var inspectDescendants func(string, int) error
	inspectDescendants = func(parent string, depth int) error {
		if depth > 128 {
			return ErrInvalid
		}
		return s.scanDirectEntriesTx(ctx, tx, parent, func(entry Entry, index string, pending *Placement) error {
			if entry.Kind == "directory" {
				if pending != nil {
					return ErrInvalid
				}
				return inspectDescendants(entry.ObjectID, depth+1)
			}
			if !nested || depth != 1 {
				return ErrConflict
			}
			return checkOwner(entry, index, pending)
		})
	}
	return s.scanDirectEntriesTx(ctx, tx, category, func(entry Entry, index string, pending *Placement) error {
		if entry.Kind != "directory" {
			if nested {
				return ErrConflict
			}
			return checkOwner(entry, index, pending)
		}
		if pending != nil {
			return ErrInvalid
		}
		return inspectDescendants(entry.ObjectID, 1)
	})
}
