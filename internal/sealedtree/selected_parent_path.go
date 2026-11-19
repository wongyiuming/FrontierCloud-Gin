package sealedtree

import "context"

// CheckSelectedParentPathTx verifies the Admin's complete logical directory
// against the authenticated parent chain in the same write transaction. It
// prevents a path resolved before locking from silently following a renamed
// or moved directory. Names never leave the trusted Master or enter an Owner
// capability. The caller owns authorization and the enclosing transaction.
func (m *CoordinatedMutation) CheckSelectedParentPathTx(ctx context.Context, tx treeQuery, parentID string, parts []string) error {
	if m == nil || ctx == nil || tx == nil || !hexID(parentID) || len(parts) == 0 || len(parts) >= 128 {
		return ErrInvalid
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.store
	if !m.active || !s.valid() || ctx.Err() != nil {
		return ErrInvalid
	}
	id := parentID
	seen := make(map[string]bool, len(parts))
	for i := len(parts) - 1; i >= 0; i-- {
		if !validComponent(parts[i]) || id == s.rootID || seen[id] {
			return ErrConflict
		}
		seen[id] = true
		_, entry, err := s.recordByID(ctx, tx, id)
		if err != nil || entry.Kind != "directory" || entry.Name != parts[i] {
			return ErrConflict
		}
		id = entry.ParentID
	}
	if id != s.rootID {
		return ErrConflict
	}
	return ctx.Err()
}
