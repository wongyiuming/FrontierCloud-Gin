package sealedtree

import "context"

// completedNativePublicationOperation identifies the single authenticated
// historical publication for an exact native placement. The caller must
// supply the already-authenticated object and blob IDs in its fenced SQL
// transaction. A historical receipt does not prove current volume contents.
func (s *SQLStore) completedNativePublicationOperation(ctx context.Context, tx treeQuery, objectID, blobID string) (string, error) {
	if !s.valid() || ctx == nil || tx == nil || objectID == s.rootID || objectID == blobID {
		return "", ErrInvalid
	}
	object, err := s.tree.ObjectIndex(objectID)
	if err != nil {
		return "", err
	}
	blob, err := s.tree.BlobIndex(blobID)
	if err != nil {
		return "", err
	}
	var op string
	var count int
	err = tx.QueryRowContext(ctx, `SELECT COALESCE(MIN(operation_id),''),COUNT(*) FROM (
		SELECT operation_id FROM sealed_tree_operation_ids WHERE completed=1 AND object_index=? AND blob_index=? LIMIT 2
	) AS candidates`, object, blob).Scan(&op, &count)
	if err != nil {
		return "", err
	}
	if count != 1 || op == objectID || op == blobID {
		return "", ErrConflict
	}
	if done, err := s.completed(ctx, tx, op); err != nil || !done {
		return "", ErrConflict
	}
	return op, nil
}

// Revalidation of a saved intent uses the operation primary key directly.
// The original reverse lookup is needed only when first queuing the delete.
func (s *SQLStore) verifyCompletedNativePublication(ctx context.Context, tx treeQuery, objectID, blobID, operation string) error {
	if !hexID(operation) || operation == objectID || operation == blobID {
		return ErrConflict
	}
	object, objectErr := s.tree.ObjectIndex(objectID)
	blob, blobErr := s.tree.BlobIndex(blobID)
	var actualObject, actualBlob string
	if objectErr != nil || blobErr != nil || tx.QueryRowContext(ctx, `SELECT object_index,blob_index FROM sealed_tree_operation_ids WHERE operation_id=? AND completed=1`, operation).Scan(&actualObject, &actualBlob) != nil ||
		actualObject != object || actualBlob != blob {
		return ErrConflict
	}
	if complete, err := s.completed(ctx, tx, operation); err != nil || !complete {
		return ErrConflict
	}
	return nil
}
