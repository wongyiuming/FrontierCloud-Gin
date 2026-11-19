package sealedtree

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
)

// Listing rows and their counts use keyed identifiers/MACs only. The trusted
// Master must still enforce authorization. An observer of the database can
// see grouping, counts and accesses, but not logical names or the keyed
// meaning of a visibility group. Whole-database rollback and non-cooperative
// SQL writers require separate fencing/recovery gates.
const listingSentinel = "0000000000000000000000000000000000000000000000000000000000000000"

func (s *SQLStore) listingMAC(domain string, values ...string) string {
	m := hmac.New(sha256.New, s.tree.indexKey[:])
	m.Write([]byte("frontiercloud:sealed-tree:listing:" + domain + ":v1\x00"))
	for _, v := range values {
		m.Write([]byte(strconv.Itoa(len(v))))
		m.Write([]byte{':'})
		m.Write([]byte(v))
	}
	return hex.EncodeToString(m.Sum(nil))
}
func (s *SQLStore) listingGroup(parent string, visible bool) string {
	v := "hidden"
	if visible {
		v = "visible"
	}
	return s.listingMAC("group", parent, v)
}

const (
	listingHidden = iota
	listingVisibleGroup
	listingInternal
)

func (s *SQLStore) listingClassGroup(parent string, class int) string {
	if class == listingInternal {
		return s.listingMAC("group", parent, "internal")
	}
	return s.listingGroup(parent, class == listingVisibleGroup)
}
func listingClass(facts *Facts) int {
	if facts != nil && (facts.InternalPlaceholder || facts.S3Deletion != nil || facts.DirectoryDeletion != nil || facts.Revocation != nil && facts.Revocation.SelectedDelete) {
		return listingInternal
	}
	if listingVisible(facts) {
		return listingVisibleGroup
	}
	return listingHidden
}
func (s *SQLStore) listingKey(group, lookup string) string { return s.listingMAC("key", group, lookup) }
func (s *SQLStore) listingSummaryObject(group string) string {
	return s.listingMAC("summary-object", group)
}
func (s *SQLStore) listingRowMAC(group, lookup, object string, count, revision int64) string {
	return s.listingMAC("row-v2", group, lookup, object, strconv.FormatInt(count, 10), strconv.FormatInt(revision, 10))
}
func (s *SQLStore) listingMetaMAC(state int, cursor string) string {
	return s.listingMAC("meta-v2-internal-group", strconv.Itoa(state), cursor)
}
func listingVisible(facts *Facts) bool {
	return facts != nil && !facts.InternalPlaceholder && facts.Revocation == nil && facts.S3Deletion == nil && facts.DirectoryDeletion == nil && (facts.Visibility == nil || facts.Visibility.Hidden == 0)
}

func (s *SQLStore) requireListingReady(ctx context.Context, tx treeQuery) error {
	var state int
	var cursor, mac string
	if tx.QueryRowContext(ctx, `SELECT state,build_cursor,mac FROM sealed_tree_listing_meta WHERE singleton=1`).Scan(&state, &cursor, &mac) != nil || state != 1 || cursor != "" || !hmac.Equal([]byte(mac), []byte(s.listingMetaMAC(state, cursor))) {
		return ErrInvalid
	}
	return nil
}
func (s *SQLStore) createListingGroup(ctx context.Context, tx treeQuery, parent string, class int) error {
	group := s.listingClassGroup(parent, class)
	object := s.listingSummaryObject(group)
	key := s.listingKey(group, listingSentinel)
	_, err := tx.ExecContext(ctx, `INSERT INTO sealed_tree_listing(index_key,group_tag,lookup_tag,object_index,entry_count,group_revision,mac) VALUES(?,?,?,?,0,0,?)`, key, group, listingSentinel, object, s.listingRowMAC(group, listingSentinel, object, 0, 0))
	if err != nil {
		return ErrConflict
	}
	return nil
}
func (s *SQLStore) initListing(ctx context.Context, tx treeQuery) error {
	if err := s.createListingGroup(ctx, tx, s.rootID, listingVisibleGroup); err != nil {
		return err
	}
	if err := s.createListingGroup(ctx, tx, s.rootID, listingHidden); err != nil {
		return err
	}
	if err := s.createListingGroup(ctx, tx, s.rootID, listingInternal); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO sealed_tree_listing_meta(singleton,state,build_cursor,mac) VALUES(1,1,'',?)`, s.listingMetaMAC(1, ""))
	return err
}

func (s *SQLStore) listingSummary(ctx context.Context, tx treeQuery, group string) (int64, int64, error) {
	key := s.listingKey(group, listingSentinel)
	object := s.listingSummaryObject(group)
	var g, l, o, mac string
	var n, revision int64
	if tx.QueryRowContext(ctx, `SELECT group_tag,lookup_tag,object_index,entry_count,group_revision,mac FROM sealed_tree_listing WHERE index_key=?`, key).Scan(&g, &l, &o, &n, &revision, &mac) != nil || g != group || l != listingSentinel || o != object || n < 0 || revision < 0 || !hmac.Equal([]byte(mac), []byte(s.listingRowMAC(group, l, o, n, revision))) {
		return 0, 0, ErrInvalid
	}
	return n, revision, nil
}
func (s *SQLStore) listingAdjust(ctx context.Context, tx treeQuery, group string, delta int64) error {
	n, revision, err := s.listingSummary(ctx, tx, group)
	if err != nil || delta < -1 || delta > 1 || delta < 0 && n == 0 || delta > 0 && n == int64(^uint64(0)>>1) || revision == int64(^uint64(0)>>1) {
		return ErrInvalid
	}
	newCount := n + delta
	object := s.listingSummaryObject(group)
	key := s.listingKey(group, listingSentinel)
	result, err := tx.ExecContext(ctx, `UPDATE sealed_tree_listing SET entry_count=?,group_revision=?,mac=? WHERE index_key=? AND entry_count=? AND group_revision=?`, newCount, revision+1, s.listingRowMAC(group, listingSentinel, object, newCount, revision+1), key, n, revision)
	if err != nil {
		return ErrConflict
	}
	if count, e := result.RowsAffected(); e != nil || count != 1 {
		return ErrConflict
	}
	return nil
}
func (s *SQLStore) listingAdd(ctx context.Context, tx treeQuery, entry Entry, record Record, class int) error {
	if record.Lookup == listingSentinel {
		return ErrInvalid
	}
	group := s.listingClassGroup(entry.ParentID, class)
	key := s.listingKey(group, record.Lookup)
	_, err := tx.ExecContext(ctx, `INSERT INTO sealed_tree_listing(index_key,group_tag,lookup_tag,object_index,entry_count,group_revision,mac) VALUES(?,?,?,?,-1,0,?)`, key, group, record.Lookup, record.ObjectIndex, s.listingRowMAC(group, record.Lookup, record.ObjectIndex, -1, 0))
	if err != nil {
		return ErrConflict
	}
	return s.listingAdjust(ctx, tx, group, 1)
}
func (s *SQLStore) listingRemove(ctx context.Context, tx treeQuery, entry Entry, record Record, class int) error {
	group := s.listingClassGroup(entry.ParentID, class)
	key := s.listingKey(group, record.Lookup)
	var object, mac string
	var count, revision int64
	if tx.QueryRowContext(ctx, `SELECT object_index,entry_count,group_revision,mac FROM sealed_tree_listing WHERE index_key=? AND group_tag=? AND lookup_tag=?`, key, group, record.Lookup).Scan(&object, &count, &revision, &mac) != nil || object != record.ObjectIndex || count != -1 || revision != 0 || !hmac.Equal([]byte(mac), []byte(s.listingRowMAC(group, record.Lookup, object, -1, revision))) {
		return ErrInvalid
	}
	result, err := tx.ExecContext(ctx, `DELETE FROM sealed_tree_listing WHERE index_key=? AND object_index=?`, key, object)
	if err != nil {
		return ErrConflict
	}
	if n, e := result.RowsAffected(); e != nil || n != 1 {
		return ErrConflict
	}
	return s.listingAdjust(ctx, tx, group, -1)
}

// lockIndexedWriter is used for every normal mutation. Incomplete/absent
// index build fails closed. The dedicated explicit builder uses lockWriter
// directly after verifying its authenticated build state.
func (s *SQLStore) lockIndexedWriter(ctx context.Context, tx treeQuery) error {
	if err := lockWriter(ctx, tx); err != nil {
		return err
	}
	return s.requireListingReady(ctx, tx)
}
