package sealedtree

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"unicode/utf8"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/logarchive"
	"github.com/wongyiuming/FrontierCloud-Gin/migrations"
)

// ErrConflict indicates an existing sibling, object, stale revision, or cycle.
// It intentionally contains no business name or identifier.
var ErrConflict = errors.New("sealed tree conflict")

// SQLStore is an isolated SQLite namespace prototype. It is not a migration,
// does not manage media bytes, and must not be attached to the running product
// until legacy tables, journals, backups and node protocols are migrated too.
// Only opaque tags and ciphertext are provided as SQL arguments.
type SQLStore struct {
	logArchive atomic.Pointer[logarchive.Catalog]
	db         *sql.DB
	tree       *Tree
	rootID     string
	fenceMu    sync.RWMutex
	fence      *TreeFence
	// Set only by same-package synthetic tests. Production constructors leave
	// this false and all mutation methods then require an attached OS fence.
	unsafePrototype bool
}

func (t *Tree) namespaceVerifier(rootID string) (string, error) {
	if t == nil || !t.ready || !hexID(rootID) {
		return "", ErrInvalid
	}
	mac := hmac.New(sha256.New, t.indexKey[:])
	_, _ = mac.Write([]byte("frontiercloud:sealed-tree:namespace:v1\x00" + rootID))
	return hex.EncodeToString(mac.Sum(nil)), nil
}

// InitializeSQLite creates a sealed-only namespace in an otherwise empty
// SQLite database. This guard prevents treating an existing plaintext database
// as encrypted merely by adding a new index table. Caller owns DB durability,
// file permissions, key/salt persistence and a verified recovery strategy.
func InitializeSQLite(ctx context.Context, db *sql.DB, tree *Tree, rootID string) (*SQLStore, error) {
	if db == nil {
		return nil, ErrInvalid
	}
	verifier, err := tree.namespaceVerifier(rootID)
	if err != nil {
		return nil, err
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var version string
	if err = tx.QueryRowContext(ctx, "SELECT sqlite_version()").Scan(&version); err != nil || version == "" {
		return nil, ErrInvalid
	}
	var count int
	if err = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM sqlite_master WHERE type IN ('table','view','trigger') AND name NOT LIKE 'sqlite_%'").Scan(&count); err != nil || count != 0 {
		return nil, ErrConflict
	}
	rootSealed, err := tree.SealRoot(rootID)
	if err != nil {
		return nil, err
	}
	rootEncryption, err := rootEncryptionID(rootSealed)
	if err != nil {
		return nil, err
	}
	statements, err := migrations.SealedTreeStatements("sqlite")
	if err != nil {
		return nil, err
	}
	for _, statement := range statements {
		if _, err = tx.ExecContext(ctx, statement); err != nil {
			return nil, err
		}
	}
	if _, err = reserveID(ctx, tx, rootEncryption); err != nil {
		return nil, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO sealed_tree_meta(singleton,version,verifier,salt,root_encryption_id,root_sealed,write_fence) VALUES(1,1,?,?,?,?,0)`, verifier, tree.salt[:], rootEncryption, rootSealed); err != nil {
		return nil, err
	}
	store := &SQLStore{db: db, tree: tree, rootID: rootID}
	if err = store.initListing(ctx, tx); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return store, nil
}

// OpenSQLite checks an expected root binding without regenerating keys or salt.
// Ordinary restarts may use OpenStoredSQLite to recover the root automatically.
func OpenSQLite(ctx context.Context, db *sql.DB, tree *Tree, rootID string) (*SQLStore, error) {
	store, err := OpenStoredSQLite(ctx, db, tree)
	if err != nil || store.rootID != rootID {
		return nil, ErrInvalid
	}
	return store, nil
}

// OpenStoredSQLite recovers the encrypted root ID with a pre-derived tree key
// and verifies its persisted salt and permanent encryption-ID reservation.
func OpenStoredSQLite(ctx context.Context, db *sql.DB, tree *Tree) (*SQLStore, error) {
	if db == nil || tree == nil || !tree.ready {
		return nil, ErrInvalid
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var version int
	var got, rootEnc string
	var salt, sealed []byte
	if err = tx.QueryRowContext(ctx, `SELECT version,verifier,salt,root_encryption_id,root_sealed FROM sealed_tree_meta WHERE singleton=1`).Scan(&version, &got, &salt, &rootEnc, &sealed); err != nil || version != 1 || !hmac.Equal(salt, tree.salt[:]) {
		return nil, ErrInvalid
	}
	rootID, err := tree.OpenRoot(sealed)
	if err != nil {
		return nil, ErrInvalid
	}
	expected, err := tree.namespaceVerifier(rootID)
	actualID, identityErr := rootEncryptionID(sealed)
	if err != nil || identityErr != nil || !hmac.Equal([]byte(got), []byte(expected)) || !hmac.Equal([]byte(rootEnc), []byte(actualID)) {
		return nil, ErrInvalid
	}
	var count int
	if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM sealed_tree_encryption_ids WHERE encryption_id=?`, actualID).Scan(&count); err != nil || count != 1 {
		return nil, ErrInvalid
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return &SQLStore{db: db, tree: tree, rootID: rootID}, nil
}

// OpenSQLiteWithMaster reads only the public persisted tree salt and derives
// the tree key; no operator-provided root identifier is necessary on restart.
// The Master secret must come from its already protected key lifecycle.
func OpenSQLiteWithMaster(ctx context.Context, db *sql.DB, master []byte) (*SQLStore, error) {
	if db == nil {
		return nil, ErrInvalid
	}
	var salt []byte
	if err := db.QueryRowContext(ctx, `SELECT salt FROM sealed_tree_meta WHERE singleton=1 AND version=1`).Scan(&salt); err != nil {
		return nil, ErrInvalid
	}
	tree, err := New(master, salt)
	if err != nil {
		return nil, ErrInvalid
	}
	return OpenStoredSQLite(ctx, db, tree)
}

func (s *SQLStore) valid() bool {
	return s != nil && s.db != nil && s.tree != nil && s.tree.ready && hexID(s.rootID)
}

// CapacityKey returns a separate Master-only subkey for the same namespace.
// The caller clears its copy and keeps it out of diagnostics and Owner traffic.
func (s *SQLStore) CapacityKey() ([]byte, error) {
	if !s.valid() {
		return nil, ErrInvalid
	}
	return append([]byte(nil), s.tree.capacityKey[:]...), nil
}

func (s *SQLStore) verifyRoot(ctx context.Context, tx treeQuery) error {
	var version int
	var verifier, storedID string
	var salt, sealed []byte
	if err := tx.QueryRowContext(ctx, `SELECT version,verifier,salt,root_encryption_id,root_sealed FROM sealed_tree_meta WHERE singleton=1`).Scan(&version, &verifier, &salt, &storedID, &sealed); err != nil || version != 1 || !hmac.Equal(salt, s.tree.salt[:]) {
		return ErrInvalid
	}
	root, err := s.tree.OpenRoot(sealed)
	expected, expectedErr := s.tree.namespaceVerifier(s.rootID)
	id, idErr := rootEncryptionID(sealed)
	if err != nil || expectedErr != nil || idErr != nil || root != s.rootID || !hmac.Equal([]byte(verifier), []byte(expected)) || !hmac.Equal([]byte(storedID), []byte(id)) {
		return ErrInvalid
	}
	var count int
	if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM sealed_tree_encryption_ids WHERE encryption_id=?`, id).Scan(&count); err != nil || count != 1 {
		return ErrInvalid
	}
	return nil
}

func lockWriter(ctx context.Context, tx treeQuery) error {
	result, err := tx.ExecContext(ctx, `UPDATE sealed_tree_meta SET write_fence=write_fence+1 WHERE singleton=1 AND write_fence<9223372036854775807`)
	if err != nil {
		return err
	}
	if count, err := result.RowsAffected(); err != nil || count != 1 {
		return ErrConflict
	}
	return nil
}

func reserveEncryptionID(ctx context.Context, tx treeQuery, record Record) (string, error) {
	id, err := EncryptionID(record)
	if err != nil {
		return "", err
	}
	return reserveID(ctx, tx, id)
}

func reserveID(ctx context.Context, tx treeQuery, id string) (string, error) {
	if !hexID(id) {
		return "", ErrInvalid
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO sealed_tree_encryption_ids(encryption_id) VALUES(?)`, id); err != nil {
		return "", ErrConflict
	}
	return id, nil
}

func scanRecord(row interface{ Scan(...any) error }) (Record, error) {
	var record Record
	var storedID string
	if err := row.Scan(&record.ObjectIndex, &record.ParentIndex, &record.Lookup, &record.Revision, &storedID, &record.Sealed); err != nil {
		return Record{}, err
	}
	actualID, err := EncryptionID(record)
	if err != nil || !hmac.Equal([]byte(storedID), []byte(actualID)) {
		return Record{}, ErrInvalid
	}
	return record, nil
}

func verifyNameReservation(ctx context.Context, tx treeQuery, record Record) error {
	id, err := EncryptionID(record)
	if err != nil {
		return ErrInvalid
	}
	var n int
	if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM sealed_tree_encryption_ids WHERE encryption_id=?`, id).Scan(&n); err != nil || n != 1 {
		return ErrInvalid
	}
	return nil
}

// Listing must not issue one database query per child on the Master. The
// caller supplies at most 257 records from one bounded page.
func verifyNameReservations(ctx context.Context, tx treeQuery, records []Record) error {
	if len(records) == 0 {
		return nil
	}
	if len(records) > 257 {
		return ErrInvalid
	}
	args := make([]any, 0, len(records))
	seen := make(map[string]bool, len(records))
	for _, record := range records {
		id, err := EncryptionID(record)
		if err != nil || seen[id] {
			return ErrInvalid
		}
		seen[id] = true
		args = append(args, id)
	}
	marks := strings.TrimSuffix(strings.Repeat("?,", len(args)), ",")
	var n int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM sealed_tree_encryption_ids WHERE encryption_id IN (`+marks+`)`, args...).Scan(&n); err != nil || n != len(args) {
		return ErrInvalid
	}
	return nil
}

func (s *SQLStore) recordByID(ctx context.Context, tx treeQuery, id string) (Record, Entry, error) {
	index, err := s.tree.ObjectIndex(id)
	if err != nil {
		return Record{}, Entry{}, err
	}
	r, err := scanRecord(tx.QueryRowContext(ctx, `SELECT object_index,parent_index,lookup_tag,revision,encryption_id,sealed FROM sealed_tree_records WHERE object_index=?`, index))
	if err != nil {
		return Record{}, Entry{}, err
	}
	entry, err := s.tree.OpenRecord(r)
	if err != nil || entry.ObjectID != id {
		return Record{}, Entry{}, ErrInvalid
	}
	if err = verifyNameReservation(ctx, tx, r); err != nil {
		return Record{}, Entry{}, err
	}
	return r, entry, nil
}

// checkDirectory validates that every ancestor is an authenticated directory
// connected to this namespace's root, while rejecting cycles and excessive
// depth. The caller owns the transaction fence throughout a mutation.
func (s *SQLStore) checkDirectory(ctx context.Context, tx treeQuery, id, forbidden string) error {
	seen := map[string]bool{}
	for depth := 0; depth < 128; depth++ {
		if id == forbidden && forbidden != "" {
			return ErrConflict
		}
		if id == s.rootID {
			return nil
		}
		if !hexID(id) || seen[id] {
			return ErrConflict
		}
		seen[id] = true
		_, entry, err := s.recordByID(ctx, tx, id)
		if err != nil || entry.Kind != "directory" {
			return ErrConflict
		}
		id = entry.ParentID
	}
	return ErrConflict
}

// checkChildPathBounds validates the complete proposed logical path without
// persisting it. A directory move must additionally preflight all descendants;
// this single-node check is not sufficient to enable product moves.
func (s *SQLStore) checkChildPathBounds(ctx context.Context, tx treeQuery, parentID, component string) error {
	if !validComponent(component) {
		return ErrInvalid
	}
	bytes, runes := len(component), utf8.RuneCountInString(component)
	current := parentID
	seen := map[string]bool{}
	for depth := 0; depth < 128 && current != s.rootID; depth++ {
		if seen[current] {
			return ErrInvalid
		}
		seen[current] = true
		_, entry, err := s.recordByID(ctx, tx, current)
		if err != nil || entry.Kind != "directory" {
			return ErrInvalid
		}
		bytes += 1 + len(entry.Name)
		runes += 1 + utf8.RuneCountInString(entry.Name)
		if bytes > 4096 || runes > 1024 {
			return ErrInvalid
		}
		current = entry.ParentID
	}
	if current != s.rootID || bytes > 4096 || runes > 1024 {
		return ErrInvalid
	}
	return nil
}

// Create inserts one complete sealed row and its permanent encryption-ID
// reservation atomically. It does not create or publish a payload file.
func (s *SQLStore) Create(ctx context.Context, entry Entry) error {
	if !s.prototypeOnly() {
		return ErrFactsRequired
	}
	return s.createDirectory(ctx, entry, nil)
}

// CreateDirectoryWithFacts commits a new directory and its encrypted facts in
// one SQLite transaction. This does not implement product authorization or
// migration activation.
func (s *SQLStore) CreateDirectoryWithFacts(ctx context.Context, entry Entry, facts Facts) error {
	if facts.InternalPlaceholder || facts.InternalPromotedPlaceholder || facts.Revocation != nil || facts.DirectoryDeletion != nil || !factsCompatible(entry, facts) {
		return ErrInvalid
	}
	return s.createDirectory(ctx, entry, &facts)
}

func (s *SQLStore) createDirectory(ctx context.Context, entry Entry, facts *Facts) error {
	if !s.valid() || entry.ObjectID == s.rootID || entry.Kind != "directory" {
		return ErrInvalid
	}
	release, err := s.acquireMutation(ctx)
	if err != nil {
		return err
	}
	defer release()
	record, err := s.tree.Seal(entry.ParentID, entry.ObjectID, entry.Kind, entry.Name, 1)
	if err != nil {
		return err
	}
	var sealedFacts *FactsRecord
	if facts != nil {
		if !factsCompatible(entry, *facts) {
			return ErrInvalid
		}
		value, sealErr := s.tree.SealFacts(*facts, 1)
		if sealErr != nil || value.ObjectIndex != record.ObjectIndex {
			return ErrInvalid
		}
		sealedFacts = &value
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = s.createDirectoryTx(ctx, tx, entry, facts, record, sealedFacts); err != nil {
		return err
	}
	return tx.Commit()
}

// createDirectoryTx is the same authenticated directory mutation on an
// already-fenced transaction. The caller owns authorization and rollback.
func (s *SQLStore) createDirectoryTx(ctx context.Context, tx treeQuery, entry Entry, facts *Facts, record Record, sealedFacts *FactsRecord) error {
	var err error
	if err = s.lockIndexedWriter(ctx, tx); err != nil {
		return err
	}
	if err = s.verifyRoot(ctx, tx); err != nil {
		return err
	}
	if err = s.checkDirectory(ctx, tx, entry.ParentID, entry.ObjectID); err != nil {
		return err
	}
	if err = s.checkChildPathBounds(ctx, tx, entry.ParentID, entry.Name); err != nil {
		return err
	}
	if !s.prototypeOnly() && (facts == nil || !facts.InternalPlaceholder) {
		if _, err = s.listingAncestorAnchor(ctx, tx, entry.ParentID, true); err != nil {
			return err
		}
	}
	encID, err := reserveEncryptionID(ctx, tx, record)
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO sealed_tree_records(object_index,parent_index,lookup_tag,revision,encryption_id,sealed) VALUES(?,?,?,?,?,?)`, record.ObjectIndex, record.ParentIndex, record.Lookup, record.Revision, encID, record.Sealed); err != nil {
		return ErrConflict
	}
	if sealedFacts != nil {
		factID, factErr := FactsEncryptionID(*sealedFacts)
		if factErr != nil {
			return factErr
		}
		if _, factErr = reserveID(ctx, tx, factID); factErr != nil {
			return factErr
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO sealed_tree_facts(object_index,revision,encryption_id,sealed) VALUES(?,?,?,?)`, sealedFacts.ObjectIndex, sealedFacts.Revision, factID, sealedFacts.Sealed); err != nil {
			return ErrConflict
		}
	}
	if err = s.listingAdd(ctx, tx, entry, record, listingClass(facts)); err != nil {
		return err
	}
	if err = s.createListingGroup(ctx, tx, entry.ObjectID, listingVisibleGroup); err != nil {
		return err
	}
	if err = s.createListingGroup(ctx, tx, entry.ObjectID, listingHidden); err != nil {
		return err
	}
	if err = s.createListingGroup(ctx, tx, entry.ObjectID, listingInternal); err != nil {
		return err
	}
	return nil
}

// CreateFile atomically stores an encrypted tree row and encrypted placement
// metadata with separate, permanently reserved random encryption identities
// and a unique blob reservation. It does not publish or prove payload bytes:
// actual use requires a separate authenticated filesystem publication journal.
func (s *SQLStore) CreateFile(ctx context.Context, entry Entry, placement Placement) error {
	if !s.prototypeOnly() {
		return ErrFactsRequired
	}
	if !s.valid() || entry.ObjectID == s.rootID || entry.Kind == "directory" || entry.ObjectID != placement.ObjectID {
		return ErrInvalid
	}
	release, err := s.acquireMutation(ctx)
	if err != nil {
		return err
	}
	defer release()
	record, err := s.tree.Seal(entry.ParentID, entry.ObjectID, entry.Kind, entry.Name, 1)
	if err != nil {
		return err
	}
	location, err := s.tree.SealPlacement(placement, 1)
	if err != nil || location.ObjectIndex != record.ObjectIndex {
		return ErrInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = s.lockIndexedWriter(ctx, tx); err != nil {
		return err
	}
	if err = s.verifyRoot(ctx, tx); err != nil {
		return err
	}
	if err = s.checkDirectory(ctx, tx, entry.ParentID, entry.ObjectID); err != nil {
		return err
	}
	if err = s.checkChildPathBounds(ctx, tx, entry.ParentID, entry.Name); err != nil {
		return err
	}
	nameID, err := reserveEncryptionID(ctx, tx, record)
	if err != nil {
		return err
	}
	locationID, err := PlacementEncryptionID(location)
	if err != nil {
		return err
	}
	if _, err = reserveID(ctx, tx, locationID); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO sealed_tree_blob_ids(blob_index) VALUES(?)`, location.BlobIndex); err != nil {
		return ErrConflict
	}
	aliasIndex, err := s.tree.BlobIndex(placement.ReadAlias)
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO sealed_tree_blob_ids(blob_index) VALUES(?)`, aliasIndex); err != nil {
		return ErrConflict
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO sealed_tree_records(object_index,parent_index,lookup_tag,revision,encryption_id,sealed) VALUES(?,?,?,?,?,?)`, record.ObjectIndex, record.ParentIndex, record.Lookup, record.Revision, nameID, record.Sealed); err != nil {
		return ErrConflict
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO sealed_tree_placements(object_index,blob_index,revision,encryption_id,sealed) VALUES(?,?,?,?,?)`, location.ObjectIndex, location.BlobIndex, location.Revision, locationID, location.Sealed); err != nil {
		return ErrConflict
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO sealed_tree_aliases(alias_index,object_index) VALUES(?,?)`, aliasIndex, location.ObjectIndex); err != nil {
		return ErrConflict
	}
	if err = s.listingAdd(ctx, tx, entry, record, listingHidden); err != nil {
		return err
	}
	return tx.Commit()
}

func scanPlacement(row interface{ Scan(...any) error }) (PlacementRecord, error) {
	var record PlacementRecord
	var storedID string
	if err := row.Scan(&record.ObjectIndex, &record.BlobIndex, &record.Revision, &storedID, &record.Sealed); err != nil {
		return PlacementRecord{}, err
	}
	actualID, err := PlacementEncryptionID(record)
	if err != nil || !hmac.Equal([]byte(storedID), []byte(actualID)) {
		return PlacementRecord{}, ErrInvalid
	}
	return record, nil
}

func (s *SQLStore) placementFor(ctx context.Context, tx treeQuery, entry Entry, index string) (Placement, error) {
	r, err := scanPlacement(tx.QueryRowContext(ctx, `SELECT object_index,blob_index,revision,encryption_id,sealed FROM sealed_tree_placements WHERE object_index=?`, index))
	if err != nil {
		return Placement{}, err
	}
	value, err := s.tree.OpenPlacement(r)
	if err != nil || value.ObjectID != entry.ObjectID {
		return Placement{}, ErrInvalid
	}
	encID, err := PlacementEncryptionID(r)
	if err != nil {
		return Placement{}, err
	}
	var encryptionCount, blobCount int
	if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM sealed_tree_encryption_ids WHERE encryption_id=?`, encID).Scan(&encryptionCount); err != nil || encryptionCount != 1 {
		return Placement{}, ErrInvalid
	}
	if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM sealed_tree_blob_ids WHERE blob_index=?`, r.BlobIndex).Scan(&blobCount); err != nil || blobCount != 1 {
		return Placement{}, ErrInvalid
	}
	aliasIndex, err := s.tree.BlobIndex(value.ReadAlias)
	if err != nil || aliasIndex == r.BlobIndex {
		return Placement{}, ErrInvalid
	}
	if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM sealed_tree_blob_ids WHERE blob_index=?`, aliasIndex).Scan(&blobCount); err != nil || blobCount != 1 {
		return Placement{}, ErrInvalid
	}
	var aliasObject string
	if err = tx.QueryRowContext(ctx, `SELECT object_index FROM sealed_tree_aliases WHERE alias_index=?`, aliasIndex).Scan(&aliasObject); err != nil || !hmac.Equal([]byte(aliasObject), []byte(r.ObjectIndex)) {
		return Placement{}, ErrInvalid
	}
	return value, nil
}

// GetPlacement returns authenticated in-memory placement after validating the
// namespace ancestry. It does not grant access to bytes or return a file path.
// This single snapshot is not a fence and must not authorize public reads;
// use ReadVisibleObjectWithLease in a future properly gated read path.
func (s *SQLStore) GetPlacement(ctx context.Context, objectID string) (Placement, error) {
	value, _, err := s.getPlacementWithRevision(ctx, objectID)
	return value, err
}

func (s *SQLStore) getPlacementWithRevision(ctx context.Context, objectID string) (Placement, int64, error) {
	if !s.valid() || objectID == s.rootID {
		return Placement{}, 0, ErrInvalid
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return Placement{}, 0, err
	}
	defer tx.Rollback()
	if err = s.verifyRoot(ctx, tx); err != nil {
		return Placement{}, 0, err
	}
	record, entry, err := s.recordByID(ctx, tx, objectID)
	if err != nil {
		return Placement{}, 0, err
	}
	if entry.Kind == "directory" || s.checkDirectory(ctx, tx, entry.ParentID, entry.ObjectID) != nil {
		return Placement{}, 0, ErrInvalid
	}
	value, err := s.placementFor(ctx, tx, entry, record.ObjectIndex)
	if err != nil {
		return Placement{}, 0, err
	}
	var revision int64
	if err = tx.QueryRowContext(ctx, `SELECT revision FROM sealed_tree_placements WHERE object_index=?`, record.ObjectIndex).Scan(&revision); err != nil || revision < 1 {
		return Placement{}, 0, ErrInvalid
	}
	if err = tx.Commit(); err != nil {
		return Placement{}, 0, err
	}
	return value, revision, nil
}

// Get authenticates the record and its full ancestor chain under one snapshot.
// It does not enforce visibility or hold a lease; it is not a public read grant.
func (s *SQLStore) Get(ctx context.Context, objectID string) (Entry, int64, error) {
	if !s.valid() || objectID == s.rootID {
		return Entry{}, 0, ErrInvalid
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return Entry{}, 0, err
	}
	defer tx.Rollback()
	if err = s.verifyRoot(ctx, tx); err != nil {
		return Entry{}, 0, err
	}
	r, entry, err := s.recordByID(ctx, tx, objectID)
	if err != nil {
		return Entry{}, 0, err
	}
	if err = s.checkDirectory(ctx, tx, entry.ParentID, entry.ObjectID); err != nil {
		return Entry{}, 0, err
	}
	if err = tx.Commit(); err != nil {
		return Entry{}, 0, err
	}
	return entry, r.Revision, nil
}

// Move uses an optimistic revision under one SQLite write fence. Directory IDs
// are stable, so moving/renaming a directory does not rewrite descendants. A
// move beneath itself or a descendant is rejected before an update is issued.
func (s *SQLStore) Move(ctx context.Context, objectID, newParentID, newName string, expectedRevision int64) (int64, error) {
	if !s.valid() || objectID == s.rootID || expectedRevision <= 0 || expectedRevision == int64(^uint64(0)>>1) {
		return 0, ErrInvalid
	}
	release, err := s.acquireMutation(ctx)
	if err != nil {
		return 0, err
	}
	defer release()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	if err = s.lockIndexedWriter(ctx, tx); err != nil {
		return 0, err
	}
	if err = s.verifyRoot(ctx, tx); err != nil {
		return 0, err
	}
	revision, err := s.moveTx(ctx, tx, objectID, newParentID, newName, expectedRevision)
	if err != nil {
		return 0, err
	}
	if err = tx.Commit(); err != nil {
		return 0, err
	}
	return revision, nil
}

// moveTx shares the authenticated, revisioned Move implementation with callers
// that resolve the source and apply related invariants in the same transaction.
func (s *SQLStore) moveTx(ctx context.Context, tx *sql.Tx, objectID, newParentID, newName string, expectedRevision int64) (int64, error) {
	var err error
	// Conservative until subtree-aware distributed fencing exists: moving an
	// ancestor while any owner revocation is unresolved could change the
	// operation's logical scope. This indexed existence check does not scan the
	// encrypted tree; no timeout silently clears an outstanding intent.
	var pending int
	if err = tx.QueryRowContext(ctx, `SELECT 1 FROM sealed_tree_revocations LIMIT 1`).Scan(&pending); err == nil {
		return 0, ErrRevocationPending
	} else if !errors.Is(err, sql.ErrNoRows) {
		return 0, ErrInvalid
	}
	old, entry, err := s.recordByID(ctx, tx, objectID)
	if err != nil {
		return 0, err
	}
	if old.Revision != expectedRevision {
		return 0, ErrConflict
	}
	if err = s.checkDirectory(ctx, tx, entry.ParentID, entry.ObjectID); err != nil {
		return 0, err
	}
	if err = s.checkDirectory(ctx, tx, newParentID, entry.ObjectID); err != nil {
		return 0, err
	}
	if err = s.checkChildPathBounds(ctx, tx, newParentID, newName); err != nil {
		return 0, err
	}
	if !s.prototypeOnly() {
		if _, err = s.listingAncestorAnchor(ctx, tx, newParentID, true); err != nil {
			return 0, err
		}
	}
	facts, _, factErr := s.factsFor(ctx, tx, entry, old.ObjectIndex)
	class := listingHidden
	if factErr == nil {
		class = listingClass(&facts)
		if class == listingInternal {
			return 0, ErrInvalid
		}
	} else if !errors.Is(factErr, sql.ErrNoRows) || !s.prototypeOnly() {
		return 0, ErrInvalid
	}
	updated, err := s.tree.Seal(newParentID, entry.ObjectID, entry.Kind, newName, old.Revision+1)
	if err != nil {
		return 0, err
	}
	encID, err := reserveEncryptionID(ctx, tx, updated)
	if err != nil {
		return 0, err
	}
	result, err := tx.ExecContext(ctx, `UPDATE sealed_tree_records SET parent_index=?,lookup_tag=?,revision=?,encryption_id=?,sealed=? WHERE object_index=? AND revision=?`, updated.ParentIndex, updated.Lookup, updated.Revision, encID, updated.Sealed, old.ObjectIndex, old.Revision)
	if err != nil {
		return 0, ErrConflict
	}
	if count, err := result.RowsAffected(); err != nil || count != 1 {
		return 0, ErrConflict
	}
	if err = s.listingRemove(ctx, tx, entry, old, class); err != nil {
		return 0, err
	}
	moved := entry
	moved.ParentID = newParentID
	moved.Name = newName
	if err = s.listingAdd(ctx, tx, moved, updated, class); err != nil {
		return 0, err
	}
	return updated.Revision, nil
}

// Find resolves an exact name inside an authenticated directory. No plaintext
// value is sent to SQLite; byte-distinct names remain distinct.
func (s *SQLStore) Find(ctx context.Context, parentID, name string) (Entry, int64, error) {
	if !s.valid() {
		return Entry{}, 0, ErrInvalid
	}
	group, err := s.tree.ParentIndex(parentID)
	if err != nil {
		return Entry{}, 0, err
	}
	lookup, err := s.tree.Lookup(parentID, name)
	if err != nil {
		return Entry{}, 0, err
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return Entry{}, 0, err
	}
	defer tx.Rollback()
	if err = s.verifyRoot(ctx, tx); err != nil {
		return Entry{}, 0, err
	}
	if err = s.checkDirectory(ctx, tx, parentID, ""); err != nil {
		return Entry{}, 0, err
	}
	r, err := scanRecord(tx.QueryRowContext(ctx, `SELECT object_index,parent_index,lookup_tag,revision,encryption_id,sealed FROM sealed_tree_records WHERE parent_index=? AND lookup_tag=?`, group, lookup))
	if err != nil {
		return Entry{}, 0, err
	}
	entry, err := s.tree.Open(parentID, r)
	if err != nil || entry.Name != name {
		return Entry{}, 0, ErrInvalid
	}
	if err = verifyNameReservation(ctx, tx, r); err != nil {
		return Entry{}, 0, err
	}
	if err = tx.Commit(); err != nil {
		return Entry{}, 0, err
	}
	return entry, r.Revision, nil
}

// List enumerates one authenticated directory in bounded pages. The cursor
// is a keyed opaque lookup tag, not a logical name or raw object identifier.
// Callers must independently authorize the directory and filter visibility.
func (s *SQLStore) List(ctx context.Context, parentID, after string, limit int) ([]Entry, string, error) {
	if !s.valid() || limit < 1 || limit > 256 || (after != "" && !hexID(after)) {
		return nil, "", ErrInvalid
	}
	group, err := s.tree.ParentIndex(parentID)
	if err != nil {
		return nil, "", err
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, "", err
	}
	defer tx.Rollback()
	if err = s.verifyRoot(ctx, tx); err != nil {
		return nil, "", err
	}
	if err = s.checkDirectory(ctx, tx, parentID, ""); err != nil {
		return nil, "", err
	}
	rows, err := tx.QueryContext(ctx, `SELECT object_index,parent_index,lookup_tag,revision,encryption_id,sealed FROM sealed_tree_records WHERE parent_index=? AND lookup_tag>? ORDER BY lookup_tag LIMIT ?`, group, after, limit+1)
	if err != nil {
		return nil, "", err
	}
	entries := make([]Entry, 0, limit)
	reservations := make([]Record, 0, limit+1)
	next := ""
	last := after
	for rows.Next() {
		r, err := scanRecord(rows)
		if err != nil {
			rows.Close()
			return nil, "", err
		}
		entry, err := s.tree.Open(parentID, r)
		if err != nil || r.Lookup <= last {
			rows.Close()
			return nil, "", ErrInvalid
		}
		reservations = append(reservations, r)
		if len(entries) == limit {
			next = last
			break
		}
		last = r.Lookup
		entries = append(entries, entry)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return nil, "", err
	}
	if err = rows.Close(); err != nil {
		return nil, "", err
	}
	if err = verifyNameReservations(ctx, tx, reservations); err != nil {
		return nil, "", err
	}
	if err = tx.Commit(); err != nil {
		return nil, "", err
	}
	return entries, next, nil
}

// Check verifies every sealed record, uniqueness history and parent chain. It
// returns counts only. It does not prove payload presence or absence of older
// plaintext files/WAL/backups outside this isolated database.
func (s *SQLStore) Check(ctx context.Context) (int64, error) {
	return s.check(ctx, nil)
}

func (s *SQLStore) check(ctx context.Context, visit func(RecoveryMediaPlacement) error) (int64, error) {
	if !s.valid() {
		return 0, ErrInvalid
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	if err = s.verifyRoot(ctx, tx); err != nil {
		return 0, err
	}
	if visit != nil {
		var unsettled bool
		if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM sealed_tree_pending_files) OR EXISTS(SELECT 1 FROM sealed_tree_revocations)`).Scan(&unsettled); err != nil {
			return 0, err
		}
		if unsettled {
			return 0, ErrConflict
		}
	}
	var orphanCount int
	if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM sealed_tree_placements p LEFT JOIN sealed_tree_records r ON p.object_index=r.object_index WHERE r.object_index IS NULL`).Scan(&orphanCount); err != nil || orphanCount != 0 {
		return 0, ErrInvalid
	}
	if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM sealed_tree_aliases a LEFT JOIN sealed_tree_placements p ON p.object_index=a.object_index WHERE p.object_index IS NULL`).Scan(&orphanCount); err != nil || orphanCount != 0 {
		return 0, ErrInvalid
	}
	if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM sealed_tree_revocations v LEFT JOIN sealed_tree_facts f ON f.object_index=v.object_index WHERE f.object_index IS NULL`).Scan(&orphanCount); err != nil || orphanCount != 0 {
		return 0, ErrInvalid
	}
	if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM (SELECT object_index FROM sealed_tree_aliases GROUP BY object_index HAVING COUNT(*)<>1) AS duplicates`).Scan(&orphanCount); err != nil || orphanCount != 0 {
		return 0, ErrInvalid
	}
	if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM sealed_tree_facts f LEFT JOIN sealed_tree_records r ON f.object_index=r.object_index WHERE r.object_index IS NULL`).Scan(&orphanCount); err != nil || orphanCount != 0 {
		return 0, ErrInvalid
	}
	if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM sealed_tree_pending_facts f LEFT JOIN sealed_tree_pending_files p ON f.operation_id=p.operation_id WHERE p.operation_id IS NULL`).Scan(&orphanCount); err != nil || orphanCount != 0 {
		return 0, ErrInvalid
	}
	hasCancellations, err := hasSelectedCancellationTable(ctx, tx)
	if err != nil {
		return 0, err
	}
	orphanQuery := `SELECT COUNT(*) FROM sealed_tree_operation_ids o LEFT JOIN sealed_tree_pending_files p ON p.operation_id=o.operation_id WHERE (o.completed=0 AND p.operation_id IS NULL) OR (o.completed=1 AND p.operation_id IS NOT NULL)`
	if hasCancellations {
		orphanQuery = `SELECT COUNT(*) FROM sealed_tree_operation_ids o LEFT JOIN sealed_tree_pending_files p ON p.operation_id=o.operation_id LEFT JOIN selected_upload_cancellations c ON c.operation_id=o.operation_id WHERE (o.completed=0 AND ((p.operation_id IS NULL AND c.operation_id IS NULL) OR (p.operation_id IS NOT NULL AND c.operation_id IS NOT NULL))) OR (o.completed=1 AND (p.operation_id IS NOT NULL OR c.operation_id IS NOT NULL))`
	}
	if err = tx.QueryRowContext(ctx, orphanQuery).Scan(&orphanCount); err != nil || orphanCount != 0 {
		return 0, ErrInvalid
	}
	if hasCancellations {
		if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM selected_upload_cancellations c LEFT JOIN sealed_tree_operation_ids o ON o.operation_id=c.operation_id WHERE o.operation_id IS NULL OR o.completed<>0`).Scan(&orphanCount); err != nil || orphanCount != 0 {
			return 0, ErrInvalid
		}
		after := ""
		for {
			rows, e := tx.QueryContext(ctx, `SELECT operation_id,object_index,blob_index,cancellation_mac FROM selected_upload_cancellations WHERE operation_id>? ORDER BY operation_id LIMIT 256`, after)
			if e != nil {
				return 0, e
			}
			count := 0
			for rows.Next() {
				var op, object, blob, mac string
				if e = rows.Scan(&op, &object, &blob, &mac); e != nil || op <= after || !hexID(op) || !hexID(object) || !hexID(blob) || !hmac.Equal([]byte(mac), []byte(s.cancellationMAC(op, object, blob))) {
					rows.Close()
					return 0, ErrInvalid
				}
				after = op
				count++
			}
			e = rows.Err()
			rows.Close()
			if e != nil {
				return 0, e
			}
			if count < 256 {
				break
			}
		}
	}
	var total int64
	after := ""
	for {
		rows, err := tx.QueryContext(ctx, `SELECT object_index,parent_index,lookup_tag,revision,encryption_id,sealed FROM sealed_tree_records WHERE object_index>? ORDER BY object_index LIMIT 256`, after)
		if err != nil {
			return 0, err
		}
		records := make([]Record, 0, 256)
		for rows.Next() {
			r, err := scanRecord(rows)
			if err != nil {
				rows.Close()
				return 0, err
			}
			records = append(records, r)
		}
		if err = rows.Err(); err != nil {
			rows.Close()
			return 0, err
		}
		if err = rows.Close(); err != nil {
			return 0, err
		}
		for _, r := range records {
			if r.ObjectIndex <= after {
				return 0, ErrInvalid
			}
			after = r.ObjectIndex
			entry, err := s.tree.OpenRecord(r)
			if err != nil || entry.ObjectID == s.rootID {
				return 0, ErrInvalid
			}
			if err = s.checkDirectory(ctx, tx, entry.ParentID, entry.ObjectID); err != nil {
				return 0, err
			}
			facts, _, factErr := s.factsFor(ctx, tx, entry, r.ObjectIndex)
			if factErr != nil && !errors.Is(factErr, sql.ErrNoRows) {
				return 0, ErrInvalid
			}
			var revocationRows int
			if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM sealed_tree_revocations WHERE object_index=?`, r.ObjectIndex).Scan(&revocationRows); err != nil || revocationRows > 1 || (revocationRows != 0) != (factErr == nil && (facts.Revocation != nil || facts.S3Deletion != nil || facts.DirectoryDeletion != nil)) {
				return 0, ErrInvalid
			}
			var expected RecoveryMediaPlacement
			if entry.Kind == "directory" {
				if facts.DirectoryDeletion != nil {
					if _, err = s.verifyDirectoryDeleteIntent(ctx, tx, entry, r, facts); err != nil {
						return 0, err
					}
				}
				var placements int
				if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM sealed_tree_placements WHERE object_index=?`, r.ObjectIndex).Scan(&placements); err != nil || placements != 0 {
					return 0, ErrInvalid
				}
			} else {
				s3, placeErr := s.checkIndexedS3(ctx, tx, entry, r.ObjectIndex)
				if placeErr != nil {
					return 0, ErrInvalid
				}
				if s3 {
					if factErr != nil || facts.Revocation != nil {
						return 0, ErrInvalid
					}
					if intent := facts.S3Deletion; intent != nil {
						placement, id, err := s.s3DeletionPlacement(ctx, tx, r, entry)
						if err != nil || s.verifyS3MediaDeletion(ctx, tx, r, intent, placement, id) != nil {
							return 0, ErrInvalid
						}
					}
					if visit != nil {
						expected, err = s.recoveryS3Media(ctx, tx, entry, r.ObjectIndex, facts)
						if err != nil {
							return 0, err
						}
					}
				} else {
					placement, placeErr := s.placementFor(ctx, tx, entry, r.ObjectIndex)
					if placeErr != nil || facts.S3Deletion != nil || (factErr == nil && facts.Revocation != nil && s.verifyRevocation(ctx, tx, facts.Revocation, placement) != nil) {
						return 0, ErrInvalid
					}
					if visit != nil {
						expected, err = s.recoveryNativeMedia(ctx, tx, entry, placement, facts)
						if err != nil {
							return 0, err
						}
					}
				}
			}
			id, err := EncryptionID(r)
			if err != nil {
				return 0, err
			}
			var count int
			if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM sealed_tree_encryption_ids WHERE encryption_id=?`, id).Scan(&count); err != nil || count != 1 {
				return 0, fmt.Errorf("%w: encryption identity reservation", ErrInvalid)
			}
			if visit != nil && entry.Kind != "directory" {
				if err = visit(expected); err != nil {
					return 0, err
				}
			}
			total++
		}
		if len(records) < 256 {
			break
		}
	}
	// Pending operations are not visible entries, but their encrypted intent
	// and permanent reservations must authenticate before recovery is allowed.
	after = ""
	for {
		rows, err := tx.QueryContext(ctx, `SELECT operation_id FROM sealed_tree_pending_files WHERE operation_id>? ORDER BY operation_id LIMIT 256`, after)
		if err != nil {
			return 0, err
		}
		ids := make([]string, 0, 256)
		for rows.Next() {
			var id string
			if err = rows.Scan(&id); err != nil {
				rows.Close()
				return 0, err
			}
			ids = append(ids, id)
		}
		if err = rows.Err(); err != nil {
			rows.Close()
			return 0, err
		}
		if err = rows.Close(); err != nil {
			return 0, err
		}
		for _, id := range ids {
			if id <= after {
				return 0, ErrInvalid
			}
			after = id
			_, entry, _, err := s.pending(ctx, tx, id)
			if err != nil {
				return 0, ErrInvalid
			}
			if err = s.checkDirectory(ctx, tx, entry.ParentID, entry.ObjectID); err != nil {
				return 0, err
			}
		}
		if len(ids) < 256 {
			break
		}
	}
	after = ""
	for {
		rows, err := tx.QueryContext(ctx, `SELECT operation_id FROM sealed_tree_operation_ids WHERE completed=1 AND operation_id>? ORDER BY operation_id LIMIT 256`, after)
		if err != nil {
			return 0, err
		}
		ids := make([]string, 0, 256)
		for rows.Next() {
			var id string
			if err = rows.Scan(&id); err != nil {
				rows.Close()
				return 0, err
			}
			ids = append(ids, id)
		}
		if err = rows.Err(); err != nil {
			rows.Close()
			return 0, err
		}
		if err = rows.Close(); err != nil {
			return 0, err
		}
		for _, id := range ids {
			if id <= after {
				return 0, ErrInvalid
			}
			after = id
			done, err := s.completed(ctx, tx, id)
			if err != nil || !done {
				return 0, ErrInvalid
			}
		}
		if len(ids) < 256 {
			break
		}
	}
	if err = tx.Commit(); err != nil {
		return 0, err
	}
	return total, nil
}
