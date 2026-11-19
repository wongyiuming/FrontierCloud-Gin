package sealedtree

import (
	"context"
	"database/sql"
	"sync"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
)

// CoordinatedMutation is a short-lived handle to a held tree mutation fence.
// It grants no user authorization and may only be used by the trusted Master
// coordinator while its Owner and ingress fences and database transaction are
// also held. No product route currently uses it.
type CoordinatedMutation struct {
	mu     sync.Mutex
	store  *SQLStore
	active bool
}

// SelectedPending contains sensitive Master-only data recovered from the
// authenticated pending records. It must not be sent to an untrusted Owner.
type SelectedPending struct {
	OperationID string
	ObjectID    string
	ParentID    string
	Name        string
	Placement   Placement
	Admission   SelectedUploadFact
	Descriptor  string
}

// WithCoordinatedMutation holds the real tree fence and binds the handle to
// the very same sql.DB object as the business repository. The trusted caller
// owns the encompassing transaction and must observe the agreed lock order.
func (s *SQLStore) WithCoordinatedMutation(ctx context.Context, db *sql.DB, fn func(*CoordinatedMutation) error) error {
	if !s.valid() || ctx == nil || db == nil || s.db != db || fn == nil || s.prototypeOnly() {
		return ErrFenceRequired
	}
	release, err := s.acquireMutation(ctx)
	if err != nil {
		return err
	}
	defer release()
	m := &CoordinatedMutation{store: s, active: true}
	defer func() { m.mu.Lock(); m.active = false; m.mu.Unlock() }()
	return fn(m)
}

// PrepareFileTx writes a pending encrypted file using the coordinator's one
// authoritative transaction, without committing it. It generates all locators
// here and never accepts a logical path as a physical name. The caller still
// must check directory ownership, business authorization and quota in the same
// transaction; failure at any point must roll that transaction back.
func (m *CoordinatedMutation) PrepareFileTx(ctx context.Context, tx treeQuery, entry Entry, placement Placement, facts Facts) (PreparedFile, error) {
	if m == nil || ctx == nil || tx == nil {
		return PreparedFile{}, ErrInvalid
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.store
	if !m.active || !s.valid() || ctx.Err() != nil || entry.ObjectID == s.rootID || entry.Kind == "directory" || entry.ObjectID != placement.ObjectID || placement.BlobID != "" || placement.ReadAlias != "" || facts.PendingSelectedUpload == nil || facts.Revocation != nil || !factsCompatiblePending(entry, facts) {
		return PreparedFile{}, ErrInvalid
	}
	blob, err := NewBlobID()
	if err != nil {
		return PreparedFile{}, err
	}
	alias, err := NewBlobID()
	if err != nil {
		return PreparedFile{}, err
	}
	placement.BlobID, placement.ReadAlias = blob, alias
	name, err := s.tree.Seal(entry.ParentID, entry.ObjectID, entry.Kind, entry.Name, 1)
	if err != nil {
		return PreparedFile{}, err
	}
	loc, err := s.tree.SealPlacement(placement, 1)
	if err != nil || name.ObjectIndex != loc.ObjectIndex {
		return PreparedFile{}, ErrInvalid
	}
	sealedFacts, err := s.tree.SealFacts(facts, 1)
	if err != nil || sealedFacts.ObjectIndex != name.ObjectIndex {
		return PreparedFile{}, ErrInvalid
	}
	op, err := NewBlobID()
	if err != nil || op == blob || op == alias || op == entry.ObjectID || op == placement.NativeObjectID {
		return PreparedFile{}, ErrInvalid
	}
	if err = s.prepareFileTx(ctx, tx, entry, placement, &facts, name, loc, &sealedFacts, op); err != nil {
		return PreparedFile{}, err
	}
	return PreparedFile{OperationID: op, BlobID: blob, ReadAlias: alias}, nil
}

// ReadSelectedFileTx reopens and authenticates the exact pending facts and
// placement from the same transaction. It is a recovery/consistency primitive,
// not a fresh authorization or proof of Owner bytes.
func (m *CoordinatedMutation) ReadSelectedFileTx(ctx context.Context, tx treeQuery, operationID string) (SelectedPending, error) {
	if m == nil || ctx == nil || tx == nil {
		return SelectedPending{}, ErrInvalid
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.readSelectedFileTx(ctx, tx, operationID)
}

// readSelectedFileTx requires m.mu. Keeping the authentication of pending data
// and the file-ID claim under the same handle prevents either from escaping the
// coordinated mutation fence.
func (m *CoordinatedMutation) readSelectedFileTx(ctx context.Context, tx treeQuery, operationID string) (SelectedPending, error) {
	if !m.active || !m.store.valid() || ctx.Err() != nil {
		return SelectedPending{}, ErrInvalid
	}
	pending, entry, placement, err := m.store.pending(ctx, tx, operationID)
	if err != nil || pending.facts == nil {
		return SelectedPending{}, ErrInvalid
	}
	facts, err := m.store.tree.OpenFacts(*pending.facts)
	if err != nil || facts.PendingSelectedUpload == nil || !factsCompatiblePending(entry, facts) {
		return SelectedPending{}, ErrInvalid
	}
	descriptor, err := protocol.IngressMediaDescriptor(placement.Bytes, placement.Encryption)
	if err != nil {
		return SelectedPending{}, ErrInvalid
	}
	return SelectedPending{OperationID: operationID, ObjectID: entry.ObjectID, ParentID: entry.ParentID, Name: entry.Name, Placement: placement, Admission: *facts.PendingSelectedUpload, Descriptor: descriptor}, nil
}

// ClaimSelectedMediaPreparationTx claims the descriptor already authenticated
// in this operation's pending tree record, on the coordinator-owned database
// transaction. The caller must authenticate the Admin and verify the transient
// preparation before its first use; a recovery caller must separately verify
// the original operation and current authorization. This method does not
// itself issue a ticket or authorize an upload.
func (m *CoordinatedMutation) ClaimSelectedMediaPreparationTx(ctx context.Context, tx treeQuery, operationID string) error {
	if m == nil || ctx == nil || tx == nil {
		return ErrInvalid
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.active || !m.store.valid() || ctx.Err() != nil {
		return ErrInvalid
	}
	if err := m.store.lockIndexedWriter(ctx, tx); err != nil {
		return err
	}
	pending, err := m.readSelectedFileTx(ctx, tx, operationID)
	if err != nil || pending.Placement.Encryption == nil || !hexID(pending.Admission.AdminBinding) {
		return ErrInvalid
	}
	return m.store.claimMediaPreparationTx(ctx, tx, *pending.Placement.Encryption, "admin:"+pending.Admission.AdminBinding, operationID)
}
