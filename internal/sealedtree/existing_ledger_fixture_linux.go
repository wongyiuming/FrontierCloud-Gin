//go:build linux && ledger_fixture

package sealedtree

import (
	"context"
	"database/sql"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/config"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/maintenance"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/vault"
	"os"
	"reflect"
)

// FixtureInitializeExisting is test-only and deliberately bypasses the closed
// production legacy-writer gate. Never build this tag into a deployed binary.
func FixtureInitializeExisting(ctx context.Context, c config.Config, gate *maintenance.Gate, tree *Tree, rootID, fenceDir string) error {
	return initializeExistingSQLiteOffline(ctx, c, gate, tree, rootID, fenceDir)
}

// FixtureImportLocalHistoryIDs uses the real local coordinator in a synthetic
// maintenance fixture. It does not authorize runtime startup or publication.
func FixtureImportLocalHistoryIDs(ctx context.Context, gate *maintenance.Gate, dataRoot, databasePath string, tree *SQLStore, fenceRoot *os.Root, nodeVault *vault.Vault, nodeID string) (HistoricalMediaIDScope, error) {
	return importLocalHistoryIDsOffline(ctx, gate, dataRoot, databasePath, tree, fenceRoot, nodeVault, nodeID)
}

// FixtureCommitSignedPending exercises a single SQLite transaction without
// purporting to provide the missing source, ingress or owner authority.
func FixtureCommitSignedPending(ctx context.Context, s *SQLStore, key []byte, nodeVault *vault.Vault, receipt protocol.OpaqueCapacityReceipt, signature string) (bool, error) {
	return fixtureCommitSignedPending(ctx, s, key, nodeVault, receipt, signature, nil)
}

// FixtureCommitSignedPendingWithCrashHook is test-only. The hook runs after
// both mutations but before COMMIT to simulate abrupt process termination.
func FixtureCommitSignedPendingWithCrashHook(ctx context.Context, s *SQLStore, key []byte, nodeVault *vault.Vault, receipt protocol.OpaqueCapacityReceipt, signature string, hook func()) (bool, error) {
	if hook == nil {
		return false, ErrInvalid
	}
	return fixtureCommitSignedPending(ctx, s, key, nodeVault, receipt, signature, func() error { hook(); return nil })
}

// FixtureCommitSignedPendingWithCheck exists only in the isolated test build.
// It is not a production authorization interface: callers can supply any
// function, and must not treat it as a source or key-vault lease.
func FixtureCommitSignedPendingWithCheck(ctx context.Context, s *SQLStore, key []byte, nodeVault *vault.Vault, receipt protocol.OpaqueCapacityReceipt, signature string, check func() error) (bool, error) {
	if check == nil {
		return false, ErrInvalid
	}
	return fixtureCommitSignedPending(ctx, s, key, nodeVault, receipt, signature, check)
}

// FixtureValidatePendingExact compares the authenticated pending record and
// its current ancestor path inside the fixture's actual SQLite transaction.
// It does not authenticate the supplied values or make them a product permit.
func FixtureValidatePendingExact(ctx context.Context, s *SQLStore, conn *sql.Conn, operation, path string, expectedEntry Entry, expectedPlacement Placement, expectedFacts Facts) error {
	if s == nil || conn == nil {
		return ErrInvalid
	}
	before, entry, placement, err := s.pending(ctx, conn, operation)
	if err != nil || before.facts == nil || !reflect.DeepEqual(entry, expectedEntry) || !reflect.DeepEqual(placement, expectedPlacement) {
		return ErrConflict
	}
	facts, err := s.tree.OpenFacts(*before.facts)
	if err != nil || !reflect.DeepEqual(facts, expectedFacts) {
		return ErrConflict
	}
	actualPath, err := s.pathInTransaction(ctx, conn, entry)
	if err != nil || actualPath != path {
		return ErrConflict
	}
	return nil
}

// FixtureCommitSignedPendingWithChecks is deliberately unavailable in a
// production build. The checks are test code, not an authorization boundary.
func FixtureCommitSignedPendingWithChecks(ctx context.Context, s *SQLStore, key []byte, nodeVault *vault.Vault, receipt protocol.OpaqueCapacityReceipt, signature string, before func(*sql.Conn) error, after func() error) (bool, error) {
	if before == nil || after == nil {
		return false, ErrInvalid
	}
	return fixtureCommitSignedPendingWithChecks(ctx, s, key, nodeVault, receipt, signature, before, after)
}

func fixtureCommitSignedPending(ctx context.Context, s *SQLStore, key []byte, nodeVault *vault.Vault, receipt protocol.OpaqueCapacityReceipt, signature string, hook func() error) (bool, error) {
	return fixtureCommitSignedPendingWithChecks(ctx, s, key, nodeVault, receipt, signature, nil, hook)
}

func fixtureCommitSignedPendingWithChecks(ctx context.Context, s *SQLStore, key []byte, nodeVault *vault.Vault, receipt protocol.OpaqueCapacityReceipt, signature string, before func(*sql.Conn) error, hook func() error) (bool, error) {
	release, err := s.acquireMutation(ctx)
	if err != nil {
		return false, err
	}
	defer release()
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return false, err
	}
	defer conn.Close()
	if _, err = conn.ExecContext(ctx, `BEGIN IMMEDIATE`); err != nil {
		return false, err
	}
	defer conn.ExecContext(context.Background(), `ROLLBACK`)
	if before != nil {
		if err = before(conn); err != nil {
			return false, err
		}
	}
	already, err := s.finalizeSignedPendingTx(ctx, conn, key, nodeVault, receipt, signature, "")
	if err != nil {
		return false, err
	}
	if hook != nil {
		if err = hook(); err != nil {
			return false, err
		}
	}
	if _, err = conn.ExecContext(ctx, `COMMIT`); err != nil {
		return false, err
	}
	return already, nil
}
