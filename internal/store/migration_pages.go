package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"hash"
)

const MigrationPageObjects = 64

// MigrationSequence hashes the same JSON array as MigrationDigest without
// retaining it. Keys must be strictly increasing, so duplicate/reordered pages
// cannot produce an accepted manifest. Empty sequences retain the v1 null hash.
type MigrationSequence struct {
	digest hash.Hash
	last   string
	count  int64
}

func (s *MigrationSequence) Add(key string, value any) error {
	if key == "" || key <= s.last {
		return ErrMigrationState
	}
	raw, err := json.Marshal(value)
	if err != nil || len(raw) > 64<<10 {
		return ErrMigrationState
	}
	if s.digest == nil {
		s.digest = sha256.New()
		s.digest.Write([]byte("["))
	} else {
		s.digest.Write([]byte(","))
	}
	s.digest.Write(raw)
	s.last = key
	s.count++
	return nil
}
func (s *MigrationSequence) Sum() string {
	if s.digest == nil {
		value := sha256.Sum256([]byte("null"))
		return hex.EncodeToString(value[:])
	}
	// Sum must not mutate the stream: callers may inspect between pages.
	clone := sha256.New()
	state, _ := s.digest.(interface{ MarshalBinary() ([]byte, error) }).MarshalBinary()
	_ = clone.(interface{ UnmarshalBinary([]byte) error }).UnmarshalBinary(state)
	clone.Write([]byte("]"))
	return hex.EncodeToString(clone.Sum(nil))
}
func (s *MigrationSequence) Count() int64 { return s.count }

// New plans persist a small header plus immutable per-object bindings. These
// APIs never materialize the complete catalog or a complete ownership unit.
type MigrationPagingRepository interface {
	MigrationHeader(context.Context, string) (MigrationWork, error)
	MigrationUnitPage(context.Context, string, string) ([]MigrationUnit, error)
	MigrationObjectPage(context.Context, string, string, string) ([]MigrationCheckpoint, error)
	MigrationObject(context.Context, string, string) (MigrationCheckpoint, error)
	MigrationUnit(context.Context, string, string) (MigrationUnit, error)
}

type MigrationPlanRepository interface {
	BuildMigrationPlan(context.Context, string, string, string) (MigrationPlan, error)
	MigrationPlanPage(context.Context, string, string) ([]MigrationObject, error)
	ObserveMigrationPlanNative(context.Context, string, string, ExpectedPhysicalItem) error
	ObserveMigrationPlanProof(context.Context, string, MigrationDiskProof) error
	MigrationPlanNative(context.Context, string, string) (ExpectedPhysicalItem, error)
	MigrationPlanPathConflict(context.Context, string, string, string, bool) (bool, error)
	SealMigrationPlan(context.Context, MigrationPlan) (MigrationPlan, error)
}

type MigrationPeerPagingRepository interface {
	PeerMigrationUnitWorkPage(context.Context, string, MigrationLease, MigrationUnitFinishGrant, bool, string) ([]MigrationPeerObject, error)
}

// Only repositories with immutable admitted unit roots implement this bounded
// per-object source authority check. Terminal cancellation uses the full grant.
type MigrationCancellationObjectRepository interface {
	MigrationCancellationObjectGrant(context.Context, MigrationLease, string) (MigrationUnitFinishGrant, error)
}
