package store

import "context"

// RecordingRequestRepository is an isolated, opt-in reservation primitive.
// It is not an HTTP authorization mechanism. A future Master-only caller must
// authenticate the user, generate/retain a random request ID, supply the exact
// original bounded request bytes and a stable independent 32-byte secret, and
// separately authorize the selected owner before returning any capability.
// Neither request bytes nor the secret may be persisted or logged.
//
// The same request ID and bytes recover the original reservation without a
// second capacity charge. A changed request or a missing/deleting reservation
// fails closed. A returned ready reservation must not receive an upload grant.
type RecordingRequestRepository interface {
	ReserveRecordingRequest(context.Context, string, []byte, []byte, Recording, int64, KaraokeAudit) (Recording, StorageMember, error)
	LookupRecordingRequest(context.Context, string, string, []byte) (Recording, error)
	// StageExpiredLegacyRecordings is an uninstalled replacement for the old
	// expiry query after the marker migration and recovery fence are verified.
	// It never selects a protected or structurally ambiguous reservation.
	StageExpiredLegacyRecordings(context.Context, int) error
}
