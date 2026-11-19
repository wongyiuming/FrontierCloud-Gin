package store

import "context"

// SelectedUploadPolicy identifies the paired owner policy a verified upload
// capability claims. It contains no URL supplied by the browser or secret.
type SelectedUploadPolicy struct {
	RelationshipID string
	MasterID       string
	OwnerID        string
	Transport      string
	Revision       int64
	ResourceOrigin string
}

// SelectedUploadOwnerPolicyRepository is an opt-in building block. A caller
// must authenticate the signed capability and administrator separately, hold
// the returned lease throughout admission and the transfer, and check its
// validity before publication. No existing upload route uses this interface.
type SelectedUploadOwnerPolicyRepository interface {
	AcquireSelectedUploadOwnerPolicy(context.Context, SelectedUploadPolicy) (OwnerControlLease, error)
}
