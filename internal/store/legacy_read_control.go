package store

import "github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"

// LegacyReadEnrollmentIntent is encrypted at rest. Its confirmed state is a
// historical observation, not a publication or activation grant.
type LegacyReadEnrollmentIntent struct {
	Version                   int                                   `json:"version"`
	OperationID               string                                `json:"operation_id"`
	Challenge                 string                                `json:"challenge"`
	ExpiresAt                 int64                                 `json:"expires_at"`
	MasterID                  string                                `json:"master_id"`
	MasterIdentity            string                                `json:"master_identity"`
	OwnerID                   string                                `json:"owner_id"`
	RelationshipID            string                                `json:"relationship_id"`
	MasterRelationshipBinding string                                `json:"master_relationship_binding"`
	State                     string                                `json:"state"`
	Receipt                   *protocol.LegacyReadEnrollmentReceipt `json:"receipt,omitempty"`
	Signature                 string                                `json:"signature,omitempty"`
}

// LegacyReadDrainIntent binds a separately generated drain operation and
// challenge to an already signed owner enrollment. Confirmed evidence remains
// historical until external rollback and complete process fences are proven.
type LegacyReadDrainIntent struct {
	Version                   int                                  `json:"version"`
	OperationID               string                               `json:"operation_id"`
	Challenge                 string                               `json:"challenge"`
	ExpiresAt                 int64                                `json:"expires_at"`
	EnrollmentOperation       string                               `json:"enrollment_operation"`
	EnrollmentChallenge       string                               `json:"enrollment_challenge"`
	MasterID                  string                               `json:"master_id"`
	MasterIdentity            string                               `json:"master_identity"`
	OwnerID                   string                               `json:"owner_id"`
	RelationshipID            string                               `json:"relationship_id"`
	MasterRelationshipBinding string                               `json:"master_relationship_binding"`
	Enrollment                protocol.LegacyReadEnrollmentReceipt `json:"enrollment"`
	EnrollmentSignature       string                               `json:"enrollment_signature"`
	State                     string                               `json:"state"`
	Receipt                   *protocol.LegacyReadDrainReceipt     `json:"receipt,omitempty"`
	Signature                 string                               `json:"signature,omitempty"`
}

// LegacyReadStatusIntent is a separately authorized, short-lived observation
// of the original drain. Draining never proves the stream set is empty.
type LegacyReadStatusIntent struct {
	Version                   int                              `json:"version"`
	Request                   protocol.LegacyReadStatusRequest `json:"request"`
	ExpiresAt                 int64                            `json:"expires_at"`
	MasterIdentity            string                           `json:"master_identity"`
	MasterRelationshipBinding string                           `json:"master_relationship_binding"`
	State                     string                           `json:"state"`
	Receipt                   *protocol.LegacyReadStatus       `json:"receipt,omitempty"`
	Signature                 string                           `json:"signature,omitempty"`
}

// LegacyReadControlCurrent is server-internal. Operation and challenge values
// are never supplied by or returned to an untrusted browser.
type LegacyReadControlCurrent struct {
	Enrollment LegacyReadEnrollmentIntent
	Drain      *LegacyReadDrainIntent
	Status     *LegacyReadStatusIntent
}
