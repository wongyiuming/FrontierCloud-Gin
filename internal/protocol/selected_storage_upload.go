package protocol

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"net/url"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
)

// SelectedRelayVerificationTimeout bounds the wait for a Relay to verify
// stored ciphertext and return a signed receipt.
const SelectedRelayVerificationTimeout = 15 * time.Minute

// SelectedStorageUpload is an isolated capability format, not an upload grant
// by itself. Issuers must authorize the caller and atomically bind the
// reservation to the paired relationship and currently applied policy. Owners
// must check that same locally applied revision under a fence that excludes a
// concurrent policy change before admitting the stream.
type SelectedStorageUpload struct {
	Relationship        string                `json:"r"`
	Master              string                `json:"m"`
	Owner               string                `json:"n"`
	MediaID             string                `json:"g"`
	ObjectID            string                `json:"i"`
	UploadID            string                `json:"upload_id"`
	OperationID         string                `json:"operation_id"`
	RelationshipBinding string                `json:"relationship_binding"`
	Generation          string                `json:"generation"`
	StageID             string                `json:"stage_id"`
	PublishChallenge    string                `json:"publish_challenge"`
	CleanupChallenge    string                `json:"cleanup_challenge"`
	ContentSHA256       string                `json:"content_sha256"`
	Size                int64                 `json:"size"`
	Policy              string                `json:"policy"`
	Revision            int64                 `json:"revision"`
	ResourceOrigin      string                `json:"resource_origin"`
	AdminOrigin         string                `json:"admin_origin"`
	AdminBinding        string                `json:"admin_binding"`
	ExpiresAt           int64                 `json:"e"`
	Version             int                   `json:"v"`
	Operation           string                `json:"op"`
	Encryption          *mediacrypto.Metadata `json:"encryption,omitempty"`
	// For recording operations, AdminOrigin carries the active public origin.
	RecordingIngressNode       string `json:"recording_ingress_node,omitempty"`
	RecordingIngressGeneration int64  `json:"recording_ingress_generation,omitempty"`
}

const selectedStorageUploadOperation = "selected-upload-policy-v1"
const selectedStorageCleanupOperation = "selected-upload-cleanup-v1"
const selectedRecordingUploadOperation = "selected-recording-upload-v1"
const selectedRecordingCleanupOperation = "selected-recording-cleanup-v1"

// IsRecordingOperation identifies the claim's operation domain. Verification
// must still use the corresponding upload or cleanup verifier.
func (v SelectedStorageUpload) IsRecordingOperation() bool {
	return v.Operation == selectedRecordingUploadOperation || v.Operation == selectedRecordingCleanupOperation
}

// SelectedStorageAdminBinding derives a relationship-scoped pseudonym from
// the authenticated Admin session hash. It never puts that hash or the cookie
// into a capability. This is a signed association, not online session
// validation: the accepting owner still needs a revocation/admission protocol.
func SelectedStorageAdminBinding(credential, relationship, sessionHash string) (string, error) {
	key, err := Decode(credential)
	if err != nil || len(key) != 48 || !identifier.MatchString(relationship) || !objectID.MatchString(sessionHash) {
		return "", errors.New("invalid selected storage upload administrator binding")
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte("frontiercloud-selected-upload-admin-v1\x00"))
	_, _ = mac.Write([]byte(relationship))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(sessionHash))
	return hex.EncodeToString(mac.Sum(nil)), nil
}

func validSelectedStorageUpload(v SelectedStorageUpload, now int64, operation string) bool {
	if !identifier.MatchString(v.Relationship) || !identifier.MatchString(v.Master) || !identifier.MatchString(v.Owner) ||
		!identifier.MatchString(v.UploadID) || !objectID.MatchString(v.MediaID) || !objectID.MatchString(v.ObjectID) || !objectID.MatchString(v.OperationID) || !objectID.MatchString(v.ContentSHA256) ||
		!objectID.MatchString(v.RelationshipBinding) || !objectID.MatchString(v.Generation) || !objectID.MatchString(v.StageID) || !objectID.MatchString(v.PublishChallenge) || !objectID.MatchString(v.CleanupChallenge) ||
		v.OperationID == v.ObjectID || v.MediaID == v.ObjectID || v.OperationID == v.MediaID ||
		v.StageID == v.OperationID || v.StageID == v.ObjectID || v.PublishChallenge == v.CleanupChallenge ||
		v.PublishChallenge == v.StageID || v.CleanupChallenge == v.StageID || v.PublishChallenge == v.OperationID || v.CleanupChallenge == v.OperationID || v.PublishChallenge == v.ObjectID || v.CleanupChallenge == v.ObjectID ||
		!objectID.MatchString(v.AdminBinding) || v.Version != Version || v.Operation != operation ||
		v.Size <= 0 || v.Size > 10*1024*1024*1024 ||
		v.Revision < 1 || now < 0 || now > math.MaxInt64-TokenSeconds || v.ExpiresAt <= now || v.ExpiresAt > now+TokenSeconds {
		return false
	}
	if v.Policy == "Direct" {
		origin, err := url.Parse(v.ResourceOrigin)
		if !validIngressOrigin(v.ResourceOrigin) || err != nil || origin.Port() != "" {
			return false
		}
	} else if v.Policy != "Relay" || v.ResourceOrigin != "" {
		return false
	}
	if !validIngressOrigin(v.AdminOrigin) {
		return false
	}
	if v.IsRecordingOperation() {
		return v.Policy == "Direct" && v.Master != v.Owner && v.Size <= 1<<30 &&
			identifier.MatchString(v.RecordingIngressNode) && v.RecordingIngressGeneration >= 1 &&
			v.Encryption != nil && v.Encryption.Validate() == nil && v.Encryption.CiphertextSize == v.Size
	}
	adminOrigin, err := url.Parse(v.AdminOrigin)
	if err != nil || adminOrigin.Port() != "" || v.RecordingIngressNode != "" || v.RecordingIngressGeneration != 0 {
		return false
	}
	return v.Encryption == nil || v.Encryption.Validate() == nil && v.Encryption.CiphertextSize == v.Size
}

// SignSelectedStorageUpload creates a policy-bound bearer with an intentionally
// new operation. Legacy upload verifiers reject it rather than ignoring policy
// fields. AdminBinding is an opaque, non-secret audit/session binding; it does
// not by itself prove that the browser session is still active.
func SignSelectedStorageUpload(credential string, value SelectedStorageUpload, now int64) (string, error) {
	return signSelectedStorageCapability(credential, value, now, selectedStorageUploadOperation)
}

// SignSelectedStorageCleanup uses a separate operation from upload. The Master
// must first durably authorize cancellation of the exact unfinished operation.
func SignSelectedStorageCleanup(credential string, value SelectedStorageUpload, now int64) (string, error) {
	return signSelectedStorageCapability(credential, value, now, selectedStorageCleanupOperation)
}

func SignSelectedRecordingUpload(credential string, value SelectedStorageUpload, now int64) (string, error) {
	return signSelectedStorageCapability(credential, value, now, selectedRecordingUploadOperation)
}

func SignSelectedRecordingCleanup(credential string, value SelectedStorageUpload, now int64) (string, error) {
	return signSelectedStorageCapability(credential, value, now, selectedRecordingCleanupOperation)
}

func signSelectedStorageCapability(credential string, value SelectedStorageUpload, now int64, operation string) (string, error) {
	value.Version, value.Operation = Version, operation
	if !validSelectedStorageUpload(value, now, operation) {
		return "", errors.New("invalid selected storage upload capability")
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	var fields map[string]any
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	if err = decoder.Decode(&fields); err != nil {
		return "", err
	}
	return capabilityToken(credential, fields)
}

// VerifySelectedStorageUpload checks the signature and complete typed claim.
// It does not check the current relationship, policy, session or target origin;
// those checks must be made by the accepting owner under the admission fence.
func VerifySelectedStorageUpload(credential, token string, now int64) (SelectedStorageUpload, error) {
	return verifySelectedStorageCapability(credential, token, now, selectedStorageUploadOperation)
}

func VerifySelectedStorageCleanup(credential, token string, now int64) (SelectedStorageUpload, error) {
	return verifySelectedStorageCapability(credential, token, now, selectedStorageCleanupOperation)
}

func VerifySelectedRecordingUpload(credential, token string, now int64) (SelectedStorageUpload, error) {
	return verifySelectedStorageCapability(credential, token, now, selectedRecordingUploadOperation)
}

func VerifySelectedRecordingCleanup(credential, token string, now int64) (SelectedStorageUpload, error) {
	return verifySelectedStorageCapability(credential, token, now, selectedRecordingCleanupOperation)
}

func verifySelectedStorageCapability(credential, token string, now int64, operation string) (SelectedStorageUpload, error) {
	var value SelectedStorageUpload
	fields, err := verifyCapabilityToken(credential, token)
	if err != nil {
		return value, errors.New("invalid selected storage upload capability")
	}
	encoded, err := json.Marshal(fields)
	if err != nil {
		return value, errors.New("invalid selected storage upload capability")
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&value); err != nil || !validSelectedStorageUpload(value, now, operation) {
		return SelectedStorageUpload{}, errors.New("invalid selected storage upload capability")
	}
	return value, nil
}
