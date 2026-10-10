// Package protocol implements the language-independent FrontierCloud protocol.
package protocol

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"io"
	"math"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	Version         = 2
	TokenSeconds    = int64(300)
	AuthSkewSeconds = int64(60)
)

var (
	encodedValue = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
	identifier   = regexp.MustCompile(`^[a-f0-9]{32}$`)
	objectID     = regexp.MustCompile(`^[a-f0-9]{64}$`)
)

var recordingContentTypes = map[string]bool{
	"audio/webm":               true,
	"audio/ogg":                true,
	"audio/mp4":                true,
	"audio/mpeg":               true,
	"audio/wav":                true,
	"application/octet-stream": true,
}

// Encode returns unpadded RFC 4648 Base64URL.
func Encode(value []byte) string {
	return base64.RawURLEncoding.EncodeToString(value)
}

// Decode validates and decodes an unpadded Base64URL protocol value.
func Decode(value string) ([]byte, error) {
	if len(value) < 1 || len(value) > 4096 || !encodedValue.MatchString(value) {
		return nil, errors.New("invalid base64url encoding")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("decode base64url: %w", err)
	}
	return decoded, nil
}

// PublicKey derives the raw Ed25519 public key for a protocol private key.
func PublicKey(private string) (string, error) {
	seed, err := Decode(private)
	if err != nil || len(seed) != ed25519.SeedSize {
		return "", errors.New("invalid Ed25519 private key")
	}
	key := ed25519.NewKeyFromSeed(seed)
	return Encode(key.Public().(ed25519.PublicKey)), nil
}

// Sign signs canonical payload bytes with a raw Ed25519 seed.
func Sign(private string, payload any) (string, error) {
	seed, err := Decode(private)
	if err != nil || len(seed) != ed25519.SeedSize {
		return "", errors.New("invalid Ed25519 private key")
	}
	canonical, err := Canonical(payload)
	if err != nil {
		return "", err
	}
	return Encode(ed25519.Sign(ed25519.NewKeyFromSeed(seed), canonical)), nil
}

// Verify validates an Ed25519 signature over canonical payload bytes.
func Verify(public string, payload any, signature string) error {
	publicBytes, err := Decode(public)
	if err != nil || len(publicBytes) != ed25519.PublicKeySize {
		return errors.New("invalid Ed25519 public key")
	}
	signatureBytes, err := Decode(signature)
	if err != nil || len(signatureBytes) != ed25519.SignatureSize {
		return errors.New("invalid Ed25519 signature")
	}
	canonical, err := Canonical(payload)
	if err != nil {
		return err
	}
	if !ed25519.Verify(ed25519.PublicKey(publicBytes), canonical, signatureBytes) {
		return errors.New("node identity signature mismatch")
	}
	return nil
}

// VerifyAuth validates the relationship HMAC and returns the accepted nonce.
func VerifyAuth(credential string, headers map[string]string, method, path string, body []byte, now int64) (string, error) {
	normalized := make(map[string]string, len(headers))
	for name, value := range headers {
		normalized[strings.ToLower(name)] = value
	}
	relationship := normalized["x-node-relationship"]
	stamp := normalized["x-node-time"]
	nonce := normalized["x-node-nonce"]
	if !identifier.MatchString(relationship) || !identifier.MatchString(nonce) {
		return "", errors.New("invalid relationship authentication")
	}
	timestamp, err := strconv.ParseInt(stamp, 10, 64)
	if err != nil || timestamp < now-AuthSkewSeconds || timestamp > now+AuthSkewSeconds {
		return "", errors.New("invalid relationship authentication")
	}
	key, err := Decode(credential)
	if err != nil || len(key) != 48 {
		return "", errors.New("invalid relationship authentication")
	}
	bodyDigest := sha256.Sum256(body)
	message := strings.Join([]string{
		relationship,
		stamp,
		nonce,
		strings.ToUpper(method),
		path,
		hex.EncodeToString(bodyDigest[:]),
	}, "\n")
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(message))
	expected := hex.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(expected), []byte(normalized["x-node-signature"])) {
		return "", errors.New("invalid relationship authentication")
	}
	return nonce, nil
}

// AuthHeaders creates the bounded, body-bound control-plane authentication.
func AuthHeaders(credential, relationship, method, path string, body []byte, now int64) (map[string]string, error) {
	key, err := Decode(credential)
	if err != nil || len(key) != 48 || !identifier.MatchString(relationship) {
		return nil, errors.New("invalid relationship credentials")
	}
	random := make([]byte, 16)
	if _, err = rand.Read(random); err != nil {
		return nil, err
	}
	stamp, nonce := strconv.FormatInt(now, 10), hex.EncodeToString(random)
	digest := sha256.Sum256(body)
	message := strings.Join([]string{relationship, stamp, nonce, strings.ToUpper(method), path, hex.EncodeToString(digest[:])}, "\n")
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(message))
	return map[string]string{"X-Node-Relationship": relationship, "X-Node-Time": stamp, "X-Node-Nonce": nonce, "X-Node-Signature": hex.EncodeToString(mac.Sum(nil))}, nil
}

// MediaToken creates a media capability compatible with the Python runtime.
func MediaToken(credential, relationship, master, owner, original, mediaID string, now int64, requestID, traceID string) (string, error) {
	if !objectID.MatchString(mediaID) || !objectID.MatchString(original) || !identifier.MatchString(relationship) || !identifier.MatchString(master) || !identifier.MatchString(owner) {
		return "", errors.New("invalid global media identity")
	}
	payload := map[string]any{
		"r": relationship, "m": master, "o": owner, "i": original,
		"g": mediaID, "e": now + TokenSeconds, "v": Version,
	}
	for name, value := range map[string]string{"request_id": requestID, "trace_id": traceID} {
		if identifier.MatchString(value) && value != strings.Repeat("0", 32) {
			payload[name] = value
		}
	}
	return capabilityToken(credential, payload)
}

// VerifyMediaToken validates and decodes a media capability.
func VerifyMediaToken(credential, token string, now int64) (map[string]any, error) {
	value, err := verifyCapabilityToken(credential, token)
	if err != nil || !validExpiry(value, now) || !objectID.MatchString(stringField(value, "g")) ||
		!identifier.MatchString(stringField(value, "r")) || !identifier.MatchString(stringField(value, "m")) ||
		!identifier.MatchString(stringField(value, "o")) || !objectID.MatchString(stringField(value, "i")) {
		return nil, errors.New("invalid or expired media capability")
	}
	for _, name := range []string{"request_id", "trace_id"} {
		if raw, present := value[name]; present {
			text, ok := raw.(string)
			if !ok || !identifier.MatchString(text) || text == strings.Repeat("0", 32) {
				return nil, errors.New("invalid or expired media capability")
			}
		}
	}
	return value, nil
}

// StorageToken creates a storage capability compatible with the Python runtime.
func StorageToken(credential, relationship, master, storageNode, mediaID, storageObjectID, operation, path string, size, now int64) (string, error) {
	return storageToken(credential, relationship, master, storageNode, mediaID, storageObjectID, operation, path, "", size, now)
}

// StorageUploadToken binds an upload to one reservation generation. Older
// storage runtimes ignore this additional signed field; new ones fence aborted
// generations before reserving or writing bytes.
func StorageUploadToken(credential, relationship, master, storageNode, mediaID, storageObjectID, path, uploadID string, size, now int64) (string, error) {
	if !identifier.MatchString(uploadID) {
		return "", errors.New("invalid storage upload generation")
	}
	return storageToken(credential, relationship, master, storageNode, mediaID, storageObjectID, "upload", path, uploadID, size, now)
}

// A distinct operation makes historical storage fail closed instead of treating
// ciphertext as an ordinary upload or ignoring an unfamiliar descriptor field.
func EncryptedStorageUploadToken(credential, relationship, master, storageNode, mediaID, storageObjectID, path, uploadID string, size, now int64, meta mediacrypto.Metadata) (string, error) {
	if !identifier.MatchString(relationship) || !identifier.MatchString(master) || !identifier.MatchString(storageNode) || !identifier.MatchString(uploadID) || !objectID.MatchString(mediaID) || !objectID.MatchString(storageObjectID) || meta.Validate() != nil || meta.CiphertextSize != size || size > 10*1024*1024*1024 || utf8.RuneCountInString(path) < 1 || utf8.RuneCountInString(path) > 1024 {
		return "", errors.New("invalid encrypted storage capability")
	}
	descriptor := map[string]any{"version": meta.Version, "algorithm": meta.Algorithm, "file_id": meta.FileID, "nonce_prefix": meta.NoncePrefix, "plaintext_size": meta.PlaintextSize, "chunk_size": meta.ChunkSize, "ciphertext_size": meta.CiphertextSize}
	return capabilityToken(credential, map[string]any{"r": relationship, "m": master, "n": storageNode, "g": mediaID, "i": storageObjectID, "op": "upload-encrypted", "path": path, "size": size, "upload_id": uploadID, "encryption": descriptor, "e": now + TokenSeconds, "v": Version})
}

func storageToken(credential, relationship, master, storageNode, mediaID, storageObjectID, operation, path, uploadID string, size, now int64) (string, error) {
	if !identifier.MatchString(relationship) || !identifier.MatchString(master) || !identifier.MatchString(storageNode) ||
		!objectID.MatchString(mediaID) || !objectID.MatchString(storageObjectID) ||
		(operation != "upload" && operation != "delete") || size < 0 || size > 10*1024*1024*1024 ||
		utf8.RuneCountInString(path) < 1 || utf8.RuneCountInString(path) > 1024 {
		return "", errors.New("invalid storage capability")
	}
	payload := map[string]any{
		"r": relationship, "m": master, "n": storageNode, "g": mediaID,
		"i": storageObjectID, "op": operation, "path": path, "size": size,
		"e": now + TokenSeconds, "v": Version,
	}
	if uploadID != "" {
		payload["upload_id"] = uploadID
	}
	return capabilityToken(credential, payload)
}

// VerifyStorageToken validates and decodes a storage capability.
func VerifyStorageToken(credential, token string, now int64) (map[string]any, error) {
	value, err := verifyCapabilityToken(credential, token)
	size, sizeOK := integerField(value, "size")
	path := stringField(value, "path")
	operation := stringField(value, "op")
	if err != nil || !validExpiry(value, now) || (operation != "upload" && operation != "upload-encrypted" && operation != "delete") ||
		!sizeOK || size < 0 || size > 10*1024*1024*1024 || utf8.RuneCountInString(path) < 1 ||
		utf8.RuneCountInString(path) > 1024 {
		return nil, errors.New("invalid or expired storage capability")
	}
	for _, name := range []string{"r", "m", "n"} {
		if !identifier.MatchString(stringField(value, name)) {
			return nil, errors.New("invalid or expired storage capability")
		}
	}
	for _, name := range []string{"g", "i"} {
		if !objectID.MatchString(stringField(value, name)) {
			return nil, errors.New("invalid or expired storage capability")
		}
	}
	if _, present := value["upload_id"]; present && !identifier.MatchString(stringField(value, "upload_id")) {
		return nil, errors.New("invalid or expired storage capability")
	}
	if operation == "upload-encrypted" {
		meta, err := StorageEncryption(value)
		if err != nil || meta == nil || meta.CiphertextSize != size || !identifier.MatchString(stringField(value, "upload_id")) {
			return nil, errors.New("invalid encrypted storage capability")
		}
	} else if _, present := value["encryption"]; present {
		return nil, errors.New("encryption descriptor requires encrypted storage operation")
	}
	return value, nil
}

func StorageEncryption(value map[string]any) (*mediacrypto.Metadata, error) {
	raw, present := value["encryption"]
	if !present {
		return nil, nil
	}
	encoded, err := json.Marshal(raw)
	if err != nil {
		return nil, mediacrypto.ErrMetadata
	}
	var meta mediacrypto.Metadata
	if json.Unmarshal(encoded, &meta) != nil || meta.Validate() != nil {
		return nil, mediacrypto.ErrMetadata
	}
	return &meta, nil
}

// RecordingToken creates a recording capability compatible with the Python runtime.
func RecordingToken(credential, relationship, master, owner, recording, operation string, now, size int64, contentType, filename string) (string, error) {
	if !identifier.MatchString(relationship) || !identifier.MatchString(master) || !identifier.MatchString(owner) ||
		!identifier.MatchString(recording) || (operation != "upload" && operation != "stream" && operation != "download") ||
		size < 0 || size > 1024*1024*1024 || !recordingContentTypes[contentType] ||
		utf8.RuneCountInString(filename) < 1 || utf8.RuneCountInString(filename) > 255 ||
		strings.ContainsAny(filename, "\r\n") {
		return "", errors.New("invalid recording capability")
	}
	payload := map[string]any{
		"r": relationship, "m": master, "u": owner, "i": recording,
		"op": operation, "size": size, "ct": contentType, "name": filename,
		"e": now + TokenSeconds, "v": Version,
	}
	return capabilityToken(credential, payload)
}

// Only the opaque footer hash and descriptor belong in a bounded capability.
// The snapshot ciphertext travels in the recording body, never its headers.
func RecordingTokenWithSnapshot(credential, relationship, master, owner, recording, operation string, now, size int64, contentType, filename string, meta *mediacrypto.Metadata, snapshotHash string) (string, error) {
	token, err := RecordingToken(credential, relationship, master, owner, recording, operation, now, size, contentType, filename)
	if err != nil || meta == nil {
		return token, err
	}
	payload, err := verifyCapabilityToken(credential, token)
	if err != nil {
		return "", err
	}
	raw, err := json.Marshal(meta)
	if err != nil {
		return "", err
	}
	value, err := ParseStrictJSON(raw, 4096)
	if err != nil {
		return "", err
	}
	payload["encrypted_lyrics_encryption"], payload["encrypted_lyrics_sha256"] = value, snapshotHash
	if _, _, err = RecordingSnapshotFromToken(payload); err != nil {
		return "", err
	}
	return capabilityToken(credential, payload)
}

func RecordingSnapshotFromToken(value map[string]any) (*mediacrypto.Metadata, string, error) {
	raw, exists := value["encrypted_lyrics_encryption"]
	hash := stringField(value, "encrypted_lyrics_sha256")
	if !exists && hash == "" {
		return nil, "", nil
	}
	encoded, err := json.Marshal(raw)
	var meta mediacrypto.Metadata
	decodedHash, hashErr := hex.DecodeString(hash)
	if err != nil || json.Unmarshal(encoded, &meta) != nil || meta.Validate() != nil || meta.PlaintextSize <= 0 || meta.PlaintextSize > 1400*1024 || hashErr != nil || len(decodedHash) != 32 || hex.EncodeToString(decodedHash) != hash {
		return nil, "", errors.New("invalid recording snapshot capability")
	}
	return &meta, hash, nil
}

// VerifyRecordingToken validates and decodes a recording capability.
func VerifyRecordingToken(credential, token string, now int64) (map[string]any, error) {
	value, err := verifyCapabilityToken(credential, token)
	size, sizeOK := integerField(value, "size")
	operation := stringField(value, "op")
	contentType := stringField(value, "ct")
	filename := stringField(value, "name")
	if err != nil || !validExpiry(value, now) ||
		(operation != "upload" && operation != "stream" && operation != "download") || !sizeOK ||
		size < 0 || size > 1024*1024*1024 || !recordingContentTypes[contentType] ||
		utf8.RuneCountInString(filename) < 1 || utf8.RuneCountInString(filename) > 255 ||
		strings.ContainsAny(filename, "\r\n") {
		return nil, errors.New("invalid or expired recording capability")
	}
	for _, name := range []string{"r", "m", "u", "i"} {
		if !identifier.MatchString(stringField(value, name)) {
			return nil, errors.New("invalid or expired recording capability")
		}
	}
	if _, _, err := RecordingSnapshotFromToken(value); err != nil {
		return nil, err
	}
	return value, nil
}

func capabilityToken(credential string, payload map[string]any) (string, error) {
	key, err := Decode(credential)
	if err != nil || len(key) != 48 {
		return "", errors.New("invalid capability credential")
	}
	canonical, err := Canonical(payload)
	if err != nil {
		return "", err
	}
	encoded := Encode(canonical)
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(encoded))
	return encoded + "." + Encode(mac.Sum(nil)), nil
}

func verifyCapabilityToken(credential, token string) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return nil, errors.New("invalid capability token")
	}
	key, err := Decode(credential)
	if err != nil || len(key) != 48 {
		return nil, err
	}
	signature, err := Decode(parts[1])
	if err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(parts[0]))
	if !hmac.Equal(mac.Sum(nil), signature) {
		return nil, errors.New("invalid capability signature")
	}
	payload, err := Decode(parts[0])
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	value := make(map[string]any)
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	if err := ensureEOF(decoder); err != nil {
		return nil, err
	}
	return value, nil
}

func ensureEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return errors.New("unexpected trailing JSON value")
		}
		return err
	}
	return nil
}

func validExpiry(value map[string]any, now int64) bool {
	version, versionOK := integerField(value, "v")
	expiry, expiryOK := integerField(value, "e")
	return versionOK && expiryOK && version == Version && expiry > now && expiry <= now+TokenSeconds+60
}

func integerField(value map[string]any, name string) (int64, bool) {
	if value == nil {
		return 0, false
	}
	switch typed := value[name].(type) {
	case json.Number:
		result, err := typed.Int64()
		return result, err == nil
	case int:
		return int64(typed), true
	case int64:
		return typed, true
	case float64:
		if math.Trunc(typed) != typed {
			return 0, false
		}
		return int64(typed), true
	default:
		return 0, false
	}
}

func stringField(value map[string]any, name string) string {
	if value == nil {
		return ""
	}
	result, _ := value[name].(string)
	return result
}
