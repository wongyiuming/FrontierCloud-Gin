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
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	Version = 2
	// IngressMediaTokenVersion is scoped to public media capabilities. It is
	// deliberately distinct from the legacy version so old nodes fail closed.
	IngressMediaTokenVersion  = 3
	PlainIngressTokenVersion  = 4
	OpaqueIngressTokenVersion = 5
	TokenSeconds              = int64(300)
	AuthSkewSeconds           = int64(60)
)

const PlainProbeFixtureSize = (1 << 20) + 24

// PlainProbeFixture is public synthetic content, never a user object. The
// signed probe descriptor and the owner's verified read use these same bytes.
func PlainProbeFixture() []byte { return bytes.Repeat([]byte("probe-v4"), (1<<20)/8+3) }

var plainProbeDigest = func() string {
	data := PlainProbeFixture()
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}()

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

// MediaToken creates a media capability compatible with historical serialized capabilities.
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

func validIngressOrigin(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || strings.ContainsAny(raw, "\\\r\n\t ") || u.Scheme != "https" || u.Hostname() == "" || u.Host != strings.ToLower(u.Host) || u.User != nil || u.Opaque != "" || u.Path != "" || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.String() != raw || strings.HasSuffix(u.Host, ":") {
		return false
	}
	if port := u.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 || n == 443 || strconv.Itoa(n) != port {
			return false
		}
	}
	return true
}

// IngressMediaToken binds a short-lived native read to its owner, immutable
// object, logical resource and the public ingress that obtained the grant.
// Only an already-authorized Master request may call this function.
func IngressMediaDescriptor(size int64, meta *mediacrypto.Metadata) (string, error) {
	if size < 0 || meta != nil && (meta.Validate() != nil || meta.CiphertextSize != size) {
		return "", errors.New("invalid media descriptor")
	}
	raw, err := json.Marshal(struct {
		Size       int64                 `json:"size"`
		Encryption *mediacrypto.Metadata `json:"encryption"`
	}{size, meta})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

// OpaquePlacementRevision binds only random locators and content identity;
// historical IDs and display paths cannot become dictionary oracles.
const emptyOpaqueSHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

func OpaquePlacementRevision(alias, blob, digest string, size int64, meta *mediacrypto.Metadata) (string, error) {
	if !objectID.MatchString(alias) || !objectID.MatchString(blob) || alias == blob || !objectID.MatchString(digest) || size < 0 || size > 10<<30 || size == 0 && (digest != emptyOpaqueSHA256 || meta != nil) {
		return "", errors.New("invalid opaque media placement")
	}
	descriptor, err := IngressMediaDescriptor(size, meta)
	if err != nil {
		return "", err
	}
	return OpaquePlacementRevisionFromDescriptor(alias, blob, digest, descriptor, size)
}

func OpaquePlacementRevisionFromDescriptor(alias, blob, digest, descriptor string, size int64) (string, error) {
	if !objectID.MatchString(alias) || !objectID.MatchString(blob) || alias == blob || !objectID.MatchString(digest) || !objectID.MatchString(descriptor) || size < 0 || size > 10<<30 || size == 0 && digest != emptyOpaqueSHA256 {
		return "", errors.New("invalid opaque media placement")
	}
	if size == 0 {
		emptyDescriptor, err := IngressMediaDescriptor(0, nil)
		if err != nil || descriptor != emptyDescriptor {
			return "", errors.New("invalid empty opaque media descriptor")
		}
	}
	sum := sha256.Sum256([]byte("frontiercloud:opaque-revision:v1\x00" + alias + blob + digest + descriptor + strconv.FormatInt(size, 10)))
	return hex.EncodeToString(sum[:]), nil
}

func IngressMediaToken(credential, relationship, master, owner, object, resource, ingress, publicOrigin, sessionID string, generation, now, expiresAt, size int64, meta *mediacrypto.Metadata) (string, error) {
	return ingressMediaToken(credential, relationship, master, owner, object, resource, ingress, publicOrigin, sessionID, generation, now, expiresAt, size, meta, "")
}

// PlainIngressMediaToken binds plaintext to a Master-authorized content digest.
// Weak historical size/mtime ETags cannot be used as a content proof.
func PlainIngressMediaToken(credential, relationship, master, owner, object, resource, ingress, publicOrigin, sessionID string, generation, now, expiresAt, size int64, digest string) (string, error) {
	if !objectID.MatchString(digest) || size <= 0 {
		return "", errors.New("invalid plaintext content proof")
	}
	return ingressMediaToken(credential, relationship, master, owner, object, resource, ingress, publicOrigin, sessionID, generation, now, expiresAt, size, nil, digest)
}

// OpaqueIngressMediaToken binds two independent random identifiers to exact
// authorized content. The owner sees neither historical object/resource IDs
// nor logical names. Legacy path-based readers reject this version.
func OpaqueIngressMediaToken(credential, relationship, master, owner, alias, ingress, publicOrigin, sessionID, blob string, generation, now, expiresAt, size int64, digest string, meta *mediacrypto.Metadata) (string, error) {
	if !objectID.MatchString(blob) || !objectID.MatchString(alias) || blob == alias || !objectID.MatchString(digest) || size < 0 || size > 10<<30 || size == 0 && (digest != emptyOpaqueSHA256 || meta != nil) {
		return "", errors.New("invalid opaque media placement")
	}
	base, err := ingressMediaToken(credential, relationship, master, owner, alias, alias, ingress, publicOrigin, sessionID, generation, now, expiresAt, size, meta, digest)
	if err != nil {
		return "", err
	}
	claims, err := verifyCapabilityToken(credential, base)
	if err != nil {
		return "", err
	}
	claims["v"], claims["kind"] = OpaqueIngressTokenVersion, "public-ingress-opaque-v1"
	claims["blob"], claims["size"] = blob, size
	claims["revision"], err = OpaquePlacementRevision(alias, blob, digest, size, meta)
	if err != nil {
		return "", err
	}
	return capabilityToken(credential, claims)
}

func VerifyOpaqueIngressMediaToken(credential, token string, now int64) (map[string]any, error) {
	return verifyOpaqueMediaToken(credential, token, now, "public-ingress-opaque-v1")
}

func verifyOpaqueMediaToken(credential, token string, now int64, kind string) (map[string]any, error) {
	claims, err := verifyIngressMediaToken(credential, token, now, OpaqueIngressTokenVersion, kind, true)
	if err != nil {
		return nil, err
	}
	blob := stringField(claims, "blob")
	size, ok := integerField(claims, "size")
	if !ok || size < 0 || size > 10<<30 || !objectID.MatchString(blob) || stringField(claims, "i") != stringField(claims, "g") || blob == stringField(claims, "i") {
		return nil, errors.New("invalid opaque media placement")
	}
	revision, err := OpaquePlacementRevisionFromDescriptor(stringField(claims, "i"), blob, stringField(claims, "content_sha256"), stringField(claims, "descriptor"), size)
	if err != nil || revision != stringField(claims, "revision") {
		return nil, errors.New("invalid opaque media placement")
	}
	return claims, nil
}

// OpaqueIngressProbeToken is accepted only by the authenticated synthetic
// probe branch, never by the business blob reader.
func OpaqueIngressProbeToken(credential, relationship, master, owner, challenge string, now int64) (string, error) {
	object, blob := strings.Repeat("0", 64), strings.Repeat("1", 64)
	base, err := OpaqueIngressMediaToken(credential, relationship, master, owner, object, master, "https://readiness.invalid", challenge, blob, 1, now, now+30, PlainProbeFixtureSize, plainProbeDigest, nil)
	if err != nil {
		return "", err
	}
	claims, err := verifyCapabilityToken(credential, base)
	if err != nil {
		return "", err
	}
	claims["kind"] = "public-ingress-opaque-probe-v1"
	return capabilityToken(credential, claims)
}

func VerifyOpaqueIngressProbeToken(credential, token, challenge string, now int64) (map[string]any, error) {
	claims, err := verifyIngressMediaToken(credential, token, now, OpaqueIngressTokenVersion, "public-ingress-opaque-probe-v1", true)
	size, sizeOK := integerField(claims, "size")
	generation, generationOK := integerField(claims, "generation")
	descriptor, _ := IngressMediaDescriptor(PlainProbeFixtureSize, nil)
	revision, _ := OpaquePlacementRevision(strings.Repeat("0", 64), strings.Repeat("1", 64), plainProbeDigest, PlainProbeFixtureSize, nil)
	if err != nil || !identifier.MatchString(challenge) || !sizeOK || size != PlainProbeFixtureSize || !generationOK || generation != 1 || stringField(claims, "session") != challenge || stringField(claims, "ingress") != stringField(claims, "m") || stringField(claims, "i") != strings.Repeat("0", 64) || stringField(claims, "g") != strings.Repeat("0", 64) || stringField(claims, "blob") != strings.Repeat("1", 64) || stringField(claims, "origin") != "https://readiness.invalid" || stringField(claims, "descriptor") != descriptor || stringField(claims, "revision") != revision || stringField(claims, "content_sha256") != plainProbeDigest {
		return nil, errors.New("invalid opaque readiness probe")
	}
	return claims, nil
}

func ingressMediaToken(credential, relationship, master, owner, object, resource, ingress, publicOrigin, sessionID string, generation, now, expiresAt, size int64, meta *mediacrypto.Metadata, digest string) (string, error) {
	if !identifier.MatchString(relationship) || !identifier.MatchString(master) || !identifier.MatchString(owner) || !identifier.MatchString(ingress) || !identifier.MatchString(sessionID) || !objectID.MatchString(object) || !objectID.MatchString(resource) || !validIngressOrigin(publicOrigin) || generation < 1 || now < 0 || now > math.MaxInt64-TokenSeconds || expiresAt <= now || expiresAt > now+TokenSeconds {
		return "", errors.New("invalid ingress media capability")
	}
	descriptor, err := IngressMediaDescriptor(size, meta)
	if err != nil {
		return "", err
	}
	claims := map[string]any{"v": IngressMediaTokenVersion, "kind": "public-ingress-media-v1", "r": relationship, "m": master, "o": owner, "i": object, "g": resource, "ingress": ingress, "origin": publicOrigin, "session": sessionID, "generation": generation, "descriptor": descriptor, "e": expiresAt}
	if digest != "" {
		claims["v"], claims["kind"] = PlainIngressTokenVersion, "public-ingress-plain-v1"
		claims["content_sha256"] = digest
	}
	return capabilityToken(credential, claims)
}

func VerifyIngressMediaToken(credential, token string, now int64) (map[string]any, error) {
	return verifyIngressMediaToken(credential, token, now, IngressMediaTokenVersion, "public-ingress-media-v1", false)
}

func VerifyPlainIngressMediaToken(credential, token string, now int64) (map[string]any, error) {
	return verifyIngressMediaToken(credential, token, now, PlainIngressTokenVersion, "public-ingress-plain-v1", true)
}

// PlainIngressProbeToken cannot authorize a media route: its distinct kind is
// accepted only by the authenticated readiness endpoint and binds fixed,
// non-user fixture data to a fresh paired challenge.
func PlainIngressProbeToken(credential, relationship, master, owner, challenge string, now int64) (string, error) {
	if !identifier.MatchString(relationship) || !identifier.MatchString(master) || !identifier.MatchString(owner) || !identifier.MatchString(challenge) || now < 0 || now > math.MaxInt64-30 {
		return "", errors.New("invalid plain readiness probe")
	}
	descriptor, err := IngressMediaDescriptor(PlainProbeFixtureSize, nil)
	if err != nil {
		return "", err
	}
	object := strings.Repeat("0", 64)
	return capabilityToken(credential, map[string]any{"v": PlainIngressTokenVersion, "kind": "public-ingress-plain-probe-v1", "r": relationship, "m": master, "o": owner, "i": object, "g": object, "ingress": master, "origin": "https://readiness.invalid", "session": challenge, "generation": 1, "descriptor": descriptor, "content_sha256": plainProbeDigest, "e": now + 30})
}

func VerifyPlainIngressProbeToken(credential, token, challenge string, now int64) (map[string]any, error) {
	value, err := verifyIngressMediaToken(credential, token, now, PlainIngressTokenVersion, "public-ingress-plain-probe-v1", true)
	descriptor, _ := IngressMediaDescriptor(PlainProbeFixtureSize, nil)
	generation, validGeneration := integerField(value, "generation")
	if err != nil || !identifier.MatchString(challenge) || !validGeneration || generation != 1 || stringField(value, "session") != challenge || stringField(value, "ingress") != stringField(value, "m") || stringField(value, "i") != strings.Repeat("0", 64) || stringField(value, "g") != strings.Repeat("0", 64) || stringField(value, "origin") != "https://readiness.invalid" || stringField(value, "descriptor") != descriptor || stringField(value, "content_sha256") != plainProbeDigest {
		return nil, errors.New("invalid plain readiness probe")
	}
	return value, nil
}

func verifyIngressMediaToken(credential, token string, now int64, expectedVersion int64, expectedKind string, plain bool) (map[string]any, error) {
	value, err := verifyCapabilityToken(credential, token)
	version, vok := integerField(value, "v")
	expiry, eok := integerField(value, "e")
	generation, gok := integerField(value, "generation")
	if err != nil || !vok || version != expectedVersion || !eok || now < 0 || now > math.MaxInt64-TokenSeconds-60 || expiry <= now || expiry > now+TokenSeconds+60 || !gok || generation < 1 || stringField(value, "kind") != expectedKind || !identifier.MatchString(stringField(value, "r")) || !identifier.MatchString(stringField(value, "m")) || !identifier.MatchString(stringField(value, "o")) || !identifier.MatchString(stringField(value, "ingress")) || !identifier.MatchString(stringField(value, "session")) || !objectID.MatchString(stringField(value, "i")) || !objectID.MatchString(stringField(value, "g")) || !objectID.MatchString(stringField(value, "descriptor")) || !validIngressOrigin(stringField(value, "origin")) {
		return nil, errors.New("invalid or expired ingress media capability")
	}
	_, present := value["content_sha256"]
	if plain && (!present || !objectID.MatchString(stringField(value, "content_sha256"))) || !plain && present {
		return nil, errors.New("invalid plaintext content proof")
	}
	return value, nil
}

// StorageToken creates a storage capability compatible with historical serialized capabilities.
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

// RecordingToken creates a recording capability compatible with historical serialized capabilities.
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
