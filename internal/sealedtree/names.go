// Package sealedtree provides cryptographic primitives for a Master-owned,
// encrypted logical namespace. It does not persist a tree, migrate a database,
// authorize a request, or make an existing storage layout safe to activate.
package sealedtree

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"strconv"
	"unicode/utf8"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/migrationpaths"
	"golang.org/x/crypto/hkdf"
)

// ErrInvalid deliberately does not include a logical name or key material.
var ErrInvalid = errors.New("invalid sealed tree record")

const recordVersion byte = 1
const nameRecordVersion byte = 2
const legacyComponentBytes = 1024
const maxComponentRunes = 1024
const maxComponentBytes = maxComponentRunes * utf8.UTFMax
const legacyPayloadBytes = 3 + 64 + 64 + legacyComponentBytes
const payloadBytes = 3 + 64 + 64 + maxComponentBytes
const recordSaltBytes = 32
const nonceBytes = 12

// Tree holds only domain-separated derived keys. The caller must keep it on the
// authoritative Master and must persist the nonsecret 32-byte salt with the
// encrypted records. Losing or changing either input makes records unreadable.
type Tree struct {
	ready       bool
	salt        [32]byte
	encKey      [32]byte
	indexKey    [32]byte
	capacityKey [32]byte
}

// Record exposes neither a logical component, type, path nor a raw node ID.
// ParentIndex and Lookup are independent keyed values; an observer can see
// sibling grouping/count, record count, changes and access patterns, but cannot
// associate a group with its parent's object ID without the Master secret.
// The database must enforce uniqueness of (ParentIndex, Lookup) and keep IDs
// and revisions authoritative; encryption alone cannot prevent deletion or a
// rollback of an entire database snapshot.
type Record struct {
	ObjectIndex string
	ParentIndex string
	Lookup      string
	Revision    int64
	Sealed      []byte
}

// Entry exists only in the trusted Master's memory; it must not be serialized
// into an unencrypted database, journal, log, backup, or remote-node index.
type Entry struct {
	ParentID string
	ObjectID string
	Kind     string
	Name     string
}

// New derives independent encryption and lookup keys from a dedicated 32-byte
// tree secret and a persistent public salt. Each environment needs its own
// independent secret. In particular, the media premaster must not be used as
// this secret: copying it into preproduction would expose production's tree.
func New(master, salt []byte) (*Tree, error) {
	if len(master) != 32 || len(salt) != 32 {
		return nil, ErrInvalid
	}
	var secretNonzero byte
	for _, value := range master {
		secretNonzero |= value
	}
	if secretNonzero == 0 {
		return nil, ErrInvalid
	}
	var nonzero byte
	for _, value := range salt {
		nonzero |= value
	}
	if nonzero == 0 {
		return nil, ErrInvalid
	}
	enc, err := derive(master, salt, "frontiercloud:sealed-tree:name:v1")
	if err != nil {
		return nil, err
	}
	defer clear(enc)
	index, err := derive(master, salt, "frontiercloud:sealed-tree:index:v1")
	if err != nil {
		return nil, err
	}
	defer clear(index)
	capacity, err := derive(master, salt, "frontiercloud:sealed-tree:capacity:v1")
	if err != nil {
		return nil, err
	}
	defer clear(capacity)
	t := &Tree{ready: true}
	copy(t.salt[:], salt)
	copy(t.encKey[:], enc)
	copy(t.indexKey[:], index)
	copy(t.capacityKey[:], capacity)
	return t, nil
}

// NewMasterSecret creates an independent random tree secret. Only call this for
// a new, empty namespace after establishing protected durable key storage and
// recovery. Never replace a missing key for existing records. The caller owns
// this slice, must keep it on the authoritative Master, never send it to a
// Storage node, and clear it when no longer needed.
func NewMasterSecret() ([]byte, error) {
	secret := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, secret); err != nil {
		clear(secret)
		return nil, ErrInvalid
	}
	var nonzero byte
	for _, value := range secret {
		nonzero |= value
	}
	if nonzero == 0 {
		clear(secret)
		return nil, ErrInvalid
	}
	return secret, nil
}

// NewSalt generates a distinct public salt for one independently initialized
// namespace. The caller must persist it before encrypting any durable records;
// regeneration after data exists makes the namespace unreadable.
func NewSalt() ([]byte, error) {
	salt := make([]byte, 32)
	for attempts := 0; attempts < 4; attempts++ {
		if _, err := io.ReadFull(rand.Reader, salt); err != nil {
			return nil, ErrInvalid
		}
		var nonzero byte
		for _, value := range salt {
			nonzero |= value
		}
		if nonzero != 0 {
			return salt, nil
		}
	}
	return nil, ErrInvalid
}

func derive(master, salt []byte, label string) ([]byte, error) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(hkdf.New(sha256.New, master, salt, []byte(label)), key); err != nil {
		clear(key)
		return nil, ErrInvalid
	}
	return key, nil
}

func hexID(s string) bool {
	if len(s) != 64 {
		return false
	}
	decoded, err := hex.DecodeString(s)
	return err == nil && hex.EncodeToString(decoded) == s
}

func validComponent(s string) bool {
	return migrationpaths.ValidComponent(s)
}

func validIdentity(parentID, objectID, kind string) bool {
	return hexID(parentID) && hexID(objectID) && parentID != objectID && (kind == "directory" || kind == "audio" || kind == "video" || kind == "lyric")
}

func nameAAD(objectIndex string, revision int64, version byte) []byte {
	return []byte("frontiercloud:sealed-tree:record:v" + strconv.Itoa(int(version)) + "\x00" + objectIndex + "\x00" + strconv.FormatInt(revision, 10))
}

// ObjectIndex hides legacy object IDs which may themselves be unkeyed path
// hashes. It is distinct from ParentIndex so parent/child links do not become
// visible by joining persisted tags without knowledge of the Master key.
func (t *Tree) ObjectIndex(objectID string) (string, error) {
	if t == nil || !t.ready || !hexID(objectID) {
		return "", ErrInvalid
	}
	mac := hmac.New(sha256.New, t.indexKey[:])
	_, _ = mac.Write([]byte("frontiercloud:sealed-tree:object:v1\x00" + objectID))
	return hex.EncodeToString(mac.Sum(nil)), nil
}

// ParentIndex allows authorized enumeration without persisting a raw parent
// identifier. A fresh process derives it from the caller's in-memory parent ID.
func (t *Tree) ParentIndex(parentID string) (string, error) {
	if t == nil || !t.ready || !hexID(parentID) {
		return "", ErrInvalid
	}
	mac := hmac.New(sha256.New, t.indexKey[:])
	_, _ = mac.Write([]byte("frontiercloud:sealed-tree:parent:v1\x00" + parentID))
	return hex.EncodeToString(mac.Sum(nil)), nil
}

func kindByte(kind string) byte {
	switch kind {
	case "directory":
		return 1
	case "audio":
		return 2
	case "video":
		return 3
	case "lyric":
		return 4
	default:
		return 0
	}
}

func decodeKind(value byte) string {
	switch value {
	case 1:
		return "directory"
	case 2:
		return "audio"
	case 3:
		return "video"
	case 4:
		return "lyric"
	default:
		return ""
	}
}

// Lookup returns a domain-separated equality token for a canonical component.
// Callers must apply their existing normalization rules before invoking it.
func (t *Tree) Lookup(parentID, component string) (string, error) {
	if t == nil || !t.ready || !hexID(parentID) || !validComponent(component) {
		return "", ErrInvalid
	}
	mac := hmac.New(sha256.New, t.indexKey[:])
	_, _ = mac.Write([]byte("frontiercloud:sealed-tree:lookup:v1\x00" + parentID + "\x00" + component))
	return hex.EncodeToString(mac.Sum(nil)), nil
}

// recordCipher derives a separate per-record encryption key from a fresh
// 256-bit record salt. GCM nonce repetition across distinct salts cannot reuse
// a (key, nonce) pair. Integration must uniquely reserve EncryptionID per tree
// epoch before publication, including concurrent writers and retained versions.
func (t *Tree) recordCipher(salt []byte, purpose string) (cipher.AEAD, error) {
	if t == nil || !t.ready || len(salt) != recordSaltBytes || (purpose != "name" && purpose != "placement" && purpose != "s3-placement" && purpose != "root" && purpose != "facts" && purpose != "cursor" && purpose != "audit") {
		return nil, ErrInvalid
	}
	mac := hmac.New(sha256.New, t.encKey[:])
	_, _ = mac.Write([]byte("frontiercloud:sealed-tree:per-record-key:v1\x00" + purpose + "\x00"))
	_, _ = mac.Write(salt)
	key := mac.Sum(nil)
	defer clear(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, ErrInvalid
	}
	aead, err := cipher.NewGCM(block)
	if err != nil || aead.NonceSize() != nonceBytes {
		return nil, ErrInvalid
	}
	return aead, nil
}

// EncryptionID extracts a nonsecret per-record random identity which storage
// must durably reserve uniquely within a key epoch before accepting a record.
// A successful extraction alone does not authenticate the record.
func EncryptionID(r Record) (string, error) {
	if len(r.Sealed) == 0 || (r.Sealed[0] == recordVersion && len(r.Sealed) != 1+recordSaltBytes+nonceBytes+legacyPayloadBytes+16) || (r.Sealed[0] == nameRecordVersion && len(r.Sealed) != 1+recordSaltBytes+nonceBytes+payloadBytes+16) || (r.Sealed[0] != recordVersion && r.Sealed[0] != nameRecordVersion) {
		return "", ErrInvalid
	}
	return hex.EncodeToString(r.Sealed[1 : 1+recordSaltBytes]), nil
}

// Seal uses a fresh random per-record key salt and GCM nonce and authenticates
// the parent and object ID. Kind and name are in a fixed-size padded payload,
// preventing straightforward disclosure of name length or type in the row.
func (t *Tree) Seal(parentID, objectID, kind, component string, revision int64) (Record, error) {
	if t == nil || !t.ready || !validIdentity(parentID, objectID, kind) || revision <= 0 {
		return Record{}, ErrInvalid
	}
	lookup, err := t.Lookup(parentID, component)
	if err != nil {
		return Record{}, err
	}
	objectIndex, err := t.ObjectIndex(objectID)
	if err != nil {
		return Record{}, err
	}
	parentIndex, err := t.ParentIndex(parentID)
	if err != nil {
		return Record{}, err
	}
	random := make([]byte, recordSaltBytes+nonceBytes)
	if _, err := io.ReadFull(rand.Reader, random); err != nil {
		return Record{}, ErrInvalid
	}
	recordSalt, nonce := random[:recordSaltBytes], random[recordSaltBytes:]
	aead, err := t.recordCipher(recordSalt, "name")
	if err != nil {
		return Record{}, err
	}
	payload := make([]byte, payloadBytes)
	defer clear(payload)
	payload[0] = kindByte(kind)
	binary.BigEndian.PutUint16(payload[1:3], uint16(len(component)))
	copy(payload[3:67], parentID)
	copy(payload[67:131], objectID)
	copy(payload[131:], component)
	sealed := append([]byte{nameRecordVersion}, random...)
	sealed = aead.Seal(sealed, nonce, payload, nameAAD(objectIndex, revision, nameRecordVersion))
	return Record{ObjectIndex: objectIndex, ParentIndex: parentIndex, Lookup: lookup, Revision: revision, Sealed: sealed}, nil
}

// Open authenticates ciphertext and keyed indexes, rejecting swapped object or
// parent IDs, secret, salt, index or malformed data without disclosing names.
func (t *Tree) Open(parentID string, r Record) (Entry, error) {
	if !hexID(parentID) {
		return Entry{}, ErrInvalid
	}
	entry, err := t.OpenRecord(r)
	if err != nil || entry.ParentID != parentID {
		return Entry{}, ErrInvalid
	}
	return entry, nil
}

// OpenRecord recovers the encrypted parent and object IDs on the trusted
// Master. It verifies all derived indexes before exposing the entry, allowing
// authorized ancestry/cycle checks without storing parent IDs in plaintext.
func (t *Tree) OpenRecord(r Record) (Entry, error) {
	if t == nil || !t.ready || !hexID(r.ObjectIndex) || !hexID(r.ParentIndex) || !hexID(r.Lookup) || r.Revision <= 0 {
		return Entry{}, ErrInvalid
	}
	if _, err := EncryptionID(r); err != nil {
		return Entry{}, ErrInvalid
	}
	version := r.Sealed[0]
	recordSalt := r.Sealed[1 : 1+recordSaltBytes]
	nonce := r.Sealed[1+recordSaltBytes : 1+recordSaltBytes+nonceBytes]
	aead, err := t.recordCipher(recordSalt, "name")
	if err != nil {
		return Entry{}, ErrInvalid
	}
	plain, err := aead.Open(nil, nonce, r.Sealed[1+recordSaltBytes+nonceBytes:], nameAAD(r.ObjectIndex, r.Revision, version))
	if err != nil {
		return Entry{}, ErrInvalid
	}
	defer clear(plain)
	kind := decodeKind(plain[0])
	length := int(binary.BigEndian.Uint16(plain[1:3]))
	parentID := string(plain[3:67])
	objectID := string(plain[67:131])
	maxLength := maxComponentBytes
	if version == recordVersion {
		maxLength = legacyComponentBytes
	}
	if !validIdentity(parentID, objectID, kind) || length == 0 || length > maxLength {
		return Entry{}, ErrInvalid
	}
	for _, value := range plain[131+length:] {
		if value != 0 {
			return Entry{}, ErrInvalid
		}
	}
	component := string(plain[131 : 131+length])
	lookup, err := t.Lookup(parentID, component)
	index, indexErr := t.ObjectIndex(objectID)
	parentIndex, parentErr := t.ParentIndex(parentID)
	if err != nil || indexErr != nil || parentErr != nil || !hmac.Equal([]byte(lookup), []byte(r.Lookup)) || !hmac.Equal([]byte(index), []byte(r.ObjectIndex)) || !hmac.Equal([]byte(parentIndex), []byte(r.ParentIndex)) {
		return Entry{}, ErrInvalid
	}
	return Entry{ParentID: parentID, ObjectID: objectID, Kind: kind, Name: component}, nil
}

// BlobPath derives an opaque physical locator from an independent 256-bit
// random blob ID. It never accepts a logical path or display name.
func BlobPath(blobID string) (string, error) {
	if !hexID(blobID) {
		return "", ErrInvalid
	}
	return "objects/" + blobID[:2] + "/" + blobID[2:4] + "/" + blobID + ".blob", nil
}

// NewBlobID creates an independent physical identity; callers persist it in
// the same durable intent as the authorized object before publishing bytes.
func NewBlobID() (string, error) {
	var id [32]byte
	if _, err := io.ReadFull(rand.Reader, id[:]); err != nil {
		return "", ErrInvalid
	}
	return hex.EncodeToString(id[:]), nil
}
