// Package mediacrypto owns the browser encryption wire format and small key
// envelopes. Media bytes are encrypted/decrypted only by the browser.
package mediacrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/fsutil"
	"golang.org/x/crypto/hkdf"
)

const ChunkSize int64 = 1024 * 1024
const SessionLifetime = 15 * time.Minute
const MaxSessions = 4096
const MaxPublicSessions = MaxSessions - 512
const MaxAdminSessions = 512
const MaxSessionsPerBinding = 16
const MaxCiphertextSize int64 = 10 * 1024 * 1024 * 1024
const MaxPlaintextSize int64 = MaxCiphertextSize - 16*((MaxCiphertextSize+ChunkSize-1)/ChunkSize)

var ErrMetadata = errors.New("invalid media encryption descriptor")
var ErrSession = errors.New("browser encryption authorization expired or invalid")
var ErrSessionLimit = errors.New("browser encryption authorization creation limit reached")
var ErrPremaster = errors.New("media premaster does not match durable business key identity")

type Metadata struct {
	Version        int    `json:"version"`
	Algorithm      string `json:"algorithm"`
	FileID         string `json:"file_id"`
	NoncePrefix    string `json:"nonce_prefix"`
	PlaintextSize  int64  `json:"plaintext_size"`
	ChunkSize      int64  `json:"chunk_size"`
	CiphertextSize int64  `json:"ciphertext_size"`
}

func NewMetadata(size int64) (Metadata, error) {
	if size <= 0 || size > MaxPlaintextSize {
		return Metadata{}, ErrMetadata
	}
	id, prefix := make([]byte, 16), make([]byte, 8)
	if _, err := rand.Read(id); err != nil {
		return Metadata{}, err
	}
	if _, err := rand.Read(prefix); err != nil {
		return Metadata{}, err
	}
	m := Metadata{Version: 1, Algorithm: "AES-256-GCM", FileID: hex.EncodeToString(id), NoncePrefix: base64.StdEncoding.EncodeToString(prefix), PlaintextSize: size, ChunkSize: ChunkSize, CiphertextSize: size + 16*((size+ChunkSize-1)/ChunkSize)}
	return m, nil
}

func (m Metadata) Validate() error {
	id, err := hex.DecodeString(m.FileID)
	prefix, prefixErr := base64.StdEncoding.Strict().DecodeString(m.NoncePrefix)
	if err != nil || len(id) != 16 || hex.EncodeToString(id) != m.FileID || prefixErr != nil || len(prefix) != 8 || m.Version != 1 || m.Algorithm != "AES-256-GCM" || m.ChunkSize != ChunkSize || m.PlaintextSize <= 0 || m.PlaintextSize > MaxPlaintextSize || m.CiphertextSize != m.PlaintextSize+16*((m.PlaintextSize+ChunkSize-1)/ChunkSize) {
		return ErrMetadata
	}
	return nil
}

func (m Metadata) ChunkNonce(index uint32) ([]byte, error) {
	if err := m.Validate(); err != nil {
		return nil, err
	}
	if int64(index) >= (m.PlaintextSize+ChunkSize-1)/ChunkSize {
		return nil, ErrMetadata
	}
	nonce := make([]byte, 12)
	prefix, _ := base64.StdEncoding.DecodeString(m.NoncePrefix)
	copy(nonce, prefix)
	binary.BigEndian.PutUint32(nonce[8:], index)
	return nonce, nil
}

func (m Metadata) ChunkAAD(index uint32) []byte {
	return []byte("frontiercloud:chunk:v1:" + m.FileID + ":" + strconv.FormatInt(m.PlaintextSize, 10) + ":" + strconv.FormatUint(uint64(index), 10))
}

type SessionGrant struct {
	SessionID string `json:"session_id"`
	PublicKey string `json:"public_key"`
	Salt      string `json:"salt"`
	ExpiresAt int64  `json:"expires_at"`
	ExpiresIn int64  `json:"expires_in"`
}
type KeyEnvelope struct {
	IV         string `json:"iv"`
	WrappedKey string `json:"wrapped_key"`
	ExpiresAt  int64  `json:"expires_at"`
}
type session struct {
	binding string
	key     []byte
	expires time.Time
}
type Manager struct {
	master   []byte
	mu       sync.Mutex
	sessions map[string]session
	now      func() time.Time
	limits   sessionLimits
}

type sessionLimits struct{ public, admin, binding int }

func New(master []byte) (*Manager, error) {
	if len(master) != 32 {
		return nil, fmt.Errorf("media premaster key must contain 32 bytes")
	}
	return &Manager{master: append([]byte(nil), master...), sessions: map[string]session{}, now: time.Now,
		limits: sessionLimits{MaxPublicSessions, MaxAdminSessions, MaxSessionsPerBinding}}, nil
}

// Admission never evicts or renews a live authorization. Public traffic cannot
// consume the separately reserved Admin capacity, and a cookie may own several
// page handshakes without owning the process-wide registry.
func (m *Manager) admitSessionLocked(binding string, now time.Time) error {
	public, admin, own := 0, 0, 0
	for id, s := range m.sessions {
		if !s.expires.After(now) {
			delete(m.sessions, id)
			continue
		}
		if strings.HasPrefix(s.binding, "admin:") {
			admin++
		} else {
			public++
		}
		if s.binding == binding {
			own++
		}
	}
	if own >= m.limits.binding || strings.HasPrefix(binding, "admin:") && admin >= m.limits.admin ||
		!strings.HasPrefix(binding, "admin:") && public >= m.limits.public {
		return ErrSessionLimit
	}
	return nil
}

// KeyID is a domain-separated public verifier. It permits database restores to
// check the independently restored secret without exporting that secret.
func (m *Manager) KeyID() string {
	h := hmac.New(sha256.New, m.master)
	h.Write([]byte("frontiercloud:premaster-id:v1"))
	return hex.EncodeToString(h.Sum(nil))
}

// Open never regenerates an unreadable or malformed persistent premaster key.
func Open(directory string) (*Manager, error) {
	return OpenForData(directory, false)
}

// OpenForData must receive the authoritative metadata presence. A missing key
// is initialization only for a database without active encrypted objects.
func OpenForData(directory string, hasEncryptedMedia bool) (*Manager, error) {
	if !hasEncryptedMedia {
		if err := os.MkdirAll(directory, 0700); err != nil {
			return nil, err
		}
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("private media-key directory required")
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	opened, err := root.Stat(".")
	if err != nil || !os.SameFile(info, opened) {
		return nil, ErrMetadata
	}
	info, err = root.Lstat("media-premaster.key")
	if errors.Is(err, os.ErrNotExist) && !hasEncryptedMedia {
		key, id := make([]byte, 32), make([]byte, 16)
		if _, err = rand.Read(key); err != nil {
			return nil, err
		}
		if _, err = rand.Read(id); err != nil {
			return nil, err
		}
		temp := ".media-premaster-" + hex.EncodeToString(id)
		f, err := root.OpenFile(temp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return nil, err
		}
		defer root.Remove(temp)
		_, err = f.Write(key)
		if err == nil {
			err = f.Sync()
		}
		closeErr := f.Close()
		if err == nil {
			err = closeErr
		}
		if err != nil {
			return nil, err
		}
		if err = root.Link(temp, "media-premaster.key"); err != nil && !errors.Is(err, os.ErrExist) {
			return nil, err
		}
		if err = fsutil.SyncDirectory(root, "."); err != nil {
			return nil, err
		}
		parent, err := os.OpenRoot(filepath.Dir(directory))
		if err != nil {
			return nil, err
		}
		err = fsutil.SyncDirectory(parent, ".")
		parent.Close()
		if err != nil {
			return nil, err
		}
		info, err = root.Lstat("media-premaster.key")
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() != 32 {
		return nil, errors.New("existing 32-byte media premaster key required")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
		return nil, errors.New("media premaster key permissions must be 0600")
	}
	f, err := root.Open("media-premaster.key")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	opened, err = f.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, ErrMetadata
	}
	key, err := io.ReadAll(io.LimitReader(f, 33))
	if err != nil {
		return nil, err
	}
	return New(key)
}

func (m *Manager) FileKey(meta Metadata) ([]byte, error) {
	if err := meta.Validate(); err != nil {
		return nil, err
	}
	h := hmac.New(sha256.New, m.master)
	h.Write([]byte("frontiercloud:file-key:v1:" + meta.FileID))
	return h.Sum(nil), nil
}

// NewSession consumes one browser public-key handshake. Its fixed 15 minute
// authorization covers multiple file envelopes; requesting a file never extends
// the deadline. The HTTP layer must recheck permission on every file request.
func (m *Manager) NewSession(binding, clientPublicKey string) (SessionGrant, error) {
	if binding == "" {
		return SessionGrant{}, ErrSession
	}
	// Reject a full binding before performing ECDH. Recheck atomically at insert
	// time so concurrent handshakes cannot exceed any admission boundary.
	m.mu.Lock()
	started := m.now()
	err := m.admitSessionLocked(binding, started)
	m.mu.Unlock()
	if err != nil {
		return SessionGrant{}, err
	}
	encoded, err := base64.StdEncoding.Strict().DecodeString(clientPublicKey)
	if err != nil {
		return SessionGrant{}, ErrSession
	}
	pub, err := ecdh.P256().NewPublicKey(encoded)
	if err != nil {
		return SessionGrant{}, ErrSession
	}
	private, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return SessionGrant{}, err
	}
	shared, err := private.ECDH(pub)
	if err != nil {
		return SessionGrant{}, ErrSession
	}
	id, salt := make([]byte, 16), make([]byte, 32)
	if _, err = rand.Read(id); err != nil {
		return SessionGrant{}, err
	}
	if _, err = rand.Read(salt); err != nil {
		return SessionGrant{}, err
	}
	sessionID := hex.EncodeToString(id)
	key := make([]byte, 32)
	if _, err = io.ReadFull(hkdf.New(sha256.New, shared, salt, []byte("frontiercloud:browser-wrap:v1:"+sessionID)), key); err != nil {
		return SessionGrant{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	if err := m.admitSessionLocked(binding, now); err != nil {
		return SessionGrant{}, err
	}
	expires := started.Add(SessionLifetime)
	// Give browsers a conservative duration independent of their wall clock.
	// Floor against the serialized deadline so its second precision never grants
	// longer than expires_at; the registry deadline remains authoritative.
	expiresIn := min(int64(SessionLifetime/time.Second), int64(time.Unix(expires.Unix(), 0).Sub(m.now())/time.Second))
	if expiresIn <= 0 {
		return SessionGrant{}, ErrSession
	}
	m.sessions[sessionID] = session{binding, key, expires}
	return SessionGrant{SessionID: sessionID, PublicKey: base64.StdEncoding.EncodeToString(private.PublicKey().Bytes()), Salt: base64.StdEncoding.EncodeToString(salt), ExpiresAt: expires.Unix(), ExpiresIn: expiresIn}, nil
}

func (m *Manager) Wrap(binding, sessionID string, meta Metadata) (KeyEnvelope, error) {
	key, err := m.FileKey(meta)
	if err != nil {
		return KeyEnvelope{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[sessionID]
	if !ok || binding == "" || s.binding != binding || !s.expires.After(m.now()) {
		if ok && !s.expires.After(m.now()) {
			delete(m.sessions, sessionID)
		}
		return KeyEnvelope{}, ErrSession
	}
	block, err := aes.NewCipher(s.key)
	if err != nil {
		return KeyEnvelope{}, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return KeyEnvelope{}, err
	}
	iv := make([]byte, aead.NonceSize())
	if _, err = rand.Read(iv); err != nil {
		return KeyEnvelope{}, err
	}
	wrapped := aead.Seal(nil, iv, key, []byte("frontiercloud:key-envelope:v1:"+sessionID+":"+meta.FileID))
	return KeyEnvelope{base64.StdEncoding.EncodeToString(iv), base64.StdEncoding.EncodeToString(wrapped), s.expires.Unix()}, nil
}

func (m *Manager) RevokeBinding(binding string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, s := range m.sessions {
		if s.binding == binding {
			delete(m.sessions, id)
		}
	}
}

type preparation struct {
	Binding  string   `json:"binding"`
	Metadata Metadata `json:"metadata"`
	Expires  int64    `json:"expires_at"`
}

func (m *Manager) SignPreparation(binding string, meta Metadata) (string, error) {
	if binding == "" {
		return "", ErrSession
	}
	if err := meta.Validate(); err != nil {
		return "", err
	}
	raw, err := json.Marshal(preparation{binding, meta, m.now().Add(SessionLifetime).Unix()})
	if err != nil {
		return "", err
	}
	h := hmac.New(sha256.New, m.master)
	h.Write([]byte("frontiercloud:preparation:v1:"))
	h.Write(raw)
	return base64.RawURLEncoding.EncodeToString(raw) + "." + base64.RawURLEncoding.EncodeToString(h.Sum(nil)), nil
}

func (m *Manager) VerifyPreparation(binding, token string, meta Metadata) error {
	if len(token) > 2048 || binding == "" {
		return ErrSession
	}
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return ErrSession
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return ErrSession
	}
	mac, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ErrSession
	}
	h := hmac.New(sha256.New, m.master)
	h.Write([]byte("frontiercloud:preparation:v1:"))
	h.Write(raw)
	if !hmac.Equal(mac, h.Sum(nil)) {
		return ErrSession
	}
	var claim preparation
	if json.Unmarshal(raw, &claim) != nil || claim.Binding != binding || claim.Expires <= m.now().Unix() || claim.Metadata != meta || meta.Validate() != nil {
		return ErrSession
	}
	return nil
}
