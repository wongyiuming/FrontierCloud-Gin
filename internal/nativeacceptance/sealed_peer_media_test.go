package nativeacceptance

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/media"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store/business"
	"golang.org/x/crypto/hkdf"
)

type fleetEncryptedUpload struct {
	plain, ciphertext []byte
	path              string
}

func sealedFleetDecode(t *testing.T, in map[string]any, out any) {
	t.Helper()
	raw, err := json.Marshal(in)
	if err != nil || json.Unmarshal(raw, out) != nil {
		t.Fatal("fixture response decode")
	}
}
func fleetUnwrap(t *testing.T, private *ecdh.PrivateKey, session mediacrypto.SessionGrant, metadata mediacrypto.Metadata, envelope mediacrypto.KeyEnvelope) []byte {
	t.Helper()
	publicBytes, err := base64.StdEncoding.DecodeString(session.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	public, err := ecdh.P256().NewPublicKey(publicBytes)
	if err != nil {
		t.Fatal(err)
	}
	shared, err := private.ECDH(public)
	if err != nil {
		t.Fatal(err)
	}
	salt, err := base64.StdEncoding.DecodeString(session.Salt)
	if err != nil {
		t.Fatal(err)
	}
	wrapping := make([]byte, 32)
	if _, err = io.ReadFull(hkdf.New(sha256.New, shared, salt, []byte("frontiercloud:browser-wrap:v1:"+session.SessionID)), wrapping); err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(wrapping)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	iv, err := base64.StdEncoding.DecodeString(envelope.IV)
	if err != nil {
		t.Fatal(err)
	}
	wrapped, err := base64.StdEncoding.DecodeString(envelope.WrappedKey)
	if err != nil {
		t.Fatal(err)
	}
	key, err := aead.Open(nil, iv, wrapped, []byte("frontiercloud:key-envelope:v1:"+session.SessionID+":"+metadata.FileID))
	if err != nil {
		t.Fatal("fixture key envelope")
	}
	return key
}
func fleetJSON(t *testing.T, ctx context.Context, site *fleetSite, method, path string, body any) map[string]any {
	t.Helper()
	code, out, err := site.request(ctx, method, path, body, map[string]string{"Origin": site.origin, "Sec-Fetch-Site": "same-origin"})
	if err != nil || code != http.StatusOK {
		message, _ := out["detail"].(string)
		switch message {
		case "存储节点不提供媒体密钥，请访问主节点", "该文件为明文落盘", "节点状态或存储操作冲突", "资源路径不可用", "临时密钥授权已失效，请重新建立浏览器会话":
		default:
			message = "other or absent"
		}
		t.Fatalf("fixture %s %s: %d %v (%s)", method, path, code, err, message)
	}
	return out
}
func fleetUploadEncrypted(t *testing.T, ctx context.Context, master, owner *fleetSite, ownerID string) fleetEncryptedUpload {
	return fleetUploadEncryptedMode(t, ctx, master, owner, ownerID, "Direct", "song.mp3")
}

func fleetUploadEncryptedMode(t *testing.T, ctx context.Context, master, owner *fleetSite, ownerID, mode, filename string) fleetEncryptedUpload {
	t.Helper()
	private, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	raw := fleetJSON(t, ctx, master, "POST", "/api/v1/media/admin/crypto/session", map[string]any{"public_key": base64.StdEncoding.EncodeToString(private.PublicKey().Bytes())})
	var session mediacrypto.SessionGrant
	sealedFleetDecode(t, raw, &session)
	plain := []byte("ID3-private-fleet-encrypted-media-20261105")
	raw = fleetJSON(t, ctx, master, "POST", "/api/v1/media/admin/crypto/prepare", map[string]any{"session_id": session.SessionID, "plaintext_size": len(plain)})
	var prepared struct {
		Encryption mediacrypto.Metadata    `json:"encryption"`
		Envelope   mediacrypto.KeyEnvelope `json:"key_envelope"`
		Token      string                  `json:"preparation_token"`
	}
	sealedFleetDecode(t, raw, &prepared)
	key := fleetUnwrap(t, private, session, prepared.Encryption, prepared.Envelope)
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	crypt, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := prepared.Encryption.ChunkNonce(0)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext := crypt.Seal(nil, nonce, plain, prepared.Encryption.ChunkAAD(0))
	digest := sha256.Sum256(ciphertext)
	id := make([]byte, 16)
	if _, err = rand.Read(id); err != nil {
		t.Fatal(err)
	}
	upload := hex.EncodeToString(id)
	parent := "music/private-fleet"
	if mode == "Relay" {
		parent = "music/private-fleet-relay"
	} else if mode == "DirectHidden" {
		parent = "music/private-fleet-hidden"
	}
	req := business.SelectedPrepareRequest{UploadID: upload, ParentPath: parent, Filename: filename, MemberID: ownerID, CipherSHA256: hex.EncodeToString(digest[:]), Encryption: prepared.Encryption, Preparation: prepared.Token}
	raw = fleetJSON(t, ctx, master, "POST", "/api/v1/media/admin/upload/selected/prepare", req)
	var ticket business.SelectedDirectTicket
	sealedFleetDecode(t, raw, &ticket)
	if mode == "Relay" {
		if ticket.Transport != "Relay" || ticket.Capability != "" || ticket.URL != "/api/v1/media/admin/upload/selected/"+upload+"/bytes" {
			t.Fatal("unexpected Relay upload route")
		}
		receipt := fleetJSON(t, ctx, master, "PUT", ticket.URL, ciphertext)
		fleetJSON(t, ctx, master, "POST", "/api/v1/media/admin/upload/selected/"+upload+"/complete", receipt)
		return fleetEncryptedUpload{plain: plain, ciphertext: ciphertext, path: parent + "/" + filename}
	}
	target, err := url.Parse(ticket.URL)
	if err != nil || target.Scheme+"://"+target.Host != owner.origin || ticket.Transport != "Direct" || ticket.Capability == "" {
		t.Fatal("unexpected owner upload route")
	}
	request, err := http.NewRequestWithContext(ctx, "PUT", ticket.URL, bytes.NewReader(ciphertext))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Origin", master.origin)
	request.Header.Set("Content-Type", "application/octet-stream")
	request.Header.Set("X-Fc-Selected-Upload", ticket.Capability)
	response, err := owner.client.Do(request)
	if err != nil {
		t.Fatal("owner upload transport", err)
	}
	var receipt map[string]any
	err = json.NewDecoder(io.LimitReader(response.Body, 64<<10)).Decode(&receipt)
	response.Body.Close()
	if err != nil || response.StatusCode != http.StatusOK {
		t.Fatal("owner upload", response.StatusCode, err)
	}
	fleetJSON(t, ctx, master, "POST", "/api/v1/media/admin/upload/selected/"+upload+"/complete", receipt)
	return fleetEncryptedUpload{plain: plain, ciphertext: ciphertext, path: parent + "/" + filename}
}
func fleetCheckEncrypted(t *testing.T, ctx context.Context, peer *fleetSite, uploaded fleetEncryptedUpload) {
	fleetCheckEncryptedMode(t, ctx, peer, uploaded, "Local")
}

func fleetCheckEncryptedMode(t *testing.T, ctx context.Context, peer *fleetSite, uploaded fleetEncryptedUpload, transport string) {
	t.Helper()
	raw := fleetJSON(t, ctx, peer, "GET", "/api/v1/media/catalog/media?media_type=music&path="+url.QueryEscape(path.Dir(uploaded.path))+"&playback_session_id=fixture", nil)
	var listing struct {
		Entries []media.Track `json:"entries"`
	}
	sealedFleetDecode(t, raw, &listing)
	var object media.Track
	for _, candidate := range listing.Entries {
		if candidate.MediaPath == uploaded.path {
			if object.MediaPath != "" {
				t.Fatal("duplicate encrypted catalog identity")
			}
			object = candidate
		}
	}
	if object.Encryption == nil || object.MediaPath != uploaded.path || object.ResourceID == "" || object.ObjectID == "" {
		t.Fatal("encrypted catalog identity incomplete")
	}
	fleetCheckEncryptedTrack(t, ctx, peer, uploaded, object, transport)
}

func fleetCheckEncryptedTrack(t *testing.T, ctx context.Context, peer *fleetSite, uploaded fleetEncryptedUpload, object media.Track, transport string) string {
	t.Helper()
	private, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	raw := fleetJSON(t, ctx, peer, "POST", "/api/v1/media/crypto/session", map[string]any{"public_key": base64.StdEncoding.EncodeToString(private.PublicKey().Bytes())})
	var session mediacrypto.SessionGrant
	sealedFleetDecode(t, raw, &session)
	raw = fleetJSON(t, ctx, peer, "POST", "/api/v1/media/crypto/key", map[string]any{"session_id": session.SessionID, "file_path": object.MediaPath, "resource_id": object.ResourceID, "object_id": object.ObjectID})
	var grant struct {
		URL       string                  `json:"source_url"`
		Headers   map[string]string       `json:"source_headers"`
		Transport string                  `json:"source_transport"`
		Envelope  mediacrypto.KeyEnvelope `json:"key_envelope"`
	}
	sealedFleetDecode(t, raw, &grant)
	target, err := url.Parse(grant.URL)
	if err != nil || target.Scheme+"://"+target.Host != peer.origin || grant.Transport != transport {
		t.Fatal("unexpected selected peer source")
	}
	request, err := http.NewRequestWithContext(ctx, "GET", grant.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Origin", peer.origin)
	request.Header.Set("Range", "bytes=0-"+fmt.Sprint(len(uploaded.ciphertext)-1))
	for k, v := range grant.Headers {
		request.Header.Set(k, v)
	}
	response, err := peer.client.Do(request)
	if err != nil {
		t.Fatal("peer ciphertext transport", err)
	}
	got, err := io.ReadAll(io.LimitReader(response.Body, int64(len(uploaded.ciphertext))+1))
	response.Body.Close()
	if err != nil || response.StatusCode != http.StatusPartialContent || !bytes.Equal(got, uploaded.ciphertext) {
		classification := "other or absent"
		if response.StatusCode == http.StatusConflict {
			if bytes.Contains(got, []byte("Resource read is fenced")) {
				classification = "read fence"
			} else if bytes.Contains(got, []byte("Resource changed")) {
				classification = "binding changed"
			}
		}
		t.Fatal("peer ciphertext range", response.StatusCode, err, classification)
	}
	key := fleetUnwrap(t, private, session, *object.Encryption, grant.Envelope)
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	crypt, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := object.Encryption.ChunkNonce(0)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := crypt.Open(nil, nonce, got, object.Encryption.ChunkAAD(0))
	if err != nil || !bytes.Equal(plain, uploaded.plain) {
		t.Fatal("peer chunk authentication")
	}
	return grant.URL
}
