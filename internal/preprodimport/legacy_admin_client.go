package preprodimport

// This private, unregistered client uses the 64901e2f Admin P-256 endpoints.
// It returns a session envelope in memory only; it is not a vault commit or
// source-signed grant. The caller must authenticate and bind the complete
// source snapshot, target identity and administrator session separately.
import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
)

type legacyAdminEnvelope struct {
	receiver *legacyReceiver
	grant mediacrypto.SessionGrant
	metadata mediacrypto.Metadata
	envelope mediacrypto.KeyEnvelope
}

func fetchLegacyAdminEnvelope(ctx context.Context, client *http.Client, origin, cookie, csrf, tlsSPKI, name, mediaID string, expected mediacrypto.Metadata) (legacyAdminEnvelope, error) {
	var empty legacyAdminEnvelope
	if ctx == nil || client == nil || cookie == "" || csrf == "" || len(cookie) > 8192 || len(csrf) > 1024 || strings.ContainsAny(cookie+csrf, "\r\n") || !id64.MatchString(tlsSPKI) || !id64.MatchString(mediaID) || expected.Validate() != nil || !(validPath(name, "audio") || validPath(name, "video")) {
		return empty, invalid("legacy admin input")
	}
	deadline, ok := ctx.Deadline()
	if !ok || time.Until(deadline) <= 0 || time.Until(deadline) > 30*time.Second {
		return empty, invalid("legacy admin deadline")
	}
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Path != "" || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || strings.ContainsAny(origin, "\r\n\t \\") {
		return empty, invalid("legacy admin origin")
	}
	copyClient := *client
	copyClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	base := client.Transport
	if base == nil { base = http.DefaultTransport }
	transport, ok := base.(*http.Transport)
	if !ok { return empty, invalid("legacy admin transport configuration") }
	transport = transport.Clone()
	defer transport.CloseIdleConnections()
	config := &tls.Config{MinVersion: tls.VersionTLS12}
	if transport.TLSClientConfig != nil { config = transport.TLSClientConfig.Clone() }
	if config.InsecureSkipVerify || config.ServerName != "" && !strings.EqualFold(config.ServerName, u.Hostname()) {
		return empty, invalid("legacy admin transport configuration")
	}
	config.ServerName = u.Hostname()
	priorVerify := config.VerifyConnection
	config.VerifyConnection = func(state tls.ConnectionState) error {
		if priorVerify != nil {
			if e := priorVerify(state); e != nil { return e }
		}
		if len(state.VerifiedChains) == 0 || len(state.PeerCertificates) == 0 { return invalid("legacy admin source identity") }
		fingerprint := sha256.Sum256(state.PeerCertificates[0].RawSubjectPublicKeyInfo)
		if subtle.ConstantTimeCompare([]byte(hex.EncodeToString(fingerprint[:])), []byte(tlsSPKI)) != 1 { return invalid("legacy admin source identity") }
		return nil
	}
	transport.TLSClientConfig = config
	copyClient.Transport = transport
	post := func(path string, body any, out any) error {
		raw, e := json.Marshal(body)
		if e != nil { return invalid("legacy admin request") }
		defer clear(raw)
		req, e := http.NewRequestWithContext(ctx, http.MethodPost, origin+path, bytes.NewReader(raw))
		if e != nil { return invalid("legacy admin request") }
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", origin)
		req.Header.Set("Cookie", cookie)
		req.Header.Set("X-CSRF-Token", csrf)
		resp, e := copyClient.Do(req)
		if e != nil { return invalid("legacy admin transport") }
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK || resp.TLS == nil || len(resp.TLS.VerifiedChains) == 0 || len(resp.TLS.PeerCertificates) == 0 {
			return invalid("legacy admin transport")
		}
		fingerprint := sha256.Sum256(resp.TLS.PeerCertificates[0].RawSubjectPublicKeyInfo)
		if subtle.ConstantTimeCompare([]byte(hex.EncodeToString(fingerprint[:])), []byte(tlsSPKI)) != 1 {
			return invalid("legacy admin source identity")
		}
		response, e := io.ReadAll(io.LimitReader(resp.Body, 65537))
		if e != nil || len(response) > 65536 { return invalid("legacy admin response") }
		defer clear(response)
		if json.Unmarshal(response, out) != nil { return invalid("legacy admin response") }
		return nil
	}
	receiver, public, err := newLegacyReceiver()
	if err != nil { return empty, err }
	var grant mediacrypto.SessionGrant
	if err = post("/api/v1/media/admin/crypto/session", map[string]string{"public_key": public}, &grant); err != nil { return empty, err }
	var result struct {
		Encryption mediacrypto.Metadata `json:"encryption"`
		Envelope mediacrypto.KeyEnvelope `json:"key_envelope"`
	}
	// Old native API compares object_id with the global media ID; it must not
	// be replaced with the owner's separate physical object ID.
	request := map[string]string{"session_id": grant.SessionID, "file_path": name, "resource_id": mediaID, "object_id": mediaID}
	if err = post("/api/v1/media/admin/crypto/key", request, &result); err != nil { return empty, err }
	if result.Encryption != expected || result.Encryption.Validate() != nil || grant.ExpiresAt <= time.Now().Unix() || result.Envelope.ExpiresAt != grant.ExpiresAt {
		return empty, invalid("legacy admin descriptor")
	}
	return legacyAdminEnvelope{receiver: receiver, grant: grant, metadata: result.Encryption, envelope: result.Envelope}, nil
}
