package httpapi

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/karaoke"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/network"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/recording"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/sealedtree"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func TestRecordingAudioPreparationHTTPRequiresAccountSessionAndReservation(t *testing.T) {
	ctx := context.Background()
	const origin = "https://record-audio.test"
	const route = "/api/v1/karaoke/account/recordings/crypto/audio-prepare"
	master := nativeRecordingFixture(t, origin, "Master", &clusterHTTP{routers: map[string]*gin.Engine{}})
	cache := &recordingCryptoCache{sessions: map[string]map[string]string{}}
	resolver, err := network.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	accounts := RegisterKaraokeAccounts(master.router, karaoke.New(master.db.Karaoke(), master.db.Nodes(), cache), master.public, nil, resolver)
	manager := recording.NewManager(master.db.Recordings(), master.db.Karaoke(), master.db.Nodes(), master.db.Pool(), master.control, master.volume)
	RegisterKaraokeRecordings(master.router, accounts, manager, master.volume)
	user := store.KaraokeUser{ID: strings.Repeat("b", 32), Username: "record-audio", NameKey: "record-audio", PasswordHash: "fixture", Quota: 4096}
	if err = master.db.Karaoke().RegisterUser(ctx, user, "192.0.2.190", "20261105", store.KaraokeAudit{}); err != nil {
		t.Fatal(err)
	}
	token, csrf := strings.Repeat("a", 43), strings.Repeat("c", 32)
	if err = cache.SaveSession(ctx, "karaoke:session:"+karaokeSessionHash(token), user.ID, csrf, karaokeSessionHash(user.PasswordHash)); err != nil {
		t.Fatal(err)
	}
	var browserCookie *http.Cookie
	perform := func(target, requestOrigin string, body any, authenticated, csrfHeader bool) *httptest.ResponseRecorder {
		t.Helper()
		data, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest(http.MethodPost, origin+target, bytes.NewReader(data))
		r.RemoteAddr = "192.0.2.190:12345"
		r.Header.Set("Content-Type", "application/json")
		if requestOrigin != "" {
			r.Header.Set("Origin", requestOrigin)
		}
		if authenticated {
			r.AddCookie(&http.Cookie{Name: "__Host-karaoke_session", Value: token})
			r.AddCookie(&http.Cookie{Name: "__Host-karaoke_csrf", Value: csrf})
		}
		if csrfHeader {
			r.Header.Set("X-Karaoke-CSRF", csrf)
		}
		if browserCookie != nil {
			r.AddCookie(browserCookie)
		}
		w := httptest.NewRecorder()
		master.router.ServeHTTP(w, r)
		return w
	}
	assertDenied := func(w *httptest.ResponseRecorder, want int) {
		t.Helper()
		if w.Code != want || strings.Contains(w.Body.String(), "key_envelope") || strings.Contains(w.Body.String(), "preparation_token") || !strings.Contains(w.Header().Get("Cache-Control"), "no-store") {
			t.Fatal("invalid recording preparation refusal", w.Code, want)
		}
	}
	client, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	w := perform("/api/v1/media/crypto/session", origin, map[string]string{"public_key": base64.StdEncoding.EncodeToString(client.PublicKey().Bytes())}, false, false)
	var session mediacrypto.SessionGrant
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &session) != nil {
		t.Fatal("browser session failed", w.Code)
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == mediaCryptoCookie {
			browserCookie = c
		}
	}
	if browserCookie == nil {
		t.Fatal("browser cookie missing")
	}
	prepare := func(id string, size int64) map[string]any {
		return map[string]any{"session_id": id, "plaintext_size": size}
	}
	const size = 64
	body := prepare(session.SessionID, size)
	tree := &sealedtree.SQLStore{}
	master.public.opaqueTree = tree
	statusRequest := httptest.NewRequest(http.MethodGet, origin+"/api/v1/karaoke/account/status", nil)
	statusRequest.RemoteAddr = "192.0.2.190:12345"
	statusRequest.AddCookie(&http.Cookie{Name: "__Host-karaoke_session", Value: token})
	status := httptest.NewRecorder()
	master.router.ServeHTTP(status, statusRequest)
	var capabilities struct {
		Authenticated bool              `json:"authenticated"`
		Protocol      string            `json:"recording_upload_protocol"`
		StorageReady  bool              `json:"storage_available"`
		Destinations  []json.RawMessage `json:"recording_destinations"`
	}
	if status.Code != http.StatusOK || json.Unmarshal(status.Body.Bytes(), &capabilities) != nil || !capabilities.Authenticated ||
		capabilities.Protocol != "sealed-v1" || capabilities.StorageReady || capabilities.Destinations == nil || len(capabilities.Destinations) != 0 {
		t.Fatal("unready sealed recording status advertised a destination", status.Code)
	}
	assertDenied(perform(route, origin, body, true, true), http.StatusServiceUnavailable)
	var reservedBinding, reservedID string
	var reservedMeta mediacrypto.Metadata
	calls, reservationUnavailable := 0, true
	err = accounts.ConfigureRecordingAudioPreparation(func(ctx context.Context, gotTree *sealedtree.SQLStore, ingress store.PublicIngress, account, browser, id string, meta mediacrypto.Metadata) error {
		calls++
		bound, _, _, active := mediacrypto.DirectSessionFromContext(ctx).Values()
		if gotTree != tree || ingress.NodeID != master.id || ingress.PublicOrigin != origin || ingress.Generation < 1 ||
			account != user.ID || browser != bound || !active || meta.PlaintextSize != size {
			t.Fatal("reservation lacks exact authenticated scope")
		}
		if reservationUnavailable {
			return errors.New("fixture reservation failure")
		}
		binding, err := recording.AudioPreparationBinding(account, browser, id)
		reservedBinding, reservedID, reservedMeta = binding, id, meta
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	assertDenied(perform(route, origin, body, false, false), http.StatusUnauthorized)
	assertDenied(perform(route, origin, body, true, false), http.StatusForbidden)
	assertDenied(perform(route, "", body, true, true), http.StatusForbidden)
	assertDenied(perform(route, "https://other.test", body, true, true), http.StatusForbidden)
	assertDenied(perform(route, origin, prepare("invalid", size), true, true), http.StatusUnauthorized)
	assertDenied(perform(route, origin, prepare(session.SessionID, user.Quota), true, true), http.StatusRequestEntityTooLarge)
	if calls != 0 {
		t.Fatal("rejected request attempted to reserve a file ID")
	}
	assertDenied(perform(route, origin, body, true, true), http.StatusServiceUnavailable)
	reservationUnavailable = false
	w = perform(route, origin, body, true, true)
	var prepared struct {
		ID         string                  `json:"recording_id"`
		Encryption mediacrypto.Metadata    `json:"encryption"`
		Envelope   mediacrypto.KeyEnvelope `json:"key_envelope"`
		Token      string                  `json:"preparation_token"`
	}
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &prepared) != nil || calls != 2 ||
		prepared.ID != reservedID || prepared.Encryption != reservedMeta || prepared.Envelope.ExpiresAt != session.ExpiresAt || prepared.Envelope.WrappedKey == "" ||
		master.public.crypto.VerifyTransientPreparation(reservedBinding, prepared.Token, reservedMeta) != nil {
		t.Fatal("recording preparation does not match reservation", w.Code, calls)
	}
	wrongAccount := strings.Replace(reservedBinding, user.ID, strings.Repeat("d", 32), 1)
	if master.public.crypto.VerifyTransientPreparation(wrongAccount, prepared.Token, reservedMeta) == nil {
		t.Fatal("another account can reuse the preparation token")
	}
	const ticketRoute = "/api/v1/karaoke/account/recordings/ticket"
	assertDenied(perform("/api/v1/karaoke/account/recordings/"+prepared.ID+"/audio-key", origin,
		map[string]string{"session_id": session.SessionID}, true, true), http.StatusServiceUnavailable)
	request := store.RecordingAudioTicketRequest{
		RecordingID: prepared.ID, MemberID: master.id, CipherSHA256: strings.Repeat("a", 64),
		Title: "私有录音", ContentType: "audio/webm; codecs=opus", SessionID: session.SessionID,
		Encryption: prepared.Encryption, PreparationToken: prepared.Token,
	}
	assertDenied(perform(ticketRoute, origin, request, true, true), http.StatusServiceUnavailable)
	reservationCalls, revoke := 0, false
	if err = accounts.ConfigureRecordingAudioReservation(func(ctx context.Context, gotTree *sealedtree.SQLStore, ingress store.PublicIngress, account store.KaraokeUser, browser string, ticket store.RecordingAudioTicketRequest, audit store.KaraokeAudit) error {
		reservationCalls++
		binding, err := store.RecordingAudioPreparationBinding(account.ID, browser, ticket.RecordingID)
		actualBrowser, sessionID, _, active := mediacrypto.DirectSessionFromContext(ctx).Values()
		if err != nil || binding != reservedBinding || !active || actualBrowser != browser || sessionID != request.SessionID ||
			gotTree != tree || ingress.NodeID != master.id || ingress.PublicOrigin != origin || ingress.Generation <= 0 ||
			account.ID != user.ID || account.PasswordHash != user.PasswordHash || audit.UserID != account.ID ||
			ticket.ContentType != "audio/webm" || ticket.Title != request.Title || ticket.MemberID != request.MemberID ||
			ticket.CipherSHA256 != request.CipherSHA256 || ticket.Encryption != request.Encryption {
			t.Fatal("recording ticket lost its authenticated scope")
		}
		if revoke {
			return cache.Delete(ctx, "karaoke:session:"+karaokeSessionHash(token))
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	assertDenied(perform(ticketRoute, origin, request, false, false), http.StatusUnauthorized)
	assertDenied(perform(ticketRoute, origin, request, true, false), http.StatusForbidden)
	assertDenied(perform(ticketRoute, "", request, true, true), http.StatusForbidden)
	assertDenied(perform(ticketRoute, "https://other.test", request, true, true), http.StatusForbidden)
	invalidTicket := request
	invalidTicket.RecordingID = strings.Repeat("e", 32)
	assertDenied(perform(ticketRoute, origin, invalidTicket, true, true), http.StatusUnauthorized)
	withUnknownField := struct {
		store.RecordingAudioTicketRequest
		Lyrics []string `json:"lyrics"`
	}{request, []string{"unsupported field"}}
	assertDenied(perform(ticketRoute, origin, withUnknownField, true, true), http.StatusUnprocessableEntity)
	if reservationCalls != 0 {
		t.Fatal("denied request reached recording admission")
	}
	w = perform(ticketRoute, origin, request, true, true)
	var ticket struct {
		ID    string `json:"recording_id"`
		Owner string `json:"storage_member_id"`
		State string `json:"state"`
	}
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &ticket) != nil || reservationCalls != 1 ||
		ticket.ID != request.RecordingID || ticket.Owner != request.MemberID || ticket.State != "pending" || strings.Contains(w.Body.String(), prepared.Token) {
		t.Fatal("recording ticket did not report only the committed reservation", w.Code)
	}
	revoke = true
	assertDenied(perform(ticketRoute, origin, request, true, true), http.StatusUnauthorized)
	if reservationCalls != 2 {
		t.Fatal("fixture did not revoke the account after the reservation call")
	}
}
