package publicproxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Every advertised public route must reach the handler after signed ingress
// admission. Adding a route to the proxy without wiring the verifier used to
// turn otherwise valid requests into 503 responses.
func TestEveryPublicRouteReachesAdmittedHandler(t *testing.T) {
	const master = "https://master.example"
	cases := append([]route(nil), routes[:]...)
	cases = append(cases, route{method: http.MethodGet, path: "/api/v1/karaoke/account/captcha/" + strings.Repeat("a", 32)})
	recording := recordingsPath + "/" + strings.Repeat("a", 32)
	for _, path := range []string{recordingTicketPath, recordingAudioPreparePath, recording + "/audio-recover", recording + "/audio-complete", recording + "/audio-key", recording + "/lyrics-key"} {
		cases = append(cases, route{method: http.MethodPost, path: path})
	}
	cases = append(cases, route{method: http.MethodDelete, path: recording}, route{method: http.MethodDelete, path: recording + "/pending"})
	for path := range publicAssets {
		cases = append(cases, route{method: http.MethodGet, path: path})
	}
	for _, item := range cases {
		t.Run(item.method+" "+item.path, func(t *testing.T) {
			verifier, _, _ := fixtureVerifier(t, master)
			// Explicitly exercise the normally dormant recording controls.
			verifier.recordingTicketReady = true
			reached := false
			recorder := &testResponseRecorder{httptest.NewRecorder()}
			verifier.Wrap(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				reached = true
				w.WriteHeader(http.StatusNoContent)
			})).ServeHTTP(recorder, signedFixtureFor(t, master, item.method, item.path))
			if !reached || recorder.Code != http.StatusNoContent {
				t.Fatalf("route did not reach admitted handler: reached=%t status=%d", reached, recorder.Code)
			}
		})
	}
}
