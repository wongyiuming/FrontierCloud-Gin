package operator

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestDiagnosticLogsNeverIncludeArbitrarySecretsURLsOrPairingEnvelopes(t *testing.T) {
	raw := []byte(`{"time":"2026-10-12T18:00:00Z","level":"ERROR","msg":"FrontierCloud stopped","error":"admin_key=secret-one https://host/file?token=secret-two","request_id":"0123456789abcdef"}
{"time":"2026-10-12T18:00:01Z","level":"INFO","msg":"Cookie: secret-three","password":"secret-four","status":403}
{"payload":{"token":"secret-five"},"signature":"secret-six"}
raw URL https://secret-user:secret-password@host/file?signature=secret-seven
{"time":"not-a-date secret-eight","level":"secret-nine","request_id":"secret-ten"}
`)
	r, e := FilterLogs(raw)
	if e != nil || !r.ReadOnly || !r.Redacted || len(r.Events) != 2 || r.Omitted != 3 {
		t.Fatal(r, e)
	}
	encoded, _ := json.Marshal(r)
	if strings.Contains(string(encoded), "secret-") || strings.Contains(string(encoded), "https://") || strings.Contains(string(encoded), "payload") {
		t.Fatal("secret escaped diagnostics", string(encoded))
	}
	if r.Events[0].Event != "FrontierCloud stopped" || r.Events[1].Status != 403 {
		t.Fatal("safe facts discarded", r)
	}
}
