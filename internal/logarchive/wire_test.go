package logarchive

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/protocol"
)

func TestLogControlWirePreservesCiphertextAndExactIntegers(t *testing.T) {
	ref := Reference{ID: strings.Repeat("a", 32), SHA256: strings.Repeat("b", 64), Bytes: MaxPlainBytes + 34}
	payload := bytes.Repeat([]byte{253}, ref.Bytes)
	input := map[string]any{"reference": ref, "payload": payload, "generation": json.Number("9007199254740993")}
	if _, e := protocol.Canonical(input); e == nil {
		t.Fatal("fixture no longer exercises the structured DTO boundary")
	}
	wire, e := ControlValue(input)
	if e != nil {
		t.Fatal(e)
	}
	raw, e := protocol.Canonical(wire)
	if e != nil || len(raw) > 512<<10 || !bytes.Contains(raw, []byte("9007199254740993")) {
		t.Fatal("canonical request lost integer identity or exceeded control budget", e)
	}
	var decoded struct {
		Reference Reference `json:"reference"`
		Payload   []byte    `json:"payload"`
	}
	if json.Unmarshal(raw, &decoded) != nil || decoded.Reference != ref || !bytes.Equal(decoded.Payload, payload) {
		t.Fatal("wire changed encrypted bytes or block identity")
	}
	packets := []IngestPacket{{Master: strings.Repeat("a", 32), Node: strings.Repeat("b", 32), Cipher: []byte{1, 2, 3}}}
	wire, e = ControlValue(packets)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = protocol.Canonical(map[string]any{"project_log_packets": wire}); e != nil {
		t.Fatal("heartbeat packets are not canonical JSON", e)
	}
	if _, e = ControlValue(bytes.Repeat([]byte{1}, 384<<10)); e == nil {
		t.Fatal("unbounded control payload accepted")
	}
}
