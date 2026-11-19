//go:build linux

package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestLegacyOwnerImportCommandRejectsMalformedInputBeforeConfig(t *testing.T) {
	for _, input := range []string{"", "{", `{"plan":{},"signature":"x","unexpected":1}`, `{"plan":{},"signature":"x"}{}`, strings.Repeat(" ", 16385)} {
		var out bytes.Buffer
		if err := legacyOwnerImportCommand(nil, strings.NewReader(input), &out); err == nil || out.Len() != 0 {
			t.Fatalf("malformed request accepted: %v", err)
		}
	}
	var out bytes.Buffer
	if err := legacyOwnerImportCommand([]string{"unexpected"}, strings.NewReader("{}"), &out); err == nil || out.Len() != 0 {
		t.Fatal("unexpected argument accepted", err)
	}
}
