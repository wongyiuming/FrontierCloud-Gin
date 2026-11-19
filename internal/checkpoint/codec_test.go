package checkpoint

import (
	"bytes"
	"context"
	"encoding/base64"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/vault"
	"io"
	"strings"
	"testing"
)

func codecVault(t *testing.T, b byte) *vault.Vault {
	t.Helper()
	v, e := vault.New(base64.URLEncoding.EncodeToString(bytes.Repeat([]byte{b}, 32)))
	if e != nil {
		t.Fatal(e)
	}
	return v
}
func TestCheckpointFramesRejectDamageTruncationWrongMasterAndKey(t *testing.T) {
	ctx := context.Background()
	v := codecVault(t, 3)
	data := bytes.Repeat([]byte("private business state"), 10000)
	var out bytes.Buffer
	if e := seal(ctx, &out, v, Header{MasterID: strings.Repeat("1", 32), Generation: 7, Schema: 13}, func(w io.Writer) error { _, e := w.Write(data); return e }); e != nil {
		t.Fatal(e)
	}
	raw := out.Bytes()
	if bytes.Contains(raw, []byte("private business state")) {
		t.Fatal("plaintext leaked")
	}
	for _, tc := range []struct {
		name   string
		data   []byte
		vault  *vault.Vault
		master string
	}{
		{"valid", raw, v, strings.Repeat("1", 32)},
		{"truncated", raw[:len(raw)-1], v, strings.Repeat("1", 32)},
		{"suffix", append(append([]byte{}, raw...), 1), v, strings.Repeat("1", 32)},
		{"wrong-key", raw, codecVault(t, 4), strings.Repeat("1", 32)},
		{"wrong-master", raw, v, strings.Repeat("2", 32)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, reader, e := open(bytes.NewReader(tc.data), tc.vault, tc.master, 7)
			var got []byte
			if e == nil {
				got, e = io.ReadAll(reader)
			}
			if tc.name == "valid" {
				if e != nil || !bytes.Equal(got, data) {
					t.Fatal("round trip", e)
				}
			} else if e == nil {
				t.Fatal("accepted invalid checkpoint")
			}
		})
	}
	damaged := append([]byte{}, raw...)
	damaged[len(damaged)/2] ^= 1
	_, reader, e := open(bytes.NewReader(damaged), v, strings.Repeat("1", 32), 7)
	if e == nil {
		_, e = io.ReadAll(reader)
	}
	if e == nil {
		t.Fatal("accepted changed frame")
	}
}
