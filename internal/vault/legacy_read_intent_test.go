package vault

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
)

func TestLegacyReadIntentCipherBindsIndexesRevisionAndVault(t *testing.T) {
	v, err := New(base64.URLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	other, _ := New(base64.URLEncoding.EncodeToString(bytes.Repeat([]byte{8}, 32)))
	index, challenge, err := v.LegacyReadIntentIndexes(strings.Repeat("a", 32), strings.Repeat("b", 64))
	if err != nil || index == challenge {
		t.Fatal(err)
	}
	headIndex, headTag, err := v.LegacyReadHeadIndexes(strings.Repeat("a", 32))
	if err != nil || headIndex == index || headTag == challenge || headIndex == headTag {
		t.Fatal("head index domains collide", err)
	}
	otherHead, _, err := other.LegacyReadHeadIndexes(strings.Repeat("a", 32))
	if err != nil || otherHead == headIndex {
		t.Fatal("head not bound to vault", err)
	}
	anchorIndex, anchorTag, err := v.LegacyReadAnchorIndexes(strings.Repeat("a", 32))
	if err != nil || anchorIndex == headIndex || anchorTag == headTag || anchorIndex == index || anchorTag == challenge {
		t.Fatal("anchor index domains collide", err)
	}
	nonce, sealed, err := v.SealLegacyReadIntent(index, challenge, 1, []byte("private scope"))
	if err != nil {
		t.Fatal(err)
	}
	opened, err := v.OpenLegacyReadIntent(index, challenge, 1, nonce, sealed)
	if err != nil || string(opened) != "private scope" {
		t.Fatal(err)
	}
	bad := append([]byte(nil), sealed...)
	bad[0] ^= 1
	for _, attempt := range []struct {
		v    *Vault
		i, c string
		rev  int64
		n, b []byte
	}{
		{other, index, challenge, 1, nonce, sealed}, {v, strings.Repeat("1", 64), challenge, 1, nonce, sealed}, {v, index, strings.Repeat("2", 64), 1, nonce, sealed}, {v, index, challenge, 2, nonce, sealed}, {v, index, challenge, 1, nonce, bad},
	} {
		if _, err = attempt.v.OpenLegacyReadIntent(attempt.i, attempt.c, attempt.rev, attempt.n, attempt.b); err == nil {
			t.Fatal("substituted record accepted")
		}
	}
}
