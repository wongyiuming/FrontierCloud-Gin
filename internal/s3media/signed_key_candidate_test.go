package s3media

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/s3store"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/vault"
)

func TestCandidateS3KeyRejectsSubstitutionWithoutClassifyingLegacy(t *testing.T) {
	v, err := vault.New(base64.URLEncoding.EncodeToString([]byte(strings.Repeat("a", 32))))
	if err != nil {
		t.Fatal(err)
	}
	other, err := vault.New(base64.URLEncoding.EncodeToString([]byte(strings.Repeat("b", 32))))
	if err != nil {
		t.Fatal(err)
	}
	binding := vault.S3Binding{BlobID: strings.Repeat("1", 64), MemberID: strings.Repeat("2", 32), MediaID: strings.Repeat("3", 64), SessionID: strings.Repeat("4", 32)}
	key, owner, err := candidateS3Key(v, binding)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = (s3store.Config{Prefix: strings.Repeat("p", 256)}).ProviderKey(key); err != nil {
		t.Fatal("candidate exceeds configured provider key bounds", err)
	}
	if strings.Contains(key, binding.MemberID) || strings.Contains(key, binding.MediaID) || strings.Contains(key, binding.SessionID) || strings.Contains(key, owner) {
		t.Fatal("physical key exposed a business identity or ownership tag")
	}
	if got, err := verifyCandidateS3Key(v, key, binding); err != nil || got != owner {
		t.Fatal("candidate did not verify", err)
	}
	withoutBlob := binding
	withoutBlob.BlobID = ""
	if got, err := verifyCandidateS3Key(v, key, withoutBlob); err != nil || got != owner {
		t.Fatal("key could not supply its authenticated blob ID", err)
	}
	for _, modify := range []func(*vault.S3Binding){
		func(b *vault.S3Binding) { b.BlobID = strings.Repeat("5", 64) },
		func(b *vault.S3Binding) { b.MemberID = strings.Repeat("6", 32) },
		func(b *vault.S3Binding) { b.MediaID = strings.Repeat("7", 64) },
		func(b *vault.S3Binding) { b.SessionID = strings.Repeat("8", 32) },
	} {
		changed := binding
		modify(&changed)
		if _, err := verifyCandidateS3Key(v, key, changed); !errors.Is(err, ErrProof) {
			t.Fatal("substituted identity accepted", err)
		}
	}
	tampered := []byte(key)
	if tampered[len(tampered)-6] == '0' {
		tampered[len(tampered)-6] = '1'
	} else {
		tampered[len(tampered)-6] = '0'
	}
	for _, bad := range []string{key + "/extra", strings.ToUpper(key), strings.Replace(key, "objects/private-v1/", "objects/legacy/", 1), strings.Replace(key, "/11/11/", "/22/11/", 1), string(tampered), "objects/legacy-id/session"} {
		if _, err := verifyCandidateS3Key(v, bad, binding); !errors.Is(err, ErrProof) {
			t.Fatalf("malformed, tampered or legacy key accepted: %q", bad)
		}
	}
	if _, err := verifyCandidateS3Key(other, key, binding); !errors.Is(err, ErrProof) {
		t.Fatal("wrong vault accepted", err)
	}
	if _, err := verifyCandidateS3Key(nil, key, binding); !errors.Is(err, ErrProof) {
		t.Fatal("missing vault accepted", err)
	}
}
