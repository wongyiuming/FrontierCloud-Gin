package vault

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestS3BindingTagsSeparateDomainsAndBindEveryIdentity(t *testing.T) {
	v, err := New(base64.URLEncoding.EncodeToString([]byte(strings.Repeat("a", 32))))
	if err != nil {
		t.Fatal(err)
	}
	other, err := New(base64.URLEncoding.EncodeToString([]byte(strings.Repeat("b", 32))))
	if err != nil {
		t.Fatal(err)
	}
	binding := S3Binding{BlobID: strings.Repeat("1", 64), MemberID: strings.Repeat("2", 32), MediaID: strings.Repeat("3", 64), SessionID: strings.Repeat("4", 32)}
	keyTag, ownerTag, err := v.S3BindingTags(binding)
	if err != nil || keyTag == ownerTag || !v.VerifyS3BindingTags(binding, keyTag, ownerTag) {
		t.Fatal("valid binding rejected or domains shared", err)
	}
	if other.VerifyS3BindingTags(binding, keyTag, ownerTag) || v.VerifyS3BindingTags(binding, ownerTag, keyTag) {
		t.Fatal("other vault or swapped tag accepted")
	}
	for _, change := range []func(*S3Binding){
		func(b *S3Binding) { b.BlobID = strings.Repeat("5", 64) },
		func(b *S3Binding) { b.MemberID = strings.Repeat("6", 32) },
		func(b *S3Binding) { b.MediaID = strings.Repeat("7", 64) },
		func(b *S3Binding) { b.SessionID = strings.Repeat("8", 32) },
	} {
		modified := binding
		change(&modified)
		key, owner, err := v.S3BindingTags(modified)
		if err != nil || key == keyTag || owner == ownerTag || v.VerifyS3BindingTags(modified, keyTag, ownerTag) {
			t.Fatal("changed identity retained authority", err)
		}
	}
	if v.VerifyS3BindingTags(binding, strings.ToUpper(keyTag), ownerTag) || v.VerifyS3BindingTags(binding, keyTag[:63], ownerTag) {
		t.Fatal("noncanonical tag accepted")
	}
	invalid := binding
	invalid.BlobID = "../invalid"
	if _, _, err := v.S3BindingTags(invalid); err == nil || (*Vault)(nil).VerifyS3BindingTags(binding, keyTag, ownerTag) {
		t.Fatal("invalid input or missing vault accepted")
	}
	if _, _, err := (&Vault{}).S3BindingTags(binding); err == nil {
		t.Fatal("uninitialized vault accepted")
	}
	invalid = binding
	invalid.BlobID = invalid.MediaID
	if _, _, err := v.S3BindingTags(invalid); err == nil {
		t.Fatal("physical ID reused public media ID")
	}
}
