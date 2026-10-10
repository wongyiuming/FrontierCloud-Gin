package protocol

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
)

func TestEncryptedStorageUploadCapabilityAuthenticatesDescriptor(t *testing.T) {
	credential := base64.RawURLEncoding.EncodeToString(make([]byte, 48))
	meta, err := mediacrypto.NewMetadata(100)
	if err != nil {
		t.Fatal(err)
	}
	token, err := EncryptedStorageUploadToken(credential, strings.Repeat("1", 32), strings.Repeat("2", 32), strings.Repeat("3", 32), strings.Repeat("4", 64), strings.Repeat("4", 64), "music/secure/file.mp3", strings.Repeat("5", 32), meta.CiphertextSize, 1000, meta)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := VerifyStorageToken(credential, token, 1001)
	if err != nil {
		t.Fatal(err)
	}
	actual, err := StorageEncryption(claims)
	if err != nil || actual == nil || *actual != meta || claims["op"] != "upload-encrypted" {
		t.Fatal("cipher claim mismatch", actual, err)
	}
	// Old storage accepts only upload/delete; the distinct operation prevents
	// an old node from silently ignoring a signed encryption extension.
	if claims["op"] == "upload" {
		t.Fatal("cipher sent as historical plaintext upload")
	}
	claims["op"] = "upload"
	bad, _ := capabilityToken(credential, claims)
	if _, err = VerifyStorageToken(credential, bad, 1001); err == nil {
		t.Fatal("cipher descriptor accepted with plaintext operation")
	}
	claims["op"] = "upload-encrypted"
	claims["size"] = meta.CiphertextSize - 1
	bad, _ = capabilityToken(credential, claims)
	if _, err = VerifyStorageToken(credential, bad, 1001); err == nil {
		t.Fatal("cipher size claim mismatch accepted")
	}
}
