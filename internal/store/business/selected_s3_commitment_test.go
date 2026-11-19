package business

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

func TestSelectedS3PartCommitment(t *testing.T) {
	part := sha256.Sum256([]byte("ciphertext"))
	digest := base64.StdEncoding.EncodeToString(part[:])
	composite := sha256.Sum256(part[:])
	want := base64.StdEncoding.EncodeToString(composite[:]) + "-1"
	if got, err := selectedS3Commitment(1, []string{digest}); err != nil || got != want || !validSelectedS3Commitment(1, got) {
		t.Fatalf("one part: %q %v", got, err)
	}
	maximum := make([]string, 1280)
	for i := range maximum {
		maximum[i] = digest
	}
	if got, err := selectedS3Commitment(store.S3MaxObjectBytes, maximum); err != nil || !validSelectedS3Commitment(store.S3MaxObjectBytes, got) {
		t.Fatalf("maximum parts: %v", err)
	}
	for _, parts := range [][]string{nil, {digest, digest}, {strings.TrimRight(digest, "=")}, {strings.Repeat("A", 44)}} {
		if _, err := selectedS3Commitment(1, parts); err == nil {
			t.Fatalf("accepted malformed parts: %v", parts)
		}
	}
}
