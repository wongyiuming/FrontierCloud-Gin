package business

import (
	"crypto/sha256"
	"encoding/base64"
	"strconv"
	"strings"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// selectedS3Commitment matches the provider's multipart composite checksum.
// It does not claim to be SHA256 of the complete ciphertext.
func selectedS3Commitment(size int64, parts []string) (string, error) {
	if size < 1 || size > store.S3MaxObjectBytes || int64(len(parts)) != (size+store.S3PartBytes-1)/store.S3PartBytes {
		return "", store.ErrNodeState
	}
	h := sha256.New()
	for _, part := range parts {
		digest, err := base64.StdEncoding.Strict().DecodeString(part)
		if err != nil || len(digest) != sha256.Size || base64.StdEncoding.EncodeToString(digest) != part {
			return "", store.ErrNodeState
		}
		_, _ = h.Write(digest)
	}
	return base64.StdEncoding.EncodeToString(h.Sum(nil)) + "-" + strconv.Itoa(len(parts)), nil
}

func validSelectedS3Commitment(size int64, value string) bool {
	if size < 1 || size > store.S3MaxObjectBytes {
		return false
	}
	sum, count, ok := strings.Cut(value, "-")
	digest, err := base64.StdEncoding.Strict().DecodeString(sum)
	return ok && err == nil && len(digest) == sha256.Size && base64.StdEncoding.EncodeToString(digest) == sum && count == strconv.FormatInt((size+store.S3PartBytes-1)/store.S3PartBytes, 10)
}
