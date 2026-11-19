package s3media

import (
	"crypto/subtle"
	"strings"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/vault"
)

// These helpers are an isolated compatibility candidate. They do not select
// legacy versus new state, mutate the provider, or grant upload authority.
// A real caller must bind a correct persisted vault identity and intent before
// it may use either result; a failed verification must never imply legacy.
const candidateKeyPrefix = "objects/private-v1/"

func candidateS3Key(v *vault.Vault, binding vault.S3Binding) (key, owner string, err error) {
	tag, owner, err := v.S3BindingTags(binding)
	if err != nil {
		return "", "", err
	}
	return candidateKeyPrefix + binding.BlobID[:2] + "/" + binding.BlobID[2:4] + "/" + binding.BlobID + "." + tag + ".blob", owner, nil
}

func verifyCandidateS3Key(v *vault.Vault, key string, binding vault.S3Binding) (string, error) {
	if !strings.HasPrefix(key, candidateKeyPrefix) {
		return "", ErrProof
	}
	parts := strings.Split(strings.TrimPrefix(key, candidateKeyPrefix), "/")
	if len(parts) != 3 || len(parts[0]) != 2 || len(parts[1]) != 2 || !strings.HasSuffix(parts[2], ".blob") {
		return "", ErrProof
	}
	values := strings.Split(strings.TrimSuffix(parts[2], ".blob"), ".")
	if len(values) != 2 || len(values[0]) != 64 || len(values[1]) != 64 || parts[0] != values[0][:2] || parts[1] != values[0][2:4] {
		return "", ErrProof
	}
	if binding.BlobID != "" && binding.BlobID != values[0] {
		return "", ErrProof
	}
	binding.BlobID = values[0]
	expected, owner, err := candidateS3Key(v, binding)
	if err != nil || subtle.ConstantTimeCompare([]byte(expected), []byte(key)) != 1 {
		return "", ErrProof
	}
	return owner, nil
}
