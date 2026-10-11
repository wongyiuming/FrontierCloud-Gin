package store

import (
	"context"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
)

// EncryptionBatchRepository reads only public descriptors, never file keys.
// All native repositories supply it. Callers still check visibility/ownership.
type EncryptionBatchRepository interface {
	Encryptions(context.Context, []string) (map[string]*mediacrypto.Metadata, error)
}
