package store

import (
	"context"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/mediacrypto"
)

// EncryptionRepository is optional for older test repositories. A real runtime
// always supplies it; an encrypted operation fails closed without it.
type EncryptionRepository interface {
	Encryption(context.Context, string) (*mediacrypto.Metadata, error)
	EncryptionUsed(context.Context, string) (bool, error)
	HasEncryption(context.Context) (bool, error)
	EncryptionKeyID(context.Context) (string, error)
	CheckEncryptionKey(context.Context, string) error
	ReserveEncryptedUpload(context.Context, string, string, int64, int64, AdminAudit, *mediacrypto.Metadata) (UploadReservation, error)
}
