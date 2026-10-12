package store

import "context"

type RecoverySample struct {
	MediaObject
	Root  string
	Bytes int64
}
type RecoveryRepository interface {
	RecoverySamples(context.Context, int) ([]RecoverySample, error)
}
