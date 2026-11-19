//go:build !linux

package recovery

import (
	"context"
	"os"
)

func openTreeMaterialStage(string) (*os.Root, func(context.Context) error, func(), error) {
	return nil, nil, nil, ErrUnsafe
}
