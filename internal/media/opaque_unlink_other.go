//go:build !linux

package media

import (
	"context"
	"os"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/store"
)

// This prototype cannot establish the required durable unlink proof on this
// platform. Production activation remains closed rather than guessing.
func opaqueSingleLink(os.FileInfo) bool                          { return false }
func opaqueExactLinks(os.FileInfo, uint64) bool                  { return false }
func opaqueDirectoryIdentity(os.FileInfo) (uint64, uint64, bool) { return 0, 0, false }
func unlinkOpaqueFile(*os.Root, string) error                    { return store.ErrNodeState }
func sameOpaqueDeleteFile(os.FileInfo, os.FileInfo) bool         { return false }
func openOpaqueDeleteFile(*os.Root, string) (*os.File, error)    { return nil, store.ErrNodeState }

func (*Service) removeOpaquePublicationLink(context.Context, string, string, int64, func(context.Context) error, func() error) error {
	return store.ErrNodeState
}
