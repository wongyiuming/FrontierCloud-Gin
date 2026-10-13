package node

import (
	"context"
	"io"
	"os"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/config"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/deployment"
)

// ValidateRetainedRuntime verifies the actual store selection and unseals the
// startup receipt for this native identity. Unlike startup admission it never
// creates locks, publishes receipts or accepts an absent Standalone receipt.
func (s *Service) ValidateRetainedRuntime(ctx context.Context, c config.Config) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	if e := s.ValidateRetainedIdentity(ctx, c.SecretsDirectory); e != nil {
		return e
	}
	binding, e := deployment.ReadRetainedBinding(c)
	if e != nil {
		return e
	}
	root, e := os.OpenRoot(c.DataRoot)
	if e != nil {
		return e
	}
	defer root.Close()
	info, e := root.Lstat(runtimeReceipt)
	if e != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 4096 {
		return ErrRuntimeAdmission
	}
	f, e := root.Open(runtimeReceipt)
	if e != nil {
		return e
	}
	defer f.Close()
	opened, e := f.Stat()
	if e != nil || !os.SameFile(info, opened) {
		return ErrRuntimeAdmission
	}
	raw, e := io.ReadAll(io.LimitReader(f, 4097))
	if e != nil || len(raw) > 4096 {
		return ErrRuntimeAdmission
	}
	proof, e := s.identity.vault.Unseal(string(raw))
	if e != nil || proof != "frontiercloud-native-runtime-v1\n"+string(binding)+s.identity.ID {
		return ErrRuntimeAdmission
	}
	after, e := root.Lstat(runtimeReceipt)
	if e != nil || !after.Mode().IsRegular() || !os.SameFile(after, opened) || after.Size() != info.Size() || after.ModTime() != info.ModTime() {
		return ErrRuntimeAdmission
	}
	return ctx.Err()
}

// The long-lived control scheduler has its own exclusive volume lock. Only the
// configured volume can attest that it holds the exact currently scanned inode.
func (s *Service) RetainsControlLease(info os.FileInfo) bool {
	v, ok := s.volume.(interface{ RetainsControlLease(os.FileInfo) bool })
	return ok && v.RetainsControlLease(info)
}

func (s *Service) ValidateRetainedControlState() error {
	if v, ok := s.volume.(interface{ ValidateRetainedControlState() error }); ok {
		return v.ValidateRetainedControlState()
	}
	return nil
}
