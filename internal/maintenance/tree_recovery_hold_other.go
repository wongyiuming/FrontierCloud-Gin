//go:build !linux

package maintenance

import "context"

// The required no-replace, durable publication and inode proof are not yet
// implemented on this platform. Never claim that a hold was installed.
func (g *Gate) publishTreeRecoveryHold(context.Context, []byte, func() error) error {
	return ErrState
}
