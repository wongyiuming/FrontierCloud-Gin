package store

import "context"

// These leases describe actual follower reads, including reads admitted before
// a migration is registered. Logical aliases share the physical cleanup fence.
// The caller renews while streaming and closes the stream if renewal fails.
type MigrationReadRepository interface {
	AcquireMigrationRead(context.Context, string, string, string, string) (string, error)
	RenewMigrationRead(context.Context, string, string) error
	ReleaseMigrationRead(context.Context, string) error
}
