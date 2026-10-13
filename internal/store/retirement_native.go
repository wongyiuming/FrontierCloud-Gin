package store

import "context"

// This host-local locator is never serialized in control or Admin responses.
type RetirementNativeRepository interface {
	RetirementDatabasePath(context.Context) (string, error)
}
