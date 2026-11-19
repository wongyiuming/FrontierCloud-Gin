package sealedtree

import "github.com/wongyiuming/FrontierCloud-Gin/internal/migrationpaths"

// These aliases preserve the existing tree API and exact error identity.
var ErrMigrationPathConflict = migrationpaths.ErrMigrationPathConflict

type MigrationPathPreflight = migrationpaths.MigrationPathPreflight

const migrationMaxEntries = migrationpaths.MaxEntries
const migrationMaxPathBytes = migrationpaths.MaxPathBytes
