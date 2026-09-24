package migrations

import "embed"

// Files contains the versioned PostgreSQL schema.
//
//go:embed sql/*.sql
var Files embed.FS
