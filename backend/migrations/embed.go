package migrations

import "embed"

// Files contains version-controlled database migrations.
//
//go:embed *.sql
var Files embed.FS
