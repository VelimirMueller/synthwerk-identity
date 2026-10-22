// Package migrations holds the SQL migrations of synthwerk-identity. The service
// applies them at startup with Exec, in order, the way pulse applies its schema.
package migrations

import _ "embed"

// Schema is 0001_init.sql: the identity schema and the outbox table.
//
//go:embed 0001_init.sql
var Schema string
