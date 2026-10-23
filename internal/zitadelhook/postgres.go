package zitadelhook

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/VelimirMueller/synthwerk-contracts/go/kit/cloudevents"
	"github.com/VelimirMueller/synthwerk-contracts/go/kit/outbox"
)

// Beginner is the part of *pgxpool.Pool that the store needs.
type Beginner interface {
	Begin(ctx context.Context) (pgx.Tx, error)
}

// Postgres stores the seen key and the outbox row in one transaction
// (table identity.zitadel_event_seen, migration 0002).
type Postgres struct{ DB Beginner }

// RecordOnce implements Store.
func (p Postgres) RecordOnce(ctx context.Context, key string, e cloudevents.Event) (bool, error) {
	tx, err := p.DB.Begin(ctx)
	if err != nil {
		return false, fmt.Errorf("zitadelhook: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }() // no-op after Commit
	tag, err := tx.Exec(ctx, `INSERT INTO zitadel_event_seen (event_key) VALUES ($1) ON CONFLICT (event_key) DO NOTHING`, key)
	if err != nil {
		return false, fmt.Errorf("zitadelhook: mark seen: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return false, nil
	}
	if err := outbox.Enqueue(ctx, tx, e); err != nil {
		return false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return false, fmt.Errorf("zitadelhook: commit: %w", err)
	}
	return true, nil
}
