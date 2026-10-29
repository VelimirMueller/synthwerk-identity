package mfagate

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// DB is the part of *pgxpool.Pool that Postgres needs.
type DB interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// Postgres stores evidence in identity.mfa_evidence (migration 0004).
type Postgres struct{ DB DB }

// Record implements Store: one row per user, a newer check replaces an older one.
func (p Postgres) Record(ctx context.Context, e Evidence) error {
	_, err := p.DB.Exec(ctx, `INSERT INTO mfa_evidence (user_sub, session_id, amr, checked_at)
VALUES ($1, $2, $3, $4)
ON CONFLICT (user_sub) DO UPDATE SET session_id = EXCLUDED.session_id, amr = EXCLUDED.amr, checked_at = EXCLUDED.checked_at
WHERE mfa_evidence.checked_at <= EXCLUDED.checked_at`, e.UserSub, e.SessionID, e.AMR, e.CheckedAt)
	if err != nil {
		return fmt.Errorf("mfagate: record: %w", err)
	}
	return nil
}

// Latest implements Store.
func (p Postgres) Latest(ctx context.Context, userSub string) (Evidence, error) {
	e := Evidence{UserSub: userSub}
	err := p.DB.QueryRow(ctx, `SELECT session_id, amr, checked_at FROM mfa_evidence WHERE user_sub = $1`, userSub).
		Scan(&e.SessionID, &e.AMR, &e.CheckedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Evidence{}, ErrNoEvidence
	}
	if err != nil {
		return Evidence{}, fmt.Errorf("mfagate: latest: %w", err)
	}
	return e, nil
}
