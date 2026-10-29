// Package apps holds the apps of an org, their origin allow-list and the widget
// token route (synthwerk#30).
//
// An app belongs to one org. A widget of the app gets a widget token only when the
// browser's Origin header equals one entry of the allow-list (MatchOrigin) and the
// caller is a signed-in member of the org.
package apps

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/VelimirMueller/synthwerk-contracts/go/kit/outbox"

	"github.com/VelimirMueller/synthwerk-identity/internal/orgs"
)

// App is a row of identity.apps.
type App struct {
	ID             string
	OrgID          string
	Name           string
	AllowedOrigins []string
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// Refusals of the store.
var (
	// ErrNotFound: unknown app, or an app of another org (404).
	ErrNotFound = errors.New("apps: not found")
	// ErrForbidden: the stored role of the caller is not owner or admin (403).
	ErrForbidden = errors.New("apps: forbidden")
)

// Store reads and writes apps (search_path=identity).
type Store struct {
	DB orgs.DB
	// Source is the CloudEvents source, /synthwerk/identity/<env>.
	Source string
}

const appCols = `id::text, org_id::text, name, allowed_origins, created_at, updated_at`

func scanApp(row pgx.Row) (App, error) {
	var a App
	err := row.Scan(&a.ID, &a.OrgID, &a.Name, &a.AllowedOrigins, &a.CreatedAt, &a.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return App{}, ErrNotFound
	}
	return a, err
}

// ByID returns the app with id, in any org. A malformed id is ErrNotFound.
func (s *Store) ByID(ctx context.Context, id string) (App, error) {
	id, ok := parseID(id)
	if !ok {
		return App{}, ErrNotFound
	}
	return scanApp(s.DB.QueryRow(ctx, `SELECT `+appCols+` FROM apps WHERE id = $1`, id))
}

// Get returns the app with id in org. An app of another org is ErrNotFound.
func (s *Store) Get(ctx context.Context, orgID, id string) (App, error) {
	id, ok := parseID(id)
	if !ok {
		return App{}, ErrNotFound
	}
	return scanApp(s.DB.QueryRow(ctx, `SELECT `+appCols+` FROM apps WHERE org_id = $1 AND id = $2`, orgID, id))
}

// List returns up to limit apps of org with id > after, by id (oldest first).
// after is "" or an app id.
func (s *Store) List(ctx context.Context, orgID, after string, limit int) ([]App, error) {
	if after == "" {
		after = uuid.Nil.String()
	}
	rows, err := s.DB.Query(ctx, `SELECT `+appCols+` FROM apps WHERE org_id = $1 AND id > $2 ORDER BY id LIMIT $3`, orgID, after, limit)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (App, error) { return scanApp(row) })
}

// Create adds an app to org as actorSub and writes app.created in the same
// transaction. origins must be canonical (CanonicalOrigins).
func (s *Store) Create(ctx context.Context, org orgs.Org, actorSub, name string, origins []string) (App, error) {
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return App{}, fmt.Errorf("apps: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }() // no-op after Commit
	if err := requireAdmin(ctx, tx, org.ID, actorSub); err != nil {
		return App{}, err
	}
	a, err := scanApp(tx.QueryRow(ctx, `INSERT INTO apps (id, org_id, name, allowed_origins) VALUES ($1, $2, $3, $4) RETURNING `+appCols,
		uuid.Must(uuid.NewV7()).String(), org.ID, name, origins))
	if err != nil {
		return App{}, fmt.Errorf("apps: insert: %w", err)
	}
	e, err := appCreated(ctx, s.Source, a, actorSub)
	if err != nil {
		return App{}, err
	}
	if err := outbox.Enqueue(ctx, tx, e); err != nil {
		return App{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return App{}, fmt.Errorf("apps: commit: %w", err)
	}
	return a, nil
}

// Update sets the name and/or the allow-list of an app of org as actorSub. A nil
// name or nil origins keeps the value. It writes no event yet.
func (s *Store) Update(ctx context.Context, org orgs.Org, actorSub, id string, name *string, origins []string) (App, error) {
	id, ok := parseID(id)
	if !ok {
		return App{}, ErrNotFound
	}
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return App{}, fmt.Errorf("apps: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := requireAdmin(ctx, tx, org.ID, actorSub); err != nil {
		return App{}, err
	}
	a, err := scanApp(tx.QueryRow(ctx, `UPDATE apps SET name = coalesce($3, name), allowed_origins = coalesce($4, allowed_origins), updated_at = now()
		WHERE org_id = $1 AND id = $2 RETURNING `+appCols, org.ID, id, name, origins))
	if err != nil {
		return App{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return App{}, fmt.Errorf("apps: commit: %w", err)
	}
	return a, nil
}

// Delete removes an app of org as actorSub. It writes no event yet.
func (s *Store) Delete(ctx context.Context, org orgs.Org, actorSub, id string) error {
	id, ok := parseID(id)
	if !ok {
		return ErrNotFound
	}
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return fmt.Errorf("apps: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := requireAdmin(ctx, tx, org.ID, actorSub); err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `DELETE FROM apps WHERE org_id = $1 AND id = $2`, org.ID, id)
	if err != nil {
		return fmt.Errorf("apps: delete: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("apps: commit: %w", err)
	}
	return nil
}

// parseID returns id in the canonical UUID form. uuid.Parse also takes forms that
// Postgres refuses ("urn:uuid:…"), so the store always passes the canonical form.
func parseID(id string) (string, bool) {
	u, err := uuid.Parse(id)
	if err != nil {
		return "", false
	}
	return u.String(), true
}

// requireAdmin checks the stored role of sub in org and holds a share lock on the
// row until the end of tx, so a parallel demotion waits for this write. The stored
// role wins over the token (spec #29).
func requireAdmin(ctx context.Context, tx pgx.Tx, orgID, sub string) error {
	var r string
	err := tx.QueryRow(ctx, `SELECT role FROM memberships WHERE org_id = $1 AND user_sub = $2 FOR SHARE`, orgID, sub).Scan(&r)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrForbidden
	}
	if err != nil {
		return fmt.Errorf("apps: member role: %w", err)
	}
	if !orgs.Role(r).AtLeast(orgs.Admin) {
		return ErrForbidden
	}
	return nil
}
