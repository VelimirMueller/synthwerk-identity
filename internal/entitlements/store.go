package entitlements

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/VelimirMueller/synthwerk-contracts/go/kit/outbox"
)

// ErrNotFound means the org has no entitlements row.
var ErrNotFound = errors.New("entitlements: not found")

// Entitlements is a row of identity.org_entitlements.
type Entitlements struct {
	OrgID     string
	Plan      string
	Limits    Limits
	Version   int64
	UpdatedAt time.Time
}

// DB is the part of *pgxpool.Pool the store needs.
type DB interface {
	Begin(ctx context.Context) (pgx.Tx, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// Store reads and writes org entitlements (search_path=identity).
type Store struct {
	DB DB
	// Source is the CloudEvents source, /synthwerk/identity/<env>.
	Source string
	// Default is the plan of a new org: the free plan from config.
	Default Plan
}

// batch is the number of orgs one Reconcile transaction changes.
const batch = 200

const cols = `org_id::text, plan, llm_tokens_per_user_per_day, llm_tokens_per_org_per_day, apps_per_org, version, updated_at`

func scan(row pgx.Row) (Entitlements, error) {
	var e Entitlements
	err := row.Scan(&e.OrgID, &e.Plan, &e.Limits.LLMTokensPerUserPerDay, &e.Limits.LLMTokensPerOrgPerDay, &e.Limits.AppsPerOrg, &e.Version, &e.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Entitlements{}, ErrNotFound
	}
	return e, err
}

// ByOrg returns the entitlements of org. A malformed id is ErrNotFound.
func (s *Store) ByOrg(ctx context.Context, orgID string) (Entitlements, error) {
	if _, err := uuid.Parse(orgID); err != nil {
		return Entitlements{}, ErrNotFound
	}
	return scan(s.DB.QueryRow(ctx, `SELECT `+cols+` FROM org_entitlements WHERE org_id = $1`, orgID))
}

// AssignDefault gives org the default plan inside tx and writes
// entitlements_changed (plan_assigned) to the outbox. An org that has a plan
// keeps it and gets no event. orgs.Store calls it when an org turns active.
func (s *Store) AssignDefault(ctx context.Context, tx pgx.Tx, orgID string) error {
	l := s.Default.Limits
	e, err := scan(tx.QueryRow(ctx, `INSERT INTO org_entitlements
		(org_id, plan, llm_tokens_per_user_per_day, llm_tokens_per_org_per_day, apps_per_org)
		VALUES ($1, $2, $3, $4, $5) ON CONFLICT (org_id) DO NOTHING RETURNING `+cols,
		orgID, s.Default.Name, l.LLMTokensPerUserPerDay, l.LLMTokensPerOrgPerDay, l.AppsPerOrg))
	if errors.Is(err, ErrNotFound) {
		return nil // the org has a plan already
	}
	if err != nil {
		return fmt.Errorf("entitlements: assign: %w", err)
	}
	return s.enqueue(ctx, tx, e, ReasonPlanAssigned)
}

func (s *Store) enqueue(ctx context.Context, tx pgx.Tx, e Entitlements, why Reason) error {
	ev, err := changed(ctx, s.Source, e, why)
	if err != nil {
		return err
	}
	return outbox.Enqueue(ctx, tx, ev)
}

// Reconciled counts what Reconcile changed.
type Reconciled struct {
	// Assigned: active orgs without a plan (from before #31) that got the default plan.
	Assigned int
	// Updated: orgs on the default plan whose limits differed from config.
	Updated int
}

// Reconcile runs at start, before the service serves. It gives every active org
// without a plan the default plan, and moves every org on the default plan to the
// limits of config. Each change writes entitlements_changed. Two replicas may run
// it at once: the insert skips existing rows, the update skips locked rows.
func (s *Store) Reconcile(ctx context.Context) (Reconciled, error) {
	if err := s.Default.Limits.Validate(); err != nil || s.Default.Name == "" {
		return Reconciled{}, fmt.Errorf("entitlements: default plan not valid: %w", err)
	}
	var r Reconciled
	for {
		n, err := s.assignMissing(ctx)
		if err != nil {
			return r, err
		}
		r.Assigned += n
		if n < batch {
			break
		}
	}
	for {
		n, err := s.updateDefaults(ctx)
		if err != nil {
			return r, err
		}
		r.Updated += n
		if n < batch {
			break
		}
	}
	return r, nil
}

func (s *Store) assignMissing(ctx context.Context) (int, error) {
	return s.inTx(ctx, func(tx pgx.Tx) (int, error) {
		rows, err := tx.Query(ctx, `SELECT o.id::text FROM orgs o
			WHERE o.status = 'active' AND NOT EXISTS (SELECT 1 FROM org_entitlements e WHERE e.org_id = o.id)
			ORDER BY o.id LIMIT $1 FOR UPDATE OF o SKIP LOCKED`, batch)
		if err != nil {
			return 0, err
		}
		ids, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			return 0, err
		}
		for _, id := range ids {
			if err := s.AssignDefault(ctx, tx, id); err != nil {
				return 0, err
			}
		}
		return len(ids), nil
	})
}

func (s *Store) updateDefaults(ctx context.Context) (int, error) {
	l := s.Default.Limits
	return s.inTx(ctx, func(tx pgx.Tx) (int, error) {
		rows, err := tx.Query(ctx, `UPDATE org_entitlements SET
				llm_tokens_per_user_per_day = $2, llm_tokens_per_org_per_day = $3, apps_per_org = $4,
				version = version + 1, updated_at = now()
			WHERE org_id IN (SELECT org_id FROM org_entitlements
				WHERE plan = $1 AND (llm_tokens_per_user_per_day <> $2 OR llm_tokens_per_org_per_day <> $3 OR apps_per_org <> $4)
				ORDER BY org_id LIMIT $5 FOR UPDATE SKIP LOCKED)
			RETURNING `+cols,
			s.Default.Name, l.LLMTokensPerUserPerDay, l.LLMTokensPerOrgPerDay, l.AppsPerOrg, batch)
		if err != nil {
			return 0, err
		}
		changed, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (Entitlements, error) { return scan(row) })
		if err != nil {
			return 0, err
		}
		for _, e := range changed {
			if err := s.enqueue(ctx, tx, e, ReasonDefaultsChanged); err != nil {
				return 0, err
			}
		}
		return len(changed), nil
	})
}

func (s *Store) inTx(ctx context.Context, fn func(pgx.Tx) (int, error)) (int, error) {
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("entitlements: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }() // no-op after Commit
	n, err := fn(tx)
	if err != nil {
		return 0, fmt.Errorf("entitlements: reconcile: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("entitlements: commit: %w", err)
	}
	return n, nil
}
