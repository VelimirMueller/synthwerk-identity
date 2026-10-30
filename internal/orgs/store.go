package orgs

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/VelimirMueller/synthwerk-contracts/go/kit/outbox"
)

// Org is a row of identity.orgs.
type Org struct {
	ID           string
	ZitadelOrgID string
	Name         string
	Slug         string
	// Status is "pending" (no owner yet) or "active".
	Status    string
	CreatedAt time.Time
}

// Membership is a row of identity.memberships.
type Membership struct {
	OrgID   string
	UserSub string
	Role    Role
	// Status is StatusActive or StatusDeactivated (synthwerk#37).
	Status    string
	GrantID   string
	UpdatedAt time.Time
}

// Member statuses (synthwerk#37).
const (
	StatusActive      = "active"
	StatusDeactivated = "deactivated"
)

// Active reports whether the membership counts for access and the owner rule.
func (m Membership) Active() bool { return m.Status == StatusActive }

// DB is the part of *pgxpool.Pool the store needs.
type DB interface {
	Begin(ctx context.Context) (pgx.Tx, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// Grants writes a role change to the Zitadel user grant. The store calls it inside
// the open transaction: an error rolls the change back.
type Grants interface {
	SetRole(ctx context.Context, zitadelOrgID, userSub, grantID string, to Role) error
}

// Plans gives a new org its default plan (internal/entitlements, synthwerk#31).
// The store calls it inside the transaction that makes the org active: an error
// rolls the activation back.
type Plans interface {
	AssignDefault(ctx context.Context, tx pgx.Tx, orgID string) error
}

// Store reads and writes orgs and memberships (search_path=identity).
type Store struct {
	DB     DB
	Grants Grants
	// Plans is nil in tests that do not need entitlements.
	Plans Plans
	// Users invites users and switches user grants on and off (synthwerk#37). Nil:
	// invite answers ErrUpstream, a status change stays in identity.
	Users Users
	// Log gets drift warnings after a failed commit. Nil: slog.Default.
	Log *slog.Logger
	// Source is the CloudEvents source, /synthwerk/identity/<env>.
	Source string
}

const orgCols = `id::text, zitadel_org_id, name, slug, status, created_at`

func scanOrg(row pgx.Row) (Org, error) {
	var o Org
	err := row.Scan(&o.ID, &o.ZitadelOrgID, &o.Name, &o.Slug, &o.Status, &o.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Org{}, ErrNotFound
	}
	return o, err
}

// OrgByID returns the org with id. A malformed id is ErrNotFound.
func (s *Store) OrgByID(ctx context.Context, id string) (Org, error) {
	if _, err := uuid.Parse(id); err != nil {
		return Org{}, ErrNotFound
	}
	return scanOrg(s.DB.QueryRow(ctx, `SELECT `+orgCols+` FROM orgs WHERE id = $1`, id))
}

// OrgByZitadelID returns the org of a Zitadel org id.
func (s *Store) OrgByZitadelID(ctx context.Context, zitadelOrgID string) (Org, error) {
	return scanOrg(s.DB.QueryRow(ctx, `SELECT `+orgCols+` FROM orgs WHERE zitadel_org_id = $1`, zitadelOrgID))
}

// MemberRole returns the stored role of sub in org, or ErrNotFound. A deactivated
// member has no role (synthwerk#37).
func (s *Store) MemberRole(ctx context.Context, orgID, sub string) (Role, error) {
	var r string
	err := s.DB.QueryRow(ctx, `SELECT role FROM memberships WHERE org_id = $1 AND user_sub = $2 AND status = 'active'`, orgID, sub).Scan(&r)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrNotFound
	}
	return Role(r), err
}

// ListMembers returns up to limit members of org with user_sub > after, by user_sub.
func (s *Store) ListMembers(ctx context.Context, orgID, after string, limit int) ([]Membership, error) {
	rows, err := s.DB.Query(ctx, `SELECT `+memberCols+`
		FROM memberships WHERE org_id = $1 AND user_sub > $2 AND status <> 'invited' ORDER BY user_sub LIMIT $3`, orgID, after, limit)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, scanMember)
}

const memberCols = `org_id::text, user_sub, role, status, coalesce(zitadel_grant_id, ''), updated_at`

func scanMember(row pgx.CollectableRow) (Membership, error) {
	var m Membership
	var role string
	err := row.Scan(&m.OrgID, &m.UserSub, &role, &m.Status, &m.GrantID, &m.UpdatedAt)
	m.Role = Role(role)
	return m, err
}

// lockMembers locks the owner rows of org plus the rows of subs, in one order, and
// returns them by user_sub and the number of active owners. Two member changes in
// one org run one after the other.
func lockMembers(ctx context.Context, tx pgx.Tx, orgID string, subs ...string) (map[string]Membership, int, error) {
	rows, err := tx.Query(ctx, `SELECT `+memberCols+`
		FROM memberships WHERE org_id = $1 AND (role = 'owner' OR user_sub = ANY($2))
		ORDER BY user_sub FOR UPDATE`, orgID, subs)
	if err != nil {
		return nil, 0, err
	}
	ms, err := pgx.CollectRows(rows, scanMember)
	if err != nil {
		return nil, 0, err
	}
	out := make(map[string]Membership, len(ms))
	owners := 0
	for _, m := range ms {
		out[m.UserSub] = m
		if m.Role == Owner && m.Active() {
			owners++
		}
	}
	return out, owners, nil
}

// ChangeRole sets the role of target in org as actor. The stored role of actor wins
// over the token. It writes the membership, the role_changed event and the Zitadel
// grant in one transaction. changed is false when target already has the role.
func (s *Store) ChangeRole(ctx context.Context, org Org, actorSub, targetSub string, to Role) (m Membership, changed bool, err error) {
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return Membership{}, false, fmt.Errorf("orgs: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }() // no-op after Commit
	locked, owners, err := lockMembers(ctx, tx, org.ID, actorSub, targetSub)
	if err != nil {
		return Membership{}, false, fmt.Errorf("orgs: lock: %w", err)
	}
	actor, ok := locked[actorSub]
	if !ok || !actor.Active() {
		return Membership{}, false, ErrForbidden // token says a role, the mirror says no (active) member
	}
	target, ok := locked[targetSub]
	if !ok {
		if !actor.Role.AtLeast(Admin) {
			return Membership{}, false, ErrForbidden
		}
		return Membership{}, false, ErrNotFound
	}
	if err := Authorize(actor.Role, target.Role, to, actorSub == targetSub); err != nil {
		return Membership{}, false, err
	}
	if target.Role == to {
		return target, false, nil
	}
	if target.Role == Owner && target.Active() && owners <= 1 {
		return Membership{}, false, ErrLastOwner
	}
	if err := tx.QueryRow(ctx, `UPDATE memberships SET role = $3, updated_at = now()
		WHERE org_id = $1 AND user_sub = $2 RETURNING updated_at`, org.ID, targetSub, string(to)).Scan(&target.UpdatedAt); err != nil {
		return Membership{}, false, fmt.Errorf("orgs: update: %w", err)
	}
	e, err := roleChanged(ctx, s.Source, org, targetSub, target.Role, to, "user:"+actorSub)
	if err != nil {
		return Membership{}, false, err
	}
	if err := outbox.Enqueue(ctx, tx, e); err != nil {
		return Membership{}, false, err
	}
	if s.Grants != nil {
		if err := s.Grants.SetRole(ctx, org.ZitadelOrgID, targetSub, target.GrantID, to); err != nil {
			return Membership{}, false, fmt.Errorf("%w: %w", ErrUpstream, err)
		}
	}
	if err := commit(ctx, tx); err != nil {
		if s.Grants != nil {
			s.repairRole(context.WithoutCancel(ctx), org, target, to)
		}
		return Membership{}, false, err
	}
	target.Role = to
	return target, true, nil
}

// repairRole runs after a failed commit whose Zitadel write went through. It
// fails closed: a downgrade stays in Zitadel (a retry repairs the row); an
// upgrade is undone only when a re-read shows the row still holds the old role.
func (s *Store) repairRole(ctx context.Context, org Org, target Membership, to Role) {
	log := s.Log
	if log == nil {
		log = slog.Default()
	}
	attrs := []any{slog.String("event.name", "orgs.role_drift"), slog.String("org.id", org.ID), slog.String("enduser.id", target.UserSub)}
	if !to.AtLeast(target.Role) {
		log.WarnContext(ctx, "role change: commit failed, Zitadel keeps the lower role", attrs...)
		return
	}
	var cur string
	err := s.DB.QueryRow(ctx, `SELECT role FROM memberships WHERE org_id = $1 AND user_sub = $2`, org.ID, target.UserSub).Scan(&cur)
	if err == nil && Role(cur) == to {
		log.WarnContext(ctx, "role change: commit error, but the row has the new role: Zitadel kept", attrs...)
		return
	}
	log.WarnContext(ctx, "role change: commit failed, Zitadel set back to the old role", attrs...)
	if err := s.Grants.SetRole(ctx, org.ZitadelOrgID, target.UserSub, target.GrantID, target.Role); err != nil {
		log.WarnContext(ctx, "Zitadel role not set back: drift", append(attrs, slog.String("exception.message", err.Error()))...)
	}
}

// commit maps the deferred owner trigger to ErrLastOwner.
func commit(ctx context.Context, tx pgx.Tx) error {
	err := tx.Commit(ctx)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.ConstraintName == "memberships_keep_an_owner" {
		return ErrLastOwner
	}
	if err != nil {
		return fmt.Errorf("orgs: commit: %w", err)
	}
	return nil
}

// GrantChange is a Zitadel user grant event of the project, as the hook sees it.
type GrantChange struct {
	// Key identifies the Zitadel event; a repeat is dropped.
	Key string
	// ZitadelOrgID is the org that holds the grant (event resource owner).
	ZitadelOrgID string
	GrantID      string
	// UserSub is empty when the event does not carry it (grant changed or removed):
	// the store finds the member by GrantID.
	UserSub string
	// Roles are the role keys of the grant. Removed or no org role: the member leaves.
	Roles   []string
	Removed bool
}

// Outcome of ApplyGrant, for the log line.
type Outcome string

// Outcomes of ApplyGrant.
const (
	OutcomeDuplicate  Outcome = "duplicate"
	OutcomeIgnored    Outcome = "ignored"
	OutcomeAdded      Outcome = "added"
	OutcomeChanged    Outcome = "changed"
	OutcomeUnchanged  Outcome = "unchanged"
	OutcomeRemoved    Outcome = "removed"
	OutcomeLastOwner  Outcome = "last_owner_kept"
	OutcomeOrgCreated Outcome = "org_created"
)

// ApplyGrant mirrors a Zitadel user grant event into memberships, in one transaction
// with the seen key and the events. orgName names an org identity does not know yet.
// The first owner of a pending org makes it active and writes org.created. A change
// that would leave an active org without an owner is not mirrored (OutcomeLastOwner).
func (s *Store) ApplyGrant(ctx context.Context, c GrantChange, orgName string) (Outcome, error) {
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return "", fmt.Errorf("orgs: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	tag, err := tx.Exec(ctx, `INSERT INTO zitadel_event_seen (event_key) VALUES ($1) ON CONFLICT (event_key) DO NOTHING`, c.Key)
	if err != nil {
		return "", fmt.Errorf("orgs: mark seen: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return OutcomeDuplicate, nil
	}
	out, err := s.applyGrant(ctx, tx, c, orgName)
	if err != nil {
		return "", err
	}
	if err := commit(ctx, tx); err != nil {
		return "", err
	}
	return out, nil
}

func (s *Store) applyGrant(ctx context.Context, tx pgx.Tx, c GrantChange, orgName string) (Outcome, error) {
	sub := c.UserSub
	if sub == "" && c.GrantID != "" {
		err := tx.QueryRow(ctx, `SELECT user_sub FROM memberships WHERE zitadel_grant_id = $1`, c.GrantID).Scan(&sub)
		if errors.Is(err, pgx.ErrNoRows) {
			return OutcomeIgnored, nil // a grant identity never mirrored
		} else if err != nil {
			return "", err
		}
	}
	role := Highest(c.Roles)
	leave := c.Removed || role == ""
	if sub == "" {
		return OutcomeIgnored, nil
	}
	// A deleted account (synthwerk#41) never comes back through a late grant event.
	var deleted bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM account_deletions WHERE user_sub_hash = sha256(convert_to($1, 'UTF8')))`, sub).Scan(&deleted); err != nil {
		return "", fmt.Errorf("orgs: deleted account: %w", err)
	}
	if deleted {
		return OutcomeIgnored, nil
	}
	org, err := scanOrg(tx.QueryRow(ctx, `SELECT `+orgCols+` FROM orgs WHERE zitadel_org_id = $1 FOR UPDATE`, c.ZitadelOrgID))
	if errors.Is(err, ErrNotFound) {
		if leave {
			return OutcomeIgnored, nil
		}
		if org, err = insertOrg(ctx, tx, c.ZitadelOrgID, orgName); err != nil {
			return "", err
		}
	} else if err != nil {
		return "", err
	}
	locked, owners, err := lockMembers(ctx, tx, org.ID, sub)
	if err != nil {
		return "", err
	}
	cur, isMember := locked[sub]
	lastOwner := org.Status == "active" && cur.Role == Owner && cur.Active() && owners <= 1
	switch {
	case leave && !isMember:
		return OutcomeIgnored, nil
	case leave && lastOwner, !leave && isMember && role != Owner && lastOwner:
		return OutcomeLastOwner, nil
	case leave:
		if _, err := tx.Exec(ctx, `DELETE FROM memberships WHERE org_id = $1 AND user_sub = $2`, org.ID, sub); err != nil {
			return "", err
		}
		return OutcomeRemoved, nil
	}
	out := OutcomeAdded
	if isMember {
		if cur.Role == role {
			out = OutcomeUnchanged
		} else {
			out = OutcomeChanged
		}
	}
	if _, err := tx.Exec(ctx, `INSERT INTO memberships (org_id, user_sub, role, zitadel_grant_id) VALUES ($1, $2, $3, nullif($4, ''))
		ON CONFLICT (org_id, user_sub) DO UPDATE SET role = EXCLUDED.role,
			zitadel_grant_id = coalesce(EXCLUDED.zitadel_grant_id, memberships.zitadel_grant_id),
			updated_at = CASE WHEN memberships.role = EXCLUDED.role THEN memberships.updated_at ELSE now() END`,
		org.ID, sub, string(role), c.GrantID); err != nil {
		return "", fmt.Errorf("orgs: upsert member: %w", err)
	}
	if out == OutcomeChanged {
		e, err := roleChanged(ctx, s.Source, org, sub, cur.Role, role, "system")
		if err != nil {
			return "", err
		}
		if err := outbox.Enqueue(ctx, tx, e); err != nil {
			return "", err
		}
	}
	if org.Status == "pending" && role == Owner {
		if _, err := tx.Exec(ctx, `UPDATE orgs SET status = 'active' WHERE id = $1`, org.ID); err != nil {
			return "", err
		}
		e, err := orgCreated(ctx, s.Source, org, sub)
		if err != nil {
			return "", err
		}
		if err := outbox.Enqueue(ctx, tx, e); err != nil {
			return "", err
		}
		if s.Plans != nil {
			if err := s.Plans.AssignDefault(ctx, tx, org.ID); err != nil {
				return "", err
			}
		}
		return OutcomeOrgCreated, nil
	}
	return out, nil
}

// insertOrg adds a pending org. The slug comes from the name; when another org has
// it, the slug is o-<zitadel org id>.
func insertOrg(ctx context.Context, tx pgx.Tx, zitadelOrgID, name string) (Org, error) {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 128 {
		name = "org " + zitadelOrgID
	}
	for _, slug := range []string{Slug(name), Slug("o-" + zitadelOrgID)} {
		org, err := scanOrg(tx.QueryRow(ctx, `INSERT INTO orgs (id, zitadel_org_id, name, slug) VALUES ($1, $2, $3, $4)
			ON CONFLICT DO NOTHING RETURNING `+orgCols, uuid.Must(uuid.NewV7()).String(), zitadelOrgID, name, slug))
		if !errors.Is(err, ErrNotFound) {
			return org, err
		}
		// A conflict: another transaction added this org, or the slug is taken.
		org, err = scanOrg(tx.QueryRow(ctx, `SELECT `+orgCols+` FROM orgs WHERE zitadel_org_id = $1 FOR UPDATE`, zitadelOrgID))
		if !errors.Is(err, ErrNotFound) {
			return org, err
		}
	}
	return Org{}, fmt.Errorf("orgs: no free slug for zitadel org %s", zitadelOrgID)
}

var nonSlug = regexp.MustCompile(`[^a-z0-9]+`)

// Slug turns a name into ^[a-z][a-z0-9-]{1,63}$: lower case, runs of other
// characters become "-", a leading digit gets "o-".
func Slug(name string) string {
	s := strings.Trim(nonSlug.ReplaceAllString(strings.ToLower(name), "-"), "-")
	if s == "" || s[0] < 'a' || s[0] > 'z' {
		s = "o-" + s
	}
	if len(s) > 64 {
		s = strings.TrimRight(s[:62], "-")
	}
	if len(s) < 2 {
		s += "-o"
	}
	return s
}
