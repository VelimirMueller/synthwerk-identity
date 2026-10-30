// Package account serves the caller's own data (synthwerk#41): the export of every
// row Synthwerk keeps about the user and the delete of the own account.
//
//   - GET /v1/me/export collects the identity rows of the user and asks each export
//     source (a service that keeps user rows, today llm) with the caller's token.
//   - DELETE /v1/me deletes the identity rows of the user in one transaction with the
//     fact dev.synthwerk.identity.user.deleted.v1. The other services consume it and
//     delete their rows. Remover then removes the Zitadel user, with retries.
//
// Last owner rule: an org with other members must keep an owner. The only owner of
// such an org gets ErrLastOwner and nothing changes. An org where the user is the
// only member closes with the account: identity deletes it with its apps and
// entitlements.
package account

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/VelimirMueller/synthwerk-contracts/go/kit/outbox"
)

// ErrLastOwner: the user is the only owner of an org with other members.
// Use errors.As with *LastOwnerError to read the orgs.
var ErrLastOwner = errors.New("account: last owner of an org with other members")

// LastOwnerError names the orgs that would lose their last owner.
type LastOwnerError struct{ OrgIDs []string }

func (e *LastOwnerError) Error() string {
	return ErrLastOwner.Error() + ": " + strings.Join(e.OrgIDs, ", ")
}

// Unwrap makes errors.Is(err, ErrLastOwner) true.
func (e *LastOwnerError) Unwrap() error { return ErrLastOwner }

// Membership is one org membership of the user, for the export.
type Membership struct {
	OrgID, OrgName, OrgSlug string
	Role                    string
	JoinedAt, UpdatedAt     time.Time
}

// DeletedOrg is an org that closed with the account.
type DeletedOrg struct {
	ID           string `json:"org_id"`
	ZitadelOrgID string `json:"zitadel_org_id"`
}

// Deletion is the result of Delete.
type Deletion struct {
	UserSub     string
	RequestedAt time.Time
	DeletedOrgs []DeletedOrg
	// Repeat: the account was deleted before; this call changed nothing.
	Repeat bool
}

// DB is the part of *pgxpool.Pool the store needs.
type DB interface {
	Begin(ctx context.Context) (pgx.Tx, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

// Store reads and deletes the identity rows of a user (search_path=identity).
type Store struct {
	DB DB
	// Source is the CloudEvents source, /synthwerk/identity/<env>.
	Source string
}

// Hash is the key of a user in account_deletions: sha256 of the sub.
func Hash(sub string) []byte {
	h := sha256.Sum256([]byte(sub))
	return h[:]
}

// Memberships returns every membership of sub, by org name.
func (s *Store) Memberships(ctx context.Context, sub string) ([]Membership, error) {
	rows, err := s.DB.Query(ctx, `SELECT o.id::text, o.name, o.slug, m.role, m.created_at, m.updated_at
		FROM memberships m JOIN orgs o ON o.id = m.org_id
		WHERE m.user_sub = $1 ORDER BY o.name, o.id`, sub)
	if err != nil {
		return nil, fmt.Errorf("account: memberships: %w", err)
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Membership, error) {
		var m Membership
		err := r.Scan(&m.OrgID, &m.OrgName, &m.OrgSlug, &m.Role, &m.JoinedAt, &m.UpdatedAt)
		return m, err
	})
}

// Deleted returns the deletion of sub, or ok false when the account is not deleted.
func (s *Store) Deleted(ctx context.Context, sub string) (d Deletion, ok bool, err error) {
	d = Deletion{UserSub: sub, DeletedOrgs: []DeletedOrg{}, Repeat: true}
	err = s.DB.QueryRow(ctx, `SELECT requested_at FROM account_deletions WHERE user_sub_hash = $1`, Hash(sub)).Scan(&d.RequestedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Deletion{}, false, nil
	}
	if err != nil {
		return Deletion{}, false, fmt.Errorf("account: deleted: %w", err)
	}
	return d, true, nil
}

// lockedOrg is an org of the user with the counts Delete decides on.
type lockedOrg struct {
	id, zitadelID, status, role string
	others, otherOwners         int
}

// Delete deletes the identity rows of sub and writes user.deleted in one
// transaction. A deleted account gives the first deletion with Repeat true.
func (s *Store) Delete(ctx context.Context, sub string) (Deletion, error) {
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return Deletion{}, fmt.Errorf("account: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }() // no-op after Commit

	// One delete per user at a time: the second waits here, then finds the row.
	var requested time.Time
	err = tx.QueryRow(ctx, `INSERT INTO account_deletions (user_sub_hash, user_sub) VALUES ($1, $2)
		ON CONFLICT (user_sub_hash) DO NOTHING RETURNING requested_at`, Hash(sub), sub).Scan(&requested)
	if errors.Is(err, pgx.ErrNoRows) {
		_ = tx.Rollback(ctx)
		d, ok, err := s.Deleted(ctx, sub)
		if err == nil && !ok {
			err = errors.New("account: deletion row vanished")
		}
		return d, err
	}
	if err != nil {
		return Deletion{}, fmt.Errorf("account: mark deleted: %w", err)
	}

	locked, err := lockOrgs(ctx, tx, sub)
	if err != nil {
		return Deletion{}, err
	}
	var lastOwner []string
	deleted := []DeletedOrg{}
	for _, o := range locked {
		switch {
		case o.others == 0:
			deleted = append(deleted, DeletedOrg{ID: o.id, ZitadelOrgID: o.zitadelID})
		case o.status == "active" && o.role == "owner" && o.otherOwners == 0:
			lastOwner = append(lastOwner, o.id)
		}
	}
	if len(lastOwner) > 0 {
		return Deletion{}, &LastOwnerError{OrgIDs: lastOwner}
	}
	for _, o := range deleted {
		// Cascades to memberships, apps and org_entitlements.
		if _, err := tx.Exec(ctx, `DELETE FROM orgs WHERE id = $1`, o.ID); err != nil {
			return Deletion{}, fmt.Errorf("account: delete org: %w", err)
		}
	}
	for _, q := range []string{
		`DELETE FROM memberships WHERE user_sub = $1`,
		`DELETE FROM mfa_evidence WHERE user_sub = $1`,
		// Seen keys of the user's own Zitadel events: <instance>:user:<sub>:<sequence>.
		`DELETE FROM zitadel_event_seen WHERE split_part(event_key, ':', 2) = 'user' AND split_part(event_key, ':', 3) = $1`,
	} {
		if _, err := tx.Exec(ctx, q, sub); err != nil {
			return Deletion{}, fmt.Errorf("account: delete rows: %w", err)
		}
	}
	e, err := userDeleted(ctx, s.Source, sub, deleted)
	if err != nil {
		return Deletion{}, err
	}
	if err := outbox.Enqueue(ctx, tx, e); err != nil {
		return Deletion{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.ConstraintName == "memberships_keep_an_owner" {
			return Deletion{}, ErrLastOwner // second guard: the deferred owner trigger
		}
		return Deletion{}, fmt.Errorf("account: commit: %w", err)
	}
	return Deletion{UserSub: sub, RequestedAt: requested, DeletedOrgs: deleted}, nil
}

// lockOrgs locks every org of sub, then the owner rows and the row of sub in each,
// in org id order. The order is the one of orgs.ApplyGrant (org row, then members),
// so a grant that adds a member and a role change both wait for the delete.
func lockOrgs(ctx context.Context, tx pgx.Tx, sub string) ([]lockedOrg, error) {
	rows, err := tx.Query(ctx, `SELECT o.id::text, o.zitadel_org_id, o.status FROM orgs o
		WHERE o.id IN (SELECT org_id FROM memberships WHERE user_sub = $1)
		ORDER BY o.id FOR UPDATE OF o`, sub)
	if err != nil {
		return nil, fmt.Errorf("account: lock orgs: %w", err)
	}
	out, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (lockedOrg, error) {
		var o lockedOrg
		err := r.Scan(&o.id, &o.zitadelID, &o.status)
		return o, err
	})
	if err != nil {
		return nil, fmt.Errorf("account: lock orgs: %w", err)
	}
	for i := range out {
		o := &out[i]
		mrows, err := tx.Query(ctx, `SELECT user_sub, role FROM memberships
			WHERE org_id = $1 AND (role = 'owner' OR user_sub = $2) ORDER BY user_sub FOR UPDATE`, o.id, sub)
		if err != nil {
			return nil, fmt.Errorf("account: lock members: %w", err)
		}
		type member struct{ sub, role string }
		ms, err := pgx.CollectRows(mrows, func(r pgx.CollectableRow) (member, error) {
			var m member
			err := r.Scan(&m.sub, &m.role)
			return m, err
		})
		if err != nil {
			return nil, fmt.Errorf("account: lock members: %w", err)
		}
		for _, m := range ms {
			if m.sub == sub {
				o.role = m.role
			} else if m.role == "owner" {
				o.otherOwners++
			}
		}
		// The org row lock keeps the member count stable: ApplyGrant adds members
		// only under it.
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM memberships WHERE org_id = $1 AND user_sub <> $2`, o.id, sub).Scan(&o.others); err != nil {
			return nil, fmt.Errorf("account: count members: %w", err)
		}
	}
	return slices.Clip(out), nil
}
