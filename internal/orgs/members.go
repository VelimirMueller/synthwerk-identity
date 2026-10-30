package orgs

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/mail"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/jackc/pgx/v5"

	"github.com/VelimirMueller/synthwerk-contracts/go/kit/outbox"
)

// Users invites users and switches user grants on and off in Zitadel
// (synthwerk#37). *zitadel.Client satisfies it.
type Users interface {
	// Invite creates a user with email in the Zitadel org, gives it a user grant
	// with role and lets Zitadel send the invite mail. It returns the subject and
	// the grant id. A user of this org is ErrMemberExists with its subject (no grant
	// id); a user of another org is ErrOutsideOrg.
	Invite(ctx context.Context, zitadelOrgID, email string, role Role) (userSub, grantID string, err error)
	// SetActive deactivates (active false) or reactivates the user grant.
	SetActive(ctx context.Context, zitadelOrgID, userSub, grantID string, active bool) error
	// Uninvite deletes a user Invite created: when identity could not commit it,
	// or when an admin revokes the invitation. A user that is gone already is no
	// error.
	Uninvite(ctx context.Context, zitadelOrgID, userSub string) error
}

// Refusals of an invite or a status change.
var (
	// ErrMemberExists: the email is an active or deactivated member of this org
	// (409 member_exists).
	ErrMemberExists = errors.New("orgs: member exists")
	// ErrOutsideOrg: the email is a user of another org. Adding such users is not
	// supported yet: the invitation stays pending. Users.Invite returns it; the
	// store records the invitation like any other, so the API does not show which
	// emails have an account.
	ErrOutsideOrg = errors.New("orgs: user of another org")
	// ErrOwnMembership: the caller tried to deactivate their own membership (409 own_membership).
	ErrOwnMembership = errors.New("orgs: own membership")
	// ErrUsersOff: no Zitadel client; an invite cannot reach Zitadel (502).
	ErrUsersOff = fmt.Errorf("%w: zitadel client off", ErrUpstream)
)

// MaxEmailLen is the longest email an invite takes (RFC 5321 path limit).
const MaxEmailLen = 254

// ValidEmail reports whether s is one plain address: local@domain, no name, no
// angle brackets, no spaces.
func ValidEmail(s string) bool {
	if len(s) < 3 || len(s) > MaxEmailLen || strings.ContainsAny(s, " <>\"\r\n\t") {
		return false
	}
	a, err := mail.ParseAddress(s)
	if err != nil || a.Address != s || a.Name != "" {
		return false
	}
	at := strings.LastIndexByte(s, '@')
	return at > 0 && at < len(s)-1 && strings.Contains(s[at+1:], ".")
}

// AuthorizeStatus applies the rules of a deactivate or reactivate: actor and
// target are the stored rows. Same owner rule as a role change.
func AuthorizeStatus(actor, target Membership, self bool) error {
	if !actor.Active() || !actor.Role.AtLeast(Admin) || !target.Role.Valid() {
		return ErrForbidden
	}
	if self {
		return ErrOwnMembership
	}
	if target.Role == Owner && actor.Role != Owner {
		return ErrForbidden
	}
	return nil
}

// AuthorizeInvite applies the rules of an invite: actor is the stored row of the
// caller, role the role of the new member.
func AuthorizeInvite(actor Membership, role Role) error {
	if !actor.Active() || !actor.Role.AtLeast(Admin) || !role.Valid() {
		return ErrForbidden
	}
	if role == Owner && actor.Role != Owner {
		return ErrForbidden
	}
	return nil
}

// Invitation is a row of identity.invitations: an email an owner or admin
// invited. It is pending until the invitee signs in to the org.
type Invitation struct {
	ID        string
	OrgID     string
	Email     string
	Role      Role
	InvitedBy string
	CreatedAt time.Time
}

// StatusInvited: the member has a user grant but has not signed in to the org
// yet. Not listed, not active, no stored role.
const StatusInvited = "invited"

func (s *Store) log() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.Default()
}

// Invite records a pending invitation of email as actor and writes
// member.invited. For a new email it also creates the Zitadel user and its user
// grant, and Zitadel sends the mail; the member row is "invited" until the first
// sign-in. For a user of another org it records the invitation only. Both leave
// the same trace: invitation, event, no listed member (no account enumeration).
//
// A pending invitation for the email (any case) is returned unchanged, before
// any Zitadel call: a repeat invite never shows whether the first one made a
// user. Only an active or deactivated member is ErrMemberExists.
func (s *Store) Invite(ctx context.Context, org Org, actorSub, email string, role Role) (Invitation, error) {
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return Invitation{}, fmt.Errorf("orgs: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	locked, _, err := lockMembers(ctx, tx, org.ID, actorSub)
	if err != nil {
		return Invitation{}, fmt.Errorf("orgs: lock: %w", err)
	}
	if err := AuthorizeInvite(locked[actorSub], role); err != nil {
		return Invitation{}, err
	}
	if pending, err := s.pendingInvitation(ctx, tx, org.ID, email); err == nil {
		return pending, nil
	} else if !errors.Is(err, ErrNotFound) {
		return Invitation{}, err
	}
	if s.Users == nil {
		return Invitation{}, ErrUsersOff
	}
	sub, grantID, err := s.Users.Invite(ctx, org.ZitadelOrgID, email, role)
	switch {
	case errors.Is(err, ErrOutsideOrg):
		sub, grantID = "", ""
	case errors.Is(err, ErrMemberExists):
		// A user of this org. 409 only for a listed member; any other user of the
		// org (no membership) gets a pending invitation like a foreign email.
		var status string
		serr := tx.QueryRow(ctx, `SELECT status FROM memberships WHERE org_id = $1 AND user_sub = $2`, org.ID, sub).Scan(&status)
		if serr == nil && (status == StatusActive || status == StatusDeactivated) {
			return Invitation{}, ErrMemberExists
		}
		if serr != nil && !errors.Is(serr, pgx.ErrNoRows) {
			return Invitation{}, fmt.Errorf("orgs: read member: %w", serr)
		}
		sub, grantID = "", ""
	case err != nil:
		return Invitation{}, fmt.Errorf("%w: %w", ErrUpstream, err)
	}
	inv := Invitation{ID: uuid.Must(uuid.NewV7()).String(), OrgID: org.ID, Email: email, Role: role, InvitedBy: actorSub}
	err = s.recordInvite(ctx, tx, org, &inv, sub, grantID)
	if err == nil {
		return inv, nil
	}
	// Delete the new Zitadel user so a retry works, but only when the invitation
	// is really not stored: a commit error can come after a commit.
	if sub != "" {
		wctx := context.WithoutCancel(ctx)
		var n int
		if rerr := s.DB.QueryRow(wctx, `SELECT count(*) FROM invitations WHERE id = $1`, inv.ID).Scan(&n); rerr != nil || n > 0 {
			s.log().WarnContext(wctx, "invite: commit failed, Zitadel user kept", slog.String("event.name", "orgs.invite_drift"),
				slog.String("org.id", org.ID), slog.String("enduser.id", sub), slog.Bool("stored", n > 0))
		} else if uerr := s.Users.Uninvite(wctx, org.ZitadelOrgID, sub); uerr != nil {
			s.log().WarnContext(wctx, "invite: Zitadel user not deleted", slog.String("event.name", "orgs.invite_drift"),
				slog.String("org.id", org.ID), slog.String("enduser.id", sub), slog.String("exception.message", uerr.Error()))
		}
	}
	return Invitation{}, err
}

func (s *Store) recordInvite(ctx context.Context, tx pgx.Tx, org Org, inv *Invitation, sub, grantID string) error {
	if err := tx.QueryRow(ctx, `INSERT INTO invitations (id, org_id, email, role, invited_by, user_sub) VALUES ($1, $2, $3, $4, $5, nullif($6, ''))
		RETURNING created_at`, inv.ID, org.ID, inv.Email, string(inv.Role), inv.InvitedBy, sub).Scan(&inv.CreatedAt); err != nil {
		return fmt.Errorf("orgs: insert invitation: %w", err)
	}
	if sub != "" {
		// The hook may mirror the new grant first (as active); the row stays
		// "invited" until the first sign-in.
		if _, err := tx.Exec(ctx, `INSERT INTO memberships (org_id, user_sub, role, status, zitadel_grant_id) VALUES ($1, $2, $3, 'invited', nullif($4, ''))
			ON CONFLICT (org_id, user_sub) DO UPDATE SET status = 'invited',
				zitadel_grant_id = coalesce(EXCLUDED.zitadel_grant_id, memberships.zitadel_grant_id)`,
			org.ID, sub, string(inv.Role), grantID); err != nil {
			return fmt.Errorf("orgs: insert member: %w", err)
		}
	}
	e, err := invitedFact(ctx, s.Source, org, *inv)
	if err != nil {
		return err
	}
	if err := outbox.Enqueue(ctx, tx, e); err != nil {
		return err
	}
	return commit(ctx, tx)
}

// pendingInvitation returns the pending invitation of email (any case) in org,
// locked, or ErrNotFound.
func (s *Store) pendingInvitation(ctx context.Context, tx pgx.Tx, orgID, email string) (Invitation, error) {
	var i Invitation
	var role string
	err := tx.QueryRow(ctx, `SELECT id::text, org_id::text, email, role, invited_by, created_at FROM invitations
		WHERE org_id = $1 AND lower(email) = lower($2) AND accepted_at IS NULL AND revoked_at IS NULL FOR UPDATE`, orgID, email).
		Scan(&i.ID, &i.OrgID, &i.Email, &role, &i.InvitedBy, &i.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Invitation{}, ErrNotFound
	}
	if err != nil {
		return Invitation{}, fmt.Errorf("orgs: read invitation: %w", err)
	}
	i.Role = Role(role)
	return i, nil
}

// RevokeInvitation revokes the pending invitation id of org as actor: the
// invitation is revoked, member.invite_revoked is written and, while the invitee
// has not joined, its "invited" row and the Zitadel user identity made for it are
// deleted, in one transaction. Same rules as an invite: active owner or admin;
// only an owner revokes an owner invitation or touches an owner. An invitation
// that is not pending is ErrNotFound.
//
// The invitee's membership row is locked and read first. When it is active or
// deactivated (the user joined by another path), only the invitation is revoked:
// the member row and the Zitadel user stay. Users.Uninvite runs only for a user
// with no row or an "invited" row.
//
// Fail closed: the Zitadel user is deleted before the commit. A failed commit
// leaves the invitation pending without a user; a retry finishes the revoke.
func (s *Store) RevokeInvitation(ctx context.Context, org Org, actorSub, id string) error {
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return fmt.Errorf("orgs: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	// The invitee first without a lock: members are locked before the invitation,
	// in the order every write uses (no deadlock with Invite).
	var sub string
	err = tx.QueryRow(ctx, `SELECT coalesce(user_sub, '') FROM invitations WHERE org_id = $1 AND id = $2::uuid`, org.ID, id).Scan(&sub)
	if errors.Is(err, pgx.ErrNoRows) {
		return s.revokeRefusal(ctx, tx, org.ID, actorSub)
	}
	if err != nil {
		return fmt.Errorf("orgs: read invitation: %w", err)
	}
	subs := []string{actorSub}
	if sub != "" && sub != actorSub {
		subs = append(subs, sub)
	}
	locked, _, err := lockMembers(ctx, tx, org.ID, subs...)
	if err != nil {
		return fmt.Errorf("orgs: lock: %w", err)
	}
	actor := locked[actorSub]
	if !actor.Active() || !actor.Role.AtLeast(Admin) {
		return ErrForbidden
	}
	inv := Invitation{ID: id, OrgID: org.ID}
	var role string
	err = tx.QueryRow(ctx, `SELECT role FROM invitations
		WHERE org_id = $1 AND id = $2::uuid AND coalesce(user_sub, '') = $3 AND accepted_at IS NULL AND revoked_at IS NULL FOR UPDATE`,
		org.ID, id, sub).Scan(&role)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("orgs: read invitation: %w", err)
	}
	inv.Role = Role(role)
	if err := AuthorizeInvite(actor, inv.Role); err != nil {
		return err
	}
	// joined: the invitee is a listed member now. Leave its row and its Zitadel user.
	m, hasRow := locked[sub]
	joined := sub != "" && hasRow && m.Status != StatusInvited
	if hasRow && m.Role == Owner && actor.Role != Owner {
		return ErrForbidden
	}
	if _, err := tx.Exec(ctx, `UPDATE invitations SET revoked_at = now() WHERE id = $1::uuid`, id); err != nil {
		return fmt.Errorf("orgs: revoke invitation: %w", err)
	}
	uninvite := sub != "" && !joined
	if uninvite && hasRow {
		if _, err := tx.Exec(ctx, `DELETE FROM memberships WHERE org_id = $1 AND user_sub = $2 AND status = 'invited'`, org.ID, sub); err != nil {
			return fmt.Errorf("orgs: delete invited member: %w", err)
		}
	}
	e, err := invitationFact(ctx, MemberInviteRevoked, MemberInviteRevokedSchema, s.Source, org, inv, actorSub)
	if err != nil {
		return err
	}
	if err := outbox.Enqueue(ctx, tx, e); err != nil {
		return err
	}
	if uninvite {
		if s.Users == nil {
			return ErrUsersOff
		}
		if err := s.Users.Uninvite(ctx, org.ZitadelOrgID, sub); err != nil {
			return fmt.Errorf("%w: %w", ErrUpstream, err)
		}
	}
	if err := commit(ctx, tx); err != nil {
		if uninvite {
			s.log().WarnContext(context.WithoutCancel(ctx), "revoke: commit failed, Zitadel user stays deleted", slog.String("event.name", "orgs.revoke_drift"),
				slog.String("org.id", org.ID), slog.String("invitation.id", id))
		}
		return err
	}
	return nil
}

// revokeRefusal answers a revoke of an unknown invitation: 403 for a caller that
// may not revoke, else 404, so the answer never shows which ids exist.
func (s *Store) revokeRefusal(ctx context.Context, tx pgx.Tx, orgID, actorSub string) error {
	locked, _, err := lockMembers(ctx, tx, orgID, actorSub)
	if err != nil {
		return fmt.Errorf("orgs: lock: %w", err)
	}
	if a := locked[actorSub]; !a.Active() || !a.Role.AtLeast(Admin) {
		return ErrForbidden
	}
	return ErrNotFound
}

// ListInvitations returns up to limit pending invitations of org with id < before
// ("" = from the newest), newest first.
func (s *Store) ListInvitations(ctx context.Context, orgID, before string, limit int) ([]Invitation, error) {
	q := `SELECT id::text, org_id::text, email, role, invited_by, created_at FROM invitations
		WHERE org_id = $1 AND accepted_at IS NULL AND revoked_at IS NULL AND ($2 = '' OR id < $2::uuid) ORDER BY id DESC LIMIT $3`
	rows, err := s.DB.Query(ctx, q, orgID, before, limit)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (Invitation, error) {
		var i Invitation
		var role string
		err := row.Scan(&i.ID, &i.OrgID, &i.Email, &role, &i.InvitedBy, &i.CreatedAt)
		i.Role = Role(role)
		return i, err
	})
}

// AcceptInvite makes an invited member of org active and its invitation no
// longer pending. The org gate calls it for a token of the org: the first sign-in
// of the invitee. It does nothing for any other caller, and nothing without a
// pending invitation: a revoked invitation is never accepted.
func (s *Store) AcceptInvite(ctx context.Context, orgID, sub string) error {
	return s.run(ctx, `WITH m AS (
			UPDATE memberships SET status = 'active', updated_at = now()
			WHERE org_id = $1 AND user_sub = $2 AND status = 'invited'
			  AND EXISTS (SELECT 1 FROM invitations i WHERE i.org_id = $1 AND i.user_sub = $2
			              AND i.accepted_at IS NULL AND i.revoked_at IS NULL)
			RETURNING user_sub)
		UPDATE invitations SET accepted_at = now() WHERE org_id = $1 AND user_sub IN (SELECT user_sub FROM m)
			AND accepted_at IS NULL AND revoked_at IS NULL`, orgID, sub)
}

// run executes sql through DB.Query (DB has no Exec) and drains the result.
func (s *Store) run(ctx context.Context, sql string, args ...any) error {
	rows, err := s.DB.Query(ctx, sql, args...)
	if err != nil {
		return err
	}
	rows.Close()
	return rows.Err()
}

// SetStatus deactivates (active false) or reactivates target in org as actor: the
// row, the event and the Zitadel user grant in one transaction. changed is false
// when target has the status already; then nothing is written. An invited
// member is not found: it is not listed until its first sign-in.
//
// A failed commit after the Zitadel write fails closed: a deactivation is never
// undone in Zitadel (a retry repairs the row); a reactivation is undone only when
// a re-read shows the row still deactivated.
func (s *Store) SetStatus(ctx context.Context, org Org, actorSub, targetSub string, active bool) (m Membership, changed bool, err error) {
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return Membership{}, false, fmt.Errorf("orgs: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	locked, owners, err := lockMembers(ctx, tx, org.ID, actorSub, targetSub)
	if err != nil {
		return Membership{}, false, fmt.Errorf("orgs: lock: %w", err)
	}
	actor, ok := locked[actorSub]
	if !ok || !actor.Active() {
		return Membership{}, false, ErrForbidden
	}
	target, ok := locked[targetSub]
	if !ok || target.Status == StatusInvited {
		if !actor.Role.AtLeast(Admin) {
			return Membership{}, false, ErrForbidden
		}
		return Membership{}, false, ErrNotFound
	}
	if err := AuthorizeStatus(actor, target, actorSub == targetSub); err != nil {
		return Membership{}, false, err
	}
	to := StatusDeactivated
	if active {
		to = StatusActive
	}
	if target.Status == to {
		return target, false, nil
	}
	if !active && target.Role == Owner && owners <= 1 {
		return Membership{}, false, ErrLastOwner
	}
	if err := tx.QueryRow(ctx, `UPDATE memberships SET status = $3, updated_at = now()
		WHERE org_id = $1 AND user_sub = $2 RETURNING updated_at`, org.ID, targetSub, to).Scan(&target.UpdatedAt); err != nil {
		return Membership{}, false, fmt.Errorf("orgs: update status: %w", err)
	}
	typ, schema := MemberDeactivated, MemberDeactivatedSchema
	if active {
		typ, schema = MemberReactivated, MemberReactivatedSchema
	}
	e, err := memberFact(ctx, typ, schema, s.Source, org, targetSub, target.Role, "user:"+actorSub)
	if err != nil {
		return Membership{}, false, err
	}
	if err := outbox.Enqueue(ctx, tx, e); err != nil {
		return Membership{}, false, err
	}
	if s.Users != nil {
		if err := s.Users.SetActive(ctx, org.ZitadelOrgID, targetSub, target.GrantID, active); err != nil {
			return Membership{}, false, fmt.Errorf("%w: %w", ErrUpstream, err)
		}
	}
	if err := commit(ctx, tx); err != nil {
		if s.Users != nil {
			s.repairStatus(context.WithoutCancel(ctx), org, target, active)
		}
		return Membership{}, false, err
	}
	target.Status = to
	return target, true, nil
}

// repairStatus runs after a failed commit whose Zitadel write went through.
func (s *Store) repairStatus(ctx context.Context, org Org, target Membership, active bool) {
	attrs := []any{slog.String("event.name", "orgs.status_drift"), slog.String("org.id", org.ID), slog.String("enduser.id", target.UserSub)}
	if !active {
		// Fail closed: the grant stays off. The row says active until a retry.
		s.log().WarnContext(ctx, "deactivate: commit failed, Zitadel grant stays deactivated", attrs...)
		return
	}
	var status string
	err := s.DB.QueryRow(ctx, `SELECT status FROM memberships WHERE org_id = $1 AND user_sub = $2`, org.ID, target.UserSub).Scan(&status)
	switch {
	case err != nil:
		s.log().WarnContext(ctx, "reactivate: commit failed, row not readable, Zitadel grant switched off", append(attrs, slog.String("exception.message", err.Error()))...)
		s.switchBack(ctx, org, target, attrs)
	case status == StatusActive:
		s.log().WarnContext(ctx, "reactivate: commit error, but the row is active: Zitadel grant kept", attrs...)
	default:
		s.log().WarnContext(ctx, "reactivate: commit failed, Zitadel grant switched off again", attrs...)
		s.switchBack(ctx, org, target, attrs)
	}
}

func (s *Store) switchBack(ctx context.Context, org Org, target Membership, attrs []any) {
	if err := s.Users.SetActive(ctx, org.ZitadelOrgID, target.UserSub, target.GrantID, false); err != nil {
		s.log().WarnContext(ctx, "Zitadel grant not switched off: drift", append(attrs, slog.String("exception.message", err.Error()))...)
	}
}
