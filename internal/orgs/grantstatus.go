package orgs

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/VelimirMueller/synthwerk-contracts/go/kit/outbox"
)

// GrantStates reads the state of a Zitadel user grant. *zitadel.Client satisfies it.
type GrantStates interface {
	// GrantActive reports whether the user grant is active in Zitadel now. A grant
	// Zitadel does not know is not active.
	GrantActive(ctx context.Context, zitadelOrgID, userSub, grantID string) (bool, error)
}

// GrantStatusChange is a Zitadel user grant deactivate or reactivate event
// (user.grant.deactivated, user.grant.reactivated), as the hook sees it. The
// events carry no payload: the store finds the member by GrantID.
type GrantStatusChange struct {
	// Key identifies the Zitadel event; a repeat is dropped.
	Key string
	// ZitadelOrgID is the org that holds the grant (event resource owner).
	ZitadelOrgID string
	GrantID      string
	// Active is true for a reactivate, false for a deactivate.
	Active bool
}

// GrantStateTimeout bounds the Zitadel read that confirms a reactivate.
const GrantStateTimeout = 5 * time.Second

// Outcomes of ApplyGrantStatus.
const (
	OutcomeDeactivated Outcome = "deactivated"
	OutcomeReactivated Outcome = "reactivated"
	// OutcomeUnconfirmed: a reactivate that Zitadel does not confirm (the grant is
	// not active now, or no GrantStates). The member stays deactivated.
	OutcomeUnconfirmed Outcome = "reactivate_unconfirmed"
)

// ApplyGrantStatus mirrors a Zitadel user grant deactivate or reactivate into the
// member status (synthwerk#37), in one transaction with the seen key and the
// member.deactivated or member.reactivated event (actor system), which the audit
// list shows.
//
// Fail closed:
//   - A deactivate applies to an active member. The last active owner of an
//     active org stays active (OutcomeLastOwner, like a removed grant): Zitadel
//     tokens carry no org role for a deactivated grant, so the org gate refuses
//     that owner anyway.
//   - A reactivate applies only to a deactivated member, and only when Zitadel
//     confirms that the grant is active now. Events can arrive late or out of
//     order: an unconfirmed reactivate changes nothing. A read error rolls back,
//     so the event is not marked seen.
//   - An unknown grant, a grant of another org, an invited member and a deleted
//     account change nothing.
//
// A change identity made itself (SetStatus) comes back as an event; the row has
// that status already, so the echo writes nothing.
func (s *Store) ApplyGrantStatus(ctx context.Context, c GrantStatusChange) (Outcome, error) {
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
	out, err := s.applyGrantStatus(ctx, tx, c)
	if err != nil {
		return "", err
	}
	if err := commit(ctx, tx); err != nil {
		return "", err
	}
	return out, nil
}

func (s *Store) applyGrantStatus(ctx context.Context, tx pgx.Tx, c GrantStatusChange) (Outcome, error) {
	if c.GrantID == "" || c.ZitadelOrgID == "" {
		return OutcomeIgnored, nil
	}
	// The grant must be one identity mirrored, in the org of the event.
	org, err := scanOrg(tx.QueryRow(ctx, `SELECT `+orgCols+` FROM orgs WHERE zitadel_org_id = $1 FOR UPDATE`, c.ZitadelOrgID))
	if errors.Is(err, ErrNotFound) {
		return OutcomeIgnored, nil
	} else if err != nil {
		return "", err
	}
	var sub string
	err = tx.QueryRow(ctx, `SELECT user_sub FROM memberships WHERE org_id = $1 AND zitadel_grant_id = $2`, org.ID, c.GrantID).Scan(&sub)
	if errors.Is(err, pgx.ErrNoRows) {
		return OutcomeIgnored, nil
	} else if err != nil {
		return "", err
	}
	var deleted bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM account_deletions WHERE user_sub_hash = sha256(convert_to($1, 'UTF8')))`, sub).Scan(&deleted); err != nil {
		return "", fmt.Errorf("orgs: deleted account: %w", err)
	}
	if deleted {
		return OutcomeIgnored, nil
	}
	locked, owners, err := lockMembers(ctx, tx, org.ID, sub)
	if err != nil {
		return "", err
	}
	cur, ok := locked[sub]
	if !ok || cur.GrantID != c.GrantID {
		return OutcomeIgnored, nil
	}
	from, to := StatusActive, StatusDeactivated
	typ, schema, out := MemberDeactivated, MemberDeactivatedSchema, OutcomeDeactivated
	if c.Active {
		from, to = StatusDeactivated, StatusActive
		typ, schema, out = MemberReactivated, MemberReactivatedSchema, OutcomeReactivated
	}
	if cur.Status != from {
		return OutcomeUnchanged, nil // the status already, or invited
	}
	if !c.Active && org.Status == "active" && cur.Role == Owner && owners <= 1 {
		return OutcomeLastOwner, nil
	}
	if c.Active {
		if s.GrantStates == nil {
			return OutcomeUnconfirmed, nil
		}
		// The read runs while the row locks are held: keep it short.
		rctx, cancel := context.WithTimeout(ctx, GrantStateTimeout)
		active, err := s.GrantStates.GrantActive(rctx, org.ZitadelOrgID, sub, c.GrantID)
		cancel()
		if err != nil {
			return "", fmt.Errorf("orgs: read grant state: %w", err)
		}
		if !active {
			return OutcomeUnconfirmed, nil
		}
	}
	if _, err := tx.Exec(ctx, `UPDATE memberships SET status = $3, updated_at = now() WHERE org_id = $1 AND user_sub = $2`, org.ID, sub, to); err != nil {
		return "", fmt.Errorf("orgs: update status: %w", err)
	}
	e, err := memberFact(ctx, typ, schema, s.Source, org, sub, cur.Role, "system")
	if err != nil {
		return "", err
	}
	if err := outbox.Enqueue(ctx, tx, e); err != nil {
		return "", err
	}
	return out, nil
}
