//go:build integration

package orgs_test

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/VelimirMueller/synthwerk-contracts/go/identity"
	"github.com/VelimirMueller/synthwerk-contracts/go/kit/auth"
	"github.com/VelimirMueller/synthwerk-contracts/go/kit/auth/authtest"

	"github.com/VelimirMueller/synthwerk-identity/internal/app"
	"github.com/VelimirMueller/synthwerk-identity/internal/audit"
	"github.com/VelimirMueller/synthwerk-identity/internal/orgs"
)

const invitee = "100000000000000005"

// fakeUsers is orgs.Users: it records calls; err makes Zitadel refuse.
// Emails: "foreign…" is a user of another org, "member…" the seeded member,
// "stranger…" a user of this org without a membership.
type fakeUsers struct {
	mu          sync.Mutex
	calls       []string
	err         error
	uninviteErr error
}

const stranger = "100000000000000099"

func (f *fakeUsers) Invite(_ context.Context, zid, email string, role orgs.Role) (string, string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return "", "", f.err
	}
	f.calls = append(f.calls, "invite/"+zid+"/"+email+"/"+string(role))
	switch {
	case strings.HasPrefix(email, "foreign"):
		return "", "", orgs.ErrOutsideOrg
	case strings.HasPrefix(email, "member"):
		return member, "", orgs.ErrMemberExists
	case strings.HasPrefix(email, "stranger"):
		return stranger, "", orgs.ErrMemberExists
	}
	return invitee, "g-invite", nil
}

func (f *fakeUsers) SetActive(_ context.Context, zid, sub, grantID string, active bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	f.calls = append(f.calls, "active/"+zid+"/"+sub+"/"+grantID+"/"+map[bool]string{true: "on", false: "off"}[active])
	return nil
}

func (f *fakeUsers) Uninvite(_ context.Context, zid, sub string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "uninvite/"+zid+"/"+sub)
	return f.uninviteErr
}

func auditRows(t *testing.T, db *pgxpool.Pool, org orgs.Org, typ string) int {
	t.Helper()
	return count(t, db, `SELECT count(*) FROM audit_events WHERE org_id = $1 AND type = $2`, org.ID, typ)
}

func TestInvite(t *testing.T) {
	t.Run("Invite - new email - invitation, invited row not listed, member.invited without subject id or email", func(t *testing.T) {
		s, db, _ := setup(t)
		s.Users = &fakeUsers{}
		org := seed(t, s)
		inv, err := s.Invite(t.Context(), org, admin, "ada@example.com", orgs.Member)
		if err != nil || inv.ID == "" || inv.Email != "ada@example.com" || inv.InvitedBy != admin {
			t.Fatalf("%+v %v", inv, err)
		}
		if _, err := s.MemberRole(t.Context(), org.ID, invitee); !errors.Is(err, orgs.ErrNotFound) {
			t.Fatalf("invited member has a role before sign-in: %v", err)
		}
		if events(t, db, orgs.MemberInvited) != 1 || auditRows(t, db, org, orgs.MemberInvited) != 1 {
			t.Fatal("event or audit row missing")
		}
		if n := count(t, db, `SELECT count(*) FROM synthwerk_outbox WHERE event::text LIKE '%ada@%' OR event::text LIKE '%`+invitee+`%'`); n != 0 {
			t.Fatalf("email or subject id in %d events", n)
		}
	})
	t.Run("Invite - admin invites owner - forbidden, Zitadel not called", func(t *testing.T) {
		s, _, _ := setup(t)
		u := &fakeUsers{}
		s.Users = u
		org := seed(t, s)
		if _, err := s.Invite(t.Context(), org, admin, "ada@example.com", orgs.Owner); !errors.Is(err, orgs.ErrForbidden) || len(u.calls) != 0 {
			t.Fatalf("%v %v", err, u.calls)
		}
	})
	t.Run("Invite - active or deactivated member - member_exists, nothing written", func(t *testing.T) {
		s, db, _ := setup(t)
		s.Users = &fakeUsers{}
		org := seed(t, s)
		if _, err := s.Invite(t.Context(), org, owner, "member@example.com", orgs.Member); !errors.Is(err, orgs.ErrMemberExists) {
			t.Fatal(err)
		}
		if _, _, err := s.SetStatus(t.Context(), org, owner, member, false); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Invite(t.Context(), org, owner, "member@example.com", orgs.Member); !errors.Is(err, orgs.ErrMemberExists) {
			t.Fatalf("deactivated: %v", err)
		}
		if events(t, db, orgs.MemberInvited) != 0 || count(t, db, `SELECT count(*) FROM invitations`) != 0 {
			t.Fatal("trace written")
		}
	})
	t.Run("Invite - user of this org without a membership - pending invitation without a user, like a foreign email", func(t *testing.T) {
		s, db, _ := setup(t)
		s.Users = &fakeUsers{}
		org := seed(t, s)
		if _, err := s.Invite(t.Context(), org, owner, "stranger@example.com", orgs.Member); err != nil {
			t.Fatal(err)
		}
		if count(t, db, `SELECT count(*) FROM invitations WHERE user_sub IS NULL`) != 1 || count(t, db, `SELECT count(*) FROM memberships WHERE user_sub = $1`, stranger) != 0 {
			t.Fatal("stranger got a row or a user")
		}
	})
	t.Run("Invite - repeat invite of a pending new and a pending foreign email - same invitation back, no Zitadel call, no event", func(t *testing.T) {
		s, db, _ := setup(t)
		u := &fakeUsers{}
		s.Users = u
		org := seed(t, s)
		for _, email := range []string{"ada@example.com", "foreign@example.com"} {
			first, err := s.Invite(t.Context(), org, owner, email, orgs.Member)
			if err != nil {
				t.Fatal(err)
			}
			calls := len(u.calls)
			again, err := s.Invite(t.Context(), org, admin, strings.ToUpper(email[:1])+email[1:], orgs.Admin)
			if err != nil || again.ID != first.ID || again.Role != orgs.Member || again.Email != email || len(u.calls) != calls {
				t.Fatalf("%s: %+v %v calls %v", email, again, err, u.calls)
			}
		}
		if events(t, db, orgs.MemberInvited) != 2 || count(t, db, `SELECT count(*) FROM invitations`) != 2 {
			t.Fatal("repeat invite wrote a trace")
		}
	})
	t.Run("Invite - no Zitadel client - upstream error", func(t *testing.T) {
		s, _, _ := setup(t)
		org := seed(t, s)
		if _, err := s.Invite(t.Context(), org, owner, "ada@example.com", orgs.Member); !errors.Is(err, orgs.ErrUpstream) {
			t.Fatal(err)
		}
	})
	t.Run("Invite - commit lost - Zitadel user deleted; commit error after commit - Zitadel user kept", func(t *testing.T) {
		s, db, _ := setup(t)
		org := seed(t, s)
		u := &fakeUsers{}
		s.Users = u
		s.DB = &flakyDB{Pool: db, mode: commitLost}
		if _, err := s.Invite(t.Context(), org, owner, "ada@example.com", orgs.Member); err == nil || !slices.Contains(u.calls, "uninvite/"+zorg+"/"+invitee) {
			t.Fatalf("lost: %v %v", err, u.calls)
		}
		u.calls = nil
		s.DB = &flakyDB{Pool: db, mode: commitAmbiguous}
		if _, err := s.Invite(t.Context(), org, owner, "ada@example.com", orgs.Member); err == nil || slices.Contains(u.calls, "uninvite/"+zorg+"/"+invitee) {
			t.Fatalf("ambiguous: %v %v", err, u.calls)
		}
	})
}

// commit modes of flakyDB.
const (
	commitLost      = "lost"      // the commit does not happen and fails
	commitAmbiguous = "ambiguous" // the commit happens, then fails
)

// flakyDB is the pool with a commit that fails.
type flakyDB struct {
	*pgxpool.Pool
	mode string
}

func (f *flakyDB) Begin(ctx context.Context) (pgx.Tx, error) {
	tx, err := f.Pool.Begin(ctx)
	return &flakyTx{Tx: tx, mode: f.mode}, err
}

type flakyTx struct {
	pgx.Tx
	mode string
}

func (t *flakyTx) Commit(ctx context.Context) error {
	if t.mode == commitAmbiguous {
		if err := t.Tx.Commit(ctx); err != nil {
			return err
		}
	} else {
		_ = t.Rollback(ctx)
	}
	return errors.New("connection reset during commit")
}

func TestCommitFailure(t *testing.T) {
	t.Run("Deactivate - commit lost - Zitadel grant stays deactivated, row still active", func(t *testing.T) {
		s, db, _ := setup(t)
		org := seed(t, s)
		u := &fakeUsers{}
		s.Users = u
		s.DB = &flakyDB{Pool: db, mode: commitLost}
		if _, _, err := s.SetStatus(t.Context(), org, owner, member, false); err == nil {
			t.Fatal("no error")
		}
		if len(u.calls) != 1 || !strings.HasSuffix(u.calls[0], "/off") {
			t.Fatalf("grant switched back: %v", u.calls)
		}
		s.DB = db
		if role(t, s, org, member) != orgs.Member {
			t.Fatal("row changed")
		}
		// A retry repairs the row; Zitadel answers the same state as a no-op.
		if _, changed, err := s.SetStatus(t.Context(), org, owner, member, false); err != nil || !changed {
			t.Fatalf("retry: %v", err)
		}
	})
	t.Run("Reactivate - commit lost - row still deactivated, Zitadel grant switched off again", func(t *testing.T) {
		s, db, _ := setup(t)
		org := seed(t, s)
		u := &fakeUsers{}
		s.Users = u
		if _, _, err := s.SetStatus(t.Context(), org, owner, member, false); err != nil {
			t.Fatal(err)
		}
		u.calls = nil
		s.DB = &flakyDB{Pool: db, mode: commitLost}
		if _, _, err := s.SetStatus(t.Context(), org, owner, member, true); err == nil {
			t.Fatal("no error")
		}
		if len(u.calls) != 2 || !strings.HasSuffix(u.calls[0], "/on") || !strings.HasSuffix(u.calls[1], "/off") {
			t.Fatalf("calls %v", u.calls)
		}
	})
	t.Run("Reactivate - commit error after the commit - row active, Zitadel grant not switched back", func(t *testing.T) {
		s, db, _ := setup(t)
		org := seed(t, s)
		u := &fakeUsers{}
		s.Users = u
		if _, _, err := s.SetStatus(t.Context(), org, owner, member, false); err != nil {
			t.Fatal(err)
		}
		u.calls = nil
		s.DB = &flakyDB{Pool: db, mode: commitAmbiguous}
		if _, _, err := s.SetStatus(t.Context(), org, owner, member, true); err == nil {
			t.Fatal("no error")
		}
		if len(u.calls) != 1 || !strings.HasSuffix(u.calls[0], "/on") {
			t.Fatalf("calls %v", u.calls)
		}
		s.DB = db
		if role(t, s, org, member) != orgs.Member {
			t.Fatal("row not active")
		}
	})
	t.Run("ChangeRole - upgrade, commit lost - Zitadel set back; downgrade, commit lost - Zitadel keeps the lower role", func(t *testing.T) {
		s, db, g := setup(t)
		org := seed(t, s)
		s.DB = &flakyDB{Pool: db, mode: commitLost}
		if _, _, err := s.ChangeRole(t.Context(), org, owner, member, orgs.Admin); err == nil {
			t.Fatal("no error")
		}
		if len(g.calls) != 2 || !strings.HasSuffix(g.calls[0], "/admin") || !strings.HasSuffix(g.calls[1], "/member") {
			t.Fatalf("upgrade calls %v", g.calls)
		}
		g.calls = nil
		if _, _, err := s.ChangeRole(t.Context(), org, owner, admin, orgs.Member); err == nil {
			t.Fatal("no error")
		}
		if len(g.calls) != 1 || !strings.HasSuffix(g.calls[0], "/member") {
			t.Fatalf("downgrade calls %v", g.calls)
		}
	})
	t.Run("ChangeRole - upgrade, commit error after the commit - Zitadel kept", func(t *testing.T) {
		s, db, g := setup(t)
		org := seed(t, s)
		s.DB = &flakyDB{Pool: db, mode: commitAmbiguous}
		if _, _, err := s.ChangeRole(t.Context(), org, owner, member, orgs.Admin); err == nil {
			t.Fatal("no error")
		}
		if len(g.calls) != 1 {
			t.Fatalf("calls %v", g.calls)
		}
	})
}

func TestSetStatus(t *testing.T) {
	t.Run("Deactivate - admin deactivates member - row kept with role, no stored role, event, audit, Zitadel grant off", func(t *testing.T) {
		s, db, _ := setup(t)
		u := &fakeUsers{}
		s.Users = u
		org := seed(t, s)
		m, changed, err := s.SetStatus(t.Context(), org, admin, member, false)
		if err != nil || !changed || m.Status != orgs.StatusDeactivated || m.Role != orgs.Member {
			t.Fatalf("%+v %v %v", m, changed, err)
		}
		if _, err := s.MemberRole(t.Context(), org.ID, member); !errors.Is(err, orgs.ErrNotFound) {
			t.Fatalf("deactivated member still has a role: %v", err)
		}
		if events(t, db, orgs.MemberDeactivated) != 1 || auditRows(t, db, org, orgs.MemberDeactivated) != 1 ||
			len(u.calls) != 1 || u.calls[0] != "active/"+zorg+"/"+member+"/g-"+zorg+"-"+member+"/off" {
			t.Fatalf("event, audit or Zitadel call missing: %v", u.calls)
		}
		if _, changed, _ := s.SetStatus(t.Context(), org, admin, member, false); changed || events(t, db, orgs.MemberDeactivated) != 1 {
			t.Fatal("second deactivate wrote again")
		}
		if _, changed, err := s.SetStatus(t.Context(), org, admin, member, true); err != nil || !changed || role(t, s, org, member) != orgs.Member {
			t.Fatalf("reactivate: %v", err)
		}
	})
	t.Run("Deactivate - last active owner by a second owner after the first is deactivated - last_owner", func(t *testing.T) {
		s, _, _ := setup(t)
		org := seed(t, s)
		grant(t, s, zorg, owner2, "owner")
		if _, _, err := s.SetStatus(t.Context(), org, owner, owner2, false); err != nil {
			t.Fatal(err)
		}
		// owner2 is deactivated: owner is the last active owner and cannot be demoted.
		if _, _, err := s.ChangeRole(t.Context(), org, owner, owner, orgs.Admin); !errors.Is(err, orgs.ErrOwnRole) {
			t.Fatalf("own role: %v", err)
		}
		if _, _, err := s.ChangeRole(t.Context(), org, owner2, owner, orgs.Admin); !errors.Is(err, orgs.ErrForbidden) {
			t.Fatalf("deactivated owner acts: %v", err)
		}
	})
	t.Run("Deactivate - own membership, admin on owner, Zitadel refuses - refused, nothing changes", func(t *testing.T) {
		s, db, _ := setup(t)
		s.Users = &fakeUsers{}
		org := seed(t, s)
		if _, _, err := s.SetStatus(t.Context(), org, admin, admin, false); !errors.Is(err, orgs.ErrOwnMembership) {
			t.Fatalf("own: %v", err)
		}
		if _, _, err := s.SetStatus(t.Context(), org, admin, owner, false); !errors.Is(err, orgs.ErrForbidden) {
			t.Fatalf("admin on owner: %v", err)
		}
		s.Users = &fakeUsers{err: errors.New("zitadel down")}
		if _, _, err := s.SetStatus(t.Context(), org, owner, member, false); !errors.Is(err, orgs.ErrUpstream) {
			t.Fatalf("upstream: %v", err)
		}
		if role(t, s, org, member) != orgs.Member || events(t, db, orgs.MemberDeactivated) != 0 || auditRows(t, db, org, orgs.MemberDeactivated) != 0 {
			t.Fatal("refused change left a trace")
		}
	})
	t.Run("Trigger - deactivate the only owner directly in SQL - commit refused", func(t *testing.T) {
		s, db, _ := setup(t)
		org := seed(t, s)
		_, err := db.Exec(t.Context(), `UPDATE memberships SET status = 'deactivated' WHERE org_id = $1 AND user_sub = $2`, org.ID, owner)
		if err == nil || !strings.Contains(err.Error(), "has no owner") {
			t.Fatalf("err %v", err)
		}
	})
}

// TestAuditHTTP is the done-looks-like of synthwerk#37: an admin changes a role;
// the change shows in the audit list.
func TestRevokeInvitation(t *testing.T) {
	t.Run("Revoke - new email - invitation revoked, invited row deleted, Zitadel user deleted, event and audit, never accepted", func(t *testing.T) {
		s, db, _ := setup(t)
		u := &fakeUsers{}
		s.Users = u
		org := seed(t, s)
		inv, err := s.Invite(t.Context(), org, owner, "ada@example.com", orgs.Member)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.RevokeInvitation(t.Context(), org, admin, inv.ID); err != nil {
			t.Fatal(err)
		}
		if !slices.Contains(u.calls, "uninvite/"+zorg+"/"+invitee) {
			t.Fatalf("calls %v", u.calls)
		}
		if list, _ := s.ListInvitations(t.Context(), org.ID, "", 10); len(list) != 0 {
			t.Fatalf("still pending: %+v", list)
		}
		if count(t, db, `SELECT count(*) FROM memberships WHERE user_sub = $1`, invitee) != 0 {
			t.Fatal("invited row kept")
		}
		if events(t, db, orgs.MemberInviteRevoked) != 1 || auditRows(t, db, org, orgs.MemberInviteRevoked) != 1 {
			t.Fatal("event or audit row missing")
		}
		if err := s.AcceptInvite(t.Context(), org.ID, invitee); err != nil {
			t.Fatal(err)
		}
		if _, err := s.MemberRole(t.Context(), org.ID, invitee); !errors.Is(err, orgs.ErrNotFound) {
			t.Fatalf("revoked invitee has a role: %v", err)
		}
		if err := s.RevokeInvitation(t.Context(), org, admin, inv.ID); !errors.Is(err, orgs.ErrNotFound) {
			t.Fatalf("second revoke: %v", err)
		}
		if again, err := s.Invite(t.Context(), org, owner, "ada@example.com", orgs.Member); err != nil || again.ID == inv.ID {
			t.Fatalf("invite after revoke: %+v %v", again, err)
		}
	})
	t.Run("Revoke - invitee is now an active owner - admin forbidden; owner revokes the invitation only, row and Zitadel user kept", func(t *testing.T) {
		s, db, _ := setup(t)
		u := &fakeUsers{}
		s.Users = u
		org := seed(t, s)
		inv, err := s.Invite(t.Context(), org, owner, "ada@example.com", orgs.Member)
		if err != nil {
			t.Fatal(err)
		}
		// The invitee joined by another path and became an owner.
		if _, err := db.Exec(t.Context(), `UPDATE memberships SET status = 'active', role = 'owner' WHERE org_id = $1 AND user_sub = $2`, org.ID, invitee); err != nil {
			t.Fatal(err)
		}
		calls := len(u.calls)
		if err := s.RevokeInvitation(t.Context(), org, admin, inv.ID); !errors.Is(err, orgs.ErrForbidden) {
			t.Fatalf("admin: %v", err)
		}
		if err := s.RevokeInvitation(t.Context(), org, owner, inv.ID); err != nil {
			t.Fatal(err)
		}
		if len(u.calls) != calls {
			t.Fatalf("Zitadel touched: %v", u.calls[calls:])
		}
		if role, err := s.MemberRole(t.Context(), org.ID, invitee); err != nil || role != orgs.Owner {
			t.Fatalf("membership changed: %v %v", role, err)
		}
		if count(t, db, `SELECT count(*) FROM invitations WHERE id = $1 AND revoked_at IS NOT NULL`, inv.ID) != 1 || events(t, db, orgs.MemberInviteRevoked) != 1 {
			t.Fatal("invitation not revoked")
		}
	})
	t.Run("Revoke - unknown id - member forbidden, admin not found", func(t *testing.T) {
		s, _, _ := setup(t)
		s.Users = &fakeUsers{}
		org := seed(t, s)
		unknown := "019a3c1e-7a1b-7c2d-8e3f-4a5b6c7d8e01"
		if err := s.RevokeInvitation(t.Context(), org, member, unknown); !errors.Is(err, orgs.ErrForbidden) {
			t.Fatalf("member: %v", err)
		}
		if err := s.RevokeInvitation(t.Context(), org, admin, unknown); !errors.Is(err, orgs.ErrNotFound) {
			t.Fatalf("admin: %v", err)
		}
	})
	t.Run("Revoke - invited row left over, invitation revoked - AcceptInvite does not activate it", func(t *testing.T) {
		s, db, _ := setup(t)
		s.Users = &fakeUsers{}
		org := seed(t, s)
		inv, err := s.Invite(t.Context(), org, owner, "ada@example.com", orgs.Member)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(t.Context(), `UPDATE invitations SET revoked_at = now() WHERE id = $1`, inv.ID); err != nil {
			t.Fatal(err)
		}
		if err := s.AcceptInvite(t.Context(), org.ID, invitee); err != nil {
			t.Fatal(err)
		}
		if count(t, db, `SELECT count(*) FROM memberships WHERE user_sub = $1 AND status = 'invited'`, invitee) != 1 {
			t.Fatal("revoked invitation accepted")
		}
	})
	t.Run("Revoke - foreign email - no Zitadel call, event", func(t *testing.T) {
		s, db, _ := setup(t)
		u := &fakeUsers{}
		s.Users = u
		org := seed(t, s)
		inv, err := s.Invite(t.Context(), org, owner, "foreign@example.com", orgs.Member)
		if err != nil {
			t.Fatal(err)
		}
		calls := len(u.calls)
		if err := s.RevokeInvitation(t.Context(), org, owner, inv.ID); err != nil || len(u.calls) != calls {
			t.Fatalf("%v %v", err, u.calls)
		}
		if events(t, db, orgs.MemberInviteRevoked) != 1 {
			t.Fatal("no event")
		}
	})
	t.Run("Revoke - admin on an owner invitation, member, deactivated admin - forbidden, still pending", func(t *testing.T) {
		s, db, _ := setup(t)
		s.Users = &fakeUsers{}
		org := seed(t, s)
		inv, err := s.Invite(t.Context(), org, owner, "foreign-owner@example.com", orgs.Owner)
		if err != nil {
			t.Fatal(err)
		}
		mem, err := s.Invite(t.Context(), org, owner, "foreign-mem@example.com", orgs.Member)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.RevokeInvitation(t.Context(), org, admin, inv.ID); !errors.Is(err, orgs.ErrForbidden) {
			t.Fatalf("admin on owner: %v", err)
		}
		if err := s.RevokeInvitation(t.Context(), org, member, mem.ID); !errors.Is(err, orgs.ErrForbidden) {
			t.Fatalf("member: %v", err)
		}
		if _, _, err := s.SetStatus(t.Context(), org, owner, admin, false); err != nil {
			t.Fatal(err)
		}
		if err := s.RevokeInvitation(t.Context(), org, admin, mem.ID); !errors.Is(err, orgs.ErrForbidden) {
			t.Fatalf("deactivated admin: %v", err)
		}
		if err := s.RevokeInvitation(t.Context(), org, owner, "019a3c1e-7a1b-7c2d-8e3f-4a5b6c7d8e00"); !errors.Is(err, orgs.ErrNotFound) {
			t.Fatalf("unknown: %v", err)
		}
		if events(t, db, orgs.MemberInviteRevoked) != 0 || count(t, db, `SELECT count(*) FROM invitations WHERE revoked_at IS NULL`) != 2 {
			t.Fatal("revoked")
		}
	})
	t.Run("Revoke - Zitadel refuses - upstream error, invitation and invited row kept, no event", func(t *testing.T) {
		s, db, _ := setup(t)
		s.Users = &fakeUsers{uninviteErr: errors.New("zitadel 403")}
		org := seed(t, s)
		inv, err := s.Invite(t.Context(), org, owner, "ada@example.com", orgs.Member)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.RevokeInvitation(t.Context(), org, owner, inv.ID); !errors.Is(err, orgs.ErrUpstream) {
			t.Fatal(err)
		}
		if events(t, db, orgs.MemberInviteRevoked) != 0 || count(t, db, `SELECT count(*) FROM invitations WHERE revoked_at IS NULL`) != 1 ||
			count(t, db, `SELECT count(*) FROM memberships WHERE user_sub = $1`, invitee) != 1 {
			t.Fatal("partial revoke")
		}
	})
}

func TestAuditHTTP(t *testing.T) {
	s, _, _ := setup(t)
	s.Users = &fakeUsers{}
	org := seed(t, s)
	iss := authtest.NewIssuer(t)
	cfg := iss.Config()
	cfg.Mapper = auth.ZitadelMapper{PlatformOrgID: platform}
	v, err := auth.NewVerifier(cfg)
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.DiscardHandler)
	oh := &orgs.Handler{Repo: s, Members: s, Log: logger}
	a, err := app.New(s.DB.(*pgxpool.Pool), logger, app.Config{Version: "0.1.0-dev", Commit: "0000000", Env: "ci",
		Verifier: v, Orgs: oh, Audit: &audit.Handler{Repo: &audit.Store{DB: s.DB.(*pgxpool.Pool)}, Orgs: oh}})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(a.Handler())
	t.Cleanup(srv.Close)
	base := srv.URL + "/v1/orgs/" + org.ID
	adminTok := iss.Mint(t, authtest.Claims(admin, zorg, "admin"))

	t.Run("Audit - admin changes a role - change is the newest audit event with actor and old and new role", func(t *testing.T) {
		if code, body := call(t, http.MethodPatch, base+"/members/"+member, adminTok, `{"role":"admin"}`); code != http.StatusOK {
			t.Fatalf("PATCH %d %s", code, body)
		}
		code, body := call(t, http.MethodGet, base+"/audit-events?limit=1", adminTok, "")
		var page identity.AuditEventPage
		if code != http.StatusOK || json.Unmarshal([]byte(body), &page) != nil || len(page.Items) != 1 || page.NextCursor == nil {
			t.Fatalf("%d %s", code, body)
		}
		e := page.Items[0]
		if e.Type != orgs.RoleChanged || e.Actor != "user:"+admin || e.Subject == nil || *e.Subject != member ||
			e.Data["old_role"] != "member" || e.Data["new_role"] != "admin" {
			t.Fatalf("got %+v", e)
		}
		// The next page holds the older events, down to org.created.
		code, body = call(t, http.MethodGet, base+"/audit-events?cursor="+*page.NextCursor, adminTok, "")
		if code != http.StatusOK || !strings.Contains(body, orgs.OrgCreated) || strings.Contains(body, `"new_role":"admin"`) {
			t.Fatalf("%d %s", code, body)
		}
	})
	t.Run("Audit - member token - 403", func(t *testing.T) {
		if code, _ := call(t, http.MethodGet, base+"/audit-events", iss.Mint(t, authtest.Claims(member, zorg, "member")), ""); code != http.StatusForbidden {
			t.Fatalf("member: %d", code)
		}
	})
	t.Run("Invite - new email and user of another org - same answer, same members list, same invitation, same audit event", func(t *testing.T) {
		ownerTok := iss.Mint(t, authtest.Claims(owner, zorg, "owner"))
		_, membersBefore := call(t, http.MethodGet, base+"/members", ownerTok, "")
		var answers [2]map[string]any
		for i, email := range []string{"new@example.com", "foreign@example.com"} {
			code, body := call(t, http.MethodPost, base+"/members", ownerTok, `{"email":"`+email+`","role":"member"}`)
			if code != http.StatusAccepted || json.Unmarshal([]byte(body), &answers[i]) != nil {
				t.Fatalf("%s: %d %s", email, code, body)
			}
		}
		if shape(answers[0], "email", "id", "created_at") != shape(answers[1], "email", "id", "created_at") {
			t.Fatalf("answers differ: %v / %v", answers[0], answers[1])
		}
		if _, membersAfter := call(t, http.MethodGet, base+"/members", ownerTok, ""); membersAfter != membersBefore {
			t.Fatalf("members list changed:\n%s\n%s", membersBefore, membersAfter)
		}
		_, body := call(t, http.MethodGet, base+"/invitations", ownerTok, "")
		var invs identity.InvitationPage
		if json.Unmarshal([]byte(body), &invs) != nil || len(invs.Items) != 2 {
			t.Fatalf("invitations %s", body)
		}
		_, body = call(t, http.MethodGet, base+"/audit-events?limit=2", ownerTok, "")
		var page identity.AuditEventPage
		if json.Unmarshal([]byte(body), &page) != nil || len(page.Items) != 2 {
			t.Fatalf("audit %s", body)
		}
		for _, e := range page.Items {
			if e.Type != orgs.MemberInvited || len(e.Data) != 3 || e.Data["role"] != "member" || e.Data["invitation_id"] != *e.Subject {
				t.Fatalf("audit item %+v", e)
			}
		}
	})
	t.Run("Invite - invitee signs in and calls the org - active, listed, invitation no longer pending", func(t *testing.T) {
		ownerTok := iss.Mint(t, authtest.Claims(owner, zorg, "owner"))
		if code, _ := call(t, http.MethodGet, base, iss.Mint(t, authtest.Claims(invitee, zorg, "member")), ""); code != http.StatusOK {
			t.Fatalf("invitee GET org: %d", code)
		}
		if _, body := call(t, http.MethodGet, base+"/members", ownerTok, ""); !strings.Contains(body, invitee) {
			t.Fatalf("invitee not listed: %s", body)
		}
		_, body := call(t, http.MethodGet, base+"/invitations", ownerTok, "")
		if strings.Contains(body, "new@example.com") || !strings.Contains(body, "foreign@example.com") {
			t.Fatalf("invitations %s", body)
		}
		if code, body := call(t, http.MethodPost, base+"/members/"+invitee+":deactivate", ownerTok, ""); code != http.StatusOK || !strings.Contains(body, `"deactivated"`) {
			t.Fatalf("deactivate %d %s", code, body)
		}
	})
	t.Run("Revoke - admin revokes the pending invitation - 204, gone from the list, newest audit event", func(t *testing.T) {
		_, body := call(t, http.MethodGet, base+"/invitations", adminTok, "")
		var invs identity.InvitationPage
		if json.Unmarshal([]byte(body), &invs) != nil || len(invs.Items) != 1 {
			t.Fatalf("invitations %s", body)
		}
		id := invs.Items[0].Id.String()
		if code, body := call(t, http.MethodDelete, base+"/invitations/"+id, adminTok, ""); code != http.StatusNoContent {
			t.Fatalf("DELETE %d %s", code, body)
		}
		if _, body := call(t, http.MethodGet, base+"/invitations", adminTok, ""); strings.Contains(body, id) {
			t.Fatalf("still listed: %s", body)
		}
		_, body = call(t, http.MethodGet, base+"/audit-events?limit=1", adminTok, "")
		var page identity.AuditEventPage
		if json.Unmarshal([]byte(body), &page) != nil || len(page.Items) != 1 || page.Items[0].Type != orgs.MemberInviteRevoked ||
			page.Items[0].Actor != "user:"+admin || *page.Items[0].Subject != id {
			t.Fatalf("audit %s", body)
		}
		if code, _ := call(t, http.MethodDelete, base+"/invitations/"+id, adminTok, ""); code != http.StatusNotFound {
			t.Fatalf("second DELETE %d", code)
		}
	})
}

// shape is m without the keys that differ per invitation, as a string.
func shape(m map[string]any, skip ...string) string {
	out := map[string]any{}
	for k, v := range m {
		if !slices.Contains(skip, k) {
			out[k] = v
		}
	}
	b, _ := json.Marshal(out)
	return string(b)
}

func TestMigrateAgain(t *testing.T) {
	t.Run("Migrate - second start - no error, audit backfill adds no duplicate, owner guard counts active owners", func(t *testing.T) {
		s, db, _ := setup(t)
		org := seed(t, s)
		before := count(t, db, `SELECT count(*) FROM audit_events WHERE org_id = $1`, org.ID)
		if before == 0 {
			t.Fatal("org.created not in the audit list")
		}
		if err := app.Migrate(t.Context(), db); err != nil {
			t.Fatal(err)
		}
		if after := count(t, db, `SELECT count(*) FROM audit_events WHERE org_id = $1`, org.ID); after != before {
			t.Fatalf("audit rows %d, want %d", after, before)
		}
		_, err := db.Exec(t.Context(), `UPDATE memberships SET status = 'deactivated' WHERE org_id = $1 AND user_sub = $2`, org.ID, owner)
		if err == nil {
			t.Fatal("0003 replaced the active-owner guard of 0009")
		}
	})
}

func TestBackfillBadRow(t *testing.T) {
	t.Run("Migrate - outbox row with a bad time - skipped with a warning, start not blocked", func(t *testing.T) {
		s, db, _ := setup(t)
		org := seed(t, s)
		if _, err := db.Exec(t.Context(), `ALTER TABLE synthwerk_outbox DISABLE TRIGGER outbox_to_audit`); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(t.Context(), `INSERT INTO synthwerk_outbox (id, nats_subject, event) VALUES ($1, 'evt.identity.x.y.v1', $2)`,
			"019a3c1f-0000-7000-8000-000000000001",
			`{"type":"dev.synthwerk.identity.x.y.v1","orgid":"`+org.ID+`","time":"2026-13-45T99:00:00Z","data":{}}`); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(t.Context(), `ALTER TABLE synthwerk_outbox ENABLE TRIGGER outbox_to_audit`); err != nil {
			t.Fatal(err)
		}
		if err := app.Migrate(t.Context(), db); err != nil {
			t.Fatalf("migrate blocked: %v", err)
		}
	})
}
