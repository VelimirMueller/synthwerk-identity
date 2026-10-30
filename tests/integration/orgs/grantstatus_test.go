//go:build integration

package orgs_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/VelimirMueller/synthwerk-identity/internal/orgs"
)

// fakeStates is orgs.GrantStates: active is the grant state Zitadel reports.
type fakeStates struct {
	mu     sync.Mutex
	active bool
	err    error
	calls  []string
}

func (f *fakeStates) GrantActive(_ context.Context, zid, sub, grantID string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, zid+"/"+sub+"/"+grantID)
	return f.active, f.err
}

var statusSeq int

// grantStatus mirrors one Zitadel user.grant.deactivated (active false) or
// user.grant.reactivated event for the grant of sub in the test org, with a new key.
func grantStatus(t *testing.T, s *orgs.Store, sub string, active bool) orgs.Outcome {
	t.Helper()
	statusSeq++
	out, err := s.ApplyGrantStatus(t.Context(), orgs.GrantStatusChange{
		Key: fmt.Sprintf("i:usergrant:status-%s:%d", sub, statusSeq), ZitadelOrgID: zorg, GrantID: "g-" + zorg + "-" + sub, Active: active,
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func memberStatus(t *testing.T, db *pgxpool.Pool, org orgs.Org, sub string) string {
	t.Helper()
	var st string
	if err := db.QueryRow(t.Context(), `SELECT status FROM memberships WHERE org_id = $1 AND user_sub = $2`, org.ID, sub).Scan(&st); err != nil {
		t.Fatal(err)
	}
	return st
}

func TestApplyGrantStatus(t *testing.T) {
	t.Run("Deactivated in Zitadel - member deactivated, no stored role, event and audit by system; repeat and echo write nothing", func(t *testing.T) {
		s, db, _ := setup(t)
		org := seed(t, s)
		if out := grantStatus(t, s, member, false); out != orgs.OutcomeDeactivated {
			t.Fatalf("outcome %s", out)
		}
		if st := memberStatus(t, db, org, member); st != orgs.StatusDeactivated {
			t.Fatalf("status %s", st)
		}
		if _, err := s.MemberRole(t.Context(), org.ID, member); !errors.Is(err, orgs.ErrNotFound) {
			t.Fatalf("deactivated member keeps a role: %v", err)
		}
		if n := count(t, db, `SELECT count(*) FROM audit_events WHERE org_id = $1 AND type = $2 AND actor = 'system' AND subject = $3`,
			org.ID, orgs.MemberDeactivated, member); n != 1 {
			t.Fatalf("audit rows %d", n)
		}
		// The same event again (same key) and a second deactivate event: no change.
		key := fmt.Sprintf("i:usergrant:status-%s:%d", member, statusSeq)
		out, err := s.ApplyGrantStatus(t.Context(), orgs.GrantStatusChange{Key: key, ZitadelOrgID: zorg, GrantID: "g-" + zorg + "-" + member})
		if err != nil || out != orgs.OutcomeDuplicate {
			t.Fatalf("repeat: %s %v", out, err)
		}
		if out := grantStatus(t, s, member, false); out != orgs.OutcomeUnchanged {
			t.Fatalf("second deactivate: %s", out)
		}
		if events(t, db, orgs.MemberDeactivated) != 1 {
			t.Fatal("more than one member.deactivated")
		}
	})
	t.Run("Reactivated in Zitadel - Zitadel confirms - member active again, event and audit by system", func(t *testing.T) {
		s, db, _ := setup(t)
		states := &fakeStates{active: true}
		s.GrantStates = states
		org := seed(t, s)
		grantStatus(t, s, member, false)
		if out := grantStatus(t, s, member, true); out != orgs.OutcomeReactivated {
			t.Fatalf("outcome %s", out)
		}
		if st := memberStatus(t, db, org, member); st != orgs.StatusActive {
			t.Fatalf("status %s", st)
		}
		if role(t, s, org, member) != orgs.Member {
			t.Fatal("role lost")
		}
		if len(states.calls) != 1 || states.calls[0] != zorg+"/"+member+"/g-"+zorg+"-"+member {
			t.Fatalf("state reads %v", states.calls)
		}
		if auditRows(t, db, org, orgs.MemberReactivated) != 1 {
			t.Fatal("audit row missing")
		}
	})
	t.Run("Reactivated - Zitadel says inactive, or no GrantStates - unconfirmed, member stays deactivated, no event", func(t *testing.T) {
		s, db, _ := setup(t)
		org := seed(t, s)
		grantStatus(t, s, member, false)
		if out := grantStatus(t, s, member, true); out != orgs.OutcomeUnconfirmed {
			t.Fatalf("no GrantStates: %s", out)
		}
		s.GrantStates = &fakeStates{active: false}
		if out := grantStatus(t, s, member, true); out != orgs.OutcomeUnconfirmed {
			t.Fatalf("inactive: %s", out)
		}
		if st := memberStatus(t, db, org, member); st != orgs.StatusDeactivated || events(t, db, orgs.MemberReactivated) != 0 {
			t.Fatalf("status %s", st)
		}
	})
	t.Run("Reactivated - grant state not readable - error, rolled back, the event is not marked seen", func(t *testing.T) {
		s, db, _ := setup(t)
		states := &fakeStates{err: errors.New("zitadel down")}
		s.GrantStates = states
		org := seed(t, s)
		grantStatus(t, s, member, false)
		c := orgs.GrantStatusChange{Key: "i:usergrant:retry:1", ZitadelOrgID: zorg, GrantID: "g-" + zorg + "-" + member, Active: true}
		if _, err := s.ApplyGrantStatus(t.Context(), c); err == nil {
			t.Fatal("no error")
		}
		if memberStatus(t, db, org, member) != orgs.StatusDeactivated {
			t.Fatal("reactivated without confirmation")
		}
		states.err, states.active = nil, true
		if out, err := s.ApplyGrantStatus(t.Context(), c); err != nil || out != orgs.OutcomeReactivated {
			t.Fatalf("retry: %s %v", out, err)
		}
	})
	t.Run("Reactivated - member is active already (echo of an identity reactivate) - unchanged, Zitadel not read", func(t *testing.T) {
		s, db, _ := setup(t)
		states := &fakeStates{active: true}
		s.GrantStates = states
		org := seed(t, s)
		if out := grantStatus(t, s, member, true); out != orgs.OutcomeUnchanged || len(states.calls) != 0 {
			t.Fatalf("%s %v", out, states.calls)
		}
		if events(t, db, orgs.MemberReactivated) != 0 || memberStatus(t, db, org, member) != orgs.StatusActive {
			t.Fatal("changed")
		}
	})
	t.Run("Deactivated - echo of an identity deactivate - unchanged, one event only", func(t *testing.T) {
		s, db, _ := setup(t)
		s.Users = &fakeUsers{}
		org := seed(t, s)
		if _, _, err := s.SetStatus(t.Context(), org, admin, member, false); err != nil {
			t.Fatal(err)
		}
		if out := grantStatus(t, s, member, false); out != orgs.OutcomeUnchanged {
			t.Fatalf("outcome %s", out)
		}
		if events(t, db, orgs.MemberDeactivated) != 1 {
			t.Fatal("echo wrote an event")
		}
	})
	t.Run("Deactivated - last active owner - kept active, no event", func(t *testing.T) {
		s, db, _ := setup(t)
		org := seed(t, s)
		if out := grantStatus(t, s, owner, false); out != orgs.OutcomeLastOwner {
			t.Fatalf("outcome %s", out)
		}
		if memberStatus(t, db, org, owner) != orgs.StatusActive || events(t, db, orgs.MemberDeactivated) != 0 {
			t.Fatal("last owner deactivated")
		}
	})
	t.Run("Deactivated - second owner exists - owner deactivated", func(t *testing.T) {
		s, db, _ := setup(t)
		org := seed(t, s)
		grant(t, s, zorg, owner2, "owner")
		if out := grantStatus(t, s, owner, false); out != orgs.OutcomeDeactivated {
			t.Fatalf("outcome %s", out)
		}
		if memberStatus(t, db, org, owner) != orgs.StatusDeactivated {
			t.Fatal("owner still active")
		}
	})
	t.Run("Unknown grant, grant of another org, unknown org - ignored", func(t *testing.T) {
		s, db, _ := setup(t)
		s.GrantStates = &fakeStates{active: true}
		org := seed(t, s)
		for _, c := range []orgs.GrantStatusChange{
			{Key: "i:usergrant:x:1", ZitadelOrgID: zorg, GrantID: "g-unknown"},
			{Key: "i:usergrant:x:2", ZitadelOrgID: otherOrg, GrantID: "g-" + zorg + "-" + member},
			{Key: "i:usergrant:x:3", ZitadelOrgID: "300000000000000077", GrantID: "g-" + zorg + "-" + member, Active: true},
		} {
			if out, err := s.ApplyGrantStatus(t.Context(), c); err != nil || out != orgs.OutcomeIgnored {
				t.Fatalf("%+v: %s %v", c, out, err)
			}
		}
		if memberStatus(t, db, org, member) != orgs.StatusActive {
			t.Fatal("member changed")
		}
	})
	t.Run("Invited member - deactivate and reactivate - unchanged, stays invited", func(t *testing.T) {
		s, db, _ := setup(t)
		s.Users = &fakeUsers{}
		s.GrantStates = &fakeStates{active: true}
		org := seed(t, s)
		if _, err := s.Invite(t.Context(), org, admin, "ada@example.com", orgs.Member); err != nil {
			t.Fatal(err)
		}
		for _, active := range []bool{false, true} {
			statusSeq++
			out, err := s.ApplyGrantStatus(t.Context(), orgs.GrantStatusChange{
				Key: fmt.Sprintf("i:usergrant:inv:%d", statusSeq), ZitadelOrgID: zorg, GrantID: "g-invite", Active: active,
			})
			if err != nil || out != orgs.OutcomeUnchanged {
				t.Fatalf("active %v: %s %v", active, out, err)
			}
		}
		if memberStatus(t, db, org, invitee) != orgs.StatusInvited {
			t.Fatal("invited row changed")
		}
	})
	t.Run("Deleted account - ignored", func(t *testing.T) {
		s, db, _ := setup(t)
		org := seed(t, s)
		if _, err := db.Exec(t.Context(), `INSERT INTO account_deletions (user_sub_hash, user_sub) VALUES (sha256(convert_to($1, 'UTF8')), $1)`, member); err != nil {
			t.Fatal(err)
		}
		if out := grantStatus(t, s, member, false); out != orgs.OutcomeIgnored {
			t.Fatalf("outcome %s", out)
		}
		if memberStatus(t, db, org, member) != orgs.StatusActive {
			t.Fatal("member changed")
		}
	})
}
