//go:build integration

package account_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/VelimirMueller/synthwerk-identity/internal/account"
	"github.com/VelimirMueller/synthwerk-identity/internal/app"
	"github.com/VelimirMueller/synthwerk-identity/internal/entitlements"
	"github.com/VelimirMueller/synthwerk-identity/internal/mfagate"
	"github.com/VelimirMueller/synthwerk-identity/internal/orgs"
	"github.com/VelimirMueller/synthwerk-identity/tests/support/containers"
)

var env *containers.Env

func TestMain(m *testing.M) {
	e, err := containers.Start(context.Background())
	if err != nil {
		fmt.Fprintln(os.Stderr, "containers:", err)
		os.Exit(1)
	}
	env = e
	code := m.Run()
	e.Stop()
	os.Exit(code)
}

const (
	zorg   = "300000000000000001" // alice (owner) + bob (member)
	zsolo  = "300000000000000002" // alice alone
	zshare = "300000000000000003" // alice and carol both owners
	alice  = "100000000000000001"
	bob    = "100000000000000002"
	carol  = "100000000000000003"
	source = "/synthwerk/identity/dev"
)

type fixture struct {
	db    *pgxpool.Pool
	orgs  *orgs.Store
	store *account.Store
}

func setup(t *testing.T) fixture {
	t.Helper()
	db := env.Database(t)
	if err := app.Migrate(t.Context(), db); err != nil {
		t.Fatal(err)
	}
	plans := &entitlements.Store{DB: db, Source: source, Default: entitlements.Plan{Name: entitlements.Free, Limits: entitlements.FreeDefaults}}
	return fixture{db: db, orgs: &orgs.Store{DB: db, Source: source, Plans: plans}, store: &account.Store{DB: db, Source: source}}
}

var (
	seqMu sync.Mutex
	seq   int
)

func grant(t *testing.T, s *orgs.Store, zid, sub string, roles ...string) orgs.Outcome {
	t.Helper()
	seqMu.Lock()
	seq++
	n := seq
	seqMu.Unlock()
	out, err := s.ApplyGrant(t.Context(), orgs.GrantChange{
		Key: fmt.Sprintf("i:usergrant:g-%s:%d", sub, n), ZitadelOrgID: zid, GrantID: "g-" + zid + "-" + sub, UserSub: sub, Roles: roles,
	}, "Org "+zid)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func org(t *testing.T, f fixture, zid string) orgs.Org {
	t.Helper()
	o, err := f.orgs.OrgByZitadelID(t.Context(), zid)
	if err != nil {
		t.Fatal(err)
	}
	return o
}

func count(t *testing.T, db *pgxpool.Pool, sql string, args ...any) int {
	t.Helper()
	var n int
	if err := db.QueryRow(t.Context(), sql, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func deletedEvents(t *testing.T, db *pgxpool.Pool) []account.UserDeletedData {
	t.Helper()
	rows, err := db.Query(t.Context(), `SELECT event->'data', event->>'subject', event->>'actor', coalesce(event->>'orgid', '')
		FROM synthwerk_outbox WHERE event->>'type' = $1 ORDER BY created_at, id`, account.UserDeleted)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []account.UserDeletedData
	for rows.Next() {
		var raw []byte
		var subject, actor, orgid string
		if err := rows.Scan(&raw, &subject, &actor, &orgid); err != nil {
			t.Fatal(err)
		}
		var d account.UserDeletedData
		if err := json.Unmarshal(raw, &d); err != nil {
			t.Fatal(err)
		}
		if subject != d.UserSub || actor != "user:"+d.UserSub || orgid != "" {
			t.Fatalf("envelope subject %q actor %q orgid %q", subject, actor, orgid)
		}
		out = append(out, d)
	}
	return out
}

func TestDelete(t *testing.T) {
	t.Run("Delete - member of a shared org, only member of another - rows gone, solo org closed, one event", func(t *testing.T) {
		f := setup(t)
		grant(t, f.orgs, zorg, bob, "owner")
		grant(t, f.orgs, zorg, alice, "member")
		grant(t, f.orgs, zsolo, alice, "owner")
		solo := org(t, f, zsolo)
		ctx := t.Context()
		if _, err := f.db.Exec(ctx, `INSERT INTO apps (id, org_id, name, allowed_origins) VALUES (gen_random_uuid(), $1, 'Shop', ARRAY['https://shop.example'])`, solo.ID); err != nil {
			t.Fatal(err)
		}
		if err := (mfagate.Postgres{DB: f.db}).Record(ctx, mfagate.Evidence{UserSub: alice, SessionID: "s", AMR: []string{"mfa"}, CheckedAt: time.Now()}); err != nil {
			t.Fatal(err)
		}
		if _, err := f.db.Exec(ctx, `INSERT INTO zitadel_event_seen (event_key) VALUES ($1), ($2)`, "i:user:"+alice+":7", "i:user:"+bob+":8"); err != nil {
			t.Fatal(err)
		}

		d, err := f.store.Delete(ctx, alice)
		if err != nil {
			t.Fatal(err)
		}
		if d.Repeat || len(d.DeletedOrgs) != 1 || d.DeletedOrgs[0].ID != solo.ID || d.DeletedOrgs[0].ZitadelOrgID != zsolo {
			t.Fatalf("got %+v", d)
		}
		for what, n := range map[string]int{
			"memberships of alice": count(t, f.db, `SELECT count(*) FROM memberships WHERE user_sub = $1`, alice),
			"solo org":             count(t, f.db, `SELECT count(*) FROM orgs WHERE id = $1`, solo.ID),
			"apps of solo org":     count(t, f.db, `SELECT count(*) FROM apps WHERE org_id = $1`, solo.ID),
			"plan of solo org":     count(t, f.db, `SELECT count(*) FROM org_entitlements WHERE org_id = $1`, solo.ID),
			"evidence of alice":    count(t, f.db, `SELECT count(*) FROM mfa_evidence WHERE user_sub = $1`, alice),
			"seen keys of alice":   count(t, f.db, `SELECT count(*) FROM zitadel_event_seen WHERE event_key = $1`, "i:user:"+alice+":7"),
		} {
			if n != 0 {
				t.Errorf("%s: %d rows left", what, n)
			}
		}
		if count(t, f.db, `SELECT count(*) FROM memberships WHERE user_sub = $1`, bob) != 1 ||
			count(t, f.db, `SELECT count(*) FROM zitadel_event_seen WHERE event_key = $1`, "i:user:"+bob+":8") != 1 {
			t.Fatal("rows of bob changed")
		}
		evs := deletedEvents(t, f.db)
		if len(evs) != 1 || evs[0].UserSub != alice || len(evs[0].DeletedOrgs) != 1 || evs[0].DeletedOrgs[0].ZitadelOrgID != zsolo {
			t.Fatalf("events %+v", evs)
		}
		if got, ok, err := f.store.Deleted(ctx, alice); err != nil || !ok || !got.RequestedAt.Equal(d.RequestedAt) {
			t.Fatalf("Deleted: %+v %v %v", got, ok, err)
		}
	})

	t.Run("Delete - repeat - first time back, Repeat true, no second event", func(t *testing.T) {
		f := setup(t)
		grant(t, f.orgs, zsolo, alice, "owner")
		first, err := f.store.Delete(t.Context(), alice)
		if err != nil {
			t.Fatal(err)
		}
		again, err := f.store.Delete(t.Context(), alice)
		if err != nil || !again.Repeat || !again.RequestedAt.Equal(first.RequestedAt) || len(again.DeletedOrgs) != 0 {
			t.Fatalf("got %+v, %v", again, err)
		}
		if n := len(deletedEvents(t, f.db)); n != 1 {
			t.Fatalf("%d events", n)
		}
	})

	t.Run("Delete - only owner of an org with a member - ErrLastOwner naming the org, nothing changed", func(t *testing.T) {
		f := setup(t)
		grant(t, f.orgs, zorg, alice, "owner")
		grant(t, f.orgs, zorg, bob, "member")
		grant(t, f.orgs, zsolo, alice, "owner")
		_, err := f.store.Delete(t.Context(), alice)
		var lo *account.LastOwnerError
		if !errors.As(err, &lo) || !errors.Is(err, account.ErrLastOwner) || len(lo.OrgIDs) != 1 || lo.OrgIDs[0] != org(t, f, zorg).ID {
			t.Fatalf("err %v", err)
		}
		if count(t, f.db, `SELECT count(*) FROM memberships WHERE user_sub = $1`, alice) != 2 ||
			count(t, f.db, `SELECT count(*) FROM account_deletions`) != 0 || len(deletedEvents(t, f.db)) != 0 {
			t.Fatal("rows changed")
		}
	})

	t.Run("Delete - one of two owners - membership gone, org keeps the other owner", func(t *testing.T) {
		f := setup(t)
		grant(t, f.orgs, zshare, alice, "owner")
		grant(t, f.orgs, zshare, carol, "owner")
		d, err := f.store.Delete(t.Context(), alice)
		if err != nil || len(d.DeletedOrgs) != 0 {
			t.Fatalf("got %+v, %v", d, err)
		}
		if count(t, f.db, `SELECT count(*) FROM memberships WHERE org_id = $1 AND role = 'owner'`, org(t, f, zshare).ID) != 1 {
			t.Fatal("owner count")
		}
	})

	t.Run("Delete - two owners delete at the same time - one wins, the other gets last_owner", func(t *testing.T) {
		f := setup(t)
		grant(t, f.orgs, zshare, alice, "owner")
		grant(t, f.orgs, zshare, carol, "owner")
		grant(t, f.orgs, zshare, bob, "member")
		var wg sync.WaitGroup
		errs := make([]error, 2)
		for i, s := range []string{alice, carol} {
			wg.Go(func() { _, errs[i] = f.store.Delete(context.WithoutCancel(t.Context()), s) })
		}
		wg.Wait()
		ok, last := 0, 0
		for _, err := range errs {
			switch {
			case err == nil:
				ok++
			case errors.Is(err, account.ErrLastOwner):
				last++
			default:
				t.Fatal(err)
			}
		}
		if ok != 1 || last != 1 || count(t, f.db, `SELECT count(*) FROM memberships WHERE org_id = $1 AND role = 'owner'`, org(t, f, zshare).ID) != 1 {
			t.Fatalf("ok %d, last_owner %d", ok, last)
		}
	})

	t.Run("ApplyGrant - grant of a deleted user arrives late - ignored, no membership", func(t *testing.T) {
		f := setup(t)
		grant(t, f.orgs, zorg, bob, "owner")
		grant(t, f.orgs, zorg, alice, "member")
		if _, err := f.store.Delete(t.Context(), alice); err != nil {
			t.Fatal(err)
		}
		if out := grant(t, f.orgs, zorg, alice, "admin"); out != orgs.OutcomeIgnored {
			t.Fatalf("outcome %s", out)
		}
		if count(t, f.db, `SELECT count(*) FROM memberships WHERE user_sub = $1`, alice) != 0 {
			t.Fatal("membership came back")
		}
	})

	t.Run("Memberships - two orgs - by org name with role and times", func(t *testing.T) {
		f := setup(t)
		grant(t, f.orgs, zsolo, alice, "owner")
		grant(t, f.orgs, zorg, alice, "member")
		ms, err := f.store.Memberships(t.Context(), alice)
		if err != nil || len(ms) != 2 || ms[0].OrgName != "Org "+zorg || ms[0].Role != "member" || ms[1].Role != "owner" || ms[0].JoinedAt.IsZero() {
			t.Fatalf("got %+v, %v", ms, err)
		}
		if ms, err := f.store.Memberships(t.Context(), bob); err != nil || len(ms) != 0 {
			t.Fatalf("bob: %+v, %v", ms, err)
		}
	})
}

type fakeUsers struct {
	mu    sync.Mutex
	calls []string
	err   error
}

func (u *fakeUsers) DeleteUser(_ context.Context, sub string) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.calls = append(u.calls, sub)
	return u.err
}

func TestRemover(t *testing.T) {
	log := slog.New(slog.DiscardHandler)

	t.Run("RunOnce - Zitadel removes the user - clear sub gone, hash stays, no second call", func(t *testing.T) {
		f := setup(t)
		grant(t, f.orgs, zsolo, alice, "owner")
		if _, err := f.store.Delete(t.Context(), alice); err != nil {
			t.Fatal(err)
		}
		users := &fakeUsers{}
		rm := &account.Remover{DB: f.db, Users: users, Log: log}
		if n, err := rm.RunOnce(t.Context()); err != nil || n != 1 || len(users.calls) != 1 || users.calls[0] != alice {
			t.Fatalf("removed %d, calls %v, %v", n, users.calls, err)
		}
		if count(t, f.db, `SELECT count(*) FROM account_deletions WHERE user_sub IS NULL AND zitadel_removed_at IS NOT NULL AND user_sub_hash = $1`, account.Hash(alice)) != 1 {
			t.Fatal("row not closed")
		}
		if n, err := rm.RunOnce(t.Context()); err != nil || n != 0 || len(users.calls) != 1 {
			t.Fatalf("second run: %d, %v", n, err)
		}
		if _, ok, err := f.store.Deleted(t.Context(), alice); err != nil || !ok {
			t.Fatal("tombstone lost")
		}
	})

	t.Run("RunOnce - Zitadel refuses - attempts 1, error kept, retry after a pause", func(t *testing.T) {
		f := setup(t)
		grant(t, f.orgs, zsolo, alice, "owner")
		if _, err := f.store.Delete(t.Context(), alice); err != nil {
			t.Fatal(err)
		}
		users := &fakeUsers{err: errors.New("zitadel DELETE: status 403")}
		rm := &account.Remover{DB: f.db, Users: users, Log: log}
		if n, err := rm.RunOnce(t.Context()); err != nil || n != 0 {
			t.Fatalf("removed %d, %v", n, err)
		}
		if count(t, f.db, `SELECT count(*) FROM account_deletions WHERE attempts = 1 AND last_error <> '' AND user_sub = $1
			AND next_attempt_at > now() + interval '50 seconds'`, alice) != 1 {
			t.Fatal("row not marked")
		}
		if _, err := rm.RunOnce(t.Context()); err != nil || len(users.calls) != 1 {
			t.Fatalf("retried before the pause: %v", users.calls)
		}
	})
}
