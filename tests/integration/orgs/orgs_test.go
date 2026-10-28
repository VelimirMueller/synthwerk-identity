//go:build integration

package orgs_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/VelimirMueller/synthwerk-contracts/go/kit/auth"
	"github.com/VelimirMueller/synthwerk-contracts/go/kit/auth/authtest"

	"github.com/VelimirMueller/synthwerk-identity/internal/app"
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
	zorg     = "300000000000000001" // Zitadel org of the test org
	otherOrg = "300000000000000002"
	platform = "300000000000000009"
	owner    = "100000000000000001"
	owner2   = "100000000000000002"
	admin    = "100000000000000003"
	member   = "100000000000000004"
)

// fakeGrants records SetRole calls; err makes Zitadel refuse.
type fakeGrants struct {
	mu    sync.Mutex
	calls []string
	err   error
}

func (f *fakeGrants) SetRole(_ context.Context, zid, sub, grantID string, to orgs.Role) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	f.calls = append(f.calls, zid+"/"+sub+"/"+grantID+"/"+string(to))
	return nil
}

func setup(t *testing.T) (*orgs.Store, *pgxpool.Pool, *fakeGrants) {
	t.Helper()
	db := env.Database(t)
	if err := app.Migrate(t.Context(), db); err != nil {
		t.Fatal(err)
	}
	g := &fakeGrants{}
	return &orgs.Store{DB: db, Grants: g, Source: "/synthwerk/identity/dev"}, db, g
}

var seq int

// grant mirrors one Zitadel grant event.
func grant(t *testing.T, s *orgs.Store, zid, sub string, roles ...string) orgs.Outcome {
	t.Helper()
	seq++
	out, err := s.ApplyGrant(t.Context(), orgs.GrantChange{
		Key: fmt.Sprintf("i:usergrant:g-%s:%d", sub, seq), ZitadelOrgID: zid, GrantID: "g-" + zid + "-" + sub, UserSub: sub, Roles: roles,
	}, "Acme Labs")
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// seed makes an active org with one owner, one admin and one member.
func seed(t *testing.T, s *orgs.Store) orgs.Org {
	t.Helper()
	grant(t, s, zorg, owner, "owner", "end_user")
	grant(t, s, zorg, admin, "admin")
	grant(t, s, zorg, member, "member")
	org, err := s.OrgByZitadelID(t.Context(), zorg)
	if err != nil {
		t.Fatal(err)
	}
	return org
}

func count(t *testing.T, db *pgxpool.Pool, sql string, args ...any) int {
	t.Helper()
	var n int
	if err := db.QueryRow(t.Context(), sql, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func events(t *testing.T, db *pgxpool.Pool, typ string) int {
	t.Helper()
	return count(t, db, `SELECT count(*) FROM synthwerk_outbox WHERE event->>'type' = $1`, typ)
}

func role(t *testing.T, s *orgs.Store, org orgs.Org, sub string) orgs.Role {
	t.Helper()
	r, err := s.MemberRole(t.Context(), org.ID, sub)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestApplyGrant(t *testing.T) {
	t.Run("ApplyGrant - member before the first owner - org pending, no org.created", func(t *testing.T) {
		s, db, _ := setup(t)
		if out := grant(t, s, zorg, member, "member"); out != orgs.OutcomeAdded {
			t.Fatalf("outcome %s", out)
		}
		org, _ := s.OrgByZitadelID(t.Context(), zorg)
		if org.Status != "pending" || events(t, db, orgs.OrgCreated) != 0 {
			t.Fatalf("org %+v", org)
		}
		if out := grant(t, s, zorg, owner, "owner"); out != orgs.OutcomeOrgCreated {
			t.Fatalf("outcome %s", out)
		}
		org, _ = s.OrgByZitadelID(t.Context(), zorg)
		if org.Status != "active" || org.Slug != "acme-labs" || events(t, db, orgs.OrgCreated) != 1 {
			t.Fatalf("org %+v", org)
		}
		var data orgs.OrgCreatedData
		var raw []byte
		if err := db.QueryRow(t.Context(), `SELECT event->'data' FROM synthwerk_outbox WHERE event->>'type' = $1`, orgs.OrgCreated).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		_ = json.Unmarshal(raw, &data)
		if data.OwnerSub != owner || data.OrgID != org.ID {
			t.Fatalf("data %+v", data)
		}
	})

	t.Run("Action org created - same event twice - one org, one owner", func(t *testing.T) {
		s, db, _ := setup(t)
		c := orgs.GrantChange{Key: "i:usergrant:g1:1", ZitadelOrgID: zorg, GrantID: "g1", UserSub: owner, Roles: []string{"owner"}}
		for range 2 {
			if _, err := s.ApplyGrant(t.Context(), c, "Acme"); err != nil {
				t.Fatal(err)
			}
		}
		if count(t, db, `SELECT count(*) FROM orgs`) != 1 || count(t, db, `SELECT count(*) FROM memberships WHERE role = 'owner'`) != 1 || events(t, db, orgs.OrgCreated) != 1 {
			t.Fatal("repeat wrote twice")
		}
	})

	t.Run("ApplyGrant - Zitadel removes the last owner - mirror keeps the owner", func(t *testing.T) {
		s, db, _ := setup(t)
		org := seed(t, s)
		out, err := s.ApplyGrant(t.Context(), orgs.GrantChange{Key: "i:usergrant:x:99", ZitadelOrgID: zorg, GrantID: "g-" + zorg + "-" + owner, Removed: true}, "")
		if err != nil || out != orgs.OutcomeLastOwner {
			t.Fatalf("out %s err %v", out, err)
		}
		if role(t, s, org, owner) != orgs.Owner || events(t, db, orgs.RoleChanged) != 0 {
			t.Fatal("last owner gone")
		}
	})

	t.Run("ApplyGrant - grant changed in Zitadel - role_changed with actor system", func(t *testing.T) {
		s, db, _ := setup(t)
		org := seed(t, s)
		out, err := s.ApplyGrant(t.Context(), orgs.GrantChange{Key: "i:usergrant:y:5", ZitadelOrgID: zorg, GrantID: "g-" + zorg + "-" + member, Roles: []string{"admin"}}, "")
		if err != nil || out != orgs.OutcomeChanged || role(t, s, org, member) != orgs.Admin {
			t.Fatalf("out %s err %v", out, err)
		}
		if count(t, db, `SELECT count(*) FROM synthwerk_outbox WHERE event->>'type' = $1 AND event->>'actor' = 'system'`, orgs.RoleChanged) != 1 {
			t.Fatal("no system role_changed")
		}
	})

	t.Run("Operator - operator grant - never a membership", func(t *testing.T) {
		s, db, _ := setup(t)
		if out := grant(t, s, platform, "100000000000000077", "operator"); out != orgs.OutcomeIgnored {
			t.Fatalf("outcome %s", out)
		}
		if count(t, db, `SELECT count(*) FROM memberships`) != 0 {
			t.Fatal("operator stored as member")
		}
	})
}

func TestChangeRole(t *testing.T) {
	t.Run("ChangeRole - success - membership and outbox row in one commit, Zitadel grant written", func(t *testing.T) {
		s, db, g := setup(t)
		org := seed(t, s)
		m, changed, err := s.ChangeRole(t.Context(), org, owner, member, orgs.Admin)
		if err != nil || !changed || m.Role != orgs.Admin || role(t, s, org, member) != orgs.Admin {
			t.Fatalf("m %+v changed %v err %v", m, changed, err)
		}
		if events(t, db, orgs.RoleChanged) != 1 || len(g.calls) != 1 || g.calls[0] != zorg+"/"+member+"/g-"+zorg+"-"+member+"/admin" {
			t.Fatalf("events or grants: %v", g.calls)
		}
		var d orgs.RoleChangedData
		var raw []byte
		var actor, orgid string
		if err := db.QueryRow(t.Context(), `SELECT event->'data', event->>'actor', event->>'orgid' FROM synthwerk_outbox WHERE event->>'type' = $1`, orgs.RoleChanged).Scan(&raw, &actor, &orgid); err != nil {
			t.Fatal(err)
		}
		_ = json.Unmarshal(raw, &d)
		if d.OldRole != orgs.Member || d.NewRole != orgs.Admin || actor != "user:"+owner || orgid != org.ID {
			t.Fatalf("event %+v %s %s", d, actor, orgid)
		}
	})

	t.Run("ChangeRole - same role again - 200, no event", func(t *testing.T) {
		s, db, _ := setup(t)
		org := seed(t, s)
		if _, changed, err := s.ChangeRole(t.Context(), org, admin, member, orgs.Member); err != nil || changed {
			t.Fatalf("changed %v err %v", changed, err)
		}
		if events(t, db, orgs.RoleChanged) != 0 {
			t.Fatal("event for no change")
		}
	})

	for _, tc := range []struct {
		name          string
		actor, target string
		to            orgs.Role
		want          error
	}{
		{"ChangeRole - member changes role - forbidden", member, admin, orgs.Member, orgs.ErrForbidden},
		{"ChangeRole - admin grants owner - forbidden", admin, member, orgs.Owner, orgs.ErrForbidden},
		{"ChangeRole - admin demotes owner - forbidden", admin, owner, orgs.Admin, orgs.ErrForbidden},
		{"ChangeRole - owner changes own role - own_role", owner, owner, orgs.Admin, orgs.ErrOwnRole},
		{"ChangeRole - unknown member - not found", owner, "100000000000000099", orgs.Admin, orgs.ErrNotFound},
		{"ChangeRole - not a member of the org - forbidden", "100000000000000098", member, orgs.Admin, orgs.ErrForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, db, g := setup(t)
			org := seed(t, s)
			if _, _, err := s.ChangeRole(t.Context(), org, tc.actor, tc.target, tc.to); !errors.Is(err, tc.want) {
				t.Fatalf("err %v, want %v", err, tc.want)
			}
			if events(t, db, orgs.RoleChanged) != 0 || len(g.calls) != 0 {
				t.Fatal("refusal wrote an event or a grant")
			}
		})
	}

	t.Run("ChangeRole - Zitadel fake fails - mirror rolled back, no event", func(t *testing.T) {
		s, db, g := setup(t)
		org := seed(t, s)
		g.err = errors.New("zitadel down")
		if _, _, err := s.ChangeRole(t.Context(), org, owner, member, orgs.Admin); !errors.Is(err, orgs.ErrUpstream) {
			t.Fatalf("err %v", err)
		}
		if role(t, s, org, member) != orgs.Member || events(t, db, orgs.RoleChanged) != 0 {
			t.Fatal("not rolled back")
		}
	})

	t.Run("ChangeRole - last owner demoted - rejected, row unchanged", func(t *testing.T) {
		s, db, _ := setup(t)
		org := seed(t, s)
		// The deferred trigger is the second guard: a direct write fails at commit.
		tx, err := db.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(t.Context(), `UPDATE memberships SET role = 'admin' WHERE user_sub = $1`, owner); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(t.Context()); err == nil || !strings.Contains(err.Error(), "has no owner") {
			t.Fatalf("commit err %v", err)
		}
		if role(t, s, org, owner) != orgs.Owner {
			t.Fatal("last owner demoted")
		}
	})

	t.Run("ChangeRole - two parallel demotions of two owners - one succeeds", func(t *testing.T) {
		s, db, _ := setup(t)
		org := seed(t, s)
		if _, _, err := s.ChangeRole(t.Context(), org, owner, owner2, orgs.Owner); !errors.Is(err, orgs.ErrNotFound) {
			t.Fatalf("owner2 exists already: %v", err)
		}
		grant(t, s, zorg, owner2, "owner")
		var wg sync.WaitGroup
		errs := make([]error, 2)
		for i, pair := range [][2]string{{owner, owner2}, {owner2, owner}} {
			wg.Go(func() { _, _, errs[i] = s.ChangeRole(t.Context(), org, pair[0], pair[1], orgs.Admin) })
		}
		wg.Wait()
		ok := 0
		for _, err := range errs {
			if err == nil {
				ok++
			} else if !errors.Is(err, orgs.ErrForbidden) && !errors.Is(err, orgs.ErrLastOwner) {
				t.Fatalf("err %v", err)
			}
		}
		if ok != 1 || count(t, db, `SELECT count(*) FROM memberships WHERE role = 'owner'`) != 1 {
			t.Fatalf("ok %d, errs %v", ok, errs)
		}
	})
}

// server is the identity app with the org routes and a fake issuer.
func server(t *testing.T, s *orgs.Store) (*httptest.Server, *authtest.Issuer) {
	t.Helper()
	iss := authtest.NewIssuer(t)
	cfg := iss.Config()
	cfg.Mapper = auth.ZitadelMapper{PlatformOrgID: platform}
	v, err := auth.NewVerifier(cfg)
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.DiscardHandler)
	a, err := app.New(s.DB.(*pgxpool.Pool), logger, app.Config{Version: "0.1.0-dev", Commit: "0000000", Env: "ci",
		Verifier: v, Orgs: &orgs.Handler{Repo: s, Log: logger}})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(a.Handler())
	t.Cleanup(srv.Close)
	return srv, iss
}

func call(t *testing.T, method, url, tok, body string) (int, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), method, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, string(b)
}

func TestHTTP(t *testing.T) {
	s, db, _ := setup(t)
	org := seed(t, s)
	srv, iss := server(t, s)
	tok := func(sub, zid string, roles ...string) string { return iss.Mint(t, authtest.Claims(sub, zid, roles...)) }
	members := srv.URL + "/v1/orgs/" + org.ID + "/members"

	t.Run("PATCH member - member token - 403 generic body", func(t *testing.T) {
		st, body := call(t, http.MethodPatch, members+"/"+admin, tok(member, zorg, "member"), `{"role":"member"}`)
		if st != http.StatusForbidden || !strings.Contains(body, `"code":"forbidden"`) || strings.Contains(body, "detail") {
			t.Fatalf("%d %s", st, body)
		}
	})
	t.Run("PATCH member - owner token - 200", func(t *testing.T) {
		st, body := call(t, http.MethodPatch, members+"/"+member, tok(owner, zorg, "owner"), `{"role":"admin"}`)
		if st != http.StatusOK || !strings.Contains(body, `"role":"admin"`) {
			t.Fatalf("%d %s", st, body)
		}
	})
	t.Run("PATCH member - admin token - 200", func(t *testing.T) {
		st, body := call(t, http.MethodPatch, members+"/"+member, tok(admin, zorg, "admin"), `{"role":"member"}`)
		if st != http.StatusOK || !strings.Contains(body, `"role":"member"`) {
			t.Fatalf("%d %s", st, body)
		}
		if events(t, db, orgs.RoleChanged) != 2 {
			t.Fatal("want 2 role_changed events")
		}
	})
	t.Run("PATCH member - token of other org - 404", func(t *testing.T) {
		st, _ := call(t, http.MethodPatch, members+"/"+member, tok(owner, otherOrg, "owner"), `{"role":"admin"}`)
		if st != http.StatusNotFound {
			t.Fatalf("%d", st)
		}
	})
	t.Run("PATCH member - forged token - 401", func(t *testing.T) {
		st, _ := call(t, http.MethodPatch, members+"/"+member, iss.MintHS256(t, authtest.Claims(owner, zorg, "owner")), `{"role":"admin"}`)
		if st != http.StatusUnauthorized {
			t.Fatalf("%d", st)
		}
	})
	t.Run("PATCH member - owner role in the body is operator - 400", func(t *testing.T) {
		st, _ := call(t, http.MethodPatch, members+"/"+member, tok(owner, zorg, "owner"), `{"role":"operator"}`)
		if st != http.StatusBadRequest {
			t.Fatalf("%d", st)
		}
	})
	t.Run("PATCH member - last owner by own token - 409 own_role", func(t *testing.T) {
		st, body := call(t, http.MethodPatch, members+"/"+owner, tok(owner, zorg, "owner"), `{"role":"admin"}`)
		if st != http.StatusConflict || !strings.Contains(body, "own_role") {
			t.Fatalf("%d %s", st, body)
		}
	})
	t.Run("Operator - other org - GET 200, PATCH 403", func(t *testing.T) {
		op := iss.Mint(t, map[string]any{"sub": "100000000000000077", auth.ClaimOrgID: platform, auth.ClaimRoles: authtest.Roles(platform, "operator")})
		if st, _ := call(t, http.MethodGet, srv.URL+"/v1/orgs/"+org.ID, op, ""); st != http.StatusOK {
			t.Fatalf("GET %d", st)
		}
		if st, _ := call(t, http.MethodGet, members, op, ""); st != http.StatusOK {
			t.Fatalf("list %d", st)
		}
		if st, _ := call(t, http.MethodPatch, members+"/"+member, op, `{"role":"admin"}`); st != http.StatusForbidden {
			t.Fatalf("PATCH %d", st)
		}
	})
	t.Run("ListMembers - admin demoted, old admin token - 403", func(t *testing.T) {
		old := tok(admin, zorg, "admin")
		if st, _ := call(t, http.MethodGet, members, old, ""); st != http.StatusOK {
			t.Fatalf("before %d", st)
		}
		if st, _ := call(t, http.MethodPatch, members+"/"+admin, tok(owner, zorg, "owner"), `{"role":"member"}`); st != http.StatusOK {
			t.Fatalf("demote %d", st)
		}
		if st, _ := call(t, http.MethodGet, members, old, ""); st != http.StatusForbidden {
			t.Fatalf("after %d", st)
		}
		// Same for a write with the old token.
		if st, _ := call(t, http.MethodPatch, members+"/"+member, old, `{"role":"admin"}`); st != http.StatusForbidden {
			t.Fatalf("write after %d", st)
		}
	})
	t.Run("ListMembers - member token - 403; paging - next_cursor", func(t *testing.T) {
		if st, _ := call(t, http.MethodGet, members, tok(member, zorg, "member"), ""); st != http.StatusForbidden {
			t.Fatalf("%d", st)
		}
		st, body := call(t, http.MethodGet, members+"?limit=2", tok(owner, zorg, "owner"), "")
		var page struct {
			Items      []map[string]any `json:"items"`
			NextCursor string           `json:"next_cursor"`
		}
		_ = json.Unmarshal([]byte(body), &page)
		if st != http.StatusOK || len(page.Items) != 2 || page.NextCursor == "" {
			t.Fatalf("%d %s", st, body)
		}
		_, body = call(t, http.MethodGet, members+"?limit=2&cursor="+page.NextCursor, tok(owner, zorg, "owner"), "")
		page.NextCursor = ""
		_ = json.Unmarshal([]byte(body), &page)
		if len(page.Items) != 1 || page.NextCursor != "" {
			t.Fatalf("page 2 %s", body)
		}
	})
	t.Run("GetMe - owner token - org and role", func(t *testing.T) {
		st, body := call(t, http.MethodGet, srv.URL+"/v1/me", tok(owner, zorg, "owner"), "")
		if st != http.StatusOK || !strings.Contains(body, `"roles":["owner"]`) || !strings.Contains(body, org.ID) {
			t.Fatalf("%d %s", st, body)
		}
	})
	t.Run("GetOrg - unknown or malformed id - 404", func(t *testing.T) {
		for _, id := range []string{"0199f3a1-2c3d-7e4f-8a5b-6c7d8e9f0a1b", "not-a-uuid"} {
			if st, _ := call(t, http.MethodGet, srv.URL+"/v1/orgs/"+id, tok(owner, zorg, "owner"), ""); st != http.StatusNotFound {
				t.Fatalf("%s: %d", id, st)
			}
		}
	})
}
