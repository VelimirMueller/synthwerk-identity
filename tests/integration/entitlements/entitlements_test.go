//go:build integration

package entitlements_test

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
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/VelimirMueller/synthwerk-contracts/go/identity"
	"github.com/VelimirMueller/synthwerk-contracts/go/kit/auth"
	"github.com/VelimirMueller/synthwerk-contracts/go/kit/auth/authtest"

	"github.com/VelimirMueller/synthwerk-identity/internal/app"
	"github.com/VelimirMueller/synthwerk-identity/internal/entitlements"
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
	zorg     = "300000000000000001"
	zorg2    = "300000000000000002"
	platform = "300000000000000009"
	owner    = "100000000000000001"
	member   = "100000000000000004"
	source   = "/synthwerk/identity/dev"
)

var free = entitlements.Plan{Name: entitlements.Free, Limits: entitlements.FreeDefaults}

func setup(t *testing.T) (*orgs.Store, *entitlements.Store, *pgxpool.Pool) {
	t.Helper()
	db := env.Database(t)
	if err := app.Migrate(t.Context(), db); err != nil {
		t.Fatal(err)
	}
	plans := &entitlements.Store{DB: db, Source: source, Default: free}
	return &orgs.Store{DB: db, Source: source, Plans: plans}, plans, db
}

var seq int

func grant(t *testing.T, s *orgs.Store, zid, sub string, roles ...string) (orgs.Outcome, error) {
	t.Helper()
	seq++
	return s.ApplyGrant(t.Context(), orgs.GrantChange{
		Key: fmt.Sprintf("i:usergrant:g-%s:%d", sub, seq), ZitadelOrgID: zid, GrantID: "g-" + zid + "-" + sub, UserSub: sub, Roles: roles,
	}, "Acme "+zid)
}

func mustGrant(t *testing.T, s *orgs.Store, zid, sub string, roles ...string) orgs.Outcome {
	t.Helper()
	out, err := grant(t, s, zid, sub, roles...)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// org is the test org (zorg).
func org(t *testing.T, s *orgs.Store) orgs.Org {
	t.Helper()
	o, err := s.OrgByZitadelID(t.Context(), zorg)
	if err != nil {
		t.Fatal(err)
	}
	return o
}

// changes returns the entitlements_changed events of org, oldest first.
func changes(t *testing.T, db *pgxpool.Pool, orgID string) []struct {
	Subject, OrgID, Actor, Schema string
	Data                          entitlements.ChangedData
} {
	t.Helper()
	rows, err := db.Query(t.Context(), `SELECT event->>'subject', event->>'orgid', event->>'actor', event->>'dataschema', event->'data'
		FROM synthwerk_outbox WHERE event->>'type' = $1 AND event->>'subject' = $2 ORDER BY created_at, id`, entitlements.Changed, orgID)
	if err != nil {
		t.Fatal(err)
	}
	type ev = struct {
		Subject, OrgID, Actor, Schema string
		Data                          entitlements.ChangedData
	}
	out, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (ev, error) {
		var e ev
		var raw []byte
		if err := r.Scan(&e.Subject, &e.OrgID, &e.Actor, &e.Schema, &raw); err != nil {
			return e, err
		}
		return e, json.Unmarshal(raw, &e.Data)
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestAssign(t *testing.T) {
	t.Run("ApplyGrant - first owner - org gets plan free and one entitlements_changed", func(t *testing.T) {
		s, plans, db := setup(t)
		if out := mustGrant(t, s, zorg, member, "member"); out != orgs.OutcomeAdded {
			t.Fatalf("outcome %s", out)
		}
		pending := org(t, s)
		if _, err := plans.ByOrg(t.Context(), pending.ID); !errors.Is(err, entitlements.ErrNotFound) {
			t.Fatalf("pending org has a plan: %v", err)
		}
		if out := mustGrant(t, s, zorg, owner, "owner"); out != orgs.OutcomeOrgCreated {
			t.Fatalf("outcome %s", out)
		}
		o := org(t, s)
		e, err := plans.ByOrg(t.Context(), o.ID)
		if err != nil {
			t.Fatal(err)
		}
		if e.Plan != "free" || e.Limits != entitlements.FreeDefaults || e.Version != 1 {
			t.Fatalf("got %+v", e)
		}
		evs := changes(t, db, o.ID)
		if len(evs) != 1 {
			t.Fatalf("%d events", len(evs))
		}
		ev := evs[0]
		if ev.OrgID != o.ID || ev.Actor != "system" || ev.Schema != entitlements.ChangedSchema ||
			ev.Data.Reason != entitlements.ReasonPlanAssigned || ev.Data.Version != 1 || ev.Data.Plan != "free" ||
			ev.Data.Limits.LLMTokensPerUserPerDay != 50000 || ev.Data.Limits.LLMTokensPerOrgPerDay != 500000 || ev.Data.Limits.AppsPerOrg != 3 {
			t.Fatalf("event %+v", ev)
		}
	})

	t.Run("ApplyGrant - second owner - plan unchanged, no second event", func(t *testing.T) {
		s, plans, db := setup(t)
		mustGrant(t, s, zorg, owner, "owner")
		mustGrant(t, s, zorg, "100000000000000002", "owner")
		o := org(t, s)
		e, _ := plans.ByOrg(t.Context(), o.ID)
		if e.Version != 1 || len(changes(t, db, o.ID)) != 1 {
			t.Fatalf("got %+v", e)
		}
	})

	t.Run("ApplyGrant - plan write fails - org stays pending, no org.created", func(t *testing.T) {
		s, _, db := setup(t)
		s.Plans = failing{}
		if _, err := grant(t, s, zorg, owner, "owner"); err == nil {
			t.Fatal("want an error")
		}
		var n int
		_ = db.QueryRow(t.Context(), `SELECT count(*) FROM synthwerk_outbox WHERE event->>'type' = $1`, orgs.OrgCreated).Scan(&n)
		if n != 0 {
			t.Fatal("org.created written without a plan")
		}
	})
}

type failing struct{}

func (failing) AssignDefault(context.Context, pgx.Tx, string) error { return errors.New("plans down") }

func TestReconcile(t *testing.T) {
	t.Run("Reconcile - active org from before #31 - gets plan free once", func(t *testing.T) {
		s, plans, db := setup(t)
		s.Plans = nil // as before #31
		mustGrant(t, s, zorg, owner, "owner")
		mustGrant(t, s, zorg2, member, "member") // pending: no plan
		o := org(t, s)
		r, err := plans.Reconcile(t.Context())
		if err != nil || r.Assigned != 1 || r.Updated != 0 {
			t.Fatalf("r %+v err %v", r, err)
		}
		if evs := changes(t, db, o.ID); len(evs) != 1 || evs[0].Data.Reason != entitlements.ReasonPlanAssigned {
			t.Fatalf("events %+v", evs)
		}
		if r, err = plans.Reconcile(t.Context()); err != nil || r != (entitlements.Reconciled{}) {
			t.Fatalf("second run %+v err %v", r, err)
		}
	})

	t.Run("Reconcile - free limits changed in config - version 2 and plan_defaults_changed", func(t *testing.T) {
		s, plans, db := setup(t)
		mustGrant(t, s, zorg, owner, "owner")
		o := org(t, s)
		plans.Default.Limits = entitlements.Limits{LLMTokensPerUserPerDay: 1000, LLMTokensPerOrgPerDay: 0, AppsPerOrg: 1}
		r, err := plans.Reconcile(t.Context())
		if err != nil || r.Updated != 1 || r.Assigned != 0 {
			t.Fatalf("r %+v err %v", r, err)
		}
		e, _ := plans.ByOrg(t.Context(), o.ID)
		if e.Version != 2 || e.Limits != plans.Default.Limits {
			t.Fatalf("got %+v", e)
		}
		evs := changes(t, db, o.ID)
		if len(evs) != 2 || evs[1].Data.Reason != entitlements.ReasonDefaultsChanged || evs[1].Data.Version != 2 || evs[1].Data.Limits.LLMTokensPerOrgPerDay != 0 {
			t.Fatalf("events %+v", evs)
		}
		if r, err = plans.Reconcile(t.Context()); err != nil || r != (entitlements.Reconciled{}) {
			t.Fatalf("second run %+v err %v", r, err)
		}
	})

	t.Run("Reconcile - 450 orgs from before #31 - all assigned over 3 batches", func(t *testing.T) {
		_, plans, db := setup(t)
		if _, err := db.Exec(t.Context(), `INSERT INTO orgs (id, zitadel_org_id, name, slug, status)
			SELECT gen_random_uuid(), 'z' || g, 'Org ' || g, 'org-' || g, 'active' FROM generate_series(1, 450) g`); err != nil {
			t.Fatal(err)
		}
		r, err := plans.Reconcile(t.Context())
		if err != nil || r.Assigned != 450 {
			t.Fatalf("r %+v err %v", r, err)
		}
	})

	t.Run("Reconcile - default plan not valid - error, nothing written", func(t *testing.T) {
		_, plans, _ := setup(t)
		plans.Default.Limits.AppsPerOrg = -1
		if _, err := plans.Reconcile(t.Context()); err == nil {
			t.Fatal("want an error")
		}
	})
}

func TestHTTP(t *testing.T) {
	s, plans, _ := setup(t)
	mustGrant(t, s, zorg, owner, "owner")
	mustGrant(t, s, zorg2, owner, "owner")
	o := org(t, s)

	iss := authtest.NewIssuer(t)
	cfg := iss.Config()
	cfg.Mapper = auth.ZitadelMapper{PlatformOrgID: platform}
	v, err := auth.NewVerifier(cfg)
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.DiscardHandler)
	a, err := app.New(s.DB.(*pgxpool.Pool), logger, app.Config{Version: "0.1.0-dev", Commit: "0000000", Env: "ci", Verifier: v,
		Orgs: &orgs.Handler{Repo: s, Log: logger}, Entitlements: &entitlements.Handler{Orgs: s, Repo: plans, Log: logger}})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(a.Handler())
	t.Cleanup(srv.Close)
	tok := func(sub, zid string, roles ...string) string { return iss.Mint(t, authtest.Claims(sub, zid, roles...)) }
	get := func(path, token string) (int, string) {
		req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+path, nil)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = res.Body.Close() }()
		b, _ := io.ReadAll(res.Body)
		return res.StatusCode, string(b)
	}

	t.Run("GET /v1/me/entitlements - member token - plan free and its limits", func(t *testing.T) {
		mustGrant(t, s, zorg, member, "member")
		st, body := get("/v1/me/entitlements", tok(member, zorg, "member"))
		var e identity.Entitlements
		dec := json.NewDecoder(strings.NewReader(body))
		dec.DisallowUnknownFields()
		if st != http.StatusOK || dec.Decode(&e) != nil || e.OrgId.String() != o.ID || e.Plan != "free" || e.Limits.LlmTokensPerUserPerDay != 50000 {
			t.Fatalf("%d %s", st, body)
		}
	})
	t.Run("GET /v1/orgs/{orgId}/entitlements - token of another org - 404", func(t *testing.T) {
		if st, body := get("/v1/orgs/"+o.ID+"/entitlements", tok(owner, zorg2, "owner")); st != http.StatusNotFound {
			t.Fatalf("%d %s", st, body)
		}
	})
	t.Run("GET /v1/orgs/{orgId}/entitlements - operator - 200", func(t *testing.T) {
		if st, body := get("/v1/orgs/"+o.ID+"/entitlements", tok("100000000000000077", platform, "operator")); st != http.StatusOK || !strings.Contains(body, `"plan":"free"`) {
			t.Fatalf("%d %s", st, body)
		}
	})
	t.Run("GET /v1/me/entitlements - no token - 401", func(t *testing.T) {
		if st, body := get("/v1/me/entitlements", ""); st != http.StatusUnauthorized {
			t.Fatalf("%d %s", st, body)
		}
	})
}
