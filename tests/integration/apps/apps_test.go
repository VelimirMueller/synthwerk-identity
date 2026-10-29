//go:build integration

package apps_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
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
	"github.com/VelimirMueller/synthwerk-identity/internal/apps"
	"github.com/VelimirMueller/synthwerk-identity/internal/entitlements"
	"github.com/VelimirMueller/synthwerk-identity/internal/orgs"
	"github.com/VelimirMueller/synthwerk-identity/internal/widget"
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
	otherOrg = "300000000000000002"
	owner    = "100000000000000001"
	admin    = "100000000000000003"
	member   = "100000000000000004"
	outsider = "100000000000000005" // member of otherOrg only
	shop     = "https://shop.example"
	issuer   = "https://identity.synthwerk.test"
)

type stores struct {
	orgs *orgs.Store
	apps *apps.Store
	db   *pgxpool.Pool
}

func setup(t *testing.T) stores {
	t.Helper()
	db := env.Database(t)
	for range 2 { // every migration file is idempotent
		if err := app.Migrate(t.Context(), db); err != nil {
			t.Fatal(err)
		}
	}
	plans := &entitlements.Store{DB: db, Source: "/synthwerk/identity/dev",
		Default: entitlements.Plan{Name: entitlements.Free, Limits: entitlements.FreeDefaults}}
	return stores{
		orgs: &orgs.Store{DB: db, Source: "/synthwerk/identity/dev", Plans: plans},
		apps: &apps.Store{DB: db, Source: "/synthwerk/identity/dev"},
		db:   db,
	}
}

var seq int

func grant(t *testing.T, s *orgs.Store, zid, sub string, roles ...string) {
	t.Helper()
	seq++
	if _, err := s.ApplyGrant(t.Context(), orgs.GrantChange{
		Key: fmt.Sprintf("i:usergrant:g-%s:%d", sub, seq), ZitadelOrgID: zid, GrantID: "g-" + zid + "-" + sub, UserSub: sub, Roles: roles,
	}, "Acme Labs "+zid); err != nil {
		t.Fatal(err)
	}
}

// seed makes two active orgs: zorg with owner, admin and member; otherOrg with outsider as owner.
func seed(t *testing.T, s stores) (orgs.Org, orgs.Org) {
	t.Helper()
	grant(t, s.orgs, zorg, owner, "owner")
	grant(t, s.orgs, zorg, admin, "admin")
	grant(t, s.orgs, zorg, member, "member")
	grant(t, s.orgs, otherOrg, outsider, "owner")
	a, err := s.orgs.OrgByZitadelID(t.Context(), zorg)
	if err != nil {
		t.Fatal(err)
	}
	b, err := s.orgs.OrgByZitadelID(t.Context(), otherOrg)
	if err != nil {
		t.Fatal(err)
	}
	return a, b
}

func count(t *testing.T, db *pgxpool.Pool, sql string, args ...any) int {
	t.Helper()
	var n int
	if err := db.QueryRow(t.Context(), sql, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestStore(t *testing.T) {
	s := setup(t)
	org, other := seed(t, s)

	t.Run("Create - owner - app row and app.created in one commit, no origins in the event", func(t *testing.T) {
		ctx := t.Context()
		a, err := s.apps.Create(ctx, org, owner, "Shop", []string{shop})
		if err != nil {
			t.Fatal(err)
		}
		var evt map[string]any
		if err := s.db.QueryRow(ctx, `SELECT event FROM synthwerk_outbox WHERE event->>'type' = $1 AND event->>'subject' = $2`, apps.AppCreated, a.ID).Scan(&evt); err != nil {
			t.Fatal(err)
		}
		data, _ := json.Marshal(evt["data"])
		if evt["orgid"] != org.ID || evt["actor"] != "user:"+owner || evt["dataschema"] != apps.AppCreatedSchema || strings.Contains(string(data), "shop.example") {
			t.Fatalf("event %v", evt)
		}
		if !strings.Contains(string(data), `"app_id":"`+a.ID+`"`) || !strings.Contains(string(data), `"org_id":"`+org.ID+`"`) {
			t.Fatalf("data %s", data)
		}
	})
	t.Run("Create - stored role member - ErrForbidden, no row, no event", func(t *testing.T) {
		ctx := t.Context()
		before := count(t, s.db, `SELECT count(*) FROM synthwerk_outbox WHERE event->>'type' = $1`, apps.AppCreated)
		if _, err := s.apps.Create(ctx, org, member, "Shop", []string{shop}); !errors.Is(err, apps.ErrForbidden) {
			t.Fatalf("err %v", err)
		}
		if _, err := s.apps.Create(ctx, org, outsider, "Shop", []string{shop}); !errors.Is(err, apps.ErrForbidden) {
			t.Fatalf("outsider err %v", err)
		}
		if count(t, s.db, `SELECT count(*) FROM synthwerk_outbox WHERE event->>'type' = $1`, apps.AppCreated) != before {
			t.Fatal("event written")
		}
	})
	t.Run("Update - new origins, name kept; app of another org - ErrNotFound", func(t *testing.T) {
		ctx := t.Context()
		a, err := s.apps.Create(ctx, org, admin, "Docs", []string{shop})
		if err != nil {
			t.Fatal(err)
		}
		u, err := s.apps.Update(ctx, org, admin, a.ID, apps.Change{Origins: []string{"https://docs.example", shop}})
		if err != nil || u.Name != "Docs" || len(u.AllowedOrigins) != 2 || !u.UpdatedAt.After(a.UpdatedAt) {
			t.Fatalf("%+v %v", u, err)
		}
		if _, err := s.apps.Update(ctx, other, outsider, a.ID, apps.Change{Origins: []string{shop}}); !errors.Is(err, apps.ErrNotFound) {
			t.Fatalf("other org err %v", err)
		}
		if _, err := s.apps.Get(ctx, other.ID, a.ID); !errors.Is(err, apps.ErrNotFound) {
			t.Fatalf("get other org err %v", err)
		}
	})
	t.Run("Delete - row gone, second delete ErrNotFound", func(t *testing.T) {
		ctx := t.Context()
		a, err := s.apps.Create(ctx, org, owner, "Tmp", []string{shop})
		if err != nil {
			t.Fatal(err)
		}
		if err := s.apps.Delete(ctx, org, owner, a.ID); err != nil {
			t.Fatal(err)
		}
		if err := s.apps.Delete(ctx, org, owner, a.ID); !errors.Is(err, apps.ErrNotFound) {
			t.Fatalf("err %v", err)
		}
	})
	t.Run("List - paging by id - oldest first, other org not listed", func(t *testing.T) {
		ctx := t.Context()
		if _, err := s.apps.Create(ctx, other, outsider, "Theirs", []string{shop}); err != nil {
			t.Fatal(err)
		}
		first, err := s.apps.List(ctx, org.ID, "", 1)
		if err != nil || len(first) != 1 {
			t.Fatalf("%v %v", first, err)
		}
		rest, err := s.apps.List(ctx, org.ID, first[0].ID, 100)
		if err != nil || len(rest) != 1 || rest[0].ID <= first[0].ID {
			t.Fatalf("%v %v", rest, err)
		}
	})
	t.Run("Migration - NULL origin in the list - refused by the table check", func(t *testing.T) {
		ctx := t.Context()
		_, err := s.db.Exec(ctx, `INSERT INTO apps (id, org_id, name, allowed_origins) VALUES (gen_random_uuid(), $1, 'x', ARRAY['https://a.example', NULL])`, org.ID)
		if err == nil {
			t.Fatal("accepted")
		}
	})
	t.Run("Migration - origin list longer than 20 - refused by the table check", func(t *testing.T) {
		ctx := t.Context()
		_, err := s.db.Exec(ctx, `INSERT INTO apps (id, org_id, name, allowed_origins) VALUES (gen_random_uuid(), $1, 'x', array_fill('https://a.example'::text, ARRAY[21]))`, org.ID)
		if err == nil {
			t.Fatal("accepted")
		}
	})
}

func server(t *testing.T, s stores) (*httptest.Server, *authtest.Issuer) {
	t.Helper()
	iss := authtest.NewIssuer(t)
	v, err := auth.NewVerifier(iss.Config())
	if err != nil {
		t.Fatal(err)
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	wi, err := widget.NewIssuer(widget.Config{Issuer: issuer, Key: key})
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.DiscardHandler)
	oh := &orgs.Handler{Repo: s.orgs, Log: logger}
	a, err := app.New(s.db, logger, app.Config{Version: "0.1.0-dev", Commit: "0000000", Env: "ci", Verifier: v, Orgs: oh,
		Apps: &apps.Handler{Repo: s.apps, Orgs: oh, Widget: wi, Log: logger}})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(a.Handler())
	t.Cleanup(srv.Close)
	return srv, iss
}

func call(t *testing.T, method, url, tok, origin, body string) (int, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), method, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	if origin != "" {
		req.Header.Set("Origin", origin)
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
	s := setup(t)
	org, _ := seed(t, s)
	srv, iss := server(t, s)
	tok := func(sub, zid string, roles ...string) string { return iss.Mint(t, authtest.Claims(sub, zid, roles...)) }
	list := srv.URL + "/v1/orgs/" + org.ID + "/apps"

	st, body := call(t, http.MethodPost, list, tok(admin, zorg, "admin"), "", `{"name":"Shop","allowed_origins":["https://shop.example","http://localhost:3000"]}`)
	if st != http.StatusCreated {
		t.Fatalf("create %d %s", st, body)
	}
	var created struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal([]byte(body), &created)
	tokens := srv.URL + "/v1/apps/" + created.ID + "/widget-tokens"

	t.Run("CreateWidgetToken - member on a listed origin - 201, verified with the key set, bound to user, org, app and origin", func(t *testing.T) {
		st, body := call(t, http.MethodPost, tokens, tok(member, zorg, "member"), shop, "")
		if st != http.StatusCreated {
			t.Fatalf("%d %s", st, body)
		}
		var wt struct {
			AccessToken string `json:"access_token"`
			ExpiresIn   int    `json:"expires_in"`
		}
		_ = json.Unmarshal([]byte(body), &wt)
		v, err := auth.NewVerifier(auth.Config{Issuer: issuer, Audiences: []string{widget.DefaultAudience}, JWKSURL: srv.URL + widget.JWKSPath})
		if err != nil {
			t.Fatal(err)
		}
		p, err := v.Verify(t.Context(), wt.AccessToken)
		if err != nil {
			t.Fatal(err)
		}
		if p.Subject != member || p.OrgID != zorg || p.ClientID != created.ID || p.Raw[auth.ClaimOrigin] != shop || wt.ExpiresIn != 600 {
			t.Fatalf("principal %+v, expires_in %d", p, wt.ExpiresIn)
		}
	})
	t.Run("CreateWidgetToken - non-listed origin - 403 origin_not_allowed", func(t *testing.T) {
		st, body := call(t, http.MethodPost, tokens, tok(member, zorg, "member"), "https://shop.example.evil.test", "")
		if st != http.StatusForbidden || !strings.Contains(body, "origin_not_allowed") {
			t.Fatalf("%d %s", st, body)
		}
	})
	t.Run("CreateWidgetToken - member of another org - 404", func(t *testing.T) {
		if st, _ := call(t, http.MethodPost, tokens, tok(outsider, otherOrg, "owner"), shop, ""); st != http.StatusNotFound {
			t.Fatalf("%d", st)
		}
	})
	t.Run("CreateWidgetToken - member left the org, old token - 404", func(t *testing.T) {
		old := tok(member, zorg, "member")
		seq++
		if _, err := s.orgs.ApplyGrant(t.Context(), orgs.GrantChange{Key: fmt.Sprintf("i:usergrant:rm:%d", seq), ZitadelOrgID: zorg,
			GrantID: "g-" + zorg + "-" + member, UserSub: member, Removed: true}, ""); err != nil {
			t.Fatal(err)
		}
		if st, _ := call(t, http.MethodPost, tokens, old, shop, ""); st != http.StatusNotFound {
			t.Fatalf("%d", st)
		}
		grant(t, s.orgs, zorg, member, "member")
	})
	t.Run("UpdateApp - origin removed - widget token on that origin 403", func(t *testing.T) {
		if st, body := call(t, http.MethodPatch, list+"/"+created.ID, tok(owner, zorg, "owner"), "", `{"allowed_origins":["http://localhost:3000"]}`); st != http.StatusOK {
			t.Fatalf("patch %d %s", st, body)
		}
		if st, _ := call(t, http.MethodPost, tokens, tok(member, zorg, "member"), shop, ""); st != http.StatusForbidden {
			t.Fatalf("%d", st)
		}
		if st, _ := call(t, http.MethodPost, tokens, tok(member, zorg, "member"), "http://localhost:3000", ""); st != http.StatusCreated {
			t.Fatalf("localhost %d", st)
		}
	})
	t.Run("CreateApp - admin demoted, old admin token - 403", func(t *testing.T) {
		old := tok(admin, zorg, "admin")
		if st, _ := call(t, http.MethodPatch, srv.URL+"/v1/orgs/"+org.ID+"/members/"+admin, tok(owner, zorg, "owner"), "", `{"role":"member"}`); st != http.StatusOK {
			t.Fatalf("demote %d", st)
		}
		if st, _ := call(t, http.MethodPost, list, old, "", `{"name":"X","allowed_origins":["https://x.example"]}`); st != http.StatusForbidden {
			t.Fatalf("%d", st)
		}
	})
	t.Run("ListApps and GetApp - member - 200", func(t *testing.T) {
		if st, body := call(t, http.MethodGet, list, tok(member, zorg, "member"), "", ""); st != http.StatusOK || !strings.Contains(body, created.ID) {
			t.Fatalf("list %d %s", st, body)
		}
		if st, _ := call(t, http.MethodGet, list+"/"+created.ID, tok(member, zorg, "member"), "", ""); st != http.StatusOK {
			t.Fatalf("get %d", st)
		}
	})
	t.Run("DeleteApp - owner - 204, then widget token 404", func(t *testing.T) {
		if st, _ := call(t, http.MethodDelete, list+"/"+created.ID, tok(owner, zorg, "owner"), "", ""); st != http.StatusNoContent {
			t.Fatalf("delete %d", st)
		}
		if st, _ := call(t, http.MethodPost, tokens, tok(member, zorg, "member"), "http://localhost:3000", ""); st != http.StatusNotFound {
			t.Fatalf("%d", st)
		}
	})
}

func TestLimitAndSettings(t *testing.T) {
	s := setup(t)
	org, other := seed(t, s)
	setLimit := func(t *testing.T, orgID string, n int) {
		t.Helper()
		if _, err := s.db.Exec(t.Context(), `UPDATE org_entitlements SET apps_per_org = $2 WHERE org_id = $1`, orgID, n); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("Create - org at apps_per_org - LimitError, no row, no event", func(t *testing.T) {
		ctx := t.Context()
		setLimit(t, org.ID, 1)
		if _, err := s.apps.Create(ctx, org, owner, "One", []string{shop}); err != nil {
			t.Fatal(err)
		}
		before := count(t, s.db, `SELECT count(*) FROM synthwerk_outbox WHERE event->>'type' = $1`, apps.AppCreated)
		_, err := s.apps.Create(ctx, org, owner, "Two", []string{shop})
		var le apps.LimitError
		if !errors.As(err, &le) || le.Limit != 1 || !errors.Is(err, apps.ErrLimitReached) {
			t.Fatalf("err %v", err)
		}
		if count(t, s.db, `SELECT count(*) FROM apps WHERE org_id = $1`, org.ID) != 1 ||
			count(t, s.db, `SELECT count(*) FROM synthwerk_outbox WHERE event->>'type' = $1`, apps.AppCreated) != before {
			t.Fatal("row or event written")
		}
	})
	t.Run("Create - limit 0 - no limit", func(t *testing.T) {
		ctx := t.Context()
		setLimit(t, org.ID, 0)
		if _, err := s.apps.Create(ctx, org, owner, "Two", []string{shop}); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("Create - eight parallel creates, one slot left - exactly one app made", func(t *testing.T) {
		ctx := t.Context()
		setLimit(t, other.ID, 1)
		var wg sync.WaitGroup
		var mu sync.Mutex
		ok, limited := 0, 0
		for i := range 8 {
			wg.Go(func() {
				_, err := s.apps.Create(ctx, other, outsider, fmt.Sprintf("P%d", i), []string{shop})
				mu.Lock()
				defer mu.Unlock()
				switch {
				case err == nil:
					ok++
				case errors.Is(err, apps.ErrLimitReached):
					limited++
				default:
					t.Errorf("err %v", err)
				}
			})
		}
		wg.Wait()
		if ok != 1 || limited != 7 || count(t, s.db, `SELECT count(*) FROM apps WHERE org_id = $1`, other.ID) != 1 {
			t.Fatalf("ok %d, limited %d", ok, limited)
		}
	})
	t.Run("Create - org without an entitlements row - error, never no limit", func(t *testing.T) {
		ctx := t.Context()
		if _, err := s.db.Exec(ctx, `DELETE FROM org_entitlements WHERE org_id = $1`, org.ID); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if _, err := s.db.Exec(ctx, `INSERT INTO org_entitlements (org_id, plan, llm_tokens_per_user_per_day, llm_tokens_per_org_per_day, apps_per_org)
				VALUES ($1, 'free', 1, 1, 0)`, org.ID); err != nil {
				t.Fatal(err)
			}
		}()
		_, err := s.apps.Create(ctx, org, owner, "X", []string{shop})
		if !errors.Is(err, apps.ErrNoEntitlements) || errors.Is(err, apps.ErrLimitReached) {
			t.Fatalf("err %v", err)
		}
	})
	t.Run("Settings - new app defaults, update replaces them, row from before 0007 reads as defaults", func(t *testing.T) {
		ctx := t.Context()
		a, err := s.apps.Create(ctx, org, owner, "Look", []string{shop})
		if err != nil || a.WidgetSettings != apps.DefaultWidgetSettings() {
			t.Fatalf("%+v %v", a.WidgetSettings, err)
		}
		want := apps.WidgetSettings{Position: "bottom-left", Theme: "contrast", Mode: "dark", Lang: "de", Accent: "venture", Greeting: "Hallo"}
		u, err := s.apps.Update(ctx, org, owner, a.ID, apps.Change{Settings: &want})
		if err != nil || u.WidgetSettings != want || u.Name != "Look" {
			t.Fatalf("%+v %v", u, err)
		}
		n := "Renamed"
		u, err = s.apps.Update(ctx, org, owner, a.ID, apps.Change{Name: &n})
		if err != nil || u.WidgetSettings != want {
			t.Fatalf("settings lost on rename: %+v %v", u, err)
		}
		if _, err := s.db.Exec(ctx, `UPDATE apps SET widget_settings = '{"mode":"neon","greeting":"Hi"}' WHERE id = $1`, a.ID); err != nil {
			t.Fatal(err)
		}
		g, err := s.apps.ByID(ctx, a.ID)
		d := apps.DefaultWidgetSettings()
		d.Greeting = "Hi"
		if err != nil || g.WidgetSettings != d {
			t.Fatalf("%+v %v", g.WidgetSettings, err)
		}
	})
	t.Run("Migration - widget_settings not an object - refused by the table check", func(t *testing.T) {
		ctx := t.Context()
		if _, err := s.db.Exec(ctx, `UPDATE apps SET widget_settings = '[]' WHERE org_id = $1`, org.ID); err == nil {
			t.Fatal("accepted")
		}
	})
}

func TestPublicWidgetSettings(t *testing.T) {
	s := setup(t)
	org, _ := seed(t, s)
	srv, _ := server(t, s)
	a, err := s.apps.Create(t.Context(), org, owner, "Shop", []string{shop})
	if err != nil {
		t.Fatal(err)
	}
	want := apps.WidgetSettings{Position: "bottom-left", Theme: "default", Mode: "light", Lang: "en", Accent: "ops", Greeting: "Hi there"}
	if _, err := s.apps.Update(t.Context(), org, owner, a.ID, apps.Change{Settings: &want}); err != nil {
		t.Fatal(err)
	}
	url := srv.URL + "/v1/apps/" + a.ID + "/widget-settings"

	get := func(t *testing.T, origin string) (int, http.Header, string) {
		t.Helper()
		req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, url, nil)
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = res.Body.Close() }()
		b, _ := io.ReadAll(res.Body)
		return res.StatusCode, res.Header, string(b)
	}
	t.Run("GetWidgetSettings - listed origin, no token - 200 stored settings, CORS, Vary, no-cache", func(t *testing.T) {
		status, h, body := get(t, shop)
		if status != http.StatusOK || h.Get("Access-Control-Allow-Origin") != shop ||
			h.Get("Vary") != "Origin" || h.Get("Cache-Control") != "no-cache" {
			t.Fatalf("%d %v %s", status, h, body)
		}
		if !strings.Contains(body, `"accent":"ops"`) || !strings.Contains(body, `"greeting":"Hi there"`) || strings.Contains(body, "Shop") {
			t.Fatalf("body %s", body)
		}
	})
	t.Run("GetWidgetSettings - other origin - 403 no-store, Vary, no CORS header", func(t *testing.T) {
		status, h, body := get(t, "https://evil.test")
		if status != http.StatusForbidden || h.Get("Access-Control-Allow-Origin") != "" ||
			h.Get("Vary") != "Origin" || h.Get("Cache-Control") != "no-store" || strings.Contains(body, "ops") {
			t.Fatalf("%d %v %s", status, h, body)
		}
	})
}
