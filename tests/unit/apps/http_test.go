package apps_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/VelimirMueller/synthwerk-contracts/go/kit/auth"
	"github.com/VelimirMueller/synthwerk-contracts/go/kit/auth/authtest"

	"github.com/VelimirMueller/synthwerk-identity/internal/app"
	"github.com/VelimirMueller/synthwerk-identity/internal/apps"
	"github.com/VelimirMueller/synthwerk-identity/internal/orgs"
	"github.com/VelimirMueller/synthwerk-identity/internal/widget"
)

const (
	orgID    = "0199f3a0-5b6c-7d8e-9f0a-1b2c3d4e5f60"
	zorg     = "300000000000000001"
	otherOrg = "300000000000000002"
	appID    = "019a3b10-7c2d-7e4f-8a5b-6c7d8e9f0a1b"
	owner    = "100000000000000001"
	member   = "100000000000000004"
	stranger = "100000000000000099" // token says member, the mirror has no row
	// deactivated: token says member, the stored membership is not active, so
	// MemberRole answers ErrNotFound like the real store (synthwerk#37).
	deactivated = "100000000000000098"
	platform    = "300000000000000009"
	shop        = "https://shop.example"
)

// fakeOrgs is orgs.Repo with one active org.
type fakeOrgs struct{ roles map[string]orgs.Role }

func (f fakeOrgs) org() orgs.Org {
	return orgs.Org{ID: orgID, ZitadelOrgID: zorg, Name: "Acme", Slug: "acme", Status: "active", CreatedAt: time.Now()}
}

func (f fakeOrgs) OrgByID(_ context.Context, id string) (orgs.Org, error) {
	if id != orgID {
		return orgs.Org{}, orgs.ErrNotFound
	}
	return f.org(), nil
}

func (f fakeOrgs) OrgByZitadelID(_ context.Context, id string) (orgs.Org, error) {
	if id != zorg {
		return orgs.Org{}, orgs.ErrNotFound
	}
	return f.org(), nil
}

func (f fakeOrgs) MemberRole(_ context.Context, _, sub string) (orgs.Role, error) {
	if r, ok := f.roles[sub]; ok {
		return r, nil
	}
	return "", orgs.ErrNotFound
}

func (fakeOrgs) ListMembers(context.Context, string, string, int) ([]orgs.Membership, error) {
	return nil, nil
}

func (fakeOrgs) ChangeRole(context.Context, orgs.Org, string, string, orgs.Role) (orgs.Membership, bool, error) {
	return orgs.Membership{}, false, nil
}

// fakeApps is apps.Repo with one app. created counts Create calls.
type fakeApps struct {
	roles    map[string]orgs.Role
	created  int
	limit    int32 // > 0: Create refuses with a LimitError
	settings *apps.WidgetSettings
}

func (f *fakeApps) app() apps.App {
	ws := apps.DefaultWidgetSettings()
	if f.settings != nil {
		ws = *f.settings
	}
	return apps.App{ID: appID, OrgID: orgID, Name: "Shop", AllowedOrigins: []string{shop, "http://localhost:3000"}, WidgetSettings: ws, CreatedAt: time.Now(), UpdatedAt: time.Now()}
}

func (f *fakeApps) ByID(_ context.Context, id string) (apps.App, error) {
	if id != appID {
		return apps.App{}, apps.ErrNotFound
	}
	return f.app(), nil
}

func (f *fakeApps) Get(ctx context.Context, org, id string) (apps.App, error) {
	if org != orgID {
		return apps.App{}, apps.ErrNotFound
	}
	return f.ByID(ctx, id)
}

func (f *fakeApps) List(context.Context, string, string, int) ([]apps.App, error) {
	return []apps.App{f.app()}, nil
}

func (f *fakeApps) Create(_ context.Context, _ orgs.Org, actor, name string, origins []string) (apps.App, error) {
	if !f.roles[actor].AtLeast(orgs.Admin) {
		return apps.App{}, apps.ErrForbidden
	}
	if f.limit > 0 {
		return apps.App{}, apps.LimitError{Limit: f.limit}
	}
	f.created++
	a := f.app()
	a.Name, a.AllowedOrigins = name, origins
	return a, nil
}

func (f *fakeApps) Update(ctx context.Context, _ orgs.Org, _, id string, c apps.Change) (apps.App, error) {
	if c.Settings != nil {
		f.settings = c.Settings
	}
	a, err := f.ByID(ctx, id)
	if c.Origins != nil {
		a.AllowedOrigins = c.Origins
	}
	return a, err
}

func (f *fakeApps) Delete(ctx context.Context, _ orgs.Org, _, id string) error {
	_, err := f.ByID(ctx, id)
	return err
}

type pinger struct{}

func (pinger) Ping(context.Context) error { return nil }

type fixture struct {
	h    http.Handler
	iss  *authtest.Issuer
	apps *fakeApps
	wi   *widget.Issuer
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	roles := map[string]orgs.Role{owner: orgs.Owner, member: orgs.Member}
	iss := authtest.NewIssuer(t)
	cfg := iss.Config()
	cfg.Mapper = auth.ZitadelMapper{PlatformOrgID: platform}
	v, err := auth.NewVerifier(cfg)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	wi, err := widget.NewIssuer(widget.Config{Issuer: "https://identity.synthwerk.test", Key: key})
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.DiscardHandler)
	oh := &orgs.Handler{Repo: fakeOrgs{roles: roles}, Log: logger}
	fa := &fakeApps{roles: roles}
	a, err := app.New(pinger{}, logger, app.Config{Version: "0.1.0-dev", Commit: "0000000", Env: "ci", Verifier: v, Orgs: oh,
		Apps: &apps.Handler{Repo: fa, Orgs: oh, Widget: wi, Log: logger}})
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{h: a.Handler(), iss: iss, apps: fa, wi: wi}
}

func (f *fixture) tok(t *testing.T, sub, zid string, roles ...string) string {
	t.Helper()
	return f.iss.Mint(t, authtest.Claims(sub, zid, roles...))
}

func (f *fixture) do(t *testing.T, method, path, tok, body string, origins ...string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), method, path, strings.NewReader(body))
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	for _, o := range origins {
		req.Header.Add("Origin", o)
	}
	rec := httptest.NewRecorder()
	f.h.ServeHTTP(rec, req)
	return rec
}

const tokens = "/v1/apps/" + appID + "/widget-tokens"

func TestWidgetToken(t *testing.T) {
	f := newFixture(t)
	memberTok := f.tok(t, member, zorg, "member")

	t.Run("CreateWidgetToken - member on a listed origin - 201, token bound to the origin, CORS header", func(t *testing.T) {
		rec := f.do(t, http.MethodPost, tokens, memberTok, "", shop)
		if rec.Code != http.StatusCreated {
			t.Fatalf("%d %s", rec.Code, rec.Body)
		}
		var body struct {
			AccessToken string `json:"access_token"`
			TokenType   string `json:"token_type"`
			ExpiresIn   int    `json:"expires_in"`
			Origin      string `json:"origin"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &body)
		if body.TokenType != "Bearer" || body.ExpiresIn < 1 || body.ExpiresIn > 900 || body.Origin != shop || body.AccessToken == "" {
			t.Fatalf("body %s", rec.Body)
		}
		if rec.Header().Get("Access-Control-Allow-Origin") != shop || rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("Vary") != "Origin" {
			t.Fatalf("headers %v", rec.Header())
		}
	})

	refused := []struct {
		name    string
		origins []string
	}{
		{"origin not listed", []string{"https://evil.test"}},
		{"suffix of a listed origin", []string{"https://shop.example.evil.test"}},
		{"subdomain of a listed origin", []string{"https://a.shop.example"}},
		{"listed host, other scheme", []string{"http://shop.example"}},
		{"listed host, other port", []string{"https://shop.example:8443"}},
		{"null origin", []string{"null"}},
		{"no Origin header", nil},
		{"two Origin headers", []string{shop, shop}},
	}
	for _, c := range refused {
		t.Run("CreateWidgetToken - "+c.name+" - 403 origin_not_allowed, no CORS header", func(t *testing.T) {
			rec := f.do(t, http.MethodPost, tokens, memberTok, "", c.origins...)
			if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), `"code":"origin_not_allowed"`) {
				t.Fatalf("%d %s", rec.Code, rec.Body)
			}
			if rec.Header().Get("Access-Control-Allow-Origin") != "" || strings.Contains(rec.Body.String(), "access_token") {
				t.Fatalf("leak: %v %s", rec.Header(), rec.Body)
			}
			if rec.Header().Get("Vary") != "Origin" || rec.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("cache headers %v", rec.Header())
			}
		})
	}

	notFound := []struct {
		name, path, tok string
	}{
		{"token of another org", tokens, f.tok(t, member, otherOrg, "member")},
		{"no stored membership", tokens, f.tok(t, stranger, zorg, "member")},
		{"deactivated member, token still has the role", tokens, f.tok(t, deactivated, zorg, "member")},
		{"token without an org role", tokens, f.tok(t, member, zorg)},
		{"unknown app", "/v1/apps/019a3b10-0000-7000-8000-000000000000/widget-tokens", memberTok},
		{"malformed app id", "/v1/apps/not-a-uuid/widget-tokens", memberTok},
	}
	for _, c := range notFound {
		t.Run("CreateWidgetToken - "+c.name+" - 404 even on a listed origin", func(t *testing.T) {
			if rec := f.do(t, http.MethodPost, c.path, c.tok, "", shop); rec.Code != http.StatusNotFound {
				t.Fatalf("%d %s", rec.Code, rec.Body)
			}
		})
	}

	t.Run("CreateWidgetToken - no user token - 401", func(t *testing.T) {
		if rec := f.do(t, http.MethodPost, tokens, "", "", shop); rec.Code != http.StatusUnauthorized {
			t.Fatalf("%d", rec.Code)
		}
	})
	t.Run("CreateWidgetToken - user token with an origin claim - 403", func(t *testing.T) {
		c := authtest.Claims(member, zorg, "member")
		c[auth.ClaimOrigin] = shop
		if rec := f.do(t, http.MethodPost, tokens, f.iss.Mint(t, c), "", shop); rec.Code != http.StatusForbidden {
			t.Fatalf("%d", rec.Code)
		}
	})
	t.Run("CreateWidgetToken - widget token as the bearer - 401, other issuer", func(t *testing.T) {
		wt, err := f.wi.Issue(widget.Subject{UserSub: member, ZitadelOrgID: zorg, AppID: appID, Origin: shop})
		if err != nil {
			t.Fatal(err)
		}
		if rec := f.do(t, http.MethodPost, tokens, wt.Raw, "", shop); rec.Code != http.StatusUnauthorized {
			t.Fatalf("%d", rec.Code)
		}
	})

	t.Run("Preflight - listed origin - 204 with CORS headers", func(t *testing.T) {
		rec := f.do(t, http.MethodOptions, tokens, "", "", shop)
		h := rec.Header()
		if rec.Code != http.StatusNoContent || h.Get("Access-Control-Allow-Origin") != shop || h.Get("Access-Control-Allow-Methods") != http.MethodPost ||
			!strings.Contains(h.Get("Access-Control-Allow-Headers"), "Authorization") || h.Get("Vary") != "Origin" {
			t.Fatalf("%d %v", rec.Code, h)
		}
	})
	t.Run("Preflight - origin not listed - 403 without CORS headers", func(t *testing.T) {
		rec := f.do(t, http.MethodOptions, tokens, "", "", "https://shop.example.evil.test")
		if rec.Code != http.StatusForbidden || rec.Header().Get("Access-Control-Allow-Origin") != "" ||
			rec.Header().Get("Vary") != "Origin" || rec.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("%d %v", rec.Code, rec.Header())
		}
	})
	t.Run("Key set - no token - 200 with one public key", func(t *testing.T) {
		rec := f.do(t, http.MethodGet, widget.JWKSPath, "", "")
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"kty":"EC"`) || strings.Contains(rec.Body.String(), `"d":`) {
			t.Fatalf("%d %s", rec.Code, rec.Body)
		}
	})
}

func TestAppRoutes(t *testing.T) {
	f := newFixture(t)
	list := "/v1/orgs/" + orgID + "/apps"
	ownerTok := f.tok(t, owner, zorg, "owner")

	t.Run("CreateApp - owner, valid origins - 201, canonical origins, Location", func(t *testing.T) {
		rec := f.do(t, http.MethodPost, list, ownerTok, `{"name":" Shop ","allowed_origins":["https://SHOP.example:443","http://localhost:3000"]}`)
		if rec.Code != http.StatusCreated || !strings.Contains(rec.Body.String(), `"allowed_origins":["https://shop.example","http://localhost:3000"]`) ||
			!strings.Contains(rec.Body.String(), `"name":"Shop"`) || rec.Header().Get("Location") != list+"/"+appID {
			t.Fatalf("%d %s %v", rec.Code, rec.Body, rec.Header())
		}
	})
	for _, c := range []struct{ name, body, detail string }{
		{"origin with a path", `{"name":"Shop","allowed_origins":["https://shop.example/"]}`, "allowed_origins[0]"},
		{"http on a public host", `{"name":"Shop","allowed_origins":["https://a.example","http://shop.example"]}`, "allowed_origins[1]"},
		{"wildcard", `{"name":"Shop","allowed_origins":["https://*.shop.example"]}`, "allowed_origins[0]"},
		{"duplicate after canonical form", `{"name":"Shop","allowed_origins":["https://a.example","https://A.example:443"]}`, "allowed_origins[1]"},
		{"empty list", `{"name":"Shop","allowed_origins":[]}`, "1 to 20"},
		{"blank name", `{"name":"  ","allowed_origins":["https://a.example"]}`, "name"},
		{"unknown field", `{"name":"Shop","allowed_origins":["https://a.example"],"x":1}`, "JSON"},
	} {
		t.Run("CreateApp - "+c.name+" - 400 invalid_request", func(t *testing.T) {
			rec := f.do(t, http.MethodPost, list, ownerTok, c.body)
			if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), c.detail) {
				t.Fatalf("%d %s", rec.Code, rec.Body)
			}
		})
	}
	t.Run("CreateApp - member token - 403, no write", func(t *testing.T) {
		before := f.apps.created
		rec := f.do(t, http.MethodPost, list, f.tok(t, member, zorg, "member"), `{"name":"Shop","allowed_origins":["https://a.example"]}`)
		if rec.Code != http.StatusForbidden || f.apps.created != before {
			t.Fatalf("%d", rec.Code)
		}
	})
	t.Run("CreateApp - admin token, stored role member - 403", func(t *testing.T) {
		rec := f.do(t, http.MethodPost, list, f.tok(t, member, zorg, "admin"), `{"name":"Shop","allowed_origins":["https://a.example"]}`)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("%d", rec.Code)
		}
	})
	t.Run("Operator - other org - CreateApp 403, ListApps 200, widget token 404", func(t *testing.T) {
		op := f.iss.Mint(t, map[string]any{"sub": "100000000000000077", auth.ClaimOrgID: platform, auth.ClaimRoles: authtest.Roles(platform, "operator")})
		if rec := f.do(t, http.MethodPost, list, op, `{"name":"Shop","allowed_origins":["https://a.example"]}`); rec.Code != http.StatusForbidden {
			t.Fatalf("POST %d", rec.Code)
		}
		if rec := f.do(t, http.MethodGet, list, op, ""); rec.Code != http.StatusOK {
			t.Fatalf("GET %d", rec.Code)
		}
		if rec := f.do(t, http.MethodPost, tokens, op, "", shop); rec.Code != http.StatusNotFound {
			t.Fatalf("widget token %d", rec.Code)
		}
	})
	t.Run("ListApps - member - 200 with one app", func(t *testing.T) {
		rec := f.do(t, http.MethodGet, list, f.tok(t, member, zorg, "member"), "")
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), appID) {
			t.Fatalf("%d %s", rec.Code, rec.Body)
		}
	})
	t.Run("ListApps - deactivated member, token still has the role - 404", func(t *testing.T) {
		if rec := f.do(t, http.MethodGet, list, f.tok(t, deactivated, zorg, "member"), ""); rec.Code != http.StatusNotFound {
			t.Fatalf("%d %s", rec.Code, rec.Body)
		}
	})
	t.Run("ListApps - bad cursor - 400", func(t *testing.T) {
		if rec := f.do(t, http.MethodGet, list+"?cursor=bm90LWEtdXVpZA", ownerTok, ""); rec.Code != http.StatusBadRequest {
			t.Fatalf("%d", rec.Code)
		}
	})
	t.Run("GetApp - token of another org - 404", func(t *testing.T) {
		if rec := f.do(t, http.MethodGet, list+"/"+appID, f.tok(t, owner, otherOrg, "owner"), ""); rec.Code != http.StatusNotFound {
			t.Fatalf("%d", rec.Code)
		}
	})
	t.Run("UpdateApp - empty body - 400", func(t *testing.T) {
		if rec := f.do(t, http.MethodPatch, list+"/"+appID, ownerTok, `{}`); rec.Code != http.StatusBadRequest {
			t.Fatalf("%d", rec.Code)
		}
	})
	t.Run("UpdateApp - owner, new origins - 200, canonical list replaces the old one", func(t *testing.T) {
		rec := f.do(t, http.MethodPatch, list+"/"+appID, ownerTok, `{"allowed_origins":["https://WWW.shop.example:443"]}`)
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"allowed_origins":["https://www.shop.example"]`) {
			t.Fatalf("%d %s", rec.Code, rec.Body)
		}
	})
	t.Run("DeleteApp - member - 403; owner - 204; unknown - 404", func(t *testing.T) {
		if rec := f.do(t, http.MethodDelete, list+"/"+appID, f.tok(t, member, zorg, "member"), ""); rec.Code != http.StatusForbidden {
			t.Fatalf("member %d", rec.Code)
		}
		if rec := f.do(t, http.MethodDelete, list+"/"+appID, ownerTok, ""); rec.Code != http.StatusNoContent {
			t.Fatalf("owner %d", rec.Code)
		}
		if rec := f.do(t, http.MethodDelete, list+"/019a3b10-0000-7000-8000-000000000000", ownerTok, ""); rec.Code != http.StatusNotFound {
			t.Fatalf("unknown %d", rec.Code)
		}
	})
}

const settingsPath = "/v1/apps/" + appID + "/widget-settings"

func TestWidgetSettings(t *testing.T) {
	f := newFixture(t)
	list := "/v1/orgs/" + orgID + "/apps"
	ownerTok := f.tok(t, owner, zorg, "owner")
	full := `{"widget_settings":{"position":"bottom-left","theme":"contrast","mode":"dark","lang":"de","accent":"lab","greeting":"  Hallo!\nWie kann ich helfen?  "}}`

	t.Run("GetWidgetSettings - new app, listed origin, no token - 200 defaults, CORS, Vary, no-cache, settings only", func(t *testing.T) {
		rec := f.do(t, http.MethodGet, settingsPath, "", "", shop)
		h := rec.Header()
		if rec.Code != http.StatusOK || h.Get("Access-Control-Allow-Origin") != shop || h.Get("Vary") != "Origin" || h.Get("Cache-Control") != "no-cache" {
			t.Fatalf("%d %v %s", rec.Code, h, rec.Body)
		}
		want := `{"accent":"flagship","greeting":"","lang":"auto","mode":"system","position":"bottom-right","theme":"default"}` + "\n"
		if rec.Body.String() != want {
			t.Fatalf("body %s", rec.Body)
		}
	})
	t.Run("UpdateApp - owner, widget settings - 200, greeting trimmed, public read shows them", func(t *testing.T) {
		rec := f.do(t, http.MethodPatch, list+"/"+appID, ownerTok, full)
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"greeting":"Hallo!\nWie kann ich helfen?"`) ||
			!strings.Contains(rec.Body.String(), `"accent":"lab"`) {
			t.Fatalf("%d %s", rec.Code, rec.Body)
		}
		got := f.do(t, http.MethodGet, settingsPath, "", "", "http://localhost:3000")
		if got.Code != http.StatusOK || !strings.Contains(got.Body.String(), `"position":"bottom-left"`) || strings.Contains(got.Body.String(), "shop.example") {
			t.Fatalf("%d %s", got.Code, got.Body)
		}
	})
	for _, c := range []struct{ name, body string }{
		{"free colour as accent", `{"widget_settings":{"position":"bottom-left","theme":"default","mode":"dark","lang":"de","accent":"#ff0000","greeting":""}}`},
		{"unknown theme", `{"widget_settings":{"position":"bottom-left","theme":"neon","mode":"dark","lang":"de","accent":"lab","greeting":""}}`},
		{"missing field", `{"widget_settings":{"position":"bottom-left","theme":"default","mode":"dark","lang":"de","greeting":""}}`},
		{"greeting too long", `{"widget_settings":{"position":"bottom-left","theme":"default","mode":"dark","lang":"de","accent":"lab","greeting":"` + strings.Repeat("a", 281) + `"}}`},
		{"control character in the greeting", `{"widget_settings":{"position":"bottom-left","theme":"default","mode":"dark","lang":"de","accent":"lab","greeting":"a\u0007b"}}`},
		{"unknown settings field", `{"widget_settings":{"position":"bottom-left","theme":"default","mode":"dark","lang":"de","accent":"lab","greeting":"","css":"x"}}`},
	} {
		t.Run("UpdateApp - "+c.name+" - 400 invalid_request, nothing stored", func(t *testing.T) {
			before := f.apps.settings
			rec := f.do(t, http.MethodPatch, list+"/"+appID, ownerTok, c.body)
			if rec.Code != http.StatusBadRequest || f.apps.settings != before {
				t.Fatalf("%d %s", rec.Code, rec.Body)
			}
		})
	}
	t.Run("UpdateApp - member token, widget settings - 403", func(t *testing.T) {
		if rec := f.do(t, http.MethodPatch, list+"/"+appID, f.tok(t, member, zorg, "member"), full); rec.Code != http.StatusForbidden {
			t.Fatalf("%d", rec.Code)
		}
	})

	for _, c := range []struct {
		name    string
		origins []string
	}{
		{"origin not listed", []string{"https://evil.test"}},
		{"suffix of a listed origin", []string{"https://shop.example.evil.test"}},
		{"no Origin header", nil},
		{"two Origin headers", []string{shop, shop}},
	} {
		t.Run("GetWidgetSettings - "+c.name+" - 403 origin_not_allowed, no CORS header, Vary, no-store", func(t *testing.T) {
			rec := f.do(t, http.MethodGet, settingsPath, "", "", c.origins...)
			h := rec.Header()
			if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), `"code":"origin_not_allowed"`) ||
				h.Get("Access-Control-Allow-Origin") != "" || h.Get("Vary") != "Origin" || h.Get("Cache-Control") != "no-store" {
				t.Fatalf("%d %v %s", rec.Code, h, rec.Body)
			}
		})
	}
	t.Run("GetWidgetSettings - unknown or malformed app - 404, Vary", func(t *testing.T) {
		for _, p := range []string{"/v1/apps/019a3b10-0000-7000-8000-000000000000/widget-settings", "/v1/apps/x/widget-settings"} {
			if rec := f.do(t, http.MethodGet, p, "", "", shop); rec.Code != http.StatusNotFound || rec.Header().Get("Vary") != "Origin" {
				t.Fatalf("%s %d %v", p, rec.Code, rec.Header())
			}
		}
	})
	t.Run("Preflight settings - listed origin - 204 GET only, Vary; other origin - 403 no-store, Vary", func(t *testing.T) {
		rec := f.do(t, http.MethodOptions, settingsPath, "", "", shop)
		h := rec.Header()
		if rec.Code != http.StatusNoContent || h.Get("Access-Control-Allow-Origin") != shop || h.Get("Access-Control-Allow-Methods") != http.MethodGet ||
			h.Get("Access-Control-Allow-Headers") != "" || h.Get("Vary") != "Origin" {
			t.Fatalf("%d %v", rec.Code, h)
		}
		rec = f.do(t, http.MethodOptions, settingsPath, "", "", "https://evil.test")
		if rec.Code != http.StatusForbidden || rec.Header().Get("Vary") != "Origin" || rec.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("%d %v", rec.Code, rec.Header())
		}
	})
	t.Run("CreateApp - org at its app limit - 403 app_limit_reached with the limit", func(t *testing.T) {
		f.apps.limit = 3
		defer func() { f.apps.limit = 0 }()
		rec := f.do(t, http.MethodPost, list, ownerTok, `{"name":"Fourth","allowed_origins":["https://a.example"]}`)
		if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), `"code":"app_limit_reached"`) ||
			!strings.Contains(rec.Body.String(), "allows 3 apps") {
			t.Fatalf("%d %s", rec.Code, rec.Body)
		}
	})
}
