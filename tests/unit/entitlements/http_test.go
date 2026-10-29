package entitlements_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/VelimirMueller/synthwerk-contracts/go/identity"
	"github.com/VelimirMueller/synthwerk-contracts/go/kit/auth"

	"github.com/VelimirMueller/synthwerk-identity/internal/entitlements"
	"github.com/VelimirMueller/synthwerk-identity/internal/orgs"
)

const (
	orgID     = "0199f3a0-5b6c-7d8e-9f0a-1b2c3d4e5f60"
	pendingID = "0199f3a0-5b6c-7d8e-9f0a-1b2c3d4e5f61"
	bareID    = "0199f3a0-5b6c-7d8e-9f0a-1b2c3d4e5f62" // active, no entitlements row
	zorg      = "300000000000000001"
	zpending  = "300000000000000002"
	zbare     = "300000000000000003"
	zother    = "300000000000000004"
)

type fakeOrgs struct{ err error }

var all = []orgs.Org{
	{ID: orgID, ZitadelOrgID: zorg, Status: "active"},
	{ID: pendingID, ZitadelOrgID: zpending, Status: "pending"},
	{ID: bareID, ZitadelOrgID: zbare, Status: "active"},
}

func (f fakeOrgs) find(match func(orgs.Org) bool) (orgs.Org, error) {
	if f.err != nil {
		return orgs.Org{}, f.err
	}
	for _, o := range all {
		if match(o) {
			return o, nil
		}
	}
	return orgs.Org{}, orgs.ErrNotFound
}

func (f fakeOrgs) OrgByID(_ context.Context, id string) (orgs.Org, error) {
	return f.find(func(o orgs.Org) bool { return o.ID == id })
}

func (f fakeOrgs) OrgByZitadelID(_ context.Context, zid string) (orgs.Org, error) {
	return f.find(func(o orgs.Org) bool { return o.ZitadelOrgID == zid })
}

type fakeRepo struct{}

func (fakeRepo) ByOrg(_ context.Context, id string) (entitlements.Entitlements, error) {
	if id != orgID {
		return entitlements.Entitlements{}, entitlements.ErrNotFound
	}
	return entitlements.Entitlements{OrgID: orgID, Plan: entitlements.Free, Limits: entitlements.FreeDefaults, Version: 2,
		UpdatedAt: time.Date(2026, 10, 29, 8, 0, 0, 0, time.FixedZone("CET", 3600))}, nil
}

// serve runs one request as p (nil: no principal) through the registered routes.
func serve(t *testing.T, o fakeOrgs, p *auth.Principal, path string) (int, []byte) {
	t.Helper()
	h := &entitlements.Handler{Orgs: o, Repo: fakeRepo{}, Log: slog.New(slog.DiscardHandler)}
	mux := http.NewServeMux()
	h.Register(mux, func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if p != nil {
				r = r.WithContext(auth.WithPrincipal(r.Context(), p))
			}
			next.ServeHTTP(w, r)
		})
	})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, path, nil))
	b, _ := io.ReadAll(rec.Body)
	return rec.Code, b
}

func user(zid string, roles ...string) *auth.Principal {
	return &auth.Principal{Subject: "100000000000000001", OrgID: zid, Roles: roles}
}

// strict decodes body into the contract type and refuses unknown fields.
func strict(t *testing.T, body []byte, v any) {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		t.Fatalf("body %s: %v", body, err)
	}
}

func TestHandler(t *testing.T) {
	ok := []struct{ name, path string }{{"GET /v1/me/entitlements", "/v1/me/entitlements"}, {"GET /v1/orgs/{orgId}/entitlements", "/v1/orgs/" + orgID + "/entitlements"}}
	for _, r := range ok {
		t.Run(r.name+" - member token - 200 contract body", func(t *testing.T) {
			st, body := serve(t, fakeOrgs{}, user(zorg, "member"), r.path)
			if st != http.StatusOK {
				t.Fatalf("%d %s", st, body)
			}
			var e identity.Entitlements
			strict(t, body, &e)
			if e.OrgId.String() != orgID || e.Plan != "free" || e.Version != 2 || e.Limits.LlmTokensPerUserPerDay != 50000 ||
				e.Limits.LlmTokensPerOrgPerDay != 500000 || e.Limits.AppsPerOrg != 3 || e.UpdatedAt.Location() != time.UTC {
				t.Fatalf("got %+v", e)
			}
		})
	}

	notFound := []struct {
		name string
		p    *auth.Principal
		path string
	}{
		{"me - token without an org role", user(zorg), "/v1/me/entitlements"},
		{"me - operator of the platform org", user("300000000000000009", auth.RoleOperator), "/v1/me/entitlements"},
		{"me - org identity does not know", user(zother, "owner"), "/v1/me/entitlements"},
		{"me - pending org", user(zpending, "owner"), "/v1/me/entitlements"},
		{"org - token of another org", user(zother, "owner"), "/v1/orgs/" + orgID + "/entitlements"},
		{"org - own org, no org role", user(zorg), "/v1/orgs/" + orgID + "/entitlements"},
		{"org - pending org, operator", user(zother, auth.RoleOperator), "/v1/orgs/" + pendingID + "/entitlements"},
		{"org - malformed id", user(zorg, "owner"), "/v1/orgs/not-a-uuid/entitlements"},
	}
	for _, tc := range notFound {
		t.Run(tc.name+" - 404 not_found", func(t *testing.T) {
			st, body := serve(t, fakeOrgs{}, tc.p, tc.path)
			var p struct {
				Code   string `json:"code"`
				Status int    `json:"status"`
				Title  string `json:"title"`
				Type   string `json:"type"`
			}
			strict(t, body, &p)
			if st != http.StatusNotFound || p.Code != "not_found" || p.Status != 404 {
				t.Fatalf("%d %s", st, body)
			}
		})
	}

	t.Run("org - operator of another org - 200", func(t *testing.T) {
		if st, body := serve(t, fakeOrgs{}, user("300000000000000009", auth.RoleOperator), "/v1/orgs/"+orgID+"/entitlements"); st != http.StatusOK {
			t.Fatalf("%d %s", st, body)
		}
	})

	t.Run("me - no principal - 401 with WWW-Authenticate", func(t *testing.T) {
		st, body := serve(t, fakeOrgs{}, nil, "/v1/me/entitlements")
		if st != http.StatusUnauthorized {
			t.Fatalf("%d %s", st, body)
		}
	})

	t.Run("org - no principal - 401", func(t *testing.T) {
		if st, body := serve(t, fakeOrgs{}, nil, "/v1/orgs/"+orgID+"/entitlements"); st != http.StatusUnauthorized {
			t.Fatalf("%d %s", st, body)
		}
	})

	t.Run("me - active org without a row - 500, never a 404", func(t *testing.T) {
		if st, body := serve(t, fakeOrgs{}, user(zbare, "owner"), "/v1/me/entitlements"); st != http.StatusInternalServerError {
			t.Fatalf("%d %s", st, body)
		}
	})

	t.Run("org - database down - 500 internal_error", func(t *testing.T) {
		st, body := serve(t, fakeOrgs{err: errors.New("db down")}, user(zorg, "owner"), "/v1/orgs/"+orgID+"/entitlements")
		if st != http.StatusInternalServerError || !bytes.Contains(body, []byte(`"code":"internal_error"`)) || bytes.Contains(body, []byte("db down")) {
			t.Fatalf("%d %s", st, body)
		}
	})
}

func TestChangedData(t *testing.T) {
	t.Run("ChangedData - marshal - exactly the fields of the contract schema", func(t *testing.T) {
		b, err := json.Marshal(entitlements.ChangedData{OrgID: orgID, Plan: "free", Version: 1, Reason: entitlements.ReasonPlanAssigned})
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]json.RawMessage
		_ = json.Unmarshal(b, &m)
		var limits map[string]json.RawMessage
		_ = json.Unmarshal(m["limits"], &limits)
		// events/identity/org.entitlements_changed.v1.schema.json in synthwerk-contracts.
		if len(m) != 5 || m["org_id"] == nil || m["plan"] == nil || m["version"] == nil || m["reason"] == nil ||
			len(limits) != 3 || limits["llm_tokens_per_user_per_day"] == nil || limits["llm_tokens_per_org_per_day"] == nil || limits["apps_per_org"] == nil {
			t.Fatalf("data %s", b)
		}
		if entitlements.Changed != "dev.synthwerk.identity.org.entitlements_changed.v1" ||
			entitlements.ChangedSchema != "https://schemas.synthwerk.dev/events/identity/org.entitlements_changed.v1.json" {
			t.Fatal("type or schema drifted from the contract")
		}
	})
}
