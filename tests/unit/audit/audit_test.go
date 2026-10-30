package audit_test

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/VelimirMueller/synthwerk-contracts/go/identity"
	"github.com/VelimirMueller/synthwerk-contracts/go/kit/auth"
	"github.com/VelimirMueller/synthwerk-contracts/go/kit/auth/authtest"

	"github.com/VelimirMueller/synthwerk-identity/internal/app"
	"github.com/VelimirMueller/synthwerk-identity/internal/audit"
	"github.com/VelimirMueller/synthwerk-identity/internal/orgs"
)

const (
	orgID    = "0199f3a0-5b6c-7d8e-9f0a-1b2c3d4e5f60"
	zorg     = "300000000000000001"
	platform = "300000000000000009"
	ownerSub = "100000000000000001"
	adminSub = "100000000000000002" // token admin, stored member: demoted
	memSub   = "100000000000000004"
)

type fakeRepo struct{ roles map[string]orgs.Role }

func (fakeRepo) org() orgs.Org {
	return orgs.Org{ID: orgID, ZitadelOrgID: zorg, Name: "Acme", Slug: "acme", Status: "active", CreatedAt: time.Now()}
}

func (f fakeRepo) OrgByID(_ context.Context, id string) (orgs.Org, error) {
	if id != orgID {
		return orgs.Org{}, orgs.ErrNotFound
	}
	return f.org(), nil
}

func (f fakeRepo) OrgByZitadelID(context.Context, string) (orgs.Org, error) { return f.org(), nil }

func (f fakeRepo) MemberRole(_ context.Context, _, sub string) (orgs.Role, error) {
	if r, ok := f.roles[sub]; ok {
		return r, nil
	}
	return "", orgs.ErrNotFound
}

func (fakeRepo) ListMembers(context.Context, string, string, int) ([]orgs.Membership, error) {
	return nil, nil
}

func (fakeRepo) ChangeRole(context.Context, orgs.Org, string, string, orgs.Role) (orgs.Membership, bool, error) {
	return orgs.Membership{}, false, nil
}

// fakeAudit holds events with seq 1..n and answers like the store: seq < before, newest first.
type fakeAudit struct {
	events []audit.Event
	before int64
}

func (f *fakeAudit) List(_ context.Context, _ string, before int64, limit int) ([]audit.Event, error) {
	f.before = before
	var out []audit.Event
	for i := len(f.events) - 1; i >= 0 && len(out) < limit; i-- {
		if before == 0 || f.events[i].Seq < before {
			out = append(out, f.events[i])
		}
	}
	return out, nil
}

type pinger struct{}

func (pinger) Ping(context.Context) error { return nil }

func TestAuditList(t *testing.T) {
	iss := authtest.NewIssuer(t)
	cfg := iss.Config()
	cfg.Mapper = auth.ZitadelMapper{PlatformOrgID: platform}
	v, err := auth.NewVerifier(cfg)
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.DiscardHandler)
	oh := &orgs.Handler{Repo: fakeRepo{roles: map[string]orgs.Role{ownerSub: orgs.Owner, adminSub: orgs.Member, memSub: orgs.Member}}, Log: logger}
	t0 := time.Date(2026, 10, 30, 9, 0, 0, 0, time.UTC)
	fa := &fakeAudit{}
	for i := 1; i <= 3; i++ {
		fa.events = append(fa.events, audit.Event{Seq: int64(i), ID: "019a3c1f-0a1b-7c2d-8e3f-4a5b6c7d8e9" + string(rune('0'+i)),
			Type: orgs.RoleChanged, Actor: "user:" + ownerSub, Subject: memSub, Time: t0.Add(time.Duration(i) * time.Minute),
			Data: map[string]any{"org_id": orgID, "user_sub": memSub, "old_role": "member", "new_role": "admin"}})
	}
	fa.events[0].Subject = ""
	a, err := app.New(pinger{}, logger, app.Config{Version: "0.1.0-dev", Commit: "0000000", Env: "ci", Verifier: v, Orgs: oh,
		Audit: &audit.Handler{Repo: fa, Orgs: oh}})
	if err != nil {
		t.Fatal(err)
	}
	h := a.Handler()
	path := "/v1/orgs/" + orgID + "/audit-events"
	get := func(t *testing.T, url, tok string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, url, nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	owner := iss.Mint(t, authtest.Claims(ownerSub, zorg, "owner"))

	t.Run("ListAuditEvents - owner, two pages - newest first, cursor walks back", func(t *testing.T) {
		rec := get(t, path+"?limit=2", owner)
		var page identity.AuditEventPage
		if err := json.Unmarshal(rec.Body.Bytes(), &page); err != nil || rec.Code != http.StatusOK {
			t.Fatalf("%d %s", rec.Code, rec.Body)
		}
		if len(page.Items) != 2 || page.NextCursor == nil || !page.Items[0].Time.After(page.Items[1].Time) || page.Items[0].Data["new_role"] != "admin" {
			t.Fatalf("page 1: %+v", page)
		}
		rec = get(t, path+"?limit=2&cursor="+*page.NextCursor, owner)
		page = identity.AuditEventPage{}
		if err := json.Unmarshal(rec.Body.Bytes(), &page); err != nil || len(page.Items) != 1 || page.NextCursor != nil || fa.before != 2 {
			t.Fatalf("page 2: %d %s before=%d", rec.Code, rec.Body, fa.before)
		}
		if page.Items[0].Subject != nil {
			t.Fatalf("empty subject must be absent: %s", rec.Body)
		}
	})
	for _, c := range []struct {
		name, tok string
		want      int
	}{
		{"member token", iss.Mint(t, authtest.Claims(memSub, zorg, "member")), http.StatusForbidden},
		{"admin token, stored role member", iss.Mint(t, authtest.Claims(adminSub, zorg, "admin")), http.StatusForbidden},
		{"operator", iss.Mint(t, map[string]any{"sub": "100000000000000077", auth.ClaimOrgID: platform, auth.ClaimRoles: authtest.Roles(platform, "operator")}), http.StatusForbidden},
		{"token of another org", iss.Mint(t, authtest.Claims(ownerSub, "300000000000000002", "owner")), http.StatusNotFound},
	} {
		t.Run("ListAuditEvents - "+c.name+" - "+http.StatusText(c.want), func(t *testing.T) {
			if rec := get(t, path, c.tok); rec.Code != c.want {
				t.Fatalf("%d %s", rec.Code, rec.Body)
			}
		})
	}
	for _, q := range []string{"limit=0", "limit=101", "cursor=***", "cursor=MA", "cursor=" + strings.Repeat("A", 300)} {
		t.Run("ListAuditEvents - "+q+" - 400", func(t *testing.T) {
			if rec := get(t, path+"?"+q, owner); rec.Code != http.StatusBadRequest {
				t.Fatalf("%d", rec.Code)
			}
		})
	}
}
