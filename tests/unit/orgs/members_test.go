package orgs_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/VelimirMueller/synthwerk-contracts/go/kit/auth"
	"github.com/VelimirMueller/synthwerk-contracts/go/kit/auth/authtest"

	"github.com/VelimirMueller/synthwerk-identity/internal/app"
	"github.com/VelimirMueller/synthwerk-identity/internal/orgs"
)

const (
	orgID    = "0199f3a0-5b6c-7d8e-9f0a-1b2c3d4e5f60"
	zorg     = "300000000000000001"
	platform = "300000000000000009"
	ownerSub = "100000000000000001"
	adminSub = "100000000000000002"
	memSub   = "100000000000000004"
)

func TestAuthorizeStatus(t *testing.T) {
	m := func(r orgs.Role, s string) orgs.Membership { return orgs.Membership{Role: r, Status: s} }
	on := orgs.StatusActive
	cases := []struct {
		name          string
		actor, target orgs.Membership
		self          bool
		want          error
	}{
		{"admin deactivates member - allowed", m(orgs.Admin, on), m(orgs.Member, on), false, nil},
		{"member deactivates member - denied", m(orgs.Member, on), m(orgs.Member, on), false, orgs.ErrForbidden},
		{"deactivated admin - denied", m(orgs.Admin, orgs.StatusDeactivated), m(orgs.Member, on), false, orgs.ErrForbidden},
		{"admin deactivates owner - denied", m(orgs.Admin, on), m(orgs.Owner, on), false, orgs.ErrForbidden},
		{"owner deactivates owner - allowed", m(orgs.Owner, on), m(orgs.Owner, on), false, nil},
		{"admin deactivates self - own membership", m(orgs.Admin, on), m(orgs.Admin, on), true, orgs.ErrOwnMembership},
	}
	for _, c := range cases {
		t.Run("AuthorizeStatus - "+c.name, func(t *testing.T) {
			if got := orgs.AuthorizeStatus(c.actor, c.target, c.self); !errors.Is(got, c.want) {
				t.Fatalf("got %v, want %v", got, c.want)
			}
		})
	}
}

func TestAuthorizeInvite(t *testing.T) {
	on := orgs.StatusActive
	for _, c := range []struct {
		name  string
		actor orgs.Membership
		role  orgs.Role
		want  error
	}{
		{"admin invites member - allowed", orgs.Membership{Role: orgs.Admin, Status: on}, orgs.Member, nil},
		{"admin invites owner - denied", orgs.Membership{Role: orgs.Admin, Status: on}, orgs.Owner, orgs.ErrForbidden},
		{"owner invites owner - allowed", orgs.Membership{Role: orgs.Owner, Status: on}, orgs.Owner, nil},
		{"member invites member - denied", orgs.Membership{Role: orgs.Member, Status: on}, orgs.Member, orgs.ErrForbidden},
		{"no membership - denied", orgs.Membership{}, orgs.Member, orgs.ErrForbidden},
		{"operator role - denied", orgs.Membership{Role: orgs.Owner, Status: on}, "operator", orgs.ErrForbidden},
	} {
		t.Run("AuthorizeInvite - "+c.name, func(t *testing.T) {
			if got := orgs.AuthorizeInvite(c.actor, c.role); !errors.Is(got, c.want) {
				t.Fatalf("got %v, want %v", got, c.want)
			}
		})
	}
}

func TestValidEmail(t *testing.T) {
	for in, want := range map[string]bool{
		"ada@example.com":                  true,
		"a.b+c@sub.example.org":            true,
		"Ada <ada@example.com>":            false,
		"ada@localhost":                    false,
		"ada example@x.org":                false,
		"@example.com":                     false,
		"ada@":                             false,
		"":                                 false,
		strings.Repeat("a", 250) + "@x.io": false,
	} {
		if got := orgs.ValidEmail(in); got != want {
			t.Errorf("ValidEmail(%q) = %v, want %v", in, got, want)
		}
	}
}

// fakeRepo is orgs.Repo with one active org and stored roles.
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
	return []orgs.Membership{{UserSub: memSub, Role: orgs.Member, Status: orgs.StatusDeactivated, UpdatedAt: time.Now()}}, nil
}

func (fakeRepo) ChangeRole(context.Context, orgs.Org, string, string, orgs.Role) (orgs.Membership, bool, error) {
	return orgs.Membership{}, false, nil
}

// fakeWriter is orgs.MemberWriter. err is returned by every call when set.
type fakeWriter struct {
	err      error
	invited  []string
	statuses []string
	revoked  []string
}

func (f *fakeWriter) RevokeInvitation(_ context.Context, _ orgs.Org, _, id string) error {
	if f.err != nil {
		return f.err
	}
	f.revoked = append(f.revoked, id)
	return nil
}

func (f *fakeWriter) Invite(_ context.Context, _ orgs.Org, actor, email string, role orgs.Role) (orgs.Invitation, error) {
	if f.err != nil {
		return orgs.Invitation{}, f.err
	}
	f.invited = append(f.invited, email)
	return orgs.Invitation{ID: "019a3c1e-7a1b-7c2d-8e3f-4a5b6c7d8e9f", OrgID: orgID, Email: email, Role: role, InvitedBy: actor, CreatedAt: time.Now()}, nil
}

func (f *fakeWriter) ListInvitations(_ context.Context, _, before string, limit int) ([]orgs.Invitation, error) {
	all := []orgs.Invitation{
		{ID: "019a3c1e-7a1b-7c2d-8e3f-4a5b6c7d8e9f", Email: "b@example.com", Role: orgs.Member, InvitedBy: ownerSub, CreatedAt: time.Now()},
		{ID: "019a3c1e-7a1b-7c2d-8e3f-4a5b6c7d8e9e", Email: "a@example.com", Role: orgs.Admin, InvitedBy: ownerSub, CreatedAt: time.Now()},
	}
	var out []orgs.Invitation
	for _, i := range all {
		if (before == "" || i.ID < before) && len(out) < limit {
			out = append(out, i)
		}
	}
	return out, nil
}

func (f *fakeWriter) SetStatus(_ context.Context, _ orgs.Org, _, target string, active bool) (orgs.Membership, bool, error) {
	if f.err != nil {
		return orgs.Membership{}, false, f.err
	}
	s := orgs.StatusDeactivated
	if active {
		s = orgs.StatusActive
	}
	f.statuses = append(f.statuses, target+":"+s)
	return orgs.Membership{UserSub: target, Role: orgs.Member, Status: s, UpdatedAt: time.Now()}, true, nil
}

type pinger struct{}

func (pinger) Ping(context.Context) error { return nil }

func memberServer(t *testing.T, w *fakeWriter) (http.Handler, *authtest.Issuer) {
	t.Helper()
	iss := authtest.NewIssuer(t)
	cfg := iss.Config()
	cfg.Mapper = auth.ZitadelMapper{PlatformOrgID: platform}
	v, err := auth.NewVerifier(cfg)
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.DiscardHandler)
	repo := fakeRepo{roles: map[string]orgs.Role{ownerSub: orgs.Owner, adminSub: orgs.Admin, memSub: orgs.Member}}
	a, err := app.New(pinger{}, logger, app.Config{Version: "0.1.0-dev", Commit: "0000000", Env: "ci", Verifier: v,
		Orgs: &orgs.Handler{Repo: repo, Members: w, Log: logger}})
	if err != nil {
		t.Fatal(err)
	}
	return a.Handler(), iss
}

func call(t *testing.T, h http.Handler, method, path, tok, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), method, path, strings.NewReader(body))
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestMemberRoutes(t *testing.T) {
	w := &fakeWriter{}
	h, iss := memberServer(t, w)
	members := "/v1/orgs/" + orgID + "/members"
	owner := iss.Mint(t, authtest.Claims(ownerSub, zorg, "owner"))
	admin := iss.Mint(t, authtest.Claims(adminSub, zorg, "admin"))
	member := iss.Mint(t, authtest.Claims(memSub, zorg, "member"))
	operator := iss.Mint(t, map[string]any{"sub": "100000000000000077", auth.ClaimOrgID: platform, auth.ClaimRoles: authtest.Roles(platform, "operator")})

	t.Run("InviteMember - admin, valid body - 202 with the pending invitation, no subject id", func(t *testing.T) {
		rec := call(t, h, http.MethodPost, members, admin, `{"email":"ada@example.com","role":"member"}`)
		if rec.Code != http.StatusAccepted || !strings.Contains(rec.Body.String(), `"email":"ada@example.com"`) ||
			!strings.Contains(rec.Body.String(), `"invited_by":"`+adminSub+`"`) || strings.Contains(rec.Body.String(), "user_id") {
			t.Fatalf("%d %s", rec.Code, rec.Body)
		}
		if len(w.invited) != 1 || w.invited[0] != "ada@example.com" {
			t.Fatalf("invited %v", w.invited)
		}
	})
	for _, c := range []struct{ name, body string }{
		{"bad email", `{"email":"Ada <ada@example.com>","role":"member"}`},
		{"operator role", `{"email":"ada@example.com","role":"operator"}`},
		{"unknown field", `{"email":"ada@example.com","role":"member","x":1}`},
		{"no body", ``},
	} {
		t.Run("InviteMember - "+c.name+" - 400 invalid_request", func(t *testing.T) {
			if rec := call(t, h, http.MethodPost, members, owner, c.body); rec.Code != http.StatusBadRequest {
				t.Fatalf("%d %s", rec.Code, rec.Body)
			}
		})
	}
	t.Run("InviteMember - member token - 403 before any write", func(t *testing.T) {
		before := len(w.invited)
		if rec := call(t, h, http.MethodPost, members, member, `{"email":"bob@example.com","role":"member"}`); rec.Code != http.StatusForbidden || len(w.invited) != before {
			t.Fatalf("%d", rec.Code)
		}
	})
	t.Run("InviteMember - operator - 403", func(t *testing.T) {
		if rec := call(t, h, http.MethodPost, members, operator, `{"email":"bob@example.com","role":"member"}`); rec.Code != http.StatusForbidden {
			t.Fatalf("%d", rec.Code)
		}
	})
	t.Run("ListInvitations - owner, two pages - newest first, cursor", func(t *testing.T) {
		rec := call(t, h, http.MethodGet, "/v1/orgs/"+orgID+"/invitations?limit=1", owner, "")
		var page struct {
			Items      []struct{ Email string } `json:"items"`
			NextCursor string                   `json:"next_cursor"`
		}
		if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &page) != nil || len(page.Items) != 1 || page.Items[0].Email != "b@example.com" || page.NextCursor == "" {
			t.Fatalf("%d %s", rec.Code, rec.Body)
		}
		rec = call(t, h, http.MethodGet, "/v1/orgs/"+orgID+"/invitations?cursor="+page.NextCursor, owner, "")
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "a@example.com") || strings.Contains(rec.Body.String(), "b@example.com") {
			t.Fatalf("%d %s", rec.Code, rec.Body)
		}
	})
	for _, c := range []struct {
		name, tok, q string
		want         int
	}{
		{"member token", member, "", http.StatusForbidden},
		{"operator", operator, "", http.StatusForbidden},
		{"bad cursor", owner, "?cursor=bm9wZQ", http.StatusBadRequest},
		{"bad limit", owner, "?limit=0", http.StatusBadRequest},
	} {
		t.Run("ListInvitations - "+c.name+" - "+http.StatusText(c.want), func(t *testing.T) {
			if rec := call(t, h, http.MethodGet, "/v1/orgs/"+orgID+"/invitations"+c.q, c.tok, ""); rec.Code != c.want {
				t.Fatalf("%d %s", rec.Code, rec.Body)
			}
		})
	}
	invitation := "/v1/orgs/" + orgID + "/invitations/019a3c1e-7a1b-7c2d-8e3f-4a5b6c7d8e9f"
	t.Run("RevokeInvitation - admin - 204, store called with the id", func(t *testing.T) {
		rec := call(t, h, http.MethodDelete, invitation, admin, "")
		if rec.Code != http.StatusNoContent || len(w.revoked) != 1 || w.revoked[0] != "019a3c1e-7a1b-7c2d-8e3f-4a5b6c7d8e9f" {
			t.Fatalf("%d %s %v", rec.Code, rec.Body, w.revoked)
		}
	})
	for _, c := range []struct {
		name, tok, path string
		want            int
	}{
		{"member token", member, invitation, http.StatusForbidden},
		{"operator", operator, invitation, http.StatusForbidden},
		{"no uuid", owner, "/v1/orgs/" + orgID + "/invitations/nope", http.StatusNotFound},
	} {
		t.Run("RevokeInvitation - "+c.name+" - "+http.StatusText(c.want)+", no write", func(t *testing.T) {
			before := len(w.revoked)
			if rec := call(t, h, http.MethodDelete, c.path, c.tok, ""); rec.Code != c.want || len(w.revoked) != before {
				t.Fatalf("%d %s", rec.Code, rec.Body)
			}
		})
	}
	t.Run("DeactivateMember - owner - 200 deactivated", func(t *testing.T) {
		rec := call(t, h, http.MethodPost, members+"/"+memSub+":deactivate", owner, "")
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"status":"deactivated"`) {
			t.Fatalf("%d %s", rec.Code, rec.Body)
		}
	})
	t.Run("ReactivateMember - admin - 200 active", func(t *testing.T) {
		rec := call(t, h, http.MethodPost, members+"/"+memSub+":reactivate", admin, "")
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"status":"active"`) {
			t.Fatalf("%d %s", rec.Code, rec.Body)
		}
	})
	for _, p := range []string{memSub + ":delete", memSub, "bad%20id:deactivate"} {
		t.Run("MemberStatus - path "+p+" - 404", func(t *testing.T) {
			if rec := call(t, h, http.MethodPost, members+"/"+p, owner, ""); rec.Code != http.StatusNotFound {
				t.Fatalf("%d", rec.Code)
			}
		})
	}
	t.Run("DeactivateMember - member token - 403", func(t *testing.T) {
		if rec := call(t, h, http.MethodPost, members+"/"+adminSub+":deactivate", member, ""); rec.Code != http.StatusForbidden {
			t.Fatalf("%d", rec.Code)
		}
	})
	t.Run("ListMembers - owner - status in every item", func(t *testing.T) {
		rec := call(t, h, http.MethodGet, members, owner, "")
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"status":"deactivated"`) {
			t.Fatalf("%d %s", rec.Code, rec.Body)
		}
	})
	for _, c := range []struct {
		err    error
		status int
		code   string
	}{
		{orgs.ErrOwnMembership, http.StatusConflict, "own_membership"},
		{orgs.ErrLastOwner, http.StatusConflict, "last_owner"},
		{orgs.ErrMemberExists, http.StatusConflict, "member_exists"},
		{orgs.ErrUsersOff, http.StatusBadGateway, "upstream_unavailable"},
		{orgs.ErrForbidden, http.StatusForbidden, "forbidden"},
		{orgs.ErrNotFound, http.StatusNotFound, "not_found"},
		{context.DeadlineExceeded, http.StatusInternalServerError, "internal_error"},
	} {
		t.Run("Member writes - store says "+c.code+" - "+http.StatusText(c.status), func(t *testing.T) {
			w.err = c.err
			defer func() { w.err = nil }()
			for _, rec := range []*httptest.ResponseRecorder{
				call(t, h, http.MethodPost, members, owner, `{"email":"ada@example.com","role":"member"}`),
				call(t, h, http.MethodPost, members+"/"+memSub+":deactivate", owner, ""),
				call(t, h, http.MethodDelete, invitation, owner, ""),
			} {
				if rec.Code != c.status || !strings.Contains(rec.Body.String(), `"code":"`+c.code+`"`) {
					t.Fatalf("%d %s", rec.Code, rec.Body)
				}
			}
		})
	}
	t.Run("Member writes - Zitadel project id not known yet - 503 with Retry-After, not 502", func(t *testing.T) {
		w.err = fmt.Errorf("%w: %w", orgs.ErrUpstream, orgs.ErrNotReady)
		defer func() { w.err = nil }()
		for _, rec := range []*httptest.ResponseRecorder{
			call(t, h, http.MethodPost, members, owner, `{"email":"ada@example.com","role":"member"}`),
			call(t, h, http.MethodPost, members+"/"+memSub+":deactivate", owner, ""),
		} {
			if rec.Code != http.StatusServiceUnavailable || rec.Header().Get("Retry-After") != orgs.NotReadyRetryAfter ||
				!strings.Contains(rec.Body.String(), `"code":"upstream_unavailable"`) {
				t.Fatalf("%d %v %s", rec.Code, rec.Header(), rec.Body)
			}
		}
	})
}

func TestInviteRateLimit(t *testing.T) {
	t.Run("InviteMember - 11th invite of one caller in an hour - 429 rate_limited with Retry-After, no write", func(t *testing.T) {
		w := &fakeWriter{}
		h, iss := memberServer(t, w)
		owner := iss.Mint(t, authtest.Claims(ownerSub, zorg, "owner"))
		for i := range orgs.InvitesPerCaller {
			if rec := call(t, h, http.MethodPost, "/v1/orgs/"+orgID+"/members", owner, `{"email":"a@example.com","role":"member"}`); rec.Code != http.StatusAccepted {
				t.Fatalf("invite %d: %d", i, rec.Code)
			}
		}
		rec := call(t, h, http.MethodPost, "/v1/orgs/"+orgID+"/members", owner, `{"email":"a@example.com","role":"member"}`)
		if rec.Code != http.StatusTooManyRequests || !strings.Contains(rec.Body.String(), `"code":"rate_limited"`) ||
			rec.Header().Get("Retry-After") == "" || len(w.invited) != orgs.InvitesPerCaller {
			t.Fatalf("%d %s %v", rec.Code, rec.Body, rec.Header())
		}
	})
	t.Run("InviteLimiter - org limit across callers, window ends - allowed again", func(t *testing.T) {
		now := time.Date(2026, 10, 30, 9, 0, 0, 0, time.UTC)
		l := &orgs.InviteLimiter{PerCaller: 2, PerOrg: 3, Window: time.Hour, Now: func() time.Time { return now }}
		for _, c := range []string{"a", "a", "b"} {
			if ok, _ := l.Allow("org", c); !ok {
				t.Fatalf("caller %s refused", c)
			}
		}
		if ok, _ := l.Allow("org", "a"); ok {
			t.Fatal("caller limit not enforced")
		}
		ok, wait := l.Allow("org", "c")
		if ok || wait != time.Hour {
			t.Fatalf("org limit: %v %v", ok, wait)
		}
		if ok, _ := l.Allow("other", "c"); !ok {
			t.Fatal("other org refused")
		}
		now = now.Add(time.Hour)
		if ok, _ := l.Allow("org", "c"); !ok {
			t.Fatal("new window refused")
		}
	})
}
