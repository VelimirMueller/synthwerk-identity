package zitadel_test

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/VelimirMueller/synthwerk-identity/internal/orgs"
	"github.com/VelimirMueller/synthwerk-identity/internal/zitadel"
)

func TestSetRole(t *testing.T) {
	t.Run("SetRole - grant with end_user and member - end_user kept, member replaced, host and org header set", func(t *testing.T) {
		var put []string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Host != "auth.localhost:8080" || r.Header.Get("Authorization") != "Bearer pat" ||
				(r.URL.Path != "/auth/v1/users/me" && r.Header.Get("x-zitadel-orgid") != "org-1") {
				http.Error(w, "bad headers", http.StatusBadRequest)
				return
			}
			if r.URL.Path == "/auth/v1/users/me" {
				_, _ = w.Write([]byte(`{"user":{"details":{"resourceOwner":"platform-1"}}}`))
				return
			}
			if r.URL.Path != "/management/v1/users/u-1/grants/g-1" {
				http.NotFound(w, r)
				return
			}
			switch r.Method {
			case http.MethodGet:
				_, _ = w.Write([]byte(`{"userGrant":{"roleKeys":["member","end_user"]}}`))
			case http.MethodPut:
				var b struct {
					RoleKeys []string `json:"roleKeys"`
				}
				_ = json.NewDecoder(r.Body).Decode(&b)
				put = b.RoleKeys
				_, _ = w.Write([]byte(`{}`))
			}
		}))
		defer srv.Close()
		c := &zitadel.Client{BaseURL: srv.URL, Host: "auth.localhost:8080", Token: func() (string, error) { return "pat", nil }}
		if err := c.SetRole(t.Context(), "org-1", "u-1", "g-1", orgs.Admin); err != nil {
			t.Fatal(err)
		}
		if len(put) != 2 || put[0] != "admin" || put[1] != "end_user" {
			t.Fatalf("put %v", put)
		}
	})
	t.Run("SetRole - Zitadel refuses - error", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"code":7,"message":"No matching permissions found"}`))
		}))
		defer srv.Close()
		c := &zitadel.Client{BaseURL: srv.URL, Token: func() (string, error) { return "pat", nil }}
		var apiErr *zitadel.APIError
		if err := c.SetRole(t.Context(), "org-1", "u-1", "g-1", orgs.Admin); !errors.As(err, &apiErr) || apiErr.Code != 7 {
			t.Fatalf("err %v", err)
		}
	})
	t.Run("SetRole - platform org, operator grant or operator role - refused, no write", func(t *testing.T) {
		var puts int
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.URL.Path == "/auth/v1/users/me":
				_, _ = w.Write([]byte(`{"user":{"details":{"resourceOwner":"platform-1"}}}`))
			case r.Method == http.MethodGet:
				_, _ = w.Write([]byte(`{"userGrant":{"roleKeys":["operator","member"]}}`))
			default:
				puts++
				_, _ = w.Write([]byte(`{}`))
			}
		}))
		defer srv.Close()
		c := &zitadel.Client{BaseURL: srv.URL, Token: func() (string, error) { return "pat", nil }}
		for name, call := range map[string]func() error{
			"platform org":   func() error { return c.SetRole(t.Context(), "platform-1", "u-1", "g-1", orgs.Admin) },
			"operator grant": func() error { return c.SetRole(t.Context(), "org-1", "u-1", "g-1", orgs.Admin) },
			"operator role":  func() error { return c.SetRole(t.Context(), "org-1", "u-1", "g-1", orgs.Role("operator")) },
		} {
			if err := call(); !errors.Is(err, zitadel.ErrRefused) {
				t.Errorf("%s: err %v, want ErrRefused", name, err)
			}
		}
		if puts != 0 {
			t.Fatalf("%d writes", puts)
		}
	})
	t.Run("OrgName - from the grant - name", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/management/v1/users/u-1/grants/g-1" || r.Header.Get("x-zitadel-orgid") != "org-1" {
				http.NotFound(w, r)
				return
			}
			_, _ = w.Write([]byte(`{"userGrant":{"orgName":"Acme Labs"}}`))
		}))
		defer srv.Close()
		c := &zitadel.Client{BaseURL: srv.URL, Token: func() (string, error) { return "pat", nil }}
		if n, err := c.OrgName(t.Context(), "org-1", "u-1", "g-1"); err != nil || n != "Acme Labs" {
			t.Fatalf("%q %v", n, err)
		}
	})
}

// zitadelFake answers the calls of Invite and SetActive and records them.
type zitadelFake struct {
	calls     []string
	bodies    map[string]string
	userErr   int // status for POST /v2/users/human, 0 = 201
	grantErr  bool
	inOrg     bool // POST /v2/users finds the email in the org
	grantKeys string
	stateErr  bool
}

func (f *zitadelFake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if f.bodies == nil {
		f.bodies = map[string]string{}
	}
	b, _ := io.ReadAll(r.Body)
	key := r.Method + " " + r.URL.Path
	f.calls = append(f.calls, key)
	f.bodies[key] = string(b)
	if r.URL.Path != "/auth/v1/users/me" && r.Header.Get("x-zitadel-orgid") != "org-1" {
		http.Error(w, "org header", http.StatusBadRequest)
		return
	}
	switch key {
	case "GET /auth/v1/users/me":
		_, _ = w.Write([]byte(`{"user":{"details":{"resourceOwner":"platform-1"}}}`))
	case "POST /management/v1/granted_projects/_search":
		_, _ = w.Write([]byte(`{"result":[{"projectId":"other","grantId":"x"},{"projectId":"proj-1","grantId":"pg-1"}]}`))
	case "POST /v2/users/human":
		if f.userErr != 0 {
			w.WriteHeader(f.userErr)
			_, _ = w.Write([]byte(`{"code":6,"message":"Errors.User.AlreadyExists"}`))
			return
		}
		_, _ = w.Write([]byte(`{"userId":"u-9"}`))
	case "POST /v2/users":
		if f.inOrg {
			_, _ = w.Write([]byte(`{"result":[{"userId":"u-1"}]}`))
			return
		}
		_, _ = w.Write([]byte(`{"result":[]}`))
	case "POST /v2/users/u-9/invite_code":
		_, _ = w.Write([]byte(`{}`))
	case "POST /management/v1/users/u-9/grants":
		if f.grantErr {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"code":7,"message":"No matching permissions found"}`))
			return
		}
		_, _ = w.Write([]byte(`{"userGrantId":"g-9"}`))
	case "DELETE /v2/users/u-9":
		_, _ = w.Write([]byte(`{}`))
	case "GET /management/v1/users/u-1/grants/g-1":
		_, _ = w.Write([]byte(`{"userGrant":{"roleKeys":` + f.grantKeys + `}}`))
	case "POST /management/v1/users/u-1/grants/g-1/_deactivate", "POST /management/v1/users/u-1/grants/g-1/_reactivate":
		if f.stateErr {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"code":9,"message":"Errors.UserGrant.NotActive (not active)"}`))
			return
		}
		_, _ = w.Write([]byte(`{}`))
	default:
		http.NotFound(w, r)
	}
}

func newUsersClient(t *testing.T, f *zitadelFake) *zitadel.Client {
	t.Helper()
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return &zitadel.Client{BaseURL: srv.URL, Host: "auth.localhost:8080", ProjectID: "proj-1", Token: func() (string, error) { return "pat", nil }}
}

func TestInvite(t *testing.T) {
	t.Run("Invite - new email - user, invite mail, grant of the project grant with the role", func(t *testing.T) {
		f := &zitadelFake{}
		sub, grant, err := newUsersClient(t, f).Invite(t.Context(), "org-1", "ada@example.com", orgs.Admin)
		if err != nil || sub != "u-9" || grant != "g-9" {
			t.Fatalf("%q %q %v", sub, grant, err)
		}
		if !strings.Contains(f.bodies["POST /v2/users/human"], `"email":"ada@example.com"`) ||
			!strings.Contains(f.bodies["POST /v2/users/human"], `"orgId":"org-1"`) ||
			!strings.Contains(f.bodies["POST /v2/users/u-9/invite_code"], `"sendCode"`) ||
			f.bodies["POST /management/v1/users/u-9/grants"] != `{"projectGrantId":"pg-1","projectId":"proj-1","roleKeys":["admin"]}` {
			t.Fatalf("bodies %v", f.bodies)
		}
	})
	t.Run("Invite - email of a user of another org - ErrOutsideOrg, no grant, no mail", func(t *testing.T) {
		f := &zitadelFake{userErr: http.StatusConflict}
		if _, _, err := newUsersClient(t, f).Invite(t.Context(), "org-1", "ada@example.com", orgs.Member); !errors.Is(err, orgs.ErrOutsideOrg) {
			t.Fatalf("err %v", err)
		}
		if !strings.Contains(f.bodies["POST /v2/users"], `"organizationId":"org-1"`) || slices.Contains(f.calls, "POST /management/v1/users/u-9/grants") {
			t.Fatalf("calls %v %v", f.calls, f.bodies)
		}
	})
	t.Run("Invite - email of a user of this org - ErrMemberExists with the user id, no invite mail", func(t *testing.T) {
		f := &zitadelFake{userErr: http.StatusConflict, inOrg: true}
		sub, _, err := newUsersClient(t, f).Invite(t.Context(), "org-1", "ada@example.com", orgs.Member)
		if !errors.Is(err, orgs.ErrMemberExists) || sub != "u-1" {
			t.Fatalf("sub %q err %v", sub, err)
		}
		if slices.Contains(f.calls, "POST /v2/users/u-9/invite_code") {
			t.Fatal("invite code sent")
		}
	})
	t.Run("Invite - grant refused - user deleted again, no invite mail", func(t *testing.T) {
		f := &zitadelFake{grantErr: true}
		var apiErr *zitadel.APIError
		if _, _, err := newUsersClient(t, f).Invite(t.Context(), "org-1", "ada@example.com", orgs.Member); !errors.As(err, &apiErr) || apiErr.Code != 7 {
			t.Fatalf("err %v", err)
		}
		if !slices.Contains(f.calls, "DELETE /v2/users/u-9") || slices.Contains(f.calls, "POST /v2/users/u-9/invite_code") {
			t.Fatalf("calls %v", f.calls)
		}
	})
	t.Run("Uninvite - user gone already (404) - no error", func(t *testing.T) {
		f := &zitadelFake{}
		if err := newUsersClient(t, f).Uninvite(t.Context(), "org-1", "u-404"); err != nil || !slices.Contains(f.calls, "DELETE /v2/users/u-404") {
			t.Fatalf("err %v calls %v", err, f.calls)
		}
	})
	t.Run("Uninvite - Zitadel refuses - error", func(t *testing.T) {
		f := &zitadelFake{}
		if err := newUsersClient(t, f).Uninvite(t.Context(), "org-2", "u-9"); err == nil {
			t.Fatal("no error")
		}
	})
	t.Run("Uninvite - platform org - refused", func(t *testing.T) {
		if err := newUsersClient(t, &zitadelFake{}).Uninvite(t.Context(), "platform-1", "u-9"); !errors.Is(err, zitadel.ErrRefused) {
			t.Fatal(err)
		}
	})
	t.Run("Invite - platform org or operator role - refused, no write", func(t *testing.T) {
		f := &zitadelFake{}
		c := newUsersClient(t, f)
		if _, _, err := c.Invite(t.Context(), "platform-1", "ada@example.com", orgs.Member); !errors.Is(err, zitadel.ErrRefused) {
			t.Fatalf("platform: %v", err)
		}
		if _, _, err := c.Invite(t.Context(), "org-1", "ada@example.com", "operator"); !errors.Is(err, zitadel.ErrRefused) {
			t.Fatalf("operator: %v", err)
		}
		if slices.Contains(f.calls, "POST /v2/users/human") {
			t.Fatal("user written")
		}
	})
}

func TestSetActive(t *testing.T) {
	for _, active := range []bool{false, true} {
		verb := map[bool]string{false: "_deactivate", true: "_reactivate"}[active]
		t.Run("SetActive - "+verb+" - POST on the grant", func(t *testing.T) {
			f := &zitadelFake{grantKeys: `["member","end_user"]`}
			if err := newUsersClient(t, f).SetActive(t.Context(), "org-1", "u-1", "g-1", active); err != nil {
				t.Fatal(err)
			}
			if !slices.Contains(f.calls, "POST /management/v1/users/u-1/grants/g-1/"+verb) {
				t.Fatalf("calls %v", f.calls)
			}
		})
	}
	t.Run("SetActive - grant already in that state - no error", func(t *testing.T) {
		f := &zitadelFake{grantKeys: `["member"]`, stateErr: true}
		if err := newUsersClient(t, f).SetActive(t.Context(), "org-1", "u-1", "g-1", false); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("SetActive - grant with operator or platform org - refused, no write", func(t *testing.T) {
		f := &zitadelFake{grantKeys: `["operator"]`}
		c := newUsersClient(t, f)
		if err := c.SetActive(t.Context(), "org-1", "u-1", "g-1", false); !errors.Is(err, zitadel.ErrRefused) {
			t.Fatalf("operator: %v", err)
		}
		if err := c.SetActive(t.Context(), "platform-1", "u-1", "g-1", false); !errors.Is(err, zitadel.ErrRefused) {
			t.Fatalf("platform: %v", err)
		}
		if slices.Contains(f.calls, "POST /management/v1/users/u-1/grants/g-1/_deactivate") {
			t.Fatal("grant written")
		}
	})
}
