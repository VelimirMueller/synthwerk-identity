package zitadel_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
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
