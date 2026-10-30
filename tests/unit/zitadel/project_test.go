package zitadel_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/VelimirMueller/synthwerk-identity/internal/orgs"
	"github.com/VelimirMueller/synthwerk-identity/internal/zitadel"
)

func TestProject(t *testing.T) {
	t.Run("Resolve - fixed id - id, file not read", func(t *testing.T) {
		p := &zitadel.Project{ID: "proj-1", File: filepath.Join(t.TempDir(), "missing")}
		if id, err := p.Resolve(t.Context()); err != nil || id != "proj-1" {
			t.Fatalf("%q %v", id, err)
		}
	})
	t.Run("Resolve - nil or nothing set - ErrNotReady", func(t *testing.T) {
		var nilProject *zitadel.Project
		for _, p := range []*zitadel.Project{nilProject, {}} {
			if _, err := p.Resolve(t.Context()); !errors.Is(err, orgs.ErrNotReady) {
				t.Fatalf("err %v", err)
			}
		}
	})
	t.Run("Resolve - file written after the start - ErrNotReady first, then the id, then kept", func(t *testing.T) {
		file := filepath.Join(t.TempDir(), "project-id")
		p := &zitadel.Project{File: file}
		if _, err := p.Resolve(t.Context()); !errors.Is(err, orgs.ErrNotReady) {
			t.Fatalf("missing file: %v", err)
		}
		if err := os.WriteFile(file, []byte("  \n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := p.Resolve(t.Context()); !errors.Is(err, orgs.ErrNotReady) {
			t.Fatalf("empty file: %v", err)
		}
		if err := os.WriteFile(file, []byte("397000000000000777\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if id, err := p.Resolve(t.Context()); err != nil || id != "397000000000000777" {
			t.Fatalf("%q %v", id, err)
		}
		if err := os.Remove(file); err != nil {
			t.Fatal(err)
		}
		if id, err := p.Resolve(t.Context()); err != nil || id != "397000000000000777" {
			t.Fatalf("cached: %q %v", id, err)
		}
	})
	t.Run("Resolve - file holds no id - ErrNotReady, not kept", func(t *testing.T) {
		file := filepath.Join(t.TempDir(), "project-id")
		if err := os.WriteFile(file, []byte("not an id\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		p := &zitadel.Project{File: file}
		if _, err := p.Resolve(t.Context()); !errors.Is(err, orgs.ErrNotReady) {
			t.Fatalf("err %v", err)
		}
	})
}

func TestProjectNotReady(t *testing.T) {
	newClient := func(f *zitadelFake) *zitadel.Client {
		srv := httptest.NewServer(f)
		t.Cleanup(srv.Close)
		return &zitadel.Client{BaseURL: srv.URL, Host: "auth.localhost:8080", Project: &zitadel.Project{File: filepath.Join(t.TempDir(), "project-id")},
			Token: func() (string, error) { return "pat", nil }}
	}
	t.Run("Invite - project id not known yet - ErrNotReady, no Zitadel call", func(t *testing.T) {
		f := &zitadelFake{}
		if _, _, err := newClient(f).Invite(t.Context(), "org-1", "ada@example.com", orgs.Member); !errors.Is(err, orgs.ErrNotReady) {
			t.Fatalf("err %v", err)
		}
		if len(f.calls) != 0 {
			t.Fatalf("calls %v", f.calls)
		}
	})
	t.Run("SetActive - no grant id, project id not known yet - ErrNotReady, no write", func(t *testing.T) {
		f := &zitadelFake{grantKeys: `["member"]`}
		if err := newClient(f).SetActive(t.Context(), "org-1", "u-1", "", false); !errors.Is(err, orgs.ErrNotReady) {
			t.Fatalf("err %v", err)
		}
		if slices.ContainsFunc(f.calls, func(c string) bool { return c != "GET /auth/v1/users/me" }) {
			t.Fatalf("calls %v", f.calls)
		}
	})
}

func TestGrantActive(t *testing.T) {
	serve := func(status int, body string) *zitadel.Client {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet || r.URL.Path != "/management/v1/users/u-1/grants/g-1" || r.Header.Get("x-zitadel-orgid") != "org-1" {
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}
			w.WriteHeader(status)
			_, _ = w.Write([]byte(body))
		}))
		t.Cleanup(srv.Close)
		return &zitadel.Client{BaseURL: srv.URL, Host: "auth.localhost:8080", Token: func() (string, error) { return "pat", nil }}
	}
	for _, tc := range []struct {
		name   string
		status int
		body   string
		want   bool
		err    bool
	}{
		{"active grant - true", 200, `{"userGrant":{"state":"USER_GRANT_STATE_ACTIVE"}}`, true, false},
		{"inactive grant - false", 200, `{"userGrant":{"state":"USER_GRANT_STATE_INACTIVE"}}`, false, false},
		{"no state - false", 200, `{"userGrant":{}}`, false, false},
		{"grant gone (404) - false", 404, `{"code":5,"message":"not found"}`, false, false},
		{"Zitadel refuses - error", 403, `{"code":7,"message":"No matching permissions found"}`, false, true},
	} {
		t.Run("GrantActive - "+tc.name, func(t *testing.T) {
			got, err := serve(tc.status, tc.body).GrantActive(t.Context(), "org-1", "u-1", "g-1")
			if got != tc.want || (err != nil) != tc.err {
				t.Fatalf("got %v err %v", got, err)
			}
		})
	}
}
