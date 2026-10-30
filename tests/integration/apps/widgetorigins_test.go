//go:build integration

package apps_test

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/VelimirMueller/synthwerk-identity/internal/apps"
)

func TestWidgetOrigins(t *testing.T) {
	s := setup(t)
	org, other := seed(t, s)
	srv, _ := server(t, s)
	if _, err := s.apps.Create(t.Context(), org, owner, "Shop", []string{shop, "http://localhost:3000"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.apps.Create(t.Context(), other, outsider, "Blog", []string{"https://blog.example"}); err != nil {
		t.Fatal(err)
	}
	ask := func(t *testing.T, origin string) (int, string) {
		t.Helper()
		return call(t, http.MethodGet, srv.URL+apps.WidgetOriginsPath+"?origin="+url.QueryEscape(origin), "", "", "")
	}

	t.Run("WidgetOrigin - origin listed by an app of an active org - 204", func(t *testing.T) {
		for _, o := range []string{shop, "http://localhost:3000", "https://blog.example", "HTTPS://SHOP.EXAMPLE:443"} {
			if status, body := ask(t, o); status != http.StatusNoContent {
				t.Fatalf("%s: %d %s", o, status, body)
			}
		}
	})
	t.Run("WidgetOrigin - origin of no app, subdomain and other port - 404", func(t *testing.T) {
		for _, o := range []string{"https://evil.test", "https://a.shop.example", "https://shop.example:8443", "http://localhost:3001"} {
			if status, body := ask(t, o); status != http.StatusNotFound {
				t.Fatalf("%s: %d %s", o, status, body)
			}
		}
	})
	t.Run("WidgetOrigin - invalid origin - 400", func(t *testing.T) {
		if status, body := ask(t, "null"); status != http.StatusBadRequest {
			t.Fatalf("%d %s", status, body)
		}
	})
	t.Run("WidgetOrigin - org of the only app not active - 404", func(t *testing.T) {
		if _, err := s.db.Exec(t.Context(), `UPDATE identity.orgs SET status = 'pending' WHERE id = $1`, other.ID); err != nil {
			t.Fatal(err)
		}
		if status, body := ask(t, "https://blog.example"); status != http.StatusNotFound {
			t.Fatalf("%d %s", status, body)
		}
		if status, body := ask(t, shop); status != http.StatusNoContent {
			t.Fatalf("active org: %d %s", status, body)
		}
	})
	t.Run("Migration - GIN index on allowed_origins - present", func(t *testing.T) {
		if n := count(t, s.db, `SELECT count(*) FROM pg_indexes WHERE schemaname = 'identity' AND indexname = 'apps_allowed_origins'`); n != 1 {
			t.Fatalf("index count %d", n)
		}
	})
}
