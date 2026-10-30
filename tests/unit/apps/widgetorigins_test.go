package apps_test

import (
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/VelimirMueller/synthwerk-identity/internal/apps"
)

func originPath(origins ...string) string {
	q := url.Values{}
	for _, o := range origins {
		q.Add("origin", o)
	}
	return apps.WidgetOriginsPath + "?" + q.Encode()
}

func TestWidgetOrigins(t *testing.T) {
	t.Run("WidgetOrigin - listed origin, no token - 204, no-store, no body", func(t *testing.T) {
		f := newFixture(t)
		rec := f.do(t, http.MethodGet, originPath(shop), "", "")
		if rec.Code != http.StatusNoContent || rec.Body.Len() != 0 || rec.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("%d %v %s", rec.Code, rec.Header(), rec.Body)
		}
	})
	t.Run("WidgetOrigin - listed origin in upper case with the default port - 204, store gets the canonical form", func(t *testing.T) {
		f := newFixture(t)
		rec := f.do(t, http.MethodGet, originPath("HTTPS://Shop.Example:443"), "", "")
		if rec.Code != http.StatusNoContent || !slices.Equal(f.apps.lookups, []string{shop}) {
			t.Fatalf("%d %v", rec.Code, f.apps.lookups)
		}
	})
	t.Run("WidgetOrigin - origin not listed - 404 not_found, no-store", func(t *testing.T) {
		f := newFixture(t)
		rec := f.do(t, http.MethodGet, originPath("https://evil.test"), "", "")
		if rec.Code != http.StatusNotFound || !strings.Contains(rec.Body.String(), `"code":"not_found"`) || rec.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("%d %v %s", rec.Code, rec.Header(), rec.Body)
		}
	})
	bad := []struct {
		name string
		path string
	}{
		{"no origin parameter", apps.WidgetOriginsPath},
		{"two origin parameters", originPath(shop, shop)},
		{"empty origin", originPath("")},
		{"null origin", originPath("null")},
		{"origin with a path", originPath(shop + "/")},
		{"wildcard origin", originPath("https://*.shop.example")},
		{"http on a public host", originPath("http://shop.example")},
		{"origin with user info", originPath("https://a@shop.example")},
	}
	for _, c := range bad {
		t.Run("WidgetOrigin - "+c.name+" - 400 invalid_request, no lookup", func(t *testing.T) {
			f := newFixture(t)
			rec := f.do(t, http.MethodGet, c.path, "", "")
			if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), `"code":"invalid_request"`) || rec.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("%d %v %s", rec.Code, rec.Header(), rec.Body)
			}
			if len(f.apps.lookups) != 0 {
				t.Fatalf("lookups %v", f.apps.lookups)
			}
		})
	}
	t.Run("WidgetOrigin - store fails - 500, never 204", func(t *testing.T) {
		f := newFixture(t)
		f.apps.lookupErr = errors.New("db down")
		rec := f.do(t, http.MethodGet, originPath(shop), "", "")
		if rec.Code != http.StatusInternalServerError || rec.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("%d %v %s", rec.Code, rec.Header(), rec.Body)
		}
	})
	t.Run("WidgetOrigin - POST - 405, route is read only", func(t *testing.T) {
		f := newFixture(t)
		rec := f.do(t, http.MethodPost, originPath(shop), "", "")
		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("%d", rec.Code)
		}
	})
}
