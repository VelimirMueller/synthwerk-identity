package app_test

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/VelimirMueller/synthwerk-identity/internal/app"
)

// fakePinger stands in for the Postgres pool: err nil means the ping works.
type fakePinger struct{ err error }

func (p fakePinger) Ping(context.Context) error { return p.err }

// router builds the app around pinger and returns its handler.
func router(t *testing.T, pinger app.Pinger, started bool) http.Handler {
	t.Helper()
	logger := slog.New(slog.DiscardHandler)
	a, err := app.New(pinger, logger, app.Config{Version: "0.1.0-dev", Commit: "0000000", Env: "ci"})
	if err != nil {
		t.Fatal(err)
	}
	if started {
		a.Health.MarkStarted()
	}
	return a.Handler()
}

func get(t *testing.T, h http.Handler, path string) int {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, path, nil))
	return rec.Code
}

func TestHealthz(t *testing.T) {
	cases := []struct {
		name    string
		pinger  app.Pinger
		started bool
	}{
		{"startup not complete - still 200", fakePinger{}, false},
		{"postgres unreachable - still 200", fakePinger{err: errors.New("connection refused")}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if code := get(t, router(t, c.pinger, c.started), "/healthz"); code != http.StatusOK {
				t.Errorf("healthz: got %d, want 200", code)
			}
		})
	}
}

func TestReadyz(t *testing.T) {
	cases := []struct {
		name    string
		pinger  app.Pinger
		started bool
		want    int
	}{
		{"startup not complete - 503", fakePinger{}, false, http.StatusServiceUnavailable},
		{"postgres reachable - 200", fakePinger{}, true, http.StatusOK},
		{"postgres unreachable - 503", fakePinger{err: errors.New("connection refused")}, true, http.StatusServiceUnavailable},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if code := get(t, router(t, c.pinger, c.started), "/readyz"); code != c.want {
				t.Errorf("readyz: got %d, want %d", code, c.want)
			}
		})
	}
}
