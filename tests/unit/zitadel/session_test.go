package zitadel_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/VelimirMueller/synthwerk-identity/internal/mfagate"
	"github.com/VelimirMueller/synthwerk-identity/internal/zitadel"
)

// session is a GetSession answer as Zitadel v4.20.0 sends it over Connect (protojson;
// ids made up).
const session = `{"session":{"id":"s-1","creationDate":"2026-10-29T12:00:00Z","sequence":"4",
"factors":{"user":{"verifiedAt":"2026-10-29T12:00:00Z","id":"u-1","loginName":"owner.demo","displayName":"Owner","organizationId":"o-1"},
"password":{"verifiedAt":"2026-10-29T12:00:01Z"},"totp":{"verifiedAt":"2026-10-29T12:00:02Z"}}}}`

func TestSession(t *testing.T) {
	t.Run("Session - password and TOTP - factors read, token in the body and not in the URL", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var b map[string]string
			_ = json.NewDecoder(r.Body).Decode(&b)
			if r.Method != http.MethodPost || r.URL.Path != "/zitadel.session.v2.SessionService/GetSession" || r.URL.RawQuery != "" ||
				r.Header.Get("Content-Type") != "application/json" || r.Header.Get("Authorization") != "Bearer pat" || r.Host != "auth.localhost:8080" ||
				b["sessionId"] != "s-1" || b["sessionToken"] != "tok" {
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}
			_, _ = w.Write([]byte(session))
		}))
		defer srv.Close()
		c := &zitadel.Client{BaseURL: srv.URL, Host: "auth.localhost:8080", Token: func() (string, error) { return "pat", nil }}
		f, err := c.Session(t.Context(), "s-1", "tok")
		if err != nil {
			t.Fatal(err)
		}
		want := mfagate.Factors{UserID: "u-1", Password: true, TOTP: true}
		if f != want {
			t.Fatalf("factors %+v, want %+v", f, want)
		}
	})
	t.Run("Session - passkey with user verification - WebAuthN and UserVerified", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"session":{"id":"s-1","factors":{"user":{"verifiedAt":"2026-10-29T12:00:00Z","id":"u-1"},"webAuthN":{"verifiedAt":"2026-10-29T12:00:01Z","userVerified":true}}}}`))
		}))
		defer srv.Close()
		c := &zitadel.Client{BaseURL: srv.URL, Token: func() (string, error) { return "pat", nil }}
		f, err := c.Session(t.Context(), "s-1", "tok")
		if err != nil || !f.WebAuthN || !f.WebAuthNUserVerified || f.Password || !mfagate.HasMFA(f) {
			t.Fatalf("factors %+v, err %v", f, err)
		}
	})
	t.Run("Session - wrong token (403) or no verified user - ErrSessionRefused; 503 - other error", func(t *testing.T) {
		for _, c := range []struct {
			status  int
			body    string
			refused bool
		}{
			{http.StatusForbidden, `{"code":"permission_denied","message":"Errors.PermissionDenied"}`, true},
			{http.StatusNotFound, `{"code":"not_found","message":"Errors.Session.NotFound"}`, true},
			{http.StatusOK, `{"session":{"id":"s-1","factors":{"password":{"verifiedAt":"2026-10-29T12:00:01Z"}}}}`, true},
			{http.StatusOK, `{"session":{"id":"s-2","factors":{"user":{"verifiedAt":"2026-10-29T12:00:00Z","id":"u-1"}}}}`, true},
			{http.StatusServiceUnavailable, `{"code":"unavailable"}`, false},
			{http.StatusUnauthorized, `{"code":"unauthenticated"}`, false},
		} {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(c.status)
				_, _ = w.Write([]byte(c.body))
			}))
			cl := &zitadel.Client{BaseURL: srv.URL, Token: func() (string, error) { return "pat", nil }}
			_, err := cl.Session(t.Context(), "s-1", "tok")
			srv.Close()
			if err == nil || errors.Is(err, mfagate.ErrSessionRefused) != c.refused {
				t.Fatalf("status %d: err %v, want refused %v", c.status, err, c.refused)
			}
		}
	})
}
