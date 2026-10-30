package account_test

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/VelimirMueller/synthwerk-contracts/go/kit/auth"
	"github.com/VelimirMueller/synthwerk-contracts/go/kit/auth/authtest"

	"github.com/VelimirMueller/synthwerk-identity/internal/account"
)

// fakeIDTokens returns tok for the raw token "good" and the caller's subject.
type fakeIDTokens struct {
	tok *auth.IDToken
	err error
}

func (f fakeIDTokens) Verify(_ context.Context, raw, subject string) (*auth.IDToken, error) {
	if f.err != nil {
		return nil, f.err
	}
	if raw != "good" || f.tok == nil || f.tok.Subject != subject {
		return nil, fmt.Errorf("%w: refused", auth.ErrUnauthenticated)
	}
	return f.tok, nil
}

func idTok(authAge time.Duration, sid string, amr ...string) *auth.IDToken {
	return &auth.IDToken{Subject: sub, AuthTime: now.Add(-authAge), SessionID: sid, AMR: amr}
}

// zitadelUser is a Zitadel access token: amr from the gate, no sid, no auth_time.
func zitadelUser() *auth.Principal { return withRaw(user("pwd", "otp", "mfa"), map[string]any{}) }

func serveID(t *testing.T, h *account.Handler, p *auth.Principal, idToken string) *httptest.ResponseRecorder {
	t.Helper()
	if h.Log == nil {
		h.Log = slog.New(slog.DiscardHandler)
	}
	if h.Now == nil {
		h.Now = func() time.Time { return now }
	}
	mux := http.NewServeMux()
	h.Register(mux, func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, r.WithContext(auth.WithPrincipal(r.Context(), p)))
		})
	})
	req := httptest.NewRequestWithContext(t.Context(), http.MethodDelete, "/v1/me", nil)
	req.Header.Set("Authorization", "Bearer user-token")
	if idToken != "" {
		req.Header.Set(account.IDTokenHeader, idToken)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

func TestDeleteMeIDToken(t *testing.T) {
	for _, tc := range []struct {
		name string
		ids  fakeIDTokens
		ev   fakeEvidence
	}{
		{"ID token with amr mfa, sign-in 2 min old", fakeIDTokens{tok: idTok(2*time.Minute, "s-9", "pwd", "otp", "mfa")}, fakeEvidence{}},
		{"ID token without amr, its session has fresh gate evidence", fakeIDTokens{tok: idTok(2*time.Minute, "s-1")}, fresh(2 * time.Minute)},
		{"ID token with amr mfa, sign-in 15 min old", fakeIDTokens{tok: idTok(15*time.Minute, "", "mfa")}, fakeEvidence{}},
	} {
		t.Run("DeleteMe - Zitadel access token + "+tc.name+" - 202", func(t *testing.T) {
			repo := &fakeRepo{}
			rec := serveID(t, &account.Handler{Repo: repo, Evidence: tc.ev, IDTokens: tc.ids}, zitadelUser(), "good")
			if rec.Code != http.StatusAccepted || repo.calls != 1 {
				t.Fatalf("status %d, calls %d: %s", rec.Code, repo.calls, rec.Body)
			}
		})
	}

	for _, tc := range []struct {
		name    string
		p       *auth.Principal
		ids     account.IDTokens
		ev      fakeEvidence
		idToken string
	}{
		{"no header (Zitadel token has no sid, no auth_time)", zitadelUser(), fakeIDTokens{tok: idTok(time.Minute, "", "mfa")}, fresh(time.Minute), ""},
		{"header, but no ID token verifier configured", zitadelUser(), nil, fresh(time.Minute), "good"},
		{"ID token refused (signature, aud, exp or other sub)", zitadelUser(), fakeIDTokens{tok: idTok(time.Minute, "", "mfa")}, fresh(time.Minute), "forged"},
		{"ID token of another user", zitadelUser(), fakeIDTokens{tok: &auth.IDToken{Subject: "other", AuthTime: now, AMR: []string{"mfa"}}}, fresh(time.Minute), "good"},
		{"ID token sign-in 16 min old", zitadelUser(), fakeIDTokens{tok: idTok(16*time.Minute, "s-1", "mfa")}, fresh(time.Minute), "good"},
		{"ID token auth_time 2 min in the future", zitadelUser(), fakeIDTokens{tok: idTok(-2*time.Minute, "s-1", "mfa")}, fresh(time.Minute), "good"},
		{"ID token without mfa and without sid", zitadelUser(), fakeIDTokens{tok: idTok(time.Minute, "", "pwd")}, fresh(time.Minute), "good"},
		{"ID token without mfa, gate evidence of another session", zitadelUser(), fakeIDTokens{tok: idTok(time.Minute, "s-2", "pwd")}, fresh(time.Minute), "good"},
		{"ID token without mfa, gate evidence of its session 20 min old", zitadelUser(), fakeIDTokens{tok: idTok(time.Minute, "s-1", "pwd")}, fresh(20 * time.Minute), "good"},
		{"access token without amr mfa, fresh ID token", withRaw(user("pwd"), map[string]any{}), fakeIDTokens{tok: idTok(time.Minute, "", "mfa")}, fresh(time.Minute), "good"},
		{"header refused, token sid would match (no fallback)", user("mfa"), fakeIDTokens{tok: idTok(time.Minute, "", "mfa")}, fresh(time.Minute), "forged"},
	} {
		t.Run("DeleteMe - "+tc.name+" - 403 recent_mfa_required, nothing deleted", func(t *testing.T) {
			repo := &fakeRepo{}
			rec := serveID(t, &account.Handler{Repo: repo, Evidence: tc.ev, IDTokens: tc.ids}, tc.p, tc.idToken)
			if rec.Code != http.StatusForbidden || problemCode(t, rec) != account.CodeRecentMFARequired || repo.calls != 0 {
				t.Fatalf("status %d, calls %d: %s", rec.Code, repo.calls, rec.Body)
			}
		})
	}

	t.Run("DeleteMe - key set unavailable - 500 internal_error, nothing deleted", func(t *testing.T) {
		repo := &fakeRepo{}
		rec := serveID(t, &account.Handler{Repo: repo, Evidence: fresh(time.Minute), IDTokens: fakeIDTokens{err: auth.ErrUnavailable}}, zitadelUser(), "good")
		if rec.Code != http.StatusInternalServerError || repo.calls != 0 {
			t.Fatalf("status %d, calls %d: %s", rec.Code, repo.calls, rec.Body)
		}
	})

	t.Run("DeleteMe - evidence error on the sid path - 500", func(t *testing.T) {
		rec := serveID(t, &account.Handler{Repo: &fakeRepo{}, Evidence: fakeEvidence{err: errors.New("db down")}, IDTokens: fakeIDTokens{tok: idTok(time.Minute, "s-1", "pwd")}}, zitadelUser(), "good")
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("status %d: %s", rec.Code, rec.Body)
		}
	})
}

// TestDeleteMeRealIDToken runs the delete with ID tokens signed by a fake issuer
// and checked by ClientIDTokens (kit/auth IDTokenVerifier).
func TestDeleteMeRealIDToken(t *testing.T) {
	iss := authtest.NewIssuer(t)
	base := iss.IDTokenConfig()
	base.Audiences = nil
	handler := func(ids account.IDTokens, repo *fakeRepo) *account.Handler {
		return &account.Handler{Repo: repo, Evidence: fakeEvidence{}, IDTokens: ids, Now: time.Now, Log: slog.New(slog.DiscardHandler)}
	}
	zitadel := func() *auth.Principal {
		return &auth.Principal{Subject: sub, OrgID: "o", Roles: []string{"owner"}, AMR: []string{"pwd", "otp", "mfa"}, Raw: map[string]any{}}
	}
	recent := time.Now().Add(-time.Minute)

	t.Run("DeleteMe - ID token of the studio client - 202", func(t *testing.T) {
		repo := &fakeRepo{}
		ids := &account.ClientIDTokens{Base: base, ClientIDs: []string{authtest.ClientID}}
		rec := serveID(t, handler(ids, repo), zitadel(), iss.Mint(t, authtest.IDTokenClaims(sub, "s-1", recent, "pwd", "otp", "mfa")))
		if rec.Code != http.StatusAccepted || repo.calls != 1 {
			t.Fatalf("status %d, calls %d: %s", rec.Code, repo.calls, rec.Body)
		}
	})

	t.Run("DeleteMe - client id from studio-client.json - 202", func(t *testing.T) {
		f := filepath.Join(t.TempDir(), "studio-client.json")
		if err := os.WriteFile(f, []byte(`{"client_id":"`+authtest.ClientID+`","client_secret":"x"}`), 0o600); err != nil {
			t.Fatal(err)
		}
		repo := &fakeRepo{}
		ids := &account.ClientIDTokens{Base: base, ClientFile: f}
		rec := serveID(t, handler(ids, repo), zitadel(), iss.Mint(t, authtest.IDTokenClaims(sub, "s-1", recent, "mfa")))
		if rec.Code != http.StatusAccepted || repo.calls != 1 {
			t.Fatalf("status %d, calls %d: %s", rec.Code, repo.calls, rec.Body)
		}
	})

	for name, tc := range map[string]struct {
		ids   *account.ClientIDTokens
		token func(t *testing.T) string
	}{
		"access token in the header": {&account.ClientIDTokens{Base: base, ClientIDs: []string{authtest.ClientID}}, func(t *testing.T) string {
			return iss.Mint(t, map[string]any{"sub": sub, "aud": []string{authtest.ClientID}, "amr": []string{"mfa"}})
		}},
		"ID token of another client": {&account.ClientIDTokens{Base: base, ClientIDs: []string{"studio"}}, func(t *testing.T) string {
			return iss.Mint(t, authtest.IDTokenClaims(sub, "s-1", recent, "mfa"))
		}},
		"ID token of another user": {&account.ClientIDTokens{Base: base, ClientIDs: []string{authtest.ClientID}}, func(t *testing.T) string {
			return iss.Mint(t, authtest.IDTokenClaims("someone-else", "s-1", recent, "mfa"))
		}},
		"client file missing": {&account.ClientIDTokens{Base: base, ClientFile: filepath.Join(t.TempDir(), "nope.json")}, func(t *testing.T) string {
			return iss.Mint(t, authtest.IDTokenClaims(sub, "s-1", recent, "mfa"))
		}},
		"ID token signed by an unknown key": {&account.ClientIDTokens{Base: base, ClientIDs: []string{authtest.ClientID}}, func(t *testing.T) string {
			return iss.MintUnpublished(t, authtest.IDTokenClaims(sub, "s-1", recent, "mfa"))
		}},
		"sign-in 20 min old": {&account.ClientIDTokens{Base: base, ClientIDs: []string{authtest.ClientID}}, func(t *testing.T) string {
			return iss.Mint(t, authtest.IDTokenClaims(sub, "s-1", time.Now().Add(-20*time.Minute), "mfa"))
		}},
	} {
		t.Run("DeleteMe - "+name+" - 403 recent_mfa_required", func(t *testing.T) {
			repo := &fakeRepo{}
			rec := serveID(t, handler(tc.ids, repo), zitadel(), tc.token(t))
			if rec.Code != http.StatusForbidden || problemCode(t, rec) != account.CodeRecentMFARequired || repo.calls != 0 {
				t.Fatalf("status %d, calls %d: %s", rec.Code, repo.calls, rec.Body)
			}
		})
	}

	t.Run("ClientIDTokens - no client at all - ErrNoClients", func(t *testing.T) {
		_, err := (&account.ClientIDTokens{Base: base}).Verify(t.Context(), "x", sub)
		if !errors.Is(err, account.ErrNoClients) || !errors.Is(err, auth.ErrUnauthenticated) {
			t.Fatalf("got %v", err)
		}
	})

}
