//go:build integration

package account_test

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/VelimirMueller/synthwerk-contracts/go/kit/auth"
	"github.com/VelimirMueller/synthwerk-contracts/go/kit/auth/authtest"

	"github.com/VelimirMueller/synthwerk-identity/internal/account"
	"github.com/VelimirMueller/synthwerk-identity/internal/app"
	"github.com/VelimirMueller/synthwerk-identity/internal/mfagate"
)

// TestDeleteHTTP runs DELETE /v1/me through the app router with real token checks
// and Postgres. The access token has the shape of Zitadel v4.20: amr from the MFA
// gate, no sid and no auth_time (synthwerk-infra#18).
func TestDeleteHTTP(t *testing.T) {
	iss := authtest.NewIssuer(t)
	v, err := auth.NewVerifier(iss.Config())
	if err != nil {
		t.Fatal(err)
	}
	base := iss.IDTokenConfig()
	base.Audiences = nil

	run := func(t *testing.T, f fixture, sub, idToken string) *httptest.ResponseRecorder {
		t.Helper()
		h := &account.Handler{
			Repo: f.store, Evidence: mfagate.Postgres{DB: f.db}, Log: slog.New(slog.DiscardHandler), Now: time.Now,
			IDTokens: &account.ClientIDTokens{Base: base, ClientIDs: []string{authtest.ClientID}},
		}
		a, err := app.New(f.db, slog.New(slog.DiscardHandler), app.Config{Version: "test", Commit: "0000000", Verifier: v, Account: h})
		if err != nil {
			t.Fatal(err)
		}
		access := iss.Mint(t, map[string]any{"sub": sub, auth.ClaimOrgID: zsolo, "amr": []string{"pwd", "otp", "mfa"}})
		req := httptest.NewRequestWithContext(t.Context(), http.MethodDelete, "/v1/me", nil)
		req.Header.Set("Authorization", "Bearer "+access)
		if idToken != "" {
			req.Header.Set(account.IDTokenHeader, idToken)
		}
		rec := httptest.NewRecorder()
		a.Handler().ServeHTTP(rec, req)
		return rec
	}
	record := func(t *testing.T, f fixture, sub, sid string) {
		t.Helper()
		if err := (mfagate.Postgres{DB: f.db}).Record(t.Context(), mfagate.Evidence{UserSub: sub, SessionID: sid, AMR: []string{"pwd", "otp", "mfa"}, CheckedAt: time.Now()}); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("DeleteMe - Zitadel access token, no ID token - 403, nothing deleted", func(t *testing.T) {
		f := setup(t)
		grant(t, f.orgs, zsolo, alice, "owner")
		record(t, f, alice, "s-1")
		rec := run(t, f, alice, "")
		if rec.Code != http.StatusForbidden || count(t, f.db, `SELECT count(*) FROM identity.memberships WHERE user_sub = $1`, alice) != 1 {
			t.Fatalf("status %d: %s", rec.Code, rec.Body)
		}
	})

	t.Run("DeleteMe - fresh ID token with amr mfa - 202, account gone", func(t *testing.T) {
		f := setup(t)
		grant(t, f.orgs, zsolo, alice, "owner")
		id := iss.Mint(t, authtest.IDTokenClaims(alice, "s-1", time.Now().Add(-time.Minute), "pwd", "otp", "mfa"))
		rec := run(t, f, alice, id)
		if rec.Code != http.StatusAccepted || count(t, f.db, `SELECT count(*) FROM identity.memberships WHERE user_sub = $1`, alice) != 0 {
			t.Fatalf("status %d: %s", rec.Code, rec.Body)
		}
	})

	t.Run("DeleteMe - ID token without amr, gate evidence of its sid - 202", func(t *testing.T) {
		f := setup(t)
		grant(t, f.orgs, zsolo, alice, "owner")
		record(t, f, alice, "s-7")
		id := iss.Mint(t, authtest.IDTokenClaims(alice, "s-7", time.Now().Add(-time.Minute)))
		if rec := run(t, f, alice, id); rec.Code != http.StatusAccepted {
			t.Fatalf("status %d: %s", rec.Code, rec.Body)
		}
	})

	t.Run("DeleteMe - ID token of another user - 403, nothing deleted", func(t *testing.T) {
		f := setup(t)
		grant(t, f.orgs, zsolo, alice, "owner")
		id := iss.Mint(t, authtest.IDTokenClaims(bob, "s-1", time.Now().Add(-time.Minute), "mfa"))
		rec := run(t, f, alice, id)
		if rec.Code != http.StatusForbidden || count(t, f.db, `SELECT count(*) FROM identity.memberships WHERE user_sub = $1`, alice) != 1 {
			t.Fatalf("status %d: %s", rec.Code, rec.Body)
		}
	})
}
