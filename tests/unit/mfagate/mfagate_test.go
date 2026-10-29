package mfagate_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/VelimirMueller/synthwerk-identity/internal/mfagate"
	"github.com/VelimirMueller/synthwerk-identity/internal/zitadelhook"
)

const (
	gateKey   = "gate-signing-key-0123456789abcdefghij"
	claimsKey = "claims-signing-key-0123456789abcdefgh"
	token     = "session-token-secret-value-do-not-log"
	userID    = "396374767738844424"
)

var now = time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)

// callback is a CreateCallback request execution as Zitadel v4.20.0 builds it
// (middleware.ContextInfoRequest; ids made up).
func callback(method, request string) string {
	return fmt.Sprintf(`{"fullMethod":%q,"instanceID":"396374393657259272","orgID":"396374393657324808","userID":"396374393657980168","request":%s,"headers":{"Content-Type":["application/grpc"]}}`, method, request)
}

const createCallback = "/zitadel.oidc.v2.OIDCService/CreateCallback"

var sessionRequest = `{"authRequestId":"V2_396375000000000001","session":{"sessionId":"396375000000000002","sessionToken":"` + token + `"}}`

type fakeSessions struct {
	factors mfagate.Factors
	err     error
	calls   int
}

func (f *fakeSessions) Session(_ context.Context, id, tok string) (mfagate.Factors, error) {
	f.calls++
	if id != "396375000000000002" || tok != token {
		return mfagate.Factors{}, fmt.Errorf("%w: status 403", mfagate.ErrSessionRefused)
	}
	return f.factors, f.err
}

type fakeStore struct {
	rows map[string]mfagate.Evidence
	err  error
}

func (f *fakeStore) Record(_ context.Context, e mfagate.Evidence) error {
	if f.err != nil {
		return f.err
	}
	if f.rows == nil {
		f.rows = map[string]mfagate.Evidence{}
	}
	f.rows[e.UserSub] = e
	return nil
}

func (f *fakeStore) Latest(_ context.Context, sub string) (mfagate.Evidence, error) {
	if f.err != nil {
		return mfagate.Evidence{}, f.err
	}
	e, ok := f.rows[sub]
	if !ok {
		return mfagate.Evidence{}, mfagate.ErrNoEvidence
	}
	return e, nil
}

func gate(s *fakeSessions, st *fakeStore, logs *bytes.Buffer) *mfagate.Gate {
	return &mfagate.Gate{
		Sessions:   s,
		Store:      st,
		SigningKey: func() (string, error) { return gateKey, nil },
		Log:        slog.New(slog.NewJSONHandler(logs, nil)),
		Now:        func() time.Time { return now },
	}
}

func post(h http.Handler, path, body, sig string) *httptest.ResponseRecorder {
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, path, strings.NewReader(body))
	if sig != "" {
		req.Header.Set(zitadelhook.SignatureHeader, sig)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// refused reports whether the answer makes Zitadel stop the call with 403.
func refused(t *testing.T, rec *httptest.ResponseRecorder) bool {
	t.Helper()
	if rec.Code != http.StatusOK {
		return false
	}
	var b struct {
		Status  int    `json:"forwardedStatusCode"`
		Message string `json:"forwardedErrorMessage"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &b); err != nil {
		t.Fatalf("body %q: %v", rec.Body, err)
	}
	return b.Status == http.StatusForbidden && strings.HasPrefix(b.Message, "mfa_required")
}

func TestAMR(t *testing.T) {
	cases := []struct {
		name string
		f    mfagate.Factors
		want []string
		mfa  bool
	}{
		{"password only - pwd, no mfa", mfagate.Factors{Password: true}, []string{"pwd"}, false},
		{"password and TOTP - pwd otp mfa", mfagate.Factors{Password: true, TOTP: true}, []string{"pwd", "otp", "mfa"}, true},
		{"passkey with user verification - user mfa", mfagate.Factors{WebAuthN: true, WebAuthNUserVerified: true}, []string{"user", "mfa"}, true},
		{"security key without user verification only - user, no mfa", mfagate.Factors{WebAuthN: true}, []string{"user"}, false},
		{"password and U2F - pwd user mfa", mfagate.Factors{Password: true, WebAuthN: true}, []string{"pwd", "user", "mfa"}, true},
		{"password and email code - pwd otp mfa", mfagate.Factors{Password: true, OTPEmail: true}, []string{"pwd", "otp", "mfa"}, true},
		{"TOTP only - otp, no mfa", mfagate.Factors{TOTP: true}, []string{"otp"}, false},
		{"identity provider only - no amr, no mfa", mfagate.Factors{Intent: true}, nil, false},
		{"no factor - no amr", mfagate.Factors{}, nil, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := mfagate.AMR(c.f); !slices.Equal(got, c.want) {
				t.Fatalf("AMR %v, want %v", got, c.want)
			}
			if got := mfagate.HasMFA(c.f); got != c.mfa {
				t.Fatalf("HasMFA %v, want %v", got, c.mfa)
			}
		})
	}
}

func TestGate(t *testing.T) {
	t.Run("CreateCallback - password-only session - refused with 403, no evidence, no token in logs", func(t *testing.T) {
		s, st, logs := &fakeSessions{factors: mfagate.Factors{UserID: userID, Password: true}}, &fakeStore{}, &bytes.Buffer{}
		body := callback(createCallback, sessionRequest)
		rec := post(gate(s, st, logs), mfagate.GatePath, body, zitadelhook.Sign([]byte(body), gateKey, now))
		if !refused(t, rec) {
			t.Fatalf("status %d, body %q: want a forwarded 403", rec.Code, rec.Body)
		}
		if len(st.rows) != 0 {
			t.Fatalf("evidence stored: %v", st.rows)
		}
		if strings.Contains(logs.String(), token) {
			t.Fatal("the session token is in the logs")
		}
		if !strings.Contains(logs.String(), `"reason":"mfa_missing"`) {
			t.Fatalf("logs %s", logs)
		}
	})
	for _, c := range []struct {
		name string
		f    mfagate.Factors
		amr  []string
	}{
		{"passkey", mfagate.Factors{UserID: userID, WebAuthN: true, WebAuthNUserVerified: true}, []string{"user", "mfa"}},
		{"password and TOTP", mfagate.Factors{UserID: userID, Password: true, TOTP: true}, []string{"pwd", "otp", "mfa"}},
	} {
		t.Run("CreateCallback - "+c.name+" session - passes unchanged, evidence stored", func(t *testing.T) {
			s, st, logs := &fakeSessions{factors: c.f}, &fakeStore{}, &bytes.Buffer{}
			body := callback(createCallback, sessionRequest)
			rec := post(gate(s, st, logs), mfagate.GatePath, body, zitadelhook.Sign([]byte(body), gateKey, now))
			if rec.Code != http.StatusNoContent || rec.Body.Len() != 0 {
				t.Fatalf("status %d, body %q: want 204 without body", rec.Code, rec.Body)
			}
			e := st.rows[userID]
			if e.SessionID != "396375000000000002" || !slices.Equal(e.AMR, c.amr) || !e.CheckedAt.Equal(now) {
				t.Fatalf("evidence %+v", e)
			}
			if strings.Contains(logs.String(), token) {
				t.Fatal("the session token is in the logs")
			}
		})
	}
	t.Run("every gated method - password-only session - refused", func(t *testing.T) {
		for _, m := range mfagate.GatedMethods {
			s := &fakeSessions{factors: mfagate.Factors{UserID: userID, Password: true}}
			req := `{"deviceAuthorizationId":"d-1","samlRequestId":"s-1","authRequestId":"a-1","session":{"sessionId":"396375000000000002","sessionToken":"` + token + `"}}`
			body := callback(m, req)
			rec := post(gate(s, &fakeStore{}, &bytes.Buffer{}), mfagate.GatePath, body, zitadelhook.Sign([]byte(body), gateKey, now))
			if !refused(t, rec) || s.calls != 1 {
				t.Fatalf("%s: status %d, body %q, session reads %d", m, rec.Code, rec.Body, s.calls)
			}
		}
	})
	t.Run("error callback or device deny - passes, no session read", func(t *testing.T) {
		for _, c := range []struct{ method, req string }{
			{createCallback, `{"authRequestId":"V2_1","error":{"error":"ERROR_REASON_ACCESS_DENIED"}}`},
			{"/zitadel.oidc.v2.OIDCService/AuthorizeOrDenyDeviceAuthorization", `{"deviceAuthorizationId":"d-1","deny":{}}`},
		} {
			s := &fakeSessions{}
			body := callback(c.method, c.req)
			rec := post(gate(s, &fakeStore{}, &bytes.Buffer{}), mfagate.GatePath, body, zitadelhook.Sign([]byte(body), gateKey, now))
			if rec.Code != http.StatusNoContent || s.calls != 0 {
				t.Fatalf("%s: status %d, session reads %d", c.method, rec.Code, s.calls)
			}
		}
	})
	t.Run("no session, no error, unknown method, wrong session token - refused", func(t *testing.T) {
		for _, c := range []struct{ method, req string }{
			{createCallback, `{"authRequestId":"V2_1"}`},
			{createCallback, `{"authRequestId":"V2_1","session":{"sessionId":"396375000000000002"}}`},
			{"/zitadel.session.v2.SessionService/CreateSession", sessionRequest},
			{createCallback, `{"authRequestId":"V2_1","session":{"sessionId":"396375000000000002","sessionToken":"wrong"}}`},
		} {
			s := &fakeSessions{factors: mfagate.Factors{UserID: userID, WebAuthN: true, WebAuthNUserVerified: true}}
			body := callback(c.method, c.req)
			rec := post(gate(s, &fakeStore{}, &bytes.Buffer{}), mfagate.GatePath, body, zitadelhook.Sign([]byte(body), gateKey, now))
			if !refused(t, rec) {
				t.Fatalf("%s %s: status %d, body %q", c.method, c.req, rec.Code, rec.Body)
			}
		}
	})
	t.Run("Zitadel unreachable - 503, Zitadel stops the sign-in", func(t *testing.T) {
		s := &fakeSessions{err: errors.New("dial tcp: connection refused")}
		body := callback(createCallback, sessionRequest)
		rec := post(gate(s, &fakeStore{}, &bytes.Buffer{}), mfagate.GatePath, body, zitadelhook.Sign([]byte(body), gateKey, now))
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("status %d", rec.Code)
		}
	})
	t.Run("evidence store fails - passes, error logged", func(t *testing.T) {
		s := &fakeSessions{factors: mfagate.Factors{UserID: userID, Password: true, TOTP: true}}
		logs := &bytes.Buffer{}
		body := callback(createCallback, sessionRequest)
		rec := post(gate(s, &fakeStore{err: errors.New("db down")}, logs), mfagate.GatePath, body, zitadelhook.Sign([]byte(body), gateKey, now))
		if rec.Code != http.StatusNoContent || !strings.Contains(logs.String(), "mfa_gate.store_failed") {
			t.Fatalf("status %d, logs %s", rec.Code, logs)
		}
	})
	t.Run("unsigned, wrong key, old signature, GET - no session read", func(t *testing.T) {
		body := callback(createCallback, sessionRequest)
		for _, c := range []struct {
			method, sig string
			want        int
		}{
			{http.MethodPost, "", http.StatusUnauthorized},
			{http.MethodPost, zitadelhook.Sign([]byte(body), "other-key", now), http.StatusUnauthorized},
			{http.MethodPost, zitadelhook.Sign([]byte(body), gateKey, now.Add(-10*time.Minute)), http.StatusUnauthorized},
			{http.MethodGet, zitadelhook.Sign([]byte(body), gateKey, now), http.StatusMethodNotAllowed},
		} {
			s := &fakeSessions{factors: mfagate.Factors{UserID: userID, WebAuthN: true, WebAuthNUserVerified: true}}
			req := httptest.NewRequestWithContext(context.Background(), c.method, mfagate.GatePath, strings.NewReader(body))
			if c.sig != "" {
				req.Header.Set(zitadelhook.SignatureHeader, c.sig)
			}
			rec := httptest.NewRecorder()
			gate(s, &fakeStore{}, &bytes.Buffer{}).ServeHTTP(rec, req)
			if rec.Code != c.want || s.calls != 0 {
				t.Fatalf("%s sig %q: status %d, want %d, session reads %d", c.method, c.sig, rec.Code, c.want, s.calls)
			}
		}
	})
}

func claimsHandler(st *fakeStore) *mfagate.Claims {
	return &mfagate.Claims{
		Store:      st,
		SigningKey: func() (string, error) { return claimsKey, nil },
		Log:        slog.New(slog.DiscardHandler),
		Now:        func() time.Time { return now },
	}
}

// preAccessToken is a pre-access-token call as Zitadel v4.20.0 builds it (oidc.ContextInfo).
func preAccessToken(sub string) string {
	return `{"function":"function/preaccesstoken","userinfo":{"sub":"` + sub + `"},"user":{"id":"` + sub + `"},"org":{"id":"396374393657324808"},"application":{"client_id":"studio"}}`
}

func appended(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, body %q", rec.Code, rec.Body)
	}
	var b struct {
		AppendClaims []struct {
			Key   string `json:"key"`
			Value any    `json:"value"`
		} `json:"append_claims"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &b); err != nil {
		t.Fatal(err)
	}
	out := map[string]any{}
	for _, c := range b.AppendClaims {
		out[c.Key] = c.Value
	}
	return out
}

func TestClaims(t *testing.T) {
	fresh := &fakeStore{rows: map[string]mfagate.Evidence{userID: {UserSub: userID, SessionID: "s-1", AMR: []string{"pwd", "otp", "mfa"}, CheckedAt: now.Add(-time.Hour)}}}
	t.Run("pre-access-token - user with fresh evidence - amr appended", func(t *testing.T) {
		body := preAccessToken(userID)
		got := appended(t, post(claimsHandler(fresh), mfagate.ClaimsPath, body, zitadelhook.Sign([]byte(body), claimsKey, now)))
		amr, _ := got["amr"].([]any)
		if len(amr) != 3 || amr[2] != "mfa" {
			t.Fatalf("claims %v", got)
		}
	})
	t.Run("pre-access-token - no evidence, old evidence, store error - no amr", func(t *testing.T) {
		old := &fakeStore{rows: map[string]mfagate.Evidence{userID: {UserSub: userID, AMR: []string{"user", "mfa"}, CheckedAt: now.Add(-13 * time.Hour)}}}
		for name, st := range map[string]*fakeStore{"none": {}, "old": old, "error": {err: errors.New("db down")}} {
			body := preAccessToken(userID)
			if got := appended(t, post(claimsHandler(st), mfagate.ClaimsPath, body, zitadelhook.Sign([]byte(body), claimsKey, now))); len(got) != 0 {
				t.Fatalf("%s: claims %v", name, got)
			}
		}
	})
	t.Run("pre-access-token - MaxAge 30m, evidence 1h old - no amr", func(t *testing.T) {
		h := claimsHandler(fresh)
		h.MaxAge = 30 * time.Minute
		body := preAccessToken(userID)
		if got := appended(t, post(h, mfagate.ClaimsPath, body, zitadelhook.Sign([]byte(body), claimsKey, now))); len(got) != 0 {
			t.Fatalf("claims %v", got)
		}
	})
	t.Run("pre-userinfo function or other user - no amr", func(t *testing.T) {
		for _, body := range []string{
			strings.Replace(preAccessToken(userID), "preaccesstoken", "preuserinfo", 1),
			preAccessToken("100000000000000009"),
		} {
			if got := appended(t, post(claimsHandler(fresh), mfagate.ClaimsPath, body, zitadelhook.Sign([]byte(body), claimsKey, now))); len(got) != 0 {
				t.Fatalf("claims %v", got)
			}
		}
	})
	t.Run("signed with the gate key - 401", func(t *testing.T) {
		body := preAccessToken(userID)
		if rec := post(claimsHandler(fresh), mfagate.ClaimsPath, body, zitadelhook.Sign([]byte(body), gateKey, now)); rec.Code != http.StatusUnauthorized {
			t.Fatalf("status %d", rec.Code)
		}
	})
}
