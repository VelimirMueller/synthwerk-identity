package account_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/VelimirMueller/synthwerk-contracts/go/identity"
	"github.com/VelimirMueller/synthwerk-contracts/go/kit/auth"
	"github.com/VelimirMueller/synthwerk-contracts/go/llm"

	"github.com/VelimirMueller/synthwerk-identity/internal/account"
	"github.com/VelimirMueller/synthwerk-identity/internal/mfagate"
)

const (
	sub   = "396370217707541255"
	orgID = "0199f3a0-5b6c-7d8e-9f0a-1b2c3d4e5f60"
	gone  = "019a3c20-1a2b-7c3d-8e4f-5a6b7c8d9e0f"
)

var now = time.Date(2026, 10, 30, 10, 0, 0, 0, time.UTC)

type fakeRepo struct {
	ms        []account.Membership
	deleted   *account.Deletion
	deleteErr error
	calls     int
	err       error
}

func (f *fakeRepo) Memberships(context.Context, string) ([]account.Membership, error) {
	return f.ms, f.err
}

func (f *fakeRepo) Deleted(context.Context, string) (account.Deletion, bool, error) {
	if f.deleted == nil {
		return account.Deletion{}, false, f.err
	}
	return *f.deleted, true, f.err
}

func (f *fakeRepo) Delete(_ context.Context, s string, _ ...string) (account.Deletion, error) {
	f.calls++
	if f.deleteErr != nil {
		return account.Deletion{}, f.deleteErr
	}
	return account.Deletion{UserSub: s, RequestedAt: now, DeletedOrgs: []account.DeletedOrg{{ID: gone, ZitadelOrgID: "300000000000000002"}}}, nil
}

type fakeEvidence struct {
	e   *mfagate.Evidence
	err error
}

func (f fakeEvidence) Latest(context.Context, string) (mfagate.Evidence, error) {
	if f.err != nil {
		return mfagate.Evidence{}, f.err
	}
	if f.e == nil {
		return mfagate.Evidence{}, mfagate.ErrNoEvidence
	}
	return *f.e, nil
}

func fresh(age time.Duration) fakeEvidence {
	return fakeEvidence{e: &mfagate.Evidence{UserSub: sub, SessionID: "s-1", AMR: []string{"pwd", "otp", "mfa"}, CheckedAt: now.Add(-age)}}
}

// user is a token of the session "s-1", the session of fresh().
func user(amr ...string) *auth.Principal {
	return &auth.Principal{Subject: sub, OrgID: "300000000000000001", Roles: []string{"owner"}, AMR: amr,
		Raw: map[string]any{"sid": "s-1"}}
}

// withRaw is p with the token claims raw instead of the default sid.
func withRaw(p *auth.Principal, raw map[string]any) *auth.Principal {
	p.Raw = raw
	return p
}

// serve runs one request as p (nil: no principal) with the bearer token "user-token".
func serve(t *testing.T, h *account.Handler, p *auth.Principal, method, path string) *httptest.ResponseRecorder {
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
			if p != nil {
				r = r.WithContext(auth.WithPrincipal(r.Context(), p))
			}
			next.ServeHTTP(w, r)
		})
	})
	req := httptest.NewRequestWithContext(t.Context(), method, path, nil)
	req.Header.Set("Authorization", "Bearer user-token")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

func strict(t *testing.T, body []byte, v any) {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		t.Fatalf("body does not fit the contract: %v: %s", err, body)
	}
}

func problemCode(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var p identity.Problem
	strict(t, rec.Body.Bytes(), &p)
	if rec.Header().Get("Content-Type") != auth.ProblemContentType || p.Status != rec.Code {
		t.Fatalf("problem %+v, content type %q", p, rec.Header().Get("Content-Type"))
	}
	return p.Code
}

func TestDeleteMe(t *testing.T) {
	t.Run("DeleteMe - token with mfa, gated sign-in 5 min old - 202 with the closed org", func(t *testing.T) {
		repo := &fakeRepo{}
		rec := serve(t, &account.Handler{Repo: repo, Evidence: fresh(5 * time.Minute)}, user("pwd", "otp", "mfa"), http.MethodDelete, "/v1/me")
		if rec.Code != http.StatusAccepted || repo.calls != 1 {
			t.Fatalf("status %d, calls %d: %s", rec.Code, repo.calls, rec.Body)
		}
		var d identity.AccountDeletion
		strict(t, rec.Body.Bytes(), &d)
		if d.UserId != sub || d.Status != identity.AccountDeletionStatusAccepted || !d.RequestedAt.Equal(now) ||
			len(d.DeletedOrgIds) != 1 || d.DeletedOrgIds[0].String() != gone || rec.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("got %+v", d)
		}
	})

	for _, tc := range []struct {
		name string
		p    *auth.Principal
		ev   fakeEvidence
	}{
		{"token without amr mfa", user("pwd"), fresh(time.Minute)},
		{"no gated sign-in stored", user("mfa"), fakeEvidence{}},
		{"gated sign-in 16 min old", user("mfa"), fresh(16 * time.Minute)},
		{"evidence from the future", user("mfa"), fresh(-2 * time.Minute)},
		{"evidence without mfa", user("mfa"), fakeEvidence{e: &mfagate.Evidence{AMR: []string{"pwd"}, CheckedAt: now}}},
		{"token of another session, fresh MFA sign-in elsewhere", withRaw(user("mfa"), map[string]any{"sid": "s-old"}), fresh(time.Minute)},
		{"token without sid, auth_time 2 h old", withRaw(user("mfa"), map[string]any{"auth_time": float64(now.Add(-2 * time.Hour).Unix())}), fresh(time.Minute)},
		{"token with only a fresh iat (renews on refresh)", withRaw(user("mfa"), map[string]any{"iat": float64(now.Unix())}), fresh(time.Minute)},
		{"token without sid and auth_time", withRaw(user("mfa"), nil), fresh(time.Minute)},
		{"token without sid, auth_time 10 min before the evidence (another sign-in)", withRaw(user("mfa"), map[string]any{"auth_time": float64(now.Add(-11 * time.Minute).Unix())}), fresh(time.Minute)},
		{"token without sid, auth_time after the evidence", withRaw(user("mfa"), map[string]any{"auth_time": float64(now.Unix())}), fresh(5 * time.Minute)},
	} {
		t.Run("DeleteMe - "+tc.name+" - 403 recent_mfa_required, nothing deleted", func(t *testing.T) {
			repo := &fakeRepo{}
			rec := serve(t, &account.Handler{Repo: repo, Evidence: tc.ev}, tc.p, http.MethodDelete, "/v1/me")
			if rec.Code != http.StatusForbidden || problemCode(t, rec) != account.CodeRecentMFARequired || repo.calls != 0 {
				t.Fatalf("status %d, calls %d: %s", rec.Code, repo.calls, rec.Body)
			}
		})
	}

	for _, tc := range []struct {
		name string
		raw  map[string]any
	}{
		{"same session", map[string]any{"sid": "s-1"}},
		{"no sid, auth_time at the evidence time", map[string]any{"auth_time": float64(now.Add(-5 * time.Minute).Unix())}},
		{"no sid, auth_time 1 min before the evidence", map[string]any{"auth_time": float64(now.Add(-6 * time.Minute).Unix())}},
	} {
		t.Run("DeleteMe - "+tc.name+", MFA sign-in within max age - 202", func(t *testing.T) {
			repo := &fakeRepo{}
			rec := serve(t, &account.Handler{Repo: repo, Evidence: fresh(5 * time.Minute)}, withRaw(user("mfa"), tc.raw), http.MethodDelete, "/v1/me")
			if rec.Code != http.StatusAccepted || repo.calls != 1 {
				t.Fatalf("status %d, calls %d: %s", rec.Code, repo.calls, rec.Body)
			}
		})
	}

	t.Run("DeleteMe - custom max age 30 min, sign-in 20 min old - 202", func(t *testing.T) {
		rec := serve(t, &account.Handler{Repo: &fakeRepo{}, Evidence: fresh(20 * time.Minute), MFAMaxAge: 30 * time.Minute}, user("mfa"), http.MethodDelete, "/v1/me")
		if rec.Code != http.StatusAccepted {
			t.Fatalf("status %d: %s", rec.Code, rec.Body)
		}
	})

	t.Run("DeleteMe - operator - 403 forbidden, nothing deleted", func(t *testing.T) {
		repo := &fakeRepo{}
		p := user("mfa")
		p.Roles = []string{auth.RoleOperator}
		rec := serve(t, &account.Handler{Repo: repo, Evidence: fresh(time.Minute)}, p, http.MethodDelete, "/v1/me")
		if rec.Code != http.StatusForbidden || problemCode(t, rec) != auth.CodeForbidden || repo.calls != 0 {
			t.Fatalf("status %d: %s", rec.Code, rec.Body)
		}
	})

	t.Run("DeleteMe - last owner of an org with members - 409 last_owner naming the org", func(t *testing.T) {
		repo := &fakeRepo{deleteErr: &account.LastOwnerError{OrgIDs: []string{orgID}}}
		rec := serve(t, &account.Handler{Repo: repo, Evidence: fresh(time.Minute)}, user("mfa"), http.MethodDelete, "/v1/me")
		if rec.Code != http.StatusConflict || problemCode(t, rec) != "last_owner" || !strings.Contains(rec.Body.String(), orgID) {
			t.Fatalf("status %d: %s", rec.Code, rec.Body)
		}
	})

	t.Run("DeleteMe - owner trigger at commit - 409 last_owner", func(t *testing.T) {
		repo := &fakeRepo{deleteErr: account.ErrLastOwner}
		rec := serve(t, &account.Handler{Repo: repo, Evidence: fresh(time.Minute)}, user("mfa"), http.MethodDelete, "/v1/me")
		if rec.Code != http.StatusConflict || problemCode(t, rec) != "last_owner" {
			t.Fatalf("status %d: %s", rec.Code, rec.Body)
		}
	})

	t.Run("DeleteMe - repeat with the old token, no evidence left - 202 with the first time, no second delete", func(t *testing.T) {
		first := now.Add(-time.Hour)
		repo := &fakeRepo{deleted: &account.Deletion{UserSub: sub, RequestedAt: first, DeletedOrgs: []account.DeletedOrg{}, Repeat: true}}
		rec := serve(t, &account.Handler{Repo: repo, Evidence: fakeEvidence{}}, user("pwd"), http.MethodDelete, "/v1/me")
		var d identity.AccountDeletion
		if rec.Code != http.StatusAccepted {
			t.Fatalf("status %d: %s", rec.Code, rec.Body)
		}
		strict(t, rec.Body.Bytes(), &d)
		if repo.calls != 0 || !d.RequestedAt.Equal(first) || len(d.DeletedOrgIds) != 0 {
			t.Fatalf("calls %d, got %+v", repo.calls, d)
		}
	})

	t.Run("DeleteMe - store or evidence error - 500 internal_error", func(t *testing.T) {
		for _, h := range []*account.Handler{
			{Repo: &fakeRepo{err: errors.New("db down")}, Evidence: fresh(time.Minute)},
			{Repo: &fakeRepo{}, Evidence: fakeEvidence{err: errors.New("db down")}},
			{Repo: &fakeRepo{deleteErr: errors.New("db down")}, Evidence: fresh(time.Minute)},
		} {
			rec := serve(t, h, user("mfa"), http.MethodDelete, "/v1/me")
			if rec.Code != http.StatusInternalServerError || problemCode(t, rec) != "internal_error" {
				t.Fatalf("status %d: %s", rec.Code, rec.Body)
			}
		}
	})

	t.Run("DeleteMe and ExportMe - no principal - 401 unauthenticated with WWW-Authenticate", func(t *testing.T) {
		for _, m := range []string{http.MethodDelete, http.MethodGet} {
			path := "/v1/me"
			if m == http.MethodGet {
				path = account.ExportPath
			}
			rec := serve(t, &account.Handler{Repo: &fakeRepo{}, Evidence: fakeEvidence{}}, nil, m, path)
			if rec.Code != http.StatusUnauthorized || problemCode(t, rec) != auth.CodeUnauthenticated || rec.Header().Get("WWW-Authenticate") != "Bearer" {
				t.Fatalf("%s: status %d: %s", m, rec.Code, rec.Body)
			}
		}
	})
}

func TestExportMe(t *testing.T) {
	ms := []account.Membership{{OrgID: orgID, OrgName: "Synthwerk", OrgSlug: "synthwerk", Role: "member",
		JoinedAt: now.Add(-48 * time.Hour), UpdatedAt: now.Add(-24 * time.Hour)}}
	llmBody := `{"conversations":[{"id":"6f1c2d3e-4a5b-4c6d-8e7f-9a0b1c2d3e4f","org_id":"300000000000000001","model":"default","created_at":"2026-10-23T09:00:00Z","messages":[{"id":"0199f3b0-1a2c-7c3d-8e4f-5a6b7c8d9e10","role":"assistant","content":"hi","status":"completed","tokens_in":12,"tokens_out":9,"created_at":"2026-10-23T09:00:05Z"}]}],"quota_usage":[{"org_id":"300000000000000001","window_start":"2026-10-23","used":9007199254740993}]}`

	t.Run("ExportMe - identity rows, evidence and the llm part - 200 attachment, data unchanged, token forwarded", func(t *testing.T) {
		var auth string
		src := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			auth = r.Header.Get("Authorization")
			if r.Method != http.MethodGet || r.URL.Path != account.ExportPath {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			_, _ = w.Write([]byte(llmBody))
		}))
		defer src.Close()
		h := &account.Handler{Repo: &fakeRepo{ms: ms}, Evidence: fresh(time.Hour),
			Fetcher: &account.Fetcher{Sources: []account.Source{{Name: "llm", BaseURL: src.URL}}}}
		rec := serve(t, h, user("mfa"), http.MethodGet, account.ExportPath)
		if rec.Code != http.StatusOK || auth != "Bearer user-token" ||
			rec.Header().Get("Content-Disposition") != `attachment; filename="synthwerk-export.json"` {
			t.Fatalf("status %d, auth %q: %s", rec.Code, auth, rec.Body)
		}
		var e identity.UserExport
		strict(t, rec.Body.Bytes(), &e)
		if e.Subject != sub || !e.Complete || e.FormatVersion != identity.UserExportFormatVersionN1 || !e.ExportedAt.Equal(now) ||
			len(e.Identity.Memberships) != 1 || e.Identity.Memberships[0].OrgSlug != "synthwerk" ||
			e.Identity.MfaEvidence == nil || e.Identity.MfaEvidence.SessionId != "s-1" ||
			len(e.Services) != 1 || e.Services[0].Status != identity.ServiceExportStatusOk {
			t.Fatalf("got %+v", e)
		}
		// The llm part passes byte for byte: a big integer keeps every digit.
		var raw struct {
			Services []struct {
				Data json.RawMessage `json:"data"`
			} `json:"services"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &raw)
		if string(raw.Services[0].Data) != llmBody {
			t.Fatalf("data changed: %s", raw.Services[0].Data)
		}
		strict(t, raw.Services[0].Data, &llm.LlmExport{})
	})

	for _, tc := range []struct {
		name        string
		status      int
		contentType string
		body        string
	}{
		{"source answers 503", http.StatusServiceUnavailable, "application/problem+json", `{"code":"model_unavailable"}`},
		{"source answers HTML", http.StatusOK, "text/html", `<html></html>`},
		{"source answers a JSON array", http.StatusOK, "application/json", `[]`},
		{"source answers broken JSON", http.StatusOK, "application/json", `{"conversations":`},
		{"source redirects", http.StatusFound, "application/json", `{}`},
	} {
		t.Run("ExportMe - "+tc.name+" - 200, service unavailable, complete false", func(t *testing.T) {
			src := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", tc.contentType)
				if tc.status == http.StatusFound {
					w.Header().Set("Location", "http://evil.test/steal")
				}
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer src.Close()
			h := &account.Handler{Repo: &fakeRepo{}, Evidence: fakeEvidence{},
				Fetcher: &account.Fetcher{Sources: []account.Source{{Name: "llm", BaseURL: src.URL}}}}
			rec := serve(t, h, user(), http.MethodGet, account.ExportPath)
			var e identity.UserExport
			if rec.Code != http.StatusOK {
				t.Fatalf("status %d: %s", rec.Code, rec.Body)
			}
			strict(t, rec.Body.Bytes(), &e)
			if e.Complete || len(e.Services) != 1 || e.Services[0].Status != identity.ServiceExportStatusUnavailable ||
				e.Services[0].Data != nil || e.Identity.MfaEvidence != nil || len(e.Identity.Memberships) != 0 {
				t.Fatalf("got %+v", e)
			}
		})
	}

	t.Run("ExportMe - source down - 200, unavailable", func(t *testing.T) {
		h := &account.Handler{Repo: &fakeRepo{}, Evidence: fakeEvidence{},
			Fetcher: &account.Fetcher{Sources: []account.Source{{Name: "llm", BaseURL: "http://127.0.0.1:1"}}}}
		rec := serve(t, h, user(), http.MethodGet, account.ExportPath)
		var e identity.UserExport
		strict(t, rec.Body.Bytes(), &e)
		if rec.Code != http.StatusOK || e.Complete || e.Services[0].Status != identity.ServiceExportStatusUnavailable {
			t.Fatalf("status %d: %+v", rec.Code, e)
		}
	})

	t.Run("ExportMe - no sources - identity rows only, complete, services empty", func(t *testing.T) {
		rec := serve(t, &account.Handler{Repo: &fakeRepo{ms: ms}, Evidence: fakeEvidence{}}, user(), http.MethodGet, account.ExportPath)
		var e identity.UserExport
		strict(t, rec.Body.Bytes(), &e)
		if rec.Code != http.StatusOK || !e.Complete || e.Services == nil || len(e.Services) != 0 {
			t.Fatalf("status %d: %s", rec.Code, rec.Body)
		}
	})

	t.Run("ExportMe - store or evidence error - 500 internal_error", func(t *testing.T) {
		for _, h := range []*account.Handler{
			{Repo: &fakeRepo{err: errors.New("db down")}, Evidence: fakeEvidence{}},
			{Repo: &fakeRepo{}, Evidence: fakeEvidence{err: errors.New("db down")}},
		} {
			rec := serve(t, h, user(), http.MethodGet, account.ExportPath)
			if rec.Code != http.StatusInternalServerError || problemCode(t, rec) != "internal_error" {
				t.Fatalf("status %d: %s", rec.Code, rec.Body)
			}
		}
	})
}

func TestParseSources(t *testing.T) {
	t.Run("ParseSources - two sources with spaces and a trailing slash - parsed in order", func(t *testing.T) {
		got, err := account.ParseSources(" llm=http://llm:8080/ , vision=https://vision.internal ")
		if err != nil || len(got) != 2 || got[0] != (account.Source{Name: "llm", BaseURL: "http://llm:8080"}) || got[1].Name != "vision" {
			t.Fatalf("got %+v, %v", got, err)
		}
	})
	t.Run("ParseSources - empty - no source", func(t *testing.T) {
		if got, err := account.ParseSources(""); err != nil || len(got) != 0 {
			t.Fatalf("got %+v, %v", got, err)
		}
	})
	for _, bad := range []string{"llm", "LLM=http://llm", "llm=ftp://llm", "llm=http://u:p@llm", "llm=http://llm?x=1", "llm=http://a,llm=http://b", "llm=/v1"} {
		t.Run("ParseSources - "+bad+" - error", func(t *testing.T) {
			if _, err := account.ParseSources(bad); err == nil {
				t.Fatal("want an error")
			}
		})
	}
}
