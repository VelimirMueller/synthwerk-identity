package entitlements

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/google/uuid"
	"go.opentelemetry.io/otel/trace"

	"github.com/VelimirMueller/synthwerk-contracts/go/identity"
	"github.com/VelimirMueller/synthwerk-contracts/go/kit/auth"

	"github.com/VelimirMueller/synthwerk-identity/internal/orgs"
)

// Orgs finds the org of a request. *orgs.Store satisfies it.
type Orgs interface {
	OrgByID(ctx context.Context, id string) (orgs.Org, error)
	OrgByZitadelID(ctx context.Context, zitadelOrgID string) (orgs.Org, error)
}

// Repo reads entitlements. *Store satisfies it.
type Repo interface {
	ByOrg(ctx context.Context, orgID string) (Entitlements, error)
}

// Handler serves the entitlement routes of openapi/identity.
type Handler struct {
	Orgs Orgs
	Repo Repo
	Log  *slog.Logger
}

// Register adds the routes to mux. authn must be auth.Middleware.
func (h *Handler) Register(mux *http.ServeMux, authn func(http.Handler) http.Handler) {
	mux.Handle("GET /v1/me/entitlements", authn(http.HandlerFunc(h.getMine)))
	mux.Handle("GET /v1/orgs/{orgId}/entitlements", authn(http.HandlerFunc(h.getOrg)))
}

// getMine serves the org the token acts in. A service that acts for a user (llm)
// forwards the caller's token here. A token without an org role answers 404.
func (h *Handler) getMine(w http.ResponseWriter, r *http.Request) {
	p, ok := auth.FromContext(r.Context())
	if !ok { // auth.Middleware never lets this through
		writeProblem(w, r, http.StatusUnauthorized, auth.CodeUnauthenticated)
		return
	}
	if !orgs.TokenRole(p).Valid() {
		writeProblem(w, r, http.StatusNotFound, codeNotFound)
		return
	}
	org, err := h.Orgs.OrgByZitadelID(r.Context(), p.OrgID)
	h.answer(w, r, org, err)
}

// getOrg serves the org of the path: same gate as GET /v1/orgs/{orgId}. Any org
// role of the token in that org, or operator; everything else is 404.
func (h *Handler) getOrg(w http.ResponseWriter, r *http.Request) {
	p, ok := auth.FromContext(r.Context())
	if !ok {
		writeProblem(w, r, http.StatusUnauthorized, auth.CodeUnauthenticated)
		return
	}
	org, err := h.Orgs.OrgByID(r.Context(), r.PathValue("orgId"))
	if err == nil && !p.IsOperator() && (org.ZitadelOrgID != p.OrgID || !orgs.TokenRole(p).Valid()) {
		err = orgs.ErrNotFound
	}
	h.answer(w, r, org, err)
}

func (h *Handler) answer(w http.ResponseWriter, r *http.Request, org orgs.Org, err error) {
	if errors.Is(err, orgs.ErrNotFound) || (err == nil && org.Status != "active") {
		writeProblem(w, r, http.StatusNotFound, codeNotFound)
		return
	}
	if err != nil {
		h.fail(w, r, err)
		return
	}
	e, err := h.Repo.ByOrg(r.Context(), org.ID)
	if err != nil {
		// An active org always has a row: it is written with org.created and by
		// Reconcile at start. ErrNotFound here is a bug, not a 404.
		h.fail(w, r, err)
		return
	}
	writeJSON(w, Body(e))
}

// Body is the contract shape of e.
func Body(e Entitlements) identity.Entitlements {
	return identity.Entitlements{
		OrgId: uuid.MustParse(e.OrgID),
		Plan:  e.Plan,
		Limits: identity.EntitlementLimits{
			LlmTokensPerUserPerDay: e.Limits.LLMTokensPerUserPerDay,
			LlmTokensPerOrgPerDay:  e.Limits.LLMTokensPerOrgPerDay,
			AppsPerOrg:             e.Limits.AppsPerOrg,
		},
		Version:   e.Version,
		UpdatedAt: e.UpdatedAt.UTC(),
	}
}

func (h *Handler) fail(w http.ResponseWriter, r *http.Request, err error) {
	h.Log.ErrorContext(r.Context(), "entitlements: request failed", slog.String("event.name", "entitlements.failed"),
		slog.String("exception.message", err.Error()))
	writeProblem(w, r, http.StatusInternalServerError, codeInternal)
}

// Problem codes of openapi/identity. The org routes write the same bodies.
const (
	codeNotFound = "not_found"
	codeInternal = "internal_error"
)

var titles = map[string]string{
	auth.CodeUnauthenticated: "Unauthenticated",
	codeNotFound:             "Not found",
	codeInternal:             "Internal error",
}

type problem struct {
	Type    string `json:"type"`
	Title   string `json:"title"`
	Status  int    `json:"status"`
	Code    string `json:"code"`
	TraceID string `json:"trace_id,omitempty"`
}

// writeProblem writes an RFC 9457 body. A 404 never says whether the org exists.
func writeProblem(w http.ResponseWriter, r *http.Request, status int, code string) {
	p := problem{Type: "https://schemas.synthwerk.dev/problems/" + code, Title: titles[code], Status: status, Code: code}
	if sc := trace.SpanContextFromContext(r.Context()); sc.HasTraceID() {
		p.TraceID = sc.TraceID().String()
	}
	if status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", "Bearer")
	}
	w.Header().Set("Content-Type", auth.ProblemContentType)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(p)
}

func writeJSON(w http.ResponseWriter, v any) {
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(v); err != nil {
		http.Error(w, "encode", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(buf.Bytes())
}
