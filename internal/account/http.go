package account

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.opentelemetry.io/otel/trace"

	"github.com/VelimirMueller/synthwerk-contracts/go/identity"
	"github.com/VelimirMueller/synthwerk-contracts/go/kit/auth"

	"github.com/VelimirMueller/synthwerk-identity/internal/mfagate"
)

// DefaultMFAMaxAge is how old the newest sign-in with MFA may be for a delete.
const DefaultMFAMaxAge = 15 * time.Minute

// Problem codes of the account routes (openapi/identity).
const (
	CodeRecentMFARequired = "recent_mfa_required"
	codeLastOwner         = "last_owner"
	codeInternal          = "internal_error"
)

// Repo is the part of Store the handler uses.
type Repo interface {
	Memberships(ctx context.Context, sub string) ([]Membership, error)
	Deleted(ctx context.Context, sub string) (Deletion, bool, error)
	Delete(ctx context.Context, sub string, emails ...string) (Deletion, error)
}

// Evidence reads the newest sign-in with MFA (mfagate.Postgres).
type Evidence interface {
	Latest(ctx context.Context, userSub string) (mfagate.Evidence, error)
}

// Handler serves GET /v1/me/export and DELETE /v1/me.
type Handler struct {
	Repo     Repo
	Evidence Evidence
	// Fetcher asks the other services. Nil: the export holds identity rows only.
	Fetcher *Fetcher
	Log     *slog.Logger
	Now     func() time.Time
	// MFAMaxAge bounds the age of the sign-in with MFA for a delete. Zero: DefaultMFAMaxAge.
	MFAMaxAge time.Duration
}

// Register adds the routes to mux. authn must be auth.Middleware.
func (h *Handler) Register(mux *http.ServeMux, authn func(http.Handler) http.Handler) {
	mux.Handle("GET "+ExportPath, authn(http.HandlerFunc(h.exportMe)))
	mux.Handle("DELETE /v1/me", authn(http.HandlerFunc(h.deleteMe)))
}

func (h *Handler) now() time.Time {
	if h.Now != nil {
		return h.Now()
	}
	return time.Now()
}

// exportDoc is identity.UserExport with the service data kept as raw JSON, so a
// service export passes unchanged (no float rounding, no reordering of members).
type exportDoc struct {
	FormatVersion identity.UserExportFormatVersion `json:"format_version"`
	Subject       string                           `json:"subject"`
	ExportedAt    time.Time                        `json:"exported_at"`
	Complete      bool                             `json:"complete"`
	Identity      identity.IdentityExport          `json:"identity"`
	Services      []serviceDoc                     `json:"services"`
}

type serviceDoc struct {
	Service string                       `json:"service"`
	Status  identity.ServiceExportStatus `json:"status"`
	Data    json.RawMessage              `json:"data,omitempty"`
}

func (h *Handler) exportMe(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, ok := auth.FromContext(ctx)
	if !ok {
		writeProblem(w, r, http.StatusUnauthorized, auth.CodeUnauthenticated, "")
		return
	}
	ms, err := h.Repo.Memberships(ctx, p.Subject)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	doc := exportDoc{
		FormatVersion: identity.UserExportFormatVersionN1,
		Subject:       p.Subject,
		ExportedAt:    h.now().UTC(),
		Complete:      true,
		Identity:      identity.IdentityExport{Memberships: []identity.ExportMembership{}},
		Services:      []serviceDoc{},
	}
	for _, m := range ms {
		id, err := uuid.Parse(m.OrgID)
		if err != nil {
			h.fail(w, r, err)
			return
		}
		doc.Identity.Memberships = append(doc.Identity.Memberships, identity.ExportMembership{
			OrgId: id, OrgName: m.OrgName, OrgSlug: m.OrgSlug, Role: identity.OrgRole(m.Role),
			JoinedAt: m.JoinedAt.UTC(), UpdatedAt: m.UpdatedAt.UTC(),
		})
	}
	e, err := h.Evidence.Latest(ctx, p.Subject)
	switch {
	case err == nil:
		amr := append([]string{}, e.AMR...)
		doc.Identity.MfaEvidence = &identity.ExportMfaEvidence{SessionId: e.SessionID, Amr: amr, CheckedAt: e.CheckedAt.UTC()}
	case !errors.Is(err, mfagate.ErrNoEvidence):
		h.fail(w, r, err)
		return
	}
	if h.Fetcher != nil {
		token := bearer(r)
		for _, s := range h.Fetcher.Sources {
			sd := serviceDoc{Service: s.Name, Status: identity.ServiceExportStatusOk}
			data, err := h.Fetcher.fetch(ctx, s, token)
			if err != nil {
				h.Log.WarnContext(ctx, "export: source unavailable", slog.String("event.name", "account.export_source_failed"),
					slog.String("service", s.Name), slog.String("exception.message", err.Error()))
				sd.Status, doc.Complete = identity.ServiceExportStatusUnavailable, false
			} else {
				sd.Data = data
			}
			doc.Services = append(doc.Services, sd)
		}
	}
	h.Log.InfoContext(ctx, "export", slog.String("event.name", "account.exported"),
		slog.String("enduser.id", p.Subject), slog.Bool("complete", doc.Complete))
	w.Header().Set("Content-Disposition", `attachment; filename="synthwerk-export.json"`)
	writeJSON(w, http.StatusOK, doc)
}

func (h *Handler) deleteMe(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, ok := auth.FromContext(ctx)
	if !ok {
		writeProblem(w, r, http.StatusUnauthorized, auth.CodeUnauthenticated, "")
		return
	}
	if p.IsOperator() {
		h.refused(r, p.Subject, "operator")
		writeProblem(w, r, http.StatusForbidden, auth.CodeForbidden, "")
		return
	}
	// A repeat with a token from before the delete: same answer, no MFA check (the
	// evidence went with the account).
	if d, done, err := h.Repo.Deleted(ctx, p.Subject); err != nil {
		h.fail(w, r, err)
		return
	} else if done {
		writeJSON(w, http.StatusAccepted, deletionBody(d))
		return
	}
	if ok, err := h.recentMFA(ctx, p); err != nil {
		h.fail(w, r, err)
		return
	} else if !ok {
		h.refused(r, p.Subject, CodeRecentMFARequired)
		writeProblem(w, r, http.StatusForbidden, CodeRecentMFARequired, "Sign in again with MFA, then retry.")
		return
	}
	d, err := h.Repo.Delete(ctx, p.Subject, verifiedEmails(p)...)
	var lo *LastOwnerError
	switch {
	case errors.As(err, &lo):
		h.refused(r, p.Subject, "last_owner")
		writeProblem(w, r, http.StatusConflict, codeLastOwner,
			"Make another member owner first. Orgs: "+strings.Join(lo.OrgIDs, ", ")+".")
	case errors.Is(err, ErrLastOwner):
		h.refused(r, p.Subject, "last_owner")
		writeProblem(w, r, http.StatusConflict, codeLastOwner, "Make another member owner first.")
	case err != nil:
		h.fail(w, r, err)
	default:
		h.Log.InfoContext(ctx, "account deleted", slog.String("event.name", "account.deleted"),
			slog.String("enduser.id", p.Subject), slog.Int("orgs.deleted", len(d.DeletedOrgs)), slog.Bool("repeat", d.Repeat))
		writeJSON(w, http.StatusAccepted, deletionBody(d))
	}
}

// recentMFA: the token has amr mfa, the user's newest gated sign-in is at most
// MFAMaxAge old, and that sign-in belongs to this token. The token alone is not
// enough: its amr may come from a sign-in up to 12 h ago (mfagate.DefaultMaxAge).
// The evidence alone is not enough either: it may come from another session, so
// an older or stolen token could ride on a fresh MFA sign-in elsewhere.
//
// Session binding: a token with a "sid" claim needs evidence of that session. A
// token without "sid" needs its "auth_time" within MFAMaxAge and from the same
// sign-in as the evidence: not after it, at most signInGap before it. "iat" is
// never used: it renews on every refresh. Neither claim: refused.
func (h *Handler) recentMFA(ctx context.Context, p *auth.Principal) (bool, error) {
	if !p.HasMFA() {
		return false, nil
	}
	e, err := h.Evidence.Latest(ctx, p.Subject)
	if errors.Is(err, mfagate.ErrNoEvidence) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	maxAge := h.MFAMaxAge
	if maxAge <= 0 {
		maxAge = DefaultMFAMaxAge
	}
	now := h.now()
	fresh := func(t time.Time) bool {
		age := now.Sub(t)
		return age <= maxAge && age >= -time.Minute
	}
	if !fresh(e.CheckedAt) || !slices.Contains(e.AMR, mfagate.AMRMFA) {
		return false, nil
	}
	if sid, _ := p.Raw["sid"].(string); sid != "" {
		return e.SessionID == sid, nil
	}
	at, ok := unixClaim(p.Raw["auth_time"])
	if !ok {
		return false, nil
	}
	gap := e.CheckedAt.Sub(at)
	return fresh(at) && gap >= -time.Minute && gap <= signInGap, nil
}

// signInGap is the longest time from the user's authentication (auth_time) to the
// MFA gate check (evidence CheckedAt) of the same sign-in.
const signInGap = 5 * time.Minute

// unixClaim reads a NumericDate claim (seconds since the epoch).
func unixClaim(v any) (time.Time, bool) {
	var sec float64
	switch n := v.(type) {
	case float64:
		sec = n
	case int64:
		sec = float64(n)
	case int:
		sec = float64(n)
	case json.Number:
		f, err := n.Float64()
		if err != nil {
			return time.Time{}, false
		}
		sec = f
	default:
		return time.Time{}, false
	}
	if sec <= 0 {
		return time.Time{}, false
	}
	return time.Unix(int64(sec), 0), true
}

func deletionBody(d Deletion) identity.AccountDeletion {
	ids := make([]uuid.UUID, 0, len(d.DeletedOrgs))
	for _, o := range d.DeletedOrgs {
		if id, err := uuid.Parse(o.ID); err == nil {
			ids = append(ids, id)
		}
	}
	return identity.AccountDeletion{
		UserId: d.UserSub, Status: identity.AccountDeletionStatusAccepted,
		RequestedAt: d.RequestedAt.UTC(), DeletedOrgIds: ids,
	}
}

// refused logs a refused delete. Refusals write no event.
func (h *Handler) refused(r *http.Request, sub, reason string) {
	h.Log.InfoContext(r.Context(), "account delete refused", slog.String("event.name", "account.delete_refused"),
		slog.String("enduser.id", sub), slog.String("reason", reason))
}

func (h *Handler) fail(w http.ResponseWriter, r *http.Request, err error) {
	h.Log.ErrorContext(r.Context(), "account: request failed", slog.String("event.name", "account.failed"),
		slog.String("exception.message", err.Error()))
	writeProblem(w, r, http.StatusInternalServerError, codeInternal, "")
}

// bearer returns the raw token of the request. auth.Middleware has verified it.
func bearer(r *http.Request) string {
	_, tok, _ := strings.Cut(r.Header.Get("Authorization"), " ")
	return strings.TrimSpace(tok)
}

var titles = map[string]string{
	auth.CodeUnauthenticated: "Unauthenticated",
	auth.CodeForbidden:       "Forbidden",
	CodeRecentMFARequired:    "Recent MFA required",
	codeLastOwner:            "Last owner",
	codeInternal:             "Internal error",
}

type problem struct {
	Type    string `json:"type"`
	Title   string `json:"title"`
	Status  int    `json:"status"`
	Code    string `json:"code"`
	Detail  string `json:"detail,omitempty"`
	TraceID string `json:"trace_id,omitempty"`
}

// writeProblem writes an RFC 9457 body like the org routes (internal/orgs).
func writeProblem(w http.ResponseWriter, r *http.Request, status int, code, detail string) {
	p := problem{Type: "https://schemas.synthwerk.dev/problems/" + code, Title: titles[code], Status: status, Code: code, Detail: detail}
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

func writeJSON(w http.ResponseWriter, status int, v any) {
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(v); err != nil {
		http.Error(w, "encode", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}

// verifiedEmails is the email claim of p when email_verified is true. An
// unverified email never deletes the invitations of that address.
func verifiedEmails(p *auth.Principal) []string {
	if v, _ := p.Raw["email_verified"].(bool); !v {
		return nil
	}
	if e, _ := p.Raw["email"].(string); e != "" {
		return []string{e}
	}
	return nil
}
