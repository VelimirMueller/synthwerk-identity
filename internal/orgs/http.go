package orgs

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"

	"github.com/google/uuid"
	"go.opentelemetry.io/otel/trace"

	"github.com/VelimirMueller/synthwerk-contracts/go/identity"
	"github.com/VelimirMueller/synthwerk-contracts/go/kit/auth"
)

// Repo is the part of Store the handlers use.
type Repo interface {
	OrgByID(ctx context.Context, id string) (Org, error)
	OrgByZitadelID(ctx context.Context, zitadelOrgID string) (Org, error)
	MemberRole(ctx context.Context, orgID, sub string) (Role, error)
	ListMembers(ctx context.Context, orgID, after string, limit int) ([]Membership, error)
	ChangeRole(ctx context.Context, org Org, actorSub, targetSub string, to Role) (Membership, bool, error)
}

// Handler serves the org routes of openapi/identity.
type Handler struct {
	Repo Repo
	// Members invites members and changes their status (synthwerk#37). Nil: those
	// routes are off.
	Members MemberWriter
	// InviteLimit limits invites per caller and per org. Nil: NewInviteLimiter.
	InviteLimit *InviteLimiter
	Log         *slog.Logger
}

// Page sizes of listMembers.
const (
	DefaultPageSize = 50
	MaxPageSize     = 100
	maxBody         = 1 << 10
)

var subPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

// Register adds the routes to mux. authn must be auth.Middleware: every route needs
// a verified token.
func (h *Handler) Register(mux *http.ServeMux, authn func(http.Handler) http.Handler) {
	mux.Handle("GET /v1/me", authn(http.HandlerFunc(h.getMe)))
	mux.Handle("GET /v1/orgs/{orgId}", authn(http.HandlerFunc(h.getOrg)))
	mux.Handle("GET /v1/orgs/{orgId}/members", authn(http.HandlerFunc(h.listMembers)))
	mux.Handle("PATCH /v1/orgs/{orgId}/members/{userId}", authn(http.HandlerFunc(h.changeMemberRole)))
	if h.Members != nil {
		h.registerMembers(mux, authn)
	}
}

// access is the result of the org gate.
type access struct {
	p   *auth.Principal
	org Org
	// own: the token acts in this org and has an org role in it.
	own bool
}

// gate resolves the org of the path. An org the caller cannot see answers 404,
// the same as an unknown org. Only active orgs (with an owner) exist for the API.
func (h *Handler) gate(w http.ResponseWriter, r *http.Request) (access, bool) {
	p, ok := auth.FromContext(r.Context())
	if !ok { // auth.Middleware never lets this through
		writeProblem(w, r, http.StatusUnauthorized, auth.CodeUnauthenticated, "")
		return access{}, false
	}
	org, err := h.Repo.OrgByID(r.Context(), r.PathValue("orgId"))
	if errors.Is(err, ErrNotFound) || (err == nil && org.Status != "active") {
		writeProblem(w, r, http.StatusNotFound, codeNotFound, "")
		return access{}, false
	}
	if err != nil {
		h.fail(w, r, err)
		return access{}, false
	}
	a := access{p: p, org: org, own: org.ZitadelOrgID == p.OrgID && TokenRole(p).Valid()}
	if !a.own && !p.IsOperator() {
		writeProblem(w, r, http.StatusNotFound, codeNotFound, "")
		return access{}, false
	}
	if a.own && !h.acceptInvite(w, r, org.ID, p.Subject) {
		return access{}, false
	}
	if a.own {
		// The token role can outlive the membership: a deactivated or invited member
		// keeps it until the token expires. Only an active stored membership counts
		// (synthwerk#37); anything else is no membership.
		_, err := h.Repo.MemberRole(r.Context(), org.ID, p.Subject)
		if err != nil && !errors.Is(err, ErrNotFound) {
			h.fail(w, r, err)
			return access{}, false
		}
		if err != nil {
			a.own = false
			if !p.IsOperator() {
				writeProblem(w, r, http.StatusNotFound, codeNotFound, "")
				return access{}, false
			}
		}
	}
	return a, true
}

// acceptInvite activates an invited member at its first call with a token of the
// org (synthwerk#37). It writes 500 and returns false on a database error.
func (h *Handler) acceptInvite(w http.ResponseWriter, r *http.Request, orgID, sub string) bool {
	acc, ok := h.Repo.(InviteAcceptor)
	if !ok || h.Members == nil {
		return true
	}
	if err := acc.AcceptInvite(r.Context(), orgID, sub); err != nil {
		h.fail(w, r, err)
		return false
	}
	return true
}

func (h *Handler) getMe(w http.ResponseWriter, r *http.Request) {
	p, ok := auth.FromContext(r.Context())
	if !ok {
		writeProblem(w, r, http.StatusUnauthorized, auth.CodeUnauthenticated, "")
		return
	}
	org, err := h.Repo.OrgByZitadelID(r.Context(), p.OrgID)
	if errors.Is(err, ErrNotFound) || (err == nil && org.Status != "active") {
		writeProblem(w, r, http.StatusNotFound, codeNotFound, "")
		return
	}
	if err != nil {
		h.fail(w, r, err)
		return
	}
	if TokenRole(p).Valid() && !h.acceptInvite(w, r, org.ID, p.Subject) {
		return
	}
	roles := []identity.Role{}
	if role := TokenRole(p); role.Valid() {
		roles = append(roles, identity.Role(role))
	}
	if p.IsOperator() {
		roles = append(roles, identity.RoleOperator)
	}
	writeJSON(w, identity.Me{Subject: p.Subject, Org: orgBody(org), Roles: roles})
}

func (h *Handler) getOrg(w http.ResponseWriter, r *http.Request) {
	a, ok := h.gate(w, r)
	if !ok {
		return
	}
	writeJSON(w, orgBody(a.org))
}

func (h *Handler) listMembers(w http.ResponseWriter, r *http.Request) {
	a, ok := h.gate(w, r)
	if !ok {
		return
	}
	if !a.p.IsOperator() {
		// Token first, then the stored role: a demoted admin's old token gets 403.
		if !TokenRole(a.p).AtLeast(Admin) {
			writeProblem(w, r, http.StatusForbidden, auth.CodeForbidden, "")
			return
		}
		stored, err := h.Repo.MemberRole(r.Context(), a.org.ID, a.p.Subject)
		if err != nil && !errors.Is(err, ErrNotFound) {
			h.fail(w, r, err)
			return
		}
		if !stored.AtLeast(Admin) {
			writeProblem(w, r, http.StatusForbidden, auth.CodeForbidden, "")
			return
		}
	}
	limit, after, ok := pageParams(r)
	if !ok {
		writeProblem(w, r, http.StatusBadRequest, codeInvalidRequest, "limit must be 1 to 100; cursor must come from next_cursor.")
		return
	}
	ms, err := h.Repo.ListMembers(r.Context(), a.org.ID, after, limit+1)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	page := identity.MemberPage{Items: []identity.Member{}}
	if len(ms) > limit {
		ms = ms[:limit]
		next := base64.RawURLEncoding.EncodeToString([]byte(ms[len(ms)-1].UserSub))
		page.NextCursor = &next
	}
	for _, m := range ms {
		page.Items = append(page.Items, memberBody(m))
	}
	writeJSON(w, page)
}

func (h *Handler) changeMemberRole(w http.ResponseWriter, r *http.Request) {
	a, ok := h.gate(w, r)
	if !ok {
		return
	}
	// Operator is read only (spec #29, decision 3). The token is the first gate.
	if !a.own || !TokenRole(a.p).AtLeast(Admin) {
		writeProblem(w, r, http.StatusForbidden, auth.CodeForbidden, "")
		return
	}
	target := r.PathValue("userId")
	if !subPattern.MatchString(target) {
		writeProblem(w, r, http.StatusNotFound, codeNotFound, "")
		return
	}
	var body identity.ChangeMemberRoleRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil || dec.More() || !Role(body.Role).Valid() {
		writeProblem(w, r, http.StatusBadRequest, codeInvalidRequest, "Body must be {\"role\": \"owner\" | \"admin\" | \"member\"}.")
		return
	}
	m, changed, err := h.Repo.ChangeRole(r.Context(), a.org, a.p.Subject, target, Role(body.Role))
	switch {
	case errors.Is(err, ErrForbidden):
		h.refused(r, a, target, "forbidden")
		writeProblem(w, r, http.StatusForbidden, auth.CodeForbidden, "")
	case errors.Is(err, ErrNotFound):
		writeProblem(w, r, http.StatusNotFound, codeNotFound, "")
	case errors.Is(err, ErrOwnRole):
		h.refused(r, a, target, codeOwnRole)
		writeProblem(w, r, http.StatusConflict, codeOwnRole, "Nobody changes their own role.")
	case errors.Is(err, ErrLastOwner):
		h.refused(r, a, target, codeLastOwner)
		writeProblem(w, r, http.StatusConflict, codeLastOwner, "The org must keep at least one owner.")
	case errors.Is(err, ErrNotReady):
		writeNotReady(w, r)
	case errors.Is(err, ErrUpstream):
		h.Log.ErrorContext(r.Context(), "role change: zitadel refused", slog.String("event.name", "orgs.role_change_upstream_failed"),
			slog.String("exception.message", err.Error()))
		writeProblem(w, r, http.StatusBadGateway, codeUpstream, "")
	case err != nil:
		h.fail(w, r, err)
	default:
		h.Log.InfoContext(r.Context(), "role change", slog.String("event.name", "orgs.role_changed"),
			slog.String("org.id", a.org.ID), slog.String("enduser.id", target), slog.String("role", string(m.Role)), slog.Bool("changed", changed))
		writeJSON(w, memberBody(m))
	}
}

// refused logs a refused role change. Refusals write no event (spec #29, audit).
func (h *Handler) refused(r *http.Request, a access, target, reason string) {
	h.Log.InfoContext(r.Context(), "role change refused", slog.String("event.name", "orgs.role_change_refused"),
		slog.String("org.id", a.org.ID), slog.String("enduser.id", target), slog.String("reason", reason))
}

func (h *Handler) fail(w http.ResponseWriter, r *http.Request, err error) {
	h.Log.ErrorContext(r.Context(), "orgs: request failed", slog.String("event.name", "orgs.failed"), slog.String("exception.message", err.Error()))
	writeProblem(w, r, http.StatusInternalServerError, codeInternal, "")
}

func pageParams(r *http.Request) (limit int, after string, ok bool) {
	q := r.URL.Query()
	limit = DefaultPageSize
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > MaxPageSize {
			return 0, "", false
		}
		limit = n
	}
	if c := q.Get("cursor"); c != "" {
		if len(c) > 256 {
			return 0, "", false
		}
		b, err := base64.RawURLEncoding.DecodeString(c)
		if err != nil || !subPattern.Match(b) {
			return 0, "", false
		}
		after = string(b)
	}
	return limit, after, true
}

func orgBody(o Org) identity.Org {
	return identity.Org{Id: uuid.MustParse(o.ID), Name: o.Name, Slug: o.Slug, CreatedAt: o.CreatedAt.UTC()}
}

func memberBody(m Membership) identity.Member {
	status := identity.MemberStatusActive
	if m.Status == StatusDeactivated {
		status = identity.MemberStatusDeactivated
	}
	return identity.Member{UserId: m.UserSub, Role: identity.OrgRole(m.Role), Status: status, UpdatedAt: m.UpdatedAt.UTC()}
}

// Problem codes of openapi/identity.
const (
	codeInvalidRequest = "invalid_request"
	codeNotFound       = "not_found"
	codeOwnRole        = "own_role"
	codeLastOwner      = "last_owner"
	codeUpstream       = "upstream_unavailable"
	codeInternal       = "internal_error"
	// codeOriginNotAllowed: widget token for an origin outside the allow-list (#30).
	codeOriginNotAllowed = "origin_not_allowed"
	// codeAppLimitReached: the org has apps_per_org apps already (#38).
	codeAppLimitReached = "app_limit_reached"
)

var titles = map[string]string{
	codeInvalidRequest:       "Invalid request",
	auth.CodeUnauthenticated: "Unauthenticated",
	auth.CodeForbidden:       "Forbidden",
	codeNotFound:             "Not found",
	codeOwnRole:              "Own role",
	codeLastOwner:            "Last owner",
	codeUpstream:             "Upstream unavailable",
	codeInternal:             "Internal error",
	codeOriginNotAllowed:     "Origin not allowed",
	codeAppLimitReached:      "App limit reached",
	codeMemberExists:         "Member exists",
	codeOwnMembership:        "Own membership",
	codeRateLimited:          "Rate limited",
}

type problem struct {
	Type    string `json:"type"`
	Title   string `json:"title"`
	Status  int    `json:"status"`
	Code    string `json:"code"`
	Detail  string `json:"detail,omitempty"`
	TraceID string `json:"trace_id,omitempty"`
}

// writeProblem writes an RFC 9457 body. 403 and 404 bodies are generic: they never
// say which rule refused or whether the org exists.
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

// NotReadyRetryAfter is the Retry-After of a 503 for a Zitadel setup that has not
// finished (ErrNotReady), in seconds.
const NotReadyRetryAfter = "5"

// writeNotReady answers ErrNotReady: 503 upstream_unavailable with Retry-After.
// Nothing changed; the same call works once zitadel-bootstrap has written the
// project id.
func writeNotReady(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Retry-After", NotReadyRetryAfter)
	writeProblem(w, r, http.StatusServiceUnavailable, codeUpstream, "The Zitadel setup is not finished. Retry later.")
}

func writeJSON(w http.ResponseWriter, v any) { writeJSONStatus(w, http.StatusOK, v) }

func writeJSONStatus(w http.ResponseWriter, status int, v any) {
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
