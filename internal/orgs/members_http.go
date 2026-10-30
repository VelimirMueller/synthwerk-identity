package orgs

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"math"
	"net/http"
	"strconv"
	"strings"

	"github.com/google/uuid"
	openapi_types "github.com/oapi-codegen/runtime/types"

	"github.com/VelimirMueller/synthwerk-contracts/go/identity"

	"github.com/VelimirMueller/synthwerk-contracts/go/kit/auth"
)

// MemberWriter invites members and changes their status (synthwerk#37). *Store
// satisfies it.
type MemberWriter interface {
	Invite(ctx context.Context, org Org, actorSub, email string, role Role) (Invitation, error)
	ListInvitations(ctx context.Context, orgID, before string, limit int) ([]Invitation, error)
	SetStatus(ctx context.Context, org Org, actorSub, targetSub string, active bool) (Membership, bool, error)
	RevokeInvitation(ctx context.Context, org Org, actorSub, id string) error
}

// InviteAcceptor turns an invited member active at its first call to the org.
// *Store satisfies it; the org gate uses it when the repo has it. AcceptInvite
// must be a no-op for every member that is not invited.
type InviteAcceptor interface {
	AcceptInvite(ctx context.Context, orgID, sub string) error
}

// The store that serves the routes must accept invites: a compile-time check.
var _ InviteAcceptor = (*Store)(nil)

// Problem codes of synthwerk#37.
const (
	codeMemberExists  = "member_exists"
	codeOwnMembership = "own_membership"
	codeRateLimited   = "rate_limited"
)

func (h *Handler) registerMembers(mux *http.ServeMux, authn func(http.Handler) http.Handler) {
	if h.InviteLimit == nil {
		h.InviteLimit = NewInviteLimiter()
	}
	mux.Handle("POST /v1/orgs/{orgId}/members", authn(http.HandlerFunc(h.inviteMember)))
	mux.Handle("GET /v1/orgs/{orgId}/invitations", authn(http.HandlerFunc(h.listInvitations)))
	mux.Handle("DELETE /v1/orgs/{orgId}/invitations/{invitationId}", authn(http.HandlerFunc(h.revokeInvitation)))
	// {userId}:deactivate and {userId}:reactivate: a wildcard is a whole segment, so
	// the handler splits the verb off.
	mux.Handle("POST /v1/orgs/{orgId}/members/{userAction}", authn(http.HandlerFunc(h.memberStatus)))
}

// writer passes the org gate and the token check of a member write: an own org
// role of admin or more. Operator access is read only (403).
func (h *Handler) writer(w http.ResponseWriter, r *http.Request) (access, bool) {
	a, ok := h.gate(w, r)
	if !ok {
		return access{}, false
	}
	if !a.own || !TokenRole(a.p).AtLeast(Admin) {
		writeProblem(w, r, http.StatusForbidden, auth.CodeForbidden, "")
		return access{}, false
	}
	return a, true
}

func (h *Handler) inviteMember(w http.ResponseWriter, r *http.Request) {
	a, ok := h.writer(w, r)
	if !ok {
		return
	}
	// Not identity.InviteMemberRequest: its Email type rewrites "Name <a@b>" to
	// "a@b". The raw string must be a plain address.
	var body struct {
		Email string `json:"email"`
		Role  string `json:"role"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil || dec.More() || !Role(body.Role).Valid() || !ValidEmail(body.Email) {
		writeProblem(w, r, http.StatusBadRequest, codeInvalidRequest, "Body must be {\"email\": <address>, \"role\": \"owner\" | \"admin\" | \"member\"}.")
		return
	}
	// Every valid attempt counts, also refused ones: the limit stops probing.
	if ok, wait := h.InviteLimit.Allow(a.org.ID, a.p.Subject); !ok {
		h.Log.InfoContext(r.Context(), "invite rate limited", slog.String("event.name", "orgs.invite_rate_limited"), slog.String("org.id", a.org.ID))
		w.Header().Set("Retry-After", strconv.Itoa(int(math.Ceil(wait.Seconds()))))
		writeProblem(w, r, http.StatusTooManyRequests, codeRateLimited, "")
		return
	}
	// A new email and a user of another org give the same answer and the same
	// trace (Store.Invite): the caller cannot tell whether an account exists.
	inv, err := h.Members.Invite(r.Context(), a.org, a.p.Subject, body.Email, Role(body.Role))
	if h.memberRefusal(w, r, a, "", "invite", err) {
		return
	}
	h.Log.InfoContext(r.Context(), "invitation", slog.String("event.name", "orgs.member_invited"),
		slog.String("org.id", a.org.ID), slog.String("invitation.id", inv.ID), slog.String("role", string(inv.Role)))
	writeJSONStatus(w, http.StatusAccepted, invitationBody(inv))
}

func (h *Handler) listInvitations(w http.ResponseWriter, r *http.Request) {
	a, ok := h.writer(w, r)
	if !ok {
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
	q := r.URL.Query()
	limit := DefaultPageSize
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > MaxPageSize {
			writeProblem(w, r, http.StatusBadRequest, codeInvalidRequest, "limit must be 1 to 100.")
			return
		}
		limit = n
	}
	before := ""
	if c := q.Get("cursor"); c != "" {
		b, err := base64.RawURLEncoding.DecodeString(c)
		id, perr := uuid.Parse(string(b))
		if len(c) > 256 || err != nil || perr != nil {
			writeProblem(w, r, http.StatusBadRequest, codeInvalidRequest, "cursor must come from next_cursor.")
			return
		}
		before = id.String()
	}
	list, err := h.Members.ListInvitations(r.Context(), a.org.ID, before, limit+1)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	page := identity.InvitationPage{Items: []identity.Invitation{}}
	if len(list) > limit {
		list = list[:limit]
		next := base64.RawURLEncoding.EncodeToString([]byte(list[len(list)-1].ID))
		page.NextCursor = &next
	}
	for _, inv := range list {
		page.Items = append(page.Items, invitationBody(inv))
	}
	writeJSON(w, page)
}

func (h *Handler) revokeInvitation(w http.ResponseWriter, r *http.Request) {
	a, ok := h.writer(w, r)
	if !ok {
		return
	}
	id, err := uuid.Parse(r.PathValue("invitationId"))
	if err != nil {
		writeProblem(w, r, http.StatusNotFound, codeNotFound, "")
		return
	}
	err = h.Members.RevokeInvitation(r.Context(), a.org, a.p.Subject, id.String())
	if h.memberRefusal(w, r, a, "", "revoke", err) {
		return
	}
	h.Log.InfoContext(r.Context(), "invitation revoked", slog.String("event.name", "orgs.invitation_revoked"),
		slog.String("org.id", a.org.ID), slog.String("invitation.id", id.String()))
	w.WriteHeader(http.StatusNoContent)
}

func invitationBody(inv Invitation) identity.Invitation {
	out := identity.Invitation{Email: openapi_types.Email(inv.Email), Role: identity.OrgRole(inv.Role), InvitedBy: inv.InvitedBy, CreatedAt: inv.CreatedAt.UTC()}
	if id, err := uuid.Parse(inv.ID); err == nil {
		out.Id = id
	}
	return out
}

func (h *Handler) memberStatus(w http.ResponseWriter, r *http.Request) {
	target, verb, found := strings.Cut(r.PathValue("userAction"), ":")
	if !found || (verb != "deactivate" && verb != "reactivate") {
		writeProblem(w, r, http.StatusNotFound, codeNotFound, "")
		return
	}
	a, ok := h.writer(w, r)
	if !ok {
		return
	}
	if !subPattern.MatchString(target) {
		writeProblem(w, r, http.StatusNotFound, codeNotFound, "")
		return
	}
	m, changed, err := h.Members.SetStatus(r.Context(), a.org, a.p.Subject, target, verb == "reactivate")
	if h.memberRefusal(w, r, a, target, verb, err) {
		return
	}
	h.Log.InfoContext(r.Context(), "member status", slog.String("event.name", "orgs.member_status_changed"),
		slog.String("org.id", a.org.ID), slog.String("enduser.id", target), slog.String("status", m.Status), slog.Bool("changed", changed))
	writeJSON(w, memberBody(m))
}

// memberRefusal writes the answer for err and reports whether it wrote one.
// Refusals write no event and are logged without the email.
func (h *Handler) memberRefusal(w http.ResponseWriter, r *http.Request, a access, target, op string, err error) bool {
	ctx := r.Context()
	refused := func(reason string) {
		h.Log.InfoContext(ctx, "member change refused", slog.String("event.name", "orgs.member_change_refused"),
			slog.String("org.id", a.org.ID), slog.String("enduser.id", target), slog.String("op", op), slog.String("reason", reason))
	}
	switch {
	case err == nil:
		return false
	case errors.Is(err, ErrForbidden):
		refused("forbidden")
		writeProblem(w, r, http.StatusForbidden, auth.CodeForbidden, "")
	case errors.Is(err, ErrNotFound):
		writeProblem(w, r, http.StatusNotFound, codeNotFound, "")
	case errors.Is(err, ErrOwnMembership):
		refused(codeOwnMembership)
		writeProblem(w, r, http.StatusConflict, codeOwnMembership, "Nobody deactivates their own membership.")
	case errors.Is(err, ErrLastOwner):
		refused(codeLastOwner)
		writeProblem(w, r, http.StatusConflict, codeLastOwner, "The org must keep at least one active owner.")
	case errors.Is(err, ErrMemberExists):
		refused(codeMemberExists)
		writeProblem(w, r, http.StatusConflict, codeMemberExists, "The email is a member of this org already.")
	case errors.Is(err, ErrNotReady):
		h.Log.WarnContext(ctx, "member change: zitadel project id not known yet", slog.String("event.name", "orgs.member_change_not_ready"),
			slog.String("op", op))
		writeNotReady(w, r)
	case errors.Is(err, ErrUpstream):
		h.Log.ErrorContext(r.Context(), "member change: zitadel refused", slog.String("event.name", "orgs.member_change_upstream_failed"),
			slog.String("op", op), slog.String("exception.message", err.Error()))
		writeProblem(w, r, http.StatusBadGateway, codeUpstream, "")
	default:
		h.fail(w, r, err)
	}
	return true
}
