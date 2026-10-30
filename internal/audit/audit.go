// Package audit serves the audit list of an org (synthwerk#37).
//
// The list is built on the outbox: a trigger (migration 0009) copies every
// identity event with a known org into identity.audit_events, in the transaction
// of the change. The outbox deletes published rows after 7 days; this table keeps
// them. The list shows them newest first to owners and admins of the org.
package audit

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/VelimirMueller/synthwerk-contracts/go/identity"
	"github.com/VelimirMueller/synthwerk-contracts/go/kit/auth"

	"github.com/VelimirMueller/synthwerk-identity/internal/orgs"
)

// Event is a row of identity.audit_events.
type Event struct {
	Seq     int64
	ID      string
	Type    string
	Actor   string
	Subject string
	Time    time.Time
	Data    map[string]any
}

// DB is the part of *pgxpool.Pool the store needs.
type DB interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

// Store reads audit events (search_path=identity).
type Store struct{ DB DB }

// List returns up to limit events of org with seq < before (0 = from the newest),
// newest first.
func (s *Store) List(ctx context.Context, orgID string, before int64, limit int) ([]Event, error) {
	if before <= 0 {
		before = 1<<63 - 1
	}
	rows, err := s.DB.Query(ctx, `SELECT seq, id::text, type, actor, coalesce(subject, ''), time, data
		FROM audit_events WHERE org_id = $1 AND seq < $2 ORDER BY seq DESC LIMIT $3`, orgID, before, limit)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (Event, error) {
		var e Event
		var data []byte
		if err := row.Scan(&e.Seq, &e.ID, &e.Type, &e.Actor, &e.Subject, &e.Time, &data); err != nil {
			return Event{}, err
		}
		if err := json.Unmarshal(data, &e.Data); err != nil {
			return Event{}, err
		}
		return e, nil
	})
}

// Repo is the part of Store the handler uses.
type Repo interface {
	List(ctx context.Context, orgID string, before int64, limit int) ([]Event, error)
}

// Handler serves GET /v1/orgs/{orgId}/audit-events.
type Handler struct {
	Repo Repo
	// Orgs gives the org gate and the stored role.
	Orgs *orgs.Handler
}

// Page sizes.
const (
	DefaultPageSize = 50
	MaxPageSize     = 100
)

// Register adds the route to mux. authn must be auth.Middleware.
func (h *Handler) Register(mux *http.ServeMux, authn func(http.Handler) http.Handler) {
	mux.Handle("GET /v1/orgs/{orgId}/audit-events", authn(http.HandlerFunc(h.list)))
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	a, ok := h.Orgs.Gate(w, r)
	if !ok {
		return
	}
	// Owner and admin of the org only: the token first, then the stored role (an
	// active membership). Operator is not enough. a.Own means "the token acts in
	// this org with an org role", not "owner"; AtLeast(Admin) is owner or admin.
	tokenAdmin := a.Own && orgs.TokenRole(a.Principal).AtLeast(orgs.Admin)
	if !tokenAdmin {
		orgs.WriteProblem(w, r, http.StatusForbidden, auth.CodeForbidden, "")
		return
	}
	stored, err := h.Orgs.Repo.MemberRole(r.Context(), a.Org.ID, a.Principal.Subject)
	if err != nil && !errors.Is(err, orgs.ErrNotFound) {
		h.Orgs.Fail(w, r, err)
		return
	}
	if !stored.AtLeast(orgs.Admin) {
		orgs.WriteProblem(w, r, http.StatusForbidden, auth.CodeForbidden, "")
		return
	}
	limit, before, ok := pageParams(r)
	if !ok {
		orgs.WriteProblem(w, r, http.StatusBadRequest, orgs.CodeInvalidRequest, "limit must be 1 to 100; cursor must come from next_cursor.")
		return
	}
	events, err := h.Repo.List(r.Context(), a.Org.ID, before, limit+1)
	if err != nil {
		h.Orgs.Fail(w, r, err)
		return
	}
	page := identity.AuditEventPage{Items: []identity.AuditEvent{}}
	if len(events) > limit {
		events = events[:limit]
		next := base64.RawURLEncoding.EncodeToString([]byte(strconv.FormatInt(events[len(events)-1].Seq, 10)))
		page.NextCursor = &next
	}
	for _, e := range events {
		page.Items = append(page.Items, body(e))
	}
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(page); err != nil {
		h.Orgs.Fail(w, r, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(buf.Bytes())
}

func body(e Event) identity.AuditEvent {
	out := identity.AuditEvent{Type: e.Type, Actor: e.Actor, Time: e.Time.UTC(), Data: e.Data}
	if id, err := uuid.Parse(e.ID); err == nil {
		out.Id = id
	}
	if e.Subject != "" {
		s := e.Subject
		out.Subject = &s
	}
	if out.Data == nil {
		out.Data = map[string]any{}
	}
	return out
}

// pageParams reads limit and the cursor: base64url of the seq of the last item.
func pageParams(r *http.Request) (limit int, before int64, ok bool) {
	q := r.URL.Query()
	limit = DefaultPageSize
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > MaxPageSize {
			return 0, 0, false
		}
		limit = n
	}
	if c := q.Get("cursor"); c != "" {
		if len(c) > 256 {
			return 0, 0, false
		}
		b, err := base64.RawURLEncoding.DecodeString(c)
		if err != nil {
			return 0, 0, false
		}
		n, err := strconv.ParseInt(string(b), 10, 64)
		if err != nil || n < 1 {
			return 0, 0, false
		}
		before = n
	}
	return limit, before, true
}
