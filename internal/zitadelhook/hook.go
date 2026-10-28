// Package zitadelhook receives Zitadel Actions v2 event calls (#28, task 5; #29).
// It checks the signature, drops repeats and
//   - turns user.human.added into the event dev.synthwerk.identity.user.created.v1,
//   - mirrors the user grants of the project (user.grant.*) into memberships
//     (package orgs), which writes org.created and member.role_changed.
//
// The handler listens on its own address, which only the network zitadel-hooks
// reaches. The edge routes /identity/* to the API port and never to this one.
package zitadelhook

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"time"

	"github.com/VelimirMueller/synthwerk-contracts/go/kit/cloudevents"

	"github.com/VelimirMueller/synthwerk-identity/internal/orgs"
)

// Path is the route Zitadel calls.
const Path = "/internal/zitadel/actions"

// MaxBody is the largest call body. A user.human.added call is about 450 bytes.
const MaxBody = 64 << 10

// Event types.
const (
	ZitadelUserAdded = "user.human.added"
	// User grant events (aggregate type "usergrant"). Their payload holds ids and
	// role keys only, no personal data.
	ZitadelGrantAdded          = "user.grant.added"
	ZitadelGrantChanged        = "user.grant.changed"
	ZitadelGrantRemoved        = "user.grant.removed"
	ZitadelGrantCascadeRemoved = "user.grant.cascade.removed"
	UserCreated                = "dev.synthwerk.identity.user.created.v1"
	UserCreatedData            = "https://schemas.synthwerk.dev/events/identity/user.created.v1.json"
)

// Call is the part of a Zitadel event call that identity reads. The call also
// holds event_payload with the email and the name: it is never decoded or logged.
type Call struct {
	AggregateID   string    `json:"aggregateID"`
	AggregateType string    `json:"aggregateType"`
	ResourceOwner string    `json:"resourceOwner"`
	InstanceID    string    `json:"instanceID"`
	Sequence      uint64    `json:"sequence"`
	EventType     string    `json:"event_type"`
	CreatedAt     time.Time `json:"created_at"`
	// EventPayload is decoded only for user grant events (ids and role keys).
	EventPayload json.RawMessage `json:"event_payload"`
}

// GrantEvents are the user grant events the hook mirrors.
var GrantEvents = []string{ZitadelGrantAdded, ZitadelGrantChanged, ZitadelGrantRemoved, ZitadelGrantCascadeRemoved}

// GrantMirror applies a user grant event to the memberships (orgs.Store).
type GrantMirror interface {
	OrgByZitadelID(ctx context.Context, zitadelOrgID string) (orgs.Org, error)
	ApplyGrant(ctx context.Context, c orgs.GrantChange, orgName string) (orgs.Outcome, error)
}

// Key identifies one Zitadel event: an aggregate's sequence is unique per instance.
func (c Call) Key() string {
	return fmt.Sprintf("%s:%s:%s:%d", c.InstanceID, c.AggregateType, c.AggregateID, c.Sequence)
}

// UserCreatedData is the data of the user.created event (contracts events/identity/user.created.v1).
type UserCreatedPayload struct {
	UserSub      string `json:"user_sub"`
	ZitadelOrgID string `json:"zitadel_org_id"`
}

// Store writes the seen key and the event in one transaction.
type Store interface {
	// RecordOnce stores the event unless key was seen before. New is false for a repeat.
	RecordOnce(ctx context.Context, key string, e cloudevents.Event) (isNew bool, err error)
}

// Handler serves Path.
type Handler struct {
	Store Store
	// SigningKey returns the target's signing key. It is read per call, because
	// zitadel-bootstrap can write the key after identity has started.
	SigningKey func() (string, error)
	// Source is the CloudEvents source, /synthwerk/identity/<env>.
	Source string
	Log    *slog.Logger
	// Now is time.Now in production.
	Now func() time.Time
	// Grants mirrors user grant events. Nil: grant events are acknowledged and dropped.
	Grants GrantMirror
	// ProjectID is the Zitadel project synthwerk-api. Grants of other projects are
	// dropped. Empty: every project counts.
	ProjectID string
	// OrgName names an org identity does not know yet. Nil: "org <zitadel id>".
	OrgName func(ctx context.Context, zitadelOrgID string) (string, error)
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxBody))
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			http.Error(w, "body too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}
	key, err := h.SigningKey()
	if err != nil {
		h.Log.ErrorContext(r.Context(), "zitadel hook: no signing key", slog.String("event.name", "zitadel_hook.key_missing"), slog.String("exception.message", err.Error()))
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	if err := Verify(body, r.Header.Get(SignatureHeader), key, h.Now()); err != nil {
		h.Log.WarnContext(r.Context(), "zitadel hook: signature rejected", slog.String("event.name", "zitadel_hook.rejected"), slog.String("error.type", err.Error()))
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var c Call
	if err := json.Unmarshal(body, &c); err != nil {
		http.Error(w, "body is not a Zitadel event", http.StatusBadRequest)
		return
	}
	if slices.Contains(GrantEvents, c.EventType) {
		h.grant(w, r, c)
		return
	}
	if c.EventType != ZitadelUserAdded {
		// Another event on this target: acknowledge, so Zitadel does not retry it.
		w.WriteHeader(http.StatusNoContent)
		return
	}
	// Every part of the dedup key must be set, else two events could share a key.
	if c.AggregateType != "user" || c.Sequence == 0 || c.AggregateID == "" || c.ResourceOwner == "" || c.InstanceID == "" || c.CreatedAt.IsZero() {
		http.Error(w, "event misses ids", http.StatusBadRequest)
		return
	}
	e, err := cloudevents.New(r.Context(), UserCreated, h.Source,
		UserCreatedPayload{UserSub: c.AggregateID, ZitadelOrgID: c.ResourceOwner},
		cloudevents.WithSubject(c.AggregateID),
		cloudevents.WithActor("system"),
		cloudevents.WithDataSchema(UserCreatedData),
		cloudevents.WithTime(c.CreatedAt),
	)
	if err != nil {
		// An id outside the envelope rules (pattern, length): not retryable.
		http.Error(w, "event does not fit the contract", http.StatusBadRequest)
		return
	}
	isNew, err := h.Store.RecordOnce(r.Context(), c.Key(), e)
	if err != nil {
		h.Log.ErrorContext(r.Context(), "zitadel hook: store failed", slog.String("event.name", "zitadel_hook.failed"), slog.String("exception.message", err.Error()))
		http.Error(w, "store failed", http.StatusInternalServerError)
		return
	}
	h.Log.InfoContext(r.Context(), "zitadel hook: user created",
		slog.String("event.name", "zitadel_hook.user_created"),
		slog.String("enduser.id", c.AggregateID),
		slog.Bool("duplicate", !isNew))
	w.WriteHeader(http.StatusNoContent)
}

// grantPayload is the part of a user grant event payload that identity reads.
type grantPayload struct {
	UserID    string   `json:"userId"`
	ProjectID string   `json:"projectId"`
	RoleKeys  []string `json:"roleKeys"`
}

// decodePayload reads event_payload as a JSON object, or as a base64 string that
// holds one (Go []byte encoding).
func decodePayload(raw json.RawMessage, out any) error {
	if len(raw) > 0 && raw[0] == '"' {
		var b []byte
		if err := json.Unmarshal(raw, &b); err != nil {
			return err
		}
		raw = b
	}
	if len(raw) == 0 {
		return errors.New("no event_payload")
	}
	return json.Unmarshal(raw, out)
}

func (h *Handler) grant(w http.ResponseWriter, r *http.Request, c Call) {
	if h.Grants == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if c.AggregateType != "usergrant" || c.Sequence == 0 || c.AggregateID == "" || c.ResourceOwner == "" || c.InstanceID == "" {
		http.Error(w, "event misses ids", http.StatusBadRequest)
		return
	}
	var p grantPayload
	if err := decodePayload(c.EventPayload, &p); err != nil {
		http.Error(w, "event payload is not a user grant", http.StatusBadRequest)
		return
	}
	if p.ProjectID != "" && h.ProjectID != "" && p.ProjectID != h.ProjectID {
		w.WriteHeader(http.StatusNoContent) // another project: not an org role
		return
	}
	change := orgs.GrantChange{
		Key:          c.Key(),
		ZitadelOrgID: c.ResourceOwner,
		GrantID:      c.AggregateID,
		UserSub:      p.UserID,
		Roles:        p.RoleKeys,
		Removed:      c.EventType == ZitadelGrantRemoved || c.EventType == ZitadelGrantCascadeRemoved,
	}
	if c.EventType == ZitadelGrantAdded && p.ProjectID == "" && h.ProjectID != "" {
		w.WriteHeader(http.StatusNoContent) // an added grant always names its project
		return
	}
	name := ""
	if !change.Removed {
		if _, err := h.Grants.OrgByZitadelID(r.Context(), c.ResourceOwner); errors.Is(err, orgs.ErrNotFound) && h.OrgName != nil {
			n, err := h.OrgName(r.Context(), c.ResourceOwner)
			if err != nil {
				// The org stays unnamed; the slug falls back to o-<id>.
				h.Log.WarnContext(r.Context(), "zitadel hook: org name not read", slog.String("event.name", "zitadel_hook.org_name_failed"),
					slog.String("exception.message", err.Error()))
			}
			name = n
		}
	}
	out, err := h.Grants.ApplyGrant(r.Context(), change, name)
	if err != nil {
		h.Log.ErrorContext(r.Context(), "zitadel hook: grant not mirrored", slog.String("event.name", "zitadel_hook.failed"), slog.String("exception.message", err.Error()))
		http.Error(w, "store failed", http.StatusInternalServerError)
		return
	}
	level := slog.LevelInfo
	if out == orgs.OutcomeLastOwner {
		level = slog.LevelWarn // Zitadel took the last owner away; the mirror keeps the owner.
	}
	h.Log.Log(r.Context(), level, "zitadel hook: grant",
		slog.String("event.name", "zitadel_hook.grant"),
		slog.String("zitadel.event_type", c.EventType),
		slog.String("enduser.id", p.UserID),
		slog.String("outcome", string(out)))
	w.WriteHeader(http.StatusNoContent)
}
