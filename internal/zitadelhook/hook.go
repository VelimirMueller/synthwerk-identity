// Package zitadelhook receives Zitadel Actions v2 event calls (#28, task 5; #29).
// It checks the signature, drops repeats and
//   - turns user.human.added into the event dev.synthwerk.identity.user.created.v1,
//   - mirrors the user grants of the project (user.grant.*) into memberships
//     (package orgs), which writes org.created and member.role_changed,
//   - mirrors a deactivated or reactivated user grant into the member status
//     (synthwerk#37), which writes member.deactivated or member.reactivated.
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
	"regexp"
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
	// Deactivate and reactivate of a user grant carry no payload (synthwerk#37).
	ZitadelGrantDeactivated = "user.grant.deactivated"
	ZitadelGrantReactivated = "user.grant.reactivated"
	UserCreated             = "dev.synthwerk.identity.user.created.v1"
	UserCreatedData         = "https://schemas.synthwerk.dev/events/identity/user.created.v1.json"
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

// GrantStatusEvents are the user grant events the hook mirrors into the member
// status (synthwerk#37).
var GrantStatusEvents = []string{ZitadelGrantDeactivated, ZitadelGrantReactivated}

// GrantMirror applies a user grant event to the memberships (orgs.Store).
type GrantMirror interface {
	OrgByZitadelID(ctx context.Context, zitadelOrgID string) (orgs.Org, error)
	ApplyGrant(ctx context.Context, c orgs.GrantChange, orgName string) (orgs.Outcome, error)
	ApplyGrantStatus(ctx context.Context, c orgs.GrantStatusChange) (orgs.Outcome, error)
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
	// Project returns the id of the Zitadel project synthwerk-api. Grants of other
	// projects are dropped. While it fails (orgs.ErrNotReady: zitadel-bootstrap has
	// not written the id yet), a grant event that names a project answers 503 and
	// changes nothing. Nil: every project counts.
	Project func(ctx context.Context) (string, error)
	// PlatformOrg returns the platform org. Its grants (operator) are never mirrored.
	// Nil: no org is skipped.
	PlatformOrg func(ctx context.Context) (string, error)
	// OrgName names an org identity does not know yet, from the grant. Nil: "org <zitadel id>".
	OrgName func(ctx context.Context, zitadelOrgID, userSub, grantID string) (string, error)
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
	if slices.Contains(GrantStatusEvents, c.EventType) {
		h.grantStatus(w, r, c)
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

var userIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

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
	if p.UserID != "" && !userIDPattern.MatchString(p.UserID) {
		http.Error(w, "event payload has a bad user id", http.StatusBadRequest)
		return
	}
	// changed and removed events may not name the project: the store then acts only
	// on a grant it mirrored before (by grant id), which was of this project.
	if !h.outsidePlatform(w, r, c) {
		return
	}
	projectID := ""
	if h.Project != nil && (p.ProjectID != "" || c.EventType == ZitadelGrantAdded) {
		id, err := h.Project(r.Context())
		if err != nil {
			h.Log.WarnContext(r.Context(), "zitadel hook: project id not known yet", slog.String("event.name", "zitadel_hook.not_ready"),
				slog.String("exception.message", err.Error()))
			http.Error(w, "project id unknown", http.StatusServiceUnavailable)
			return
		}
		projectID = id
	}
	if p.ProjectID != "" && projectID != "" && p.ProjectID != projectID {
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
	if c.EventType == ZitadelGrantAdded && p.ProjectID == "" && projectID != "" {
		w.WriteHeader(http.StatusNoContent) // an added grant always names its project
		return
	}
	name := ""
	if !change.Removed {
		_, err := h.Grants.OrgByZitadelID(r.Context(), c.ResourceOwner)
		if err != nil && !errors.Is(err, orgs.ErrNotFound) {
			h.Log.ErrorContext(r.Context(), "zitadel hook: org not read", slog.String("event.name", "zitadel_hook.failed"), slog.String("exception.message", err.Error()))
			http.Error(w, "store failed", http.StatusInternalServerError)
			return
		}
		if errors.Is(err, orgs.ErrNotFound) && h.OrgName != nil && p.UserID != "" {
			n, err := h.OrgName(r.Context(), c.ResourceOwner, p.UserID, c.AggregateID)
			if err != nil {
				// The org stays unnamed; the slug falls back to o-<id>.
				h.Log.WarnContext(r.Context(), "zitadel hook: org name not read", slog.String("event.name", "zitadel_hook.org_name_failed"),
					slog.String("exception.message", err.Error()))
			}
			name = n
		}
	}
	// ApplyGrant drops a repeat by change.Key (zitadel_event_seen), like RecordOnce.
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

// outsidePlatform reports whether the event's org is not the platform org. It
// answers the call and returns false for the platform org (its grants, operator,
// are never mirrored: 204) and when the platform org cannot be read (503).
func (h *Handler) outsidePlatform(w http.ResponseWriter, r *http.Request, c Call) bool {
	if h.PlatformOrg == nil {
		return true
	}
	platform, err := h.PlatformOrg(r.Context())
	if err != nil {
		h.Log.ErrorContext(r.Context(), "zitadel hook: platform org not read", slog.String("event.name", "zitadel_hook.failed"), slog.String("exception.message", err.Error()))
		http.Error(w, "platform org unknown", http.StatusServiceUnavailable)
		return false
	}
	if c.ResourceOwner == platform {
		w.WriteHeader(http.StatusNoContent) // platform users are never org members
		return false
	}
	return true
}

// grantStatus mirrors user.grant.deactivated and user.grant.reactivated. The
// events carry no payload; the store acts only on a grant it mirrored before (by
// grant id, in the org of the event), so no project check is needed.
func (h *Handler) grantStatus(w http.ResponseWriter, r *http.Request, c Call) {
	if h.Grants == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if c.AggregateType != "usergrant" || c.Sequence == 0 || c.AggregateID == "" || c.ResourceOwner == "" || c.InstanceID == "" {
		http.Error(w, "event misses ids", http.StatusBadRequest)
		return
	}
	if !h.outsidePlatform(w, r, c) {
		return
	}
	out, err := h.Grants.ApplyGrantStatus(r.Context(), orgs.GrantStatusChange{
		Key:          c.Key(),
		ZitadelOrgID: c.ResourceOwner,
		GrantID:      c.AggregateID,
		Active:       c.EventType == ZitadelGrantReactivated,
	})
	if err != nil {
		h.Log.ErrorContext(r.Context(), "zitadel hook: grant status not mirrored", slog.String("event.name", "zitadel_hook.failed"),
			slog.String("zitadel.event_type", c.EventType), slog.String("exception.message", err.Error()))
		http.Error(w, "store failed", http.StatusInternalServerError)
		return
	}
	level := slog.LevelInfo
	if out == orgs.OutcomeLastOwner || out == orgs.OutcomeUnconfirmed {
		level = slog.LevelWarn // identity and Zitadel disagree; the mirror fails closed.
	}
	h.Log.Log(r.Context(), level, "zitadel hook: grant status",
		slog.String("event.name", "zitadel_hook.grant_status"),
		slog.String("zitadel.event_type", c.EventType),
		slog.String("zitadel.grant_id", c.AggregateID),
		slog.String("outcome", string(out)))
	w.WriteHeader(http.StatusNoContent)
}
