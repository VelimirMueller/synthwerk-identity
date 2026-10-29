package mfagate

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"time"

	"github.com/VelimirMueller/synthwerk-identity/internal/zitadelhook"
)

// Routes on the hook address.
const (
	GatePath   = "/internal/zitadel/mfa-gate"
	ClaimsPath = "/internal/zitadel/token-claims"
)

// MaxBody is the largest call body. A request execution also carries the request
// headers; a pre-access-token call carries the user, metadata and grants.
const MaxBody = 256 << 10

// GatedMethods are the Zitadel API calls that finish a sign-in with a session. The
// bootstrap in synthwerk-infra points a request execution on each at Gate.
var GatedMethods = []string{
	"/zitadel.oidc.v2.OIDCService/CreateCallback",
	"/zitadel.oidc.v2beta.OIDCService/CreateCallback",
	"/zitadel.oidc.v2.OIDCService/AuthorizeOrDenyDeviceAuthorization",
	"/zitadel.saml.v2.SAMLService/CreateResponse",
}

// CodeMFARequired is the message Zitadel returns to the caller on a refusal.
const CodeMFARequired = "mfa_required: the session has no second factor"

// ErrSessionRefused: Zitadel did not return the session (unknown id or wrong token).
var ErrSessionRefused = errors.New("mfagate: Zitadel refused the session")

// Sessions reads the factors of a Zitadel session. zitadel.Client implements it.
type Sessions interface {
	// Session returns ErrSessionRefused (wrapped) when Zitadel refuses id and token.
	Session(ctx context.Context, id, token string) (Factors, error)
}

// ErrNoEvidence: no stored evidence for the user.
var ErrNoEvidence = errors.New("mfagate: no evidence")

// Store keeps the newest evidence per user (table identity.mfa_evidence).
type Store interface {
	Record(ctx context.Context, e Evidence) error
	// Latest returns ErrNoEvidence when the user has none.
	Latest(ctx context.Context, userSub string) (Evidence, error)
}

// gateCall is the part of a request execution body that Gate reads. The request is
// the protojson form of the gRPC request.
type gateCall struct {
	FullMethod string `json:"fullMethod"`
	Request    struct {
		Session *struct {
			SessionID    string `json:"sessionId"`
			SessionToken string `json:"sessionToken"`
		} `json:"session"`
		// The caller ends the flow with an error (CreateCallback, CreateResponse) or
		// denies a device. No token follows.
		Error json.RawMessage `json:"error"`
		Deny  json.RawMessage `json:"deny"`
	} `json:"request"`
}

// forwarded is the answer that makes Zitadel stop the call with this status.
// Source: zitadel internal/execution/execution.go HandleResponse (v4.20.0).
type forwarded struct {
	Status  int    `json:"forwardedStatusCode"`
	Message string `json:"forwardedErrorMessage"`
}

// Gate refuses every sign-in whose session has no second factor. Zitadel calls it
// with interruptOnError: any answer other than 2xx without an error body, or no
// answer, also stops the sign-in (fail closed).
type Gate struct {
	Sessions Sessions
	// Store receives the evidence of a passed session. A failed write does not
	// stop the sign-in: the token then has no amr and RequireMFA refuses it.
	Store Store
	// SigningKey returns the signing key of the gate target, read per call.
	SigningKey func() (string, error)
	Log        *slog.Logger
	// Now is time.Now in production.
	Now func() time.Time
}

func (g *Gate) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, ok := readSigned(w, r, g.SigningKey, g.Now(), g.Log, "mfa_gate")
	if !ok {
		return
	}
	var c gateCall
	if err := json.Unmarshal(body, &c); err != nil {
		http.Error(w, "body is not a Zitadel request execution", http.StatusBadRequest)
		return
	}
	ctx := r.Context()
	if !slices.Contains(GatedMethods, c.FullMethod) {
		// A method this gate does not know: refuse rather than guess its shape.
		g.refuse(ctx, w, "", "unknown_method", slog.String("rpc.method", c.FullMethod))
		return
	}
	s := c.Request.Session
	if s == nil {
		if len(c.Request.Error) > 0 || len(c.Request.Deny) > 0 {
			w.WriteHeader(http.StatusNoContent) // the flow ends without a token
			return
		}
		g.refuse(ctx, w, "", "no_session", slog.String("rpc.method", c.FullMethod))
		return
	}
	if s.SessionID == "" || s.SessionToken == "" {
		g.refuse(ctx, w, "", "no_session", slog.String("rpc.method", c.FullMethod))
		return
	}
	f, err := g.Sessions.Session(ctx, s.SessionID, s.SessionToken)
	if err != nil {
		if errors.Is(err, ErrSessionRefused) {
			g.refuse(ctx, w, "", "session_refused", slog.String("rpc.method", c.FullMethod))
			return
		}
		g.Log.ErrorContext(ctx, "mfa gate: session not read", slog.String("event.name", "mfa_gate.failed"),
			slog.String("exception.message", err.Error()))
		http.Error(w, "session not read", http.StatusServiceUnavailable)
		return
	}
	amr := AMR(f)
	if !HasMFA(f) || f.UserID == "" {
		g.refuse(ctx, w, f.UserID, "mfa_missing", slog.String("rpc.method", c.FullMethod), slog.Any("amr", amr))
		return
	}
	e := Evidence{UserSub: f.UserID, SessionID: s.SessionID, AMR: amr, CheckedAt: g.Now()}
	if err := g.Store.Record(ctx, e); err != nil {
		g.Log.ErrorContext(ctx, "mfa gate: evidence not stored", slog.String("event.name", "mfa_gate.store_failed"),
			slog.String("enduser.id", f.UserID), slog.String("exception.message", err.Error()))
	}
	g.Log.InfoContext(ctx, "mfa gate: passed", slog.String("event.name", "mfa_gate.passed"),
		slog.String("enduser.id", f.UserID), slog.String("rpc.method", c.FullMethod), slog.Any("amr", amr))
	w.WriteHeader(http.StatusNoContent) // Zitadel keeps the request as it is
}

// refuse answers 200 with an error body: Zitadel turns it into 403 PermissionDenied
// with CodeMFARequired for the caller. The log line holds no session token.
func (g *Gate) refuse(ctx context.Context, w http.ResponseWriter, userID, reason string, attrs ...slog.Attr) {
	attrs = append(attrs, slog.String("event.name", "mfa_gate.refused"), slog.String("reason", reason))
	if userID != "" {
		attrs = append(attrs, slog.String("enduser.id", userID))
	}
	g.Log.LogAttrs(ctx, slog.LevelWarn, "mfa gate: refused", attrs...)
	writeJSON(w, forwarded{Status: http.StatusForbidden, Message: CodeMFARequired})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// readSigned reads the body and checks the Zitadel signature, as zitadelhook does.
// On false the answer is written.
func readSigned(w http.ResponseWriter, r *http.Request, signingKey func() (string, error), now time.Time, log *slog.Logger, name string) ([]byte, bool) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return nil, false
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxBody))
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			http.Error(w, "body too large", http.StatusRequestEntityTooLarge)
			return nil, false
		}
		http.Error(w, "read body", http.StatusBadRequest)
		return nil, false
	}
	key, err := signingKey()
	if err != nil {
		log.ErrorContext(r.Context(), name+": no signing key", slog.String("event.name", name+".key_missing"), slog.String("exception.message", err.Error()))
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return nil, false
	}
	if err := zitadelhook.Verify(body, r.Header.Get(zitadelhook.SignatureHeader), key, now); err != nil {
		log.WarnContext(r.Context(), name+": signature rejected", slog.String("event.name", name+".rejected"), slog.String("error.type", err.Error()))
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return nil, false
	}
	return body, true
}
