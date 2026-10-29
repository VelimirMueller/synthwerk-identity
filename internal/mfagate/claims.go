package mfagate

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"
)

// PreAccessToken is the function name in a pre-access-token call.
const PreAccessToken = "function/preaccesstoken" //nolint:gosec // G101: a function name, not a credential

// DefaultMaxAge is how long evidence counts after the gate stored it.
const DefaultMaxAge = 12 * time.Hour

// claimsCall is the part of a pre-access-token call that Claims reads
// (zitadel internal/api/oidc/userinfo.go ContextInfo, v4.20.0).
type claimsCall struct {
	Function string `json:"function"`
	UserInfo struct {
		Subject string `json:"sub"`
	} `json:"userinfo"`
}

type appendClaim struct {
	Key   string `json:"key"`
	Value any    `json:"value"`
}

type claimsResponse struct {
	AppendClaims []appendClaim `json:"append_claims,omitempty"`
}

// Claims adds "amr" to an access token from the evidence the gate stored for the
// user. Without fresh evidence the token gets no amr, and RequireMFA refuses it.
//
// The amr is the one of the user's newest sign-in that passed the gate, not
// necessarily of the session behind this token: Zitadel shows no session to this
// function. The gate refuses every sign-in without a second factor, so no user
// token comes from a session without one.
//
// Zitadel calls it without interruptOnError: a failure gives a token without amr.
type Claims struct {
	Store      Store
	SigningKey func() (string, error)
	Log        *slog.Logger
	Now        func() time.Time
	// MaxAge bounds the age of the evidence. Zero: DefaultMaxAge.
	MaxAge time.Duration
}

func (c *Claims) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, ok := readSigned(w, r, c.SigningKey, c.Now(), c.Log, "token_claims")
	if !ok {
		return
	}
	var call claimsCall
	if err := json.Unmarshal(body, &call); err != nil {
		http.Error(w, "body is not a Zitadel function call", http.StatusBadRequest)
		return
	}
	if call.Function != PreAccessToken || call.UserInfo.Subject == "" {
		writeJSON(w, claimsResponse{})
		return
	}
	ctx := r.Context()
	e, err := c.Store.Latest(ctx, call.UserInfo.Subject)
	if err != nil {
		if !errors.Is(err, ErrNoEvidence) {
			c.Log.ErrorContext(ctx, "token claims: evidence not read", slog.String("event.name", "token_claims.failed"),
				slog.String("exception.message", err.Error()))
		}
		writeJSON(w, claimsResponse{}) // machine users and users without a gated sign-in
		return
	}
	maxAge := c.MaxAge
	if maxAge <= 0 {
		maxAge = DefaultMaxAge
	}
	if age := c.Now().Sub(e.CheckedAt); age > maxAge || age < -time.Minute || len(e.AMR) == 0 {
		writeJSON(w, claimsResponse{})
		return
	}
	writeJSON(w, claimsResponse{AppendClaims: []appendClaim{{Key: "amr", Value: e.AMR}}})
}
