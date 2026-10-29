// Package mfagate enforces MFA on the server before Zitadel issues a token
// (synthwerk#94, synthwerk-infra ADR-0002 option C).
//
//   - Gate serves a Zitadel request execution on the calls that finish a sign-in
//     (OIDC CreateCallback, device authorization, SAML CreateResponse). It reads the
//     session factors from Zitadel and refuses a session without a second factor.
//     Zitadel then answers the caller 403 and issues no code and no token.
//   - Claims serves the pre-access-token function. It adds "amr" to the access token
//     from the evidence that Gate stored for the user. kit/auth RequireMFA reads it.
//
// Both handlers listen on the hook address (network zitadel-hooks only), next to
// package zitadelhook. Each Zitadel target has its own signing key.
package mfagate

import (
	"slices"
	"time"
)

// Factors are the checks a Zitadel session passed (session v2 Factors). A field is
// true when the factor has a verification time.
type Factors struct {
	// UserID is the user of the session (factors.user.id).
	UserID string
	// Password: the password check passed.
	Password bool
	// WebAuthN: a passkey or security key check passed. WebAuthNUserVerified: with
	// user verification (PIN or biometrics), which makes it a passkey sign-in.
	WebAuthN             bool
	WebAuthNUserVerified bool
	// Intent: an external identity provider signed the user in.
	Intent bool
	// One-time codes.
	TOTP, OTPSMS, OTPEmail, RecoveryCode bool
}

// AMR values (RFC 8176), as Zitadel writes them into the ID token.
const (
	AMRPassword = "pwd"
	AMRUser     = "user"
	AMROTP      = "otp"
	AMRMFA      = "mfa"
)

// AMR maps factors to amr values with the rule of Zitadel's own ID token
// (internal/api/oidc/amr.go, v4.20.0): a passkey with user verification counts two
// factors, every other check one; two factors or more add "mfa".
func AMR(f Factors) []string {
	var amr []string
	factors, otp := 0, false
	if f.Password {
		amr = append(amr, AMRPassword)
		factors++
	}
	if f.WebAuthN {
		amr = append(amr, AMRUser)
		factors++
		if f.WebAuthNUserVerified {
			factors++
		}
	}
	if f.Intent {
		factors++ // no amr value in RFC 8176
	}
	for _, ok := range []bool{f.TOTP, f.OTPSMS, f.OTPEmail, f.RecoveryCode} {
		if ok {
			otp = true
			factors++
		}
	}
	if otp {
		amr = append(amr, AMROTP)
	}
	if factors >= 2 {
		amr = append(amr, AMRMFA)
	}
	return amr
}

// HasMFA reports whether the factors make a sign-in with MFA.
func HasMFA(f Factors) bool {
	return slices.Contains(AMR(f), AMRMFA)
}

// Evidence is what Gate stores for a user after a session with MFA passed.
type Evidence struct {
	UserSub   string
	SessionID string
	AMR       []string
	CheckedAt time.Time
}
