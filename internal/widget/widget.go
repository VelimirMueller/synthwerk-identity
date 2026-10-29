// Package widget issues the short-lived widget token (synthwerk#30) and serves the
// public key set that verifies it.
//
// The token is a JWT: header typ "at+jwt", alg ES256, kid = RFC 7638 thumbprint of
// the key. The claim names follow Zitadel access tokens, so kit/auth.ZitadelMapper
// maps a widget token like a user token: sub, the Zitadel org id and client_id (the
// app id). synthwerk:origin binds the token to one origin. A widget token carries no
// roles: it is never an admin token.
package widget

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/uuid"
)

// Token lifetime. The contract caps expires_in at 900 s.
const (
	MaxTTL     = 15 * time.Minute
	MinTTL     = time.Minute
	DefaultTTL = 10 * time.Minute
)

// DefaultAudience is the audience of the services that accept a widget token.
const DefaultAudience = "synthwerk-api"

// JWKSPath serves the public keys. It is outside the OpenAPI: it needs no token.
const JWKSPath = "/.well-known/jwks.json"

// TokenType is the header typ (RFC 9068). kit/auth accepts it by default.
const TokenType = "at+jwt"

// Config of an Issuer.
type Config struct {
	// Issuer is the iss claim: the public URL of identity. Required, absolute.
	Issuer string
	// Audiences is the aud claim. Default [DefaultAudience].
	Audiences []string
	// TTL is the token lifetime: MinTTL to MaxTTL. Default DefaultTTL.
	TTL time.Duration
	// Key signs the tokens: ECDSA P-256. Required.
	Key *ecdsa.PrivateKey
	// Now is the clock. Default time.Now.
	Now func() time.Time
}

// Issuer signs widget tokens. It is safe for concurrent use.
type Issuer struct {
	issuer    string
	audiences []string
	ttl       time.Duration
	now       func() time.Time
	signer    jose.Signer
	jwks      []byte
}

// Token is one issued widget token.
type Token struct {
	// Raw is the signed JWT. Never log it.
	Raw       string
	ExpiresAt time.Time
	// ExpiresIn is the lifetime in whole seconds.
	ExpiresIn int
}

// Subject of a widget token: who, in which org, for which app and origin.
type Subject struct {
	UserSub      string
	ZitadelOrgID string
	AppID        string
	Origin       string
}

// NewIssuer checks cfg and builds the signer and the key set.
func NewIssuer(cfg Config) (*Issuer, error) {
	if u, err := url.Parse(cfg.Issuer); cfg.Issuer == "" || err != nil || u.Scheme == "" || u.Host == "" {
		return nil, errors.New("widget: issuer must be an absolute URL")
	}
	if cfg.Key == nil || cfg.Key.Curve != elliptic.P256() {
		return nil, errors.New("widget: the signing key must be ECDSA P-256")
	}
	if cfg.TTL == 0 {
		cfg.TTL = DefaultTTL
	}
	if cfg.TTL < MinTTL || cfg.TTL > MaxTTL {
		return nil, fmt.Errorf("widget: token lifetime %s is not between %s and %s", cfg.TTL, MinTTL, MaxTTL)
	}
	if len(cfg.Audiences) == 0 {
		cfg.Audiences = []string{DefaultAudience}
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	pub := jose.JSONWebKey{Key: cfg.Key.Public(), Algorithm: string(jose.ES256), Use: "sig"}
	thumb, err := pub.Thumbprint(crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("widget: key id: %w", err)
	}
	pub.KeyID = base64.RawURLEncoding.EncodeToString(thumb)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: cfg.Key},
		(&jose.SignerOptions{}).WithType(TokenType).WithHeader(jose.HeaderKey("kid"), pub.KeyID))
	if err != nil {
		return nil, fmt.Errorf("widget: signer: %w", err)
	}
	jwks, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{pub}})
	if err != nil {
		return nil, fmt.Errorf("widget: key set: %w", err)
	}
	return &Issuer{
		issuer:    cfg.Issuer,
		audiences: append([]string(nil), cfg.Audiences...),
		ttl:       cfg.TTL,
		now:       cfg.Now,
		signer:    signer,
		jwks:      jwks,
	}, nil
}

// TTL is the token lifetime.
func (i *Issuer) TTL() time.Duration { return i.ttl }

// claims of a widget token. The names equal kit/auth ClaimOrgID, ClaimClientID and
// ClaimOrigin; a unit test checks it.
type claims struct {
	jwt.Claims
	OrgID    string `json:"urn:zitadel:iam:user:resourceowner:id"`
	ClientID string `json:"client_id"`
	Origin   string `json:"synthwerk:origin"`
}

// Issue signs a token for s. Every field of s is required.
func (i *Issuer) Issue(s Subject) (Token, error) {
	if s.UserSub == "" || s.ZitadelOrgID == "" || s.AppID == "" || s.Origin == "" {
		return Token{}, errors.New("widget: subject, org, app and origin are required")
	}
	now := i.now().UTC().Truncate(time.Second)
	exp := now.Add(i.ttl)
	c := claims{
		Claims: jwt.Claims{
			Issuer:    i.issuer,
			Subject:   s.UserSub,
			Audience:  jwt.Audience(i.audiences),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			Expiry:    jwt.NewNumericDate(exp),
			ID:        uuid.Must(uuid.NewV7()).String(),
		},
		OrgID:    s.ZitadelOrgID,
		ClientID: s.AppID,
		Origin:   s.Origin,
	}
	raw, err := jwt.Signed(i.signer).Claims(c).Serialize()
	if err != nil {
		return Token{}, fmt.Errorf("widget: sign: %w", err)
	}
	return Token{Raw: raw, ExpiresAt: exp, ExpiresIn: int(i.ttl / time.Second)}, nil
}

// JWKSHandler serves the public key set (RFC 7517). No token needed.
func (i *Issuer) JWKSHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/jwk-set+json")
		w.Header().Set("Cache-Control", "public, max-age=300")
		_, _ = w.Write(i.jwks)
	})
}

// ParseKey reads an ECDSA P-256 private key from PEM: "PRIVATE KEY" (PKCS #8) or
// "EC PRIVATE KEY" (SEC 1). The error never holds key bytes.
func ParseKey(pemBytes []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("widget: signing key is not PEM")
	}
	var key any
	var err error
	switch block.Type {
	case "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("widget: PEM block %q is not a private key", block.Type)
	}
	if err != nil {
		return nil, errors.New("widget: signing key does not parse")
	}
	ec, ok := key.(*ecdsa.PrivateKey)
	if !ok || ec.Curve != elliptic.P256() {
		return nil, errors.New("widget: the signing key must be ECDSA P-256")
	}
	return ec, nil
}
