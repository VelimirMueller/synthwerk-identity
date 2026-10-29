package widget_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/VelimirMueller/synthwerk-contracts/go/kit/auth"

	"github.com/VelimirMueller/synthwerk-identity/internal/widget"
)

const issuer = "https://identity.synthwerk.test"

var subject = widget.Subject{
	UserSub:      "100000000000000001",
	ZitadelOrgID: "300000000000000001",
	AppID:        "019a3b10-7c2d-7e4f-8a5b-6c7d8e9f0a1b",
	Origin:       "https://shop.example",
}

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func newIssuer(t *testing.T, ttl time.Duration, now func() time.Time) *widget.Issuer {
	t.Helper()
	i, err := widget.NewIssuer(widget.Config{Issuer: issuer, TTL: ttl, Key: newKey(t), Now: now})
	if err != nil {
		t.Fatal(err)
	}
	return i
}

// verifier is the kit verifier a consumer such as llm uses, on the key set of i.
func verifier(t *testing.T, i *widget.Issuer) *auth.Verifier {
	t.Helper()
	srv := httptest.NewServer(i.JWKSHandler())
	t.Cleanup(srv.Close)
	v, err := auth.NewVerifier(auth.Config{Issuer: issuer, Audiences: []string{widget.DefaultAudience}, JWKSURL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func payload(t *testing.T, raw string) map[string]any {
	t.Helper()
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWS: %d parts", len(parts))
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestIssue(t *testing.T) {
	t.Run("Issue - default lifetime - 10 minutes, verified by the kit verifier with Zitadel claim names", func(t *testing.T) {
		i := newIssuer(t, 0, nil)
		tok, err := i.Issue(subject)
		if err != nil {
			t.Fatal(err)
		}
		if tok.ExpiresIn != 600 || time.Until(tok.ExpiresAt) > widget.MaxTTL {
			t.Fatalf("expires_in %d, at %s", tok.ExpiresIn, tok.ExpiresAt)
		}
		p, err := verifier(t, i).Verify(t.Context(), tok.Raw)
		if err != nil {
			t.Fatal(err)
		}
		if p.Subject != subject.UserSub || p.OrgID != subject.ZitadelOrgID || p.ClientID != subject.AppID || len(p.Roles) != 0 {
			t.Fatalf("principal %+v", p)
		}
		if p.Raw[auth.ClaimOrigin] != subject.Origin {
			t.Fatalf("origin claim %v", p.Raw[auth.ClaimOrigin])
		}
	})

	t.Run("Issue - claims - exp minus iat is the lifetime, nbf = iat, jti set, no roles", func(t *testing.T) {
		tok, err := newIssuer(t, 15*time.Minute, nil).Issue(subject)
		if err != nil {
			t.Fatal(err)
		}
		c := payload(t, tok.Raw)
		iat, exp, nbf := c["iat"].(float64), c["exp"].(float64), c["nbf"].(float64)
		if exp-iat != 900 || nbf != iat || c["jti"] == "" || c["iss"] != issuer {
			t.Fatalf("claims %v", c)
		}
		if _, has := c[auth.ClaimRoles]; has {
			t.Fatal("widget token carries roles")
		}
	})

	t.Run("Issue - header - typ at+jwt, alg ES256, kid of the published key", func(t *testing.T) {
		i := newIssuer(t, 0, nil)
		tok, err := i.Issue(subject)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := base64.RawURLEncoding.DecodeString(strings.Split(tok.Raw, ".")[0])
		var h map[string]string
		_ = json.Unmarshal(b, &h)
		rec := httptest.NewRecorder()
		i.JWKSHandler().ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, widget.JWKSPath, nil))
		var set struct {
			Keys []map[string]any `json:"keys"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &set)
		if h["typ"] != widget.TokenType || h["alg"] != "ES256" || len(set.Keys) != 1 || set.Keys[0]["kid"] != h["kid"] {
			t.Fatalf("header %v, keys %v", h, set.Keys)
		}
		if _, private := set.Keys[0]["d"]; private {
			t.Fatal("key set holds the private key")
		}
	})

	t.Run("Issue - missing origin - refused", func(t *testing.T) {
		s := subject
		s.Origin = ""
		if _, err := newIssuer(t, 0, nil).Issue(s); err == nil {
			t.Fatal("issued")
		}
	})
}

func TestExpiry(t *testing.T) {
	t.Run("Verify - token issued 16 minutes ago with the max lifetime - expired", func(t *testing.T) {
		past := func() time.Time { return time.Now().Add(-16 * time.Minute) }
		i := newIssuer(t, widget.MaxTTL, past)
		tok, err := i.Issue(subject)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := verifier(t, i).Verify(t.Context(), tok.Raw); !errors.Is(err, auth.ErrExpired) {
			t.Fatalf("err %v, want ErrExpired", err)
		}
	})

	t.Run("Verify - token issued 14 minutes ago with the max lifetime - still valid", func(t *testing.T) {
		past := func() time.Time { return time.Now().Add(-14 * time.Minute) }
		i := newIssuer(t, widget.MaxTTL, past)
		tok, err := i.Issue(subject)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := verifier(t, i).Verify(t.Context(), tok.Raw); err != nil {
			t.Fatal(err)
		}
	})

	for _, ttl := range []time.Duration{-time.Minute, 30 * time.Second, widget.MaxTTL + time.Second, time.Hour} {
		t.Run("NewIssuer - lifetime "+ttl.String()+" - refused", func(t *testing.T) {
			if _, err := widget.NewIssuer(widget.Config{Issuer: issuer, TTL: ttl, Key: newKey(t)}); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func TestNewIssuer(t *testing.T) {
	t.Run("NewIssuer - relative issuer - refused", func(t *testing.T) {
		if _, err := widget.NewIssuer(widget.Config{Issuer: "identity", Key: newKey(t)}); err == nil {
			t.Fatal("accepted")
		}
	})
	t.Run("NewIssuer - P-384 key - refused", func(t *testing.T) {
		k, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if _, err := widget.NewIssuer(widget.Config{Issuer: issuer, Key: k}); err == nil {
			t.Fatal("accepted")
		}
	})
	t.Run("Verify - other key signed the token - refused", func(t *testing.T) {
		tok, err := newIssuer(t, 0, nil).Issue(subject)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := verifier(t, newIssuer(t, 0, nil)).Verify(t.Context(), tok.Raw); !errors.Is(err, auth.ErrUnauthenticated) {
			t.Fatalf("err %v", err)
		}
	})
}

func TestParseKey(t *testing.T) {
	k := newKey(t)
	pkcs8, _ := x509.MarshalPKCS8PrivateKey(k)
	sec1, _ := x509.MarshalECPrivateKey(k)
	rk, _ := rsa.GenerateKey(rand.Reader, 2048)
	rsa8, _ := x509.MarshalPKCS8PrivateKey(rk)
	pub, _ := x509.MarshalPKIXPublicKey(k.Public())

	for _, c := range []struct {
		name string
		pem  []byte
	}{
		{"PKCS #8", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})},
		{"SEC 1", pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: sec1})},
	} {
		t.Run("ParseKey - "+c.name+" - P-256 key", func(t *testing.T) {
			got, err := widget.ParseKey(c.pem)
			if err != nil || !got.Equal(k) {
				t.Fatalf("err %v", err)
			}
		})
	}
	for _, c := range []struct {
		name string
		pem  []byte
	}{
		{"not PEM", []byte("not a key")},
		{"RSA key", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: rsa8})},
		{"public key", pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pub})},
		{"broken bytes", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("xx")})},
	} {
		t.Run("ParseKey - "+c.name+" - refused", func(t *testing.T) {
			if _, err := widget.ParseKey(c.pem); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}
