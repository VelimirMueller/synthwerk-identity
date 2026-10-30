package account

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"sync"

	"github.com/VelimirMueller/synthwerk-contracts/go/kit/auth"
)

// ErrNoClients: no OIDC client id is configured, so no ID token can pass.
var ErrNoClients = errors.New("account: no ID token client configured")

// ClientIDTokens verifies ID tokens of the accepted OIDC clients (the studio). The
// client ids are ClientIDs plus the one in ClientFile. The file is read per call,
// because zitadel-bootstrap writes it after identity starts. The verifier, with its
// key set cache, is rebuilt only when the ids change.
type ClientIDTokens struct {
	// Base holds Issuer, JWKSURL and HTTPClient. Its Audiences are ignored.
	Base      auth.Config
	ClientIDs []string
	// ClientFile holds one client id: plain text, or JSON with "client_id" (the
	// studio-client.json of zitadel-bootstrap). Empty: none.
	ClientFile string

	mu   sync.Mutex
	key  string
	v    *auth.IDTokenVerifier
	errV error
}

// Verify implements IDTokens. Without a client id it refuses every token
// (ErrUnauthenticated and ErrNoClients).
func (c *ClientIDTokens) Verify(ctx context.Context, raw, subject string) (*auth.IDToken, error) {
	v, err := c.verifier()
	if err != nil {
		return nil, err
	}
	return v.Verify(ctx, raw, subject)
}

func (c *ClientIDTokens) verifier() (*auth.IDTokenVerifier, error) {
	ids := append([]string(nil), c.ClientIDs...)
	if c.ClientFile != "" {
		id, err := readClientID(c.ClientFile)
		if err != nil && len(ids) == 0 {
			return nil, fmt.Errorf("%w: %w: %w", auth.ErrUnauthenticated, ErrNoClients, err)
		}
		if id != "" && !slices.Contains(ids, id) {
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		return nil, fmt.Errorf("%w: %w", auth.ErrUnauthenticated, ErrNoClients)
	}
	key := strings.Join(ids, ",")
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.key != key {
		cfg := c.Base
		cfg.Audiences = ids
		c.v, c.errV = auth.NewIDTokenVerifier(cfg)
		c.key = key
	}
	return c.v, c.errV
}

// readClientID reads a client id file: plain text or JSON with "client_id".
func readClientID(path string) (string, error) {
	b, err := os.ReadFile(path) //nolint:gosec // G304: path from our own config
	if err != nil {
		return "", err
	}
	s := strings.TrimSpace(string(b))
	if strings.HasPrefix(s, "{") {
		var f struct {
			ClientID string `json:"client_id"`
		}
		if err := json.Unmarshal(b, &f); err != nil {
			return "", fmt.Errorf("%s: %w", path, err)
		}
		s = strings.TrimSpace(f.ClientID)
	}
	if s == "" {
		return "", fmt.Errorf("%s: no client id", path)
	}
	return s, nil
}
