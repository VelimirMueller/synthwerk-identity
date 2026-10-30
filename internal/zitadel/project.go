package zitadel

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"regexp"
	"strings"
	"sync"

	"github.com/VelimirMueller/synthwerk-identity/internal/orgs"
)

// Project resolves the id of the Zitadel project synthwerk-api (synthwerk#37).
//
// zitadel-bootstrap makes the project after identity has started, so compose
// cannot set the id. The bootstrap writes it to File in the volume zitadel-hooks,
// like the PAT and the signing keys. Resolve reads File until it holds an id and
// then keeps it: a project id never changes.
//
// A fixed ID wins over File. The zero Project knows no id.
type Project struct {
	// ID is a fixed project id (SYNTHWERK_IDENTITY_ZITADEL_PROJECT_ID).
	ID string
	// File holds the project id (SYNTHWERK_IDENTITY_ZITADEL_PROJECT_ID_FILE).
	File string

	mu       sync.Mutex
	resolved string
}

var projectIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

// Resolve returns the project id. Until the id is known it returns an error that
// wraps orgs.ErrNotReady, so an invite answers 503 and the next call reads again.
func (p *Project) Resolve(context.Context) (string, error) {
	if p == nil {
		return "", fmt.Errorf("%w: no project id configured", orgs.ErrNotReady)
	}
	if p.ID != "" {
		return p.ID, nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.resolved != "" {
		return p.resolved, nil
	}
	if p.File == "" {
		return "", fmt.Errorf("%w: no project id configured", orgs.ErrNotReady)
	}
	b, err := os.ReadFile(p.File) //nolint:gosec // G304: path from our own config
	if errors.Is(err, fs.ErrNotExist) {
		return "", fmt.Errorf("%w: %s not written yet", orgs.ErrNotReady, p.File)
	}
	if err != nil {
		return "", fmt.Errorf("%w: %w", orgs.ErrNotReady, err)
	}
	id := strings.TrimSpace(string(b))
	if id == "" {
		return "", fmt.Errorf("%w: %s is empty", orgs.ErrNotReady, p.File)
	}
	if !projectIDPattern.MatchString(id) {
		return "", fmt.Errorf("%w: %s holds no project id", orgs.ErrNotReady, p.File)
	}
	p.resolved = id
	return id, nil
}
