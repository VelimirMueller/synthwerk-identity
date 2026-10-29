package account

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// ExportPath is the export route of every service that keeps user rows.
const ExportPath = "/v1/me/export"

// Export limits per source.
const (
	DefaultSourceTimeout = 10 * time.Second
	MaxSourceBytes       = 32 << 20
)

// Source is a service that keeps user rows and serves ExportPath.
type Source struct {
	// Name is the service name in the export, for example "llm".
	Name string
	// BaseURL is the service address inside the stack, for example http://llm:8080.
	BaseURL string
}

var sourceName = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)

// ParseSources reads "name=url,name=url". Empty: no source.
func ParseSources(v string) ([]Source, error) {
	var out []Source
	seen := map[string]bool{}
	for _, part := range strings.Split(v, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		name, raw, ok := strings.Cut(part, "=")
		name, raw = strings.TrimSpace(name), strings.TrimSpace(raw)
		if !ok || !sourceName.MatchString(name) || seen[name] {
			return nil, fmt.Errorf("account: export source %q: want name=url with a unique name ^[a-z][a-z0-9-]*$", name)
		}
		u, err := url.Parse(raw)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return nil, fmt.Errorf("account: export source %s: want an http(s) base URL without user info, query or fragment", name)
		}
		seen[name] = true
		out = append(out, Source{Name: name, BaseURL: strings.TrimRight(raw, "/")})
	}
	return out, nil
}

// Fetcher asks the sources with the caller's token.
type Fetcher struct {
	Sources []Source
	// HTTP is the client. Nil: a client with DefaultSourceTimeout and no redirects.
	HTTP *http.Client
}

// errUnavailable: the source did not give a usable answer. The cause is logged only.
var errUnavailable = errors.New("account: export source unavailable")

// fetch returns the JSON body of one source. token is the caller's raw access token.
func (f *Fetcher) fetch(ctx context.Context, s Source, token string) (json.RawMessage, error) {
	hc := f.HTTP
	if hc == nil {
		hc = &http.Client{
			Timeout: DefaultSourceTimeout,
			// The token goes to the configured host only, never to a redirect target.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.BaseURL+ExportPath, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	res, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %w", errUnavailable, s.Name, err)
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: %s: status %d", errUnavailable, s.Name, res.StatusCode)
	}
	if mt, _, err := mime.ParseMediaType(res.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		return nil, fmt.Errorf("%w: %s: content type %q", errUnavailable, s.Name, res.Header.Get("Content-Type"))
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, MaxSourceBytes+1))
	if err != nil {
		return nil, fmt.Errorf("%w: %s: read: %w", errUnavailable, s.Name, err)
	}
	if len(body) > MaxSourceBytes {
		return nil, fmt.Errorf("%w: %s: body above %d bytes", errUnavailable, s.Name, MaxSourceBytes)
	}
	// The data member is an object: anything else is not a service export.
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(body, &probe); err != nil || probe == nil {
		return nil, fmt.Errorf("%w: %s: body is not a JSON object", errUnavailable, s.Name)
	}
	return json.RawMessage(body), nil
}
