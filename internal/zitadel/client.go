// Package zitadel writes org role changes to Zitadel user grants (synthwerk#29) and
// reads org names. It calls the v1 management REST API inside the stack with the PAT
// of a machine user that may manage user grants.
package zitadel

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/VelimirMueller/synthwerk-identity/internal/orgs"
)

// Client calls Zitadel. Zitadel finds its instance by host name, so every request
// carries Host.
type Client struct {
	// BaseURL is the API address, for example http://zitadel:8080.
	BaseURL string
	// Host is the instance host (external domain and port), for example auth.localhost:8080.
	Host string
	// Token returns the PAT. It is read per call, so a PAT written after the start works.
	Token func() (string, error)
	// ProjectID is the project synthwerk-api whose grants hold the org roles.
	ProjectID string
	// HTTP is the client. Nil: a client with a 10 s timeout.
	HTTP *http.Client
}

// APIError is a non-2xx answer. Message is Zitadel's text; it holds no secrets.
type APIError struct {
	Method, Path string
	Status, Code int
	Message      string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("zitadel %s %s: status %d, code %d: %s", e.Method, e.Path, e.Status, e.Code, e.Message)
}

func notChanged(err error) bool {
	var e *APIError
	if !errors.As(err, &e) || e.Code != 9 {
		return false
	}
	m := strings.ToLower(e.Message)
	return strings.Contains(m, "not changed") || strings.Contains(m, "not been changed") || strings.Contains(m, "no changes")
}

// SetRole implements orgs.Grants: the grant keeps its other role keys (end_user)
// and gets exactly one org role, to.
func (c *Client) SetRole(ctx context.Context, zitadelOrgID, userSub, grantID string, to orgs.Role) error {
	if grantID == "" {
		id, err := c.findGrant(ctx, zitadelOrgID, userSub)
		if err != nil {
			return err
		}
		grantID = id
	}
	path := "/management/v1/users/" + url.PathEscape(userSub) + "/grants/" + url.PathEscape(grantID)
	var got struct {
		UserGrant struct {
			RoleKeys []string `json:"roleKeys"`
		} `json:"userGrant"`
	}
	if err := c.do(ctx, http.MethodGet, path, zitadelOrgID, nil, &got); err != nil {
		return err
	}
	keys := slices.DeleteFunc(slices.Clone(got.UserGrant.RoleKeys), func(k string) bool { return orgs.Role(k).Valid() })
	keys = append(keys, string(to))
	slices.Sort(keys)
	err := c.do(ctx, http.MethodPut, path, zitadelOrgID, map[string]any{"roleKeys": keys}, nil)
	if notChanged(err) {
		return nil
	}
	return err
}

func (c *Client) findGrant(ctx context.Context, zitadelOrgID, userSub string) (string, error) {
	var found struct {
		Result []struct {
			ID string `json:"id"`
		} `json:"result"`
	}
	q := map[string]any{"queries": []any{
		map[string]any{"userIdQuery": map[string]any{"userId": userSub}},
		map[string]any{"projectIdQuery": map[string]any{"projectId": c.ProjectID}},
	}}
	if err := c.do(ctx, http.MethodPost, "/management/v1/users/grants/_search", zitadelOrgID, q, &found); err != nil {
		return "", err
	}
	if len(found.Result) != 1 {
		return "", fmt.Errorf("zitadel: want 1 grant of the user in project, got %d", len(found.Result))
	}
	return found.Result[0].ID, nil
}

// OrgName returns the name of a Zitadel org.
func (c *Client) OrgName(ctx context.Context, zitadelOrgID string) (string, error) {
	var got struct {
		Org struct {
			Name string `json:"name"`
		} `json:"org"`
	}
	if err := c.do(ctx, http.MethodGet, "/management/v1/orgs/me", zitadelOrgID, nil, &got); err != nil {
		return "", err
	}
	return got.Org.Name, nil
}

func (c *Client) do(ctx context.Context, method, path, orgID string, body, out any) error {
	tok, err := c.Token()
	if err != nil {
		return fmt.Errorf("zitadel: token: %w", err)
	}
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(c.BaseURL, "/")+path, rd)
	if err != nil {
		return err
	}
	req.Host = c.Host
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("x-zitadel-orgid", orgID)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	hc := c.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 10 * time.Second}
	}
	res, err := hc.Do(req)
	if err != nil {
		return fmt.Errorf("zitadel %s %s: %w", method, path, err)
	}
	defer func() { _ = res.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("zitadel %s %s: read: %w", method, path, err)
	}
	if res.StatusCode < 200 || res.StatusCode > 299 {
		e := &APIError{Method: method, Path: path, Status: res.StatusCode}
		var g struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		}
		if json.Unmarshal(data, &g) == nil {
			e.Code, e.Message = g.Code, g.Message
		}
		return e
	}
	if out != nil && len(data) > 0 {
		if err := json.Unmarshal(data, out); err != nil {
			return fmt.Errorf("zitadel %s %s: decode: %w", method, path, err)
		}
	}
	return nil
}
