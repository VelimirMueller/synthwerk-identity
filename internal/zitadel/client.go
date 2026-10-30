// Package zitadel writes org role changes to Zitadel user grants (synthwerk#29),
// reads org names and reads the factors of a sign-in session for the MFA gate
// (synthwerk#94). It calls the Zitadel API inside the stack with the PAT of the
// machine user identity-sync. That user lives in the platform org and is
// PROJECT_GRANT_OWNER on each project grant of synthwerk-api: no instance role.
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
	"sync"
	"time"

	"github.com/VelimirMueller/synthwerk-contracts/go/kit/auth"

	"github.com/VelimirMueller/synthwerk-identity/internal/mfagate"
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
	// Project resolves the project synthwerk-api whose grants hold the org roles.
	// Nil or not resolved yet: calls that need it fail with orgs.ErrNotReady.
	Project *Project
	// HTTP is the client. Nil: a client with a 10 s timeout.
	HTTP *http.Client

	mu       sync.Mutex
	platform string // org of the machine user = the platform org, once read
}

// ErrRefused: the write would touch the platform org or the operator role. identity
// never changes platform users or operator grants (synthwerk#29).
var ErrRefused = errors.New("zitadel: refused: platform org or operator grant")

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
	if !to.Valid() {
		return ErrRefused
	}
	platform, err := c.PlatformOrg(ctx)
	if err != nil {
		return err
	}
	if zitadelOrgID == platform {
		return ErrRefused
	}
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
	if slices.Contains(got.UserGrant.RoleKeys, auth.RoleOperator) {
		return ErrRefused
	}
	keys := slices.DeleteFunc(slices.Clone(got.UserGrant.RoleKeys), func(k string) bool { return orgs.Role(k).Valid() })
	keys = append(keys, string(to))
	slices.Sort(keys)
	err = c.do(ctx, http.MethodPut, path, zitadelOrgID, map[string]any{"roleKeys": keys}, nil)
	if notChanged(err) {
		return nil
	}
	return err
}

func (c *Client) findGrant(ctx context.Context, zitadelOrgID, userSub string) (string, error) {
	projectID, err := c.Project.Resolve(ctx)
	if err != nil {
		return "", err
	}
	var found struct {
		Result []struct {
			ID string `json:"id"`
		} `json:"result"`
	}
	q := map[string]any{"queries": []any{
		map[string]any{"userIdQuery": map[string]any{"userId": userSub}},
		map[string]any{"projectIdQuery": map[string]any{"projectId": projectID}},
	}}
	if err := c.do(ctx, http.MethodPost, "/management/v1/users/grants/_search", zitadelOrgID, q, &found); err != nil {
		return "", err
	}
	if len(found.Result) != 1 {
		return "", fmt.Errorf("zitadel: want 1 grant of the user in project, got %d", len(found.Result))
	}
	return found.Result[0].ID, nil
}

// GrantActive implements orgs.GrantStates: it reads the user grant and reports
// whether its state is active. A grant Zitadel does not know (404) is not active.
func (c *Client) GrantActive(ctx context.Context, zitadelOrgID, userSub, grantID string) (bool, error) {
	if userSub == "" || grantID == "" {
		return false, errors.New("zitadel: grant state: empty id")
	}
	var got struct {
		UserGrant struct {
			State string `json:"state"`
		} `json:"userGrant"`
	}
	path := "/management/v1/users/" + url.PathEscape(userSub) + "/grants/" + url.PathEscape(grantID)
	err := c.do(ctx, http.MethodGet, path, zitadelOrgID, nil, &got)
	var e *APIError
	// Code 5 is gRPC NOT_FOUND, as in Uninvite. Not found = not active (fail closed).
	if errors.As(err, &e) && (e.Status == http.StatusNotFound || e.Code == 5) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return got.UserGrant.State == "USER_GRANT_STATE_ACTIVE", nil
}

// DeleteUser implements account.Users (synthwerk#41): UserService v2 DeleteUser.
// A user Zitadel does not know (404) counts as removed, so a retry after a lost
// answer succeeds. The machine user needs the permission user.delete on the user's
// org (synthwerk-infra zitadel-bootstrap).
func (c *Client) DeleteUser(ctx context.Context, userSub string) error {
	if userSub == "" {
		return errors.New("zitadel: delete user: empty id")
	}
	err := c.do(ctx, http.MethodDelete, "/v2/users/"+url.PathEscape(userSub), "", nil, nil)
	var e *APIError
	if errors.As(err, &e) && e.Status == http.StatusNotFound {
		return nil
	}
	return err
}

// PlatformOrg returns the org of the machine user, which is the platform org
// (synthwerk). It is read once from Zitadel and kept.
func (c *Client) PlatformOrg(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.platform != "" {
		return c.platform, nil
	}
	var me struct {
		User struct {
			Details struct {
				ResourceOwner string `json:"resourceOwner"`
			} `json:"details"`
		} `json:"user"`
	}
	if err := c.do(ctx, http.MethodGet, "/auth/v1/users/me", "", nil, &me); err != nil {
		return "", err
	}
	if me.User.Details.ResourceOwner == "" {
		return "", errors.New("zitadel: the machine user has no org")
	}
	c.platform = me.User.Details.ResourceOwner
	return c.platform, nil
}

// OrgName returns the name of the org that holds a user grant. It reads the grant,
// not the org: identity-sync is PROJECT_GRANT_OWNER on the project grant only and
// may not read the org itself (least privilege, synthwerk#29).
func (c *Client) OrgName(ctx context.Context, zitadelOrgID, userSub, grantID string) (string, error) {
	var got struct {
		UserGrant struct {
			OrgName string `json:"orgName"`
		} `json:"userGrant"`
	}
	path := "/management/v1/users/" + url.PathEscape(userSub) + "/grants/" + url.PathEscape(grantID)
	if err := c.do(ctx, http.MethodGet, path, zitadelOrgID, nil, &got); err != nil {
		return "", err
	}
	return got.UserGrant.OrgName, nil
}

// factor is a session factor; only its verification time counts.
type factor struct {
	VerifiedAt string `json:"verifiedAt"`
}

func (f *factor) ok() bool { return f != nil && f.VerifiedAt != "" }

// Session implements mfagate.Sessions. It calls SessionService/GetSession over the
// Connect protocol (POST, JSON body), so the session token stays out of URLs and
// access logs. The session token is the permission: any authenticated caller with
// it may read the session (zitadel query.SessionByID, v4.20.0).
func (c *Client) Session(ctx context.Context, id, token string) (mfagate.Factors, error) {
	var got struct {
		Session struct {
			ID      string `json:"id"`
			Factors struct {
				User *struct {
					VerifiedAt string `json:"verifiedAt"`
					ID         string `json:"id"`
				} `json:"user"`
				Password *factor `json:"password"`
				WebAuthN *struct {
					VerifiedAt   string `json:"verifiedAt"`
					UserVerified bool   `json:"userVerified"`
				} `json:"webAuthN"`
				Intent       *factor `json:"intent"`
				TOTP         *factor `json:"totp"`
				OTPSMS       *factor `json:"otpSms"`
				OTPEmail     *factor `json:"otpEmail"`
				RecoveryCode *factor `json:"recoveryCode"`
			} `json:"factors"`
		} `json:"session"`
	}
	err := c.do(ctx, http.MethodPost, "/zitadel.session.v2.SessionService/GetSession", "",
		map[string]string{"sessionId": id, "sessionToken": token}, &got)
	var apiErr *APIError
	// 400, 403 and 404 come from the session id or token. 401 means our own PAT
	// failed: a config error, not a refused session.
	if errors.As(err, &apiErr) && (apiErr.Status == http.StatusBadRequest || apiErr.Status == http.StatusForbidden || apiErr.Status == http.StatusNotFound) {
		return mfagate.Factors{}, fmt.Errorf("%w: status %d", mfagate.ErrSessionRefused, apiErr.Status)
	}
	if err != nil {
		return mfagate.Factors{}, err
	}
	s := got.Session.Factors
	if got.Session.ID != id || s.User == nil || s.User.VerifiedAt == "" {
		return mfagate.Factors{}, fmt.Errorf("%w: no verified user", mfagate.ErrSessionRefused)
	}
	f := mfagate.Factors{
		UserID:       s.User.ID,
		Password:     s.Password.ok(),
		Intent:       s.Intent.ok(),
		TOTP:         s.TOTP.ok(),
		OTPSMS:       s.OTPSMS.ok(),
		OTPEmail:     s.OTPEmail.ok(),
		RecoveryCode: s.RecoveryCode.ok(),
	}
	if s.WebAuthN != nil && s.WebAuthN.VerifiedAt != "" {
		f.WebAuthN, f.WebAuthNUserVerified = true, s.WebAuthN.UserVerified
	}
	return f, nil
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
	if orgID != "" {
		req.Header.Set("x-zitadel-orgid", orgID)
	}
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
