package zitadel

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/VelimirMueller/synthwerk-contracts/go/kit/auth"

	"github.com/VelimirMueller/synthwerk-identity/internal/orgs"
)

// Invite implements orgs.Users (synthwerk#37). It creates a human user in the
// org, asks Zitadel to send the invite mail (its SMTP provider: Mailpit in local,
// Resend in dev and prd) and adds the user grant of the project with role.
//
// Permissions: creating the user and the invite code need user.write in the org
// (Zitadel org role ORG_USER_MANAGER). PROJECT_GRANT_OWNER (ADR-0003) covers the
// user grant only. Without user.write, Zitadel answers 403 and nothing changes.
func (c *Client) Invite(ctx context.Context, zitadelOrgID, email string, role orgs.Role) (string, string, error) {
	if !role.Valid() {
		return "", "", ErrRefused
	}
	// The project first: before the Zitadel setup is done, nothing is written.
	projectID, err := c.Project.Resolve(ctx)
	if err != nil {
		return "", "", err
	}
	platform, err := c.PlatformOrg(ctx)
	if err != nil {
		return "", "", err
	}
	if zitadelOrgID == platform {
		return "", "", ErrRefused
	}
	grantID, err := c.projectGrant(ctx, zitadelOrgID, projectID)
	if err != nil {
		return "", "", err
	}
	name := profileName(email)
	var created struct {
		UserID string `json:"userId"`
	}
	// returnCode: Zitadel sends no separate verification mail; the invite mail
	// verifies the address when the user accepts it.
	err = c.do(ctx, http.MethodPost, "/v2/users/human", zitadelOrgID, map[string]any{
		"organization": map[string]string{"orgId": zitadelOrgID},
		"username":     email,
		"profile":      map[string]string{"givenName": name, "familyName": name},
		"email":        map[string]any{"email": email, "returnCode": map[string]any{}},
	}, &created)
	if exists(err) {
		// The user name is the email, unique in the instance. Only a user of this
		// org is member_exists; a user of another org must not be told apart from
		// a new email (no account enumeration).
		id, serr := c.userInOrg(ctx, zitadelOrgID, email)
		if serr != nil {
			return "", "", serr
		}
		if id != "" {
			return id, "", orgs.ErrMemberExists
		}
		return "", "", orgs.ErrOutsideOrg
	}
	if err != nil {
		return "", "", err
	}
	if created.UserID == "" {
		return "", "", errors.New("zitadel: user created without an id")
	}
	// The grant first, then the mail: an invitee never gets a mail without access.
	var grant struct {
		UserGrantID string `json:"userGrantId"`
	}
	path := "/management/v1/users/" + url.PathEscape(created.UserID) + "/grants"
	err = c.do(ctx, http.MethodPost, path, zitadelOrgID, map[string]any{
		"projectId": projectID, "projectGrantId": grantID, "roleKeys": []string{string(role)},
	}, &grant)
	if err == nil {
		path = "/v2/users/" + url.PathEscape(created.UserID) + "/invite_code"
		err = c.do(ctx, http.MethodPost, path, zitadelOrgID, map[string]any{"sendCode": map[string]any{}}, nil)
	}
	if err != nil {
		// Delete the half-made user, so a retry with the same email works.
		if derr := c.Uninvite(context.WithoutCancel(ctx), zitadelOrgID, created.UserID); derr != nil {
			return "", "", fmt.Errorf("%w (user %s not deleted: %w)", err, created.UserID, derr)
		}
		return "", "", err
	}
	return created.UserID, grant.UserGrantID, nil
}

// Uninvite implements orgs.Users: it deletes a user that Invite created. It
// refuses the platform org. A user that is gone already (404) is no error.
func (c *Client) Uninvite(ctx context.Context, zitadelOrgID, userSub string) error {
	platform, err := c.PlatformOrg(ctx)
	if err != nil {
		return err
	}
	if zitadelOrgID == platform {
		return ErrRefused
	}
	err = c.do(ctx, http.MethodDelete, "/v2/users/"+url.PathEscape(userSub), zitadelOrgID, nil, nil)
	var e *APIError
	if errors.As(err, &e) && (e.Status == http.StatusNotFound || e.Code == 5) {
		return nil
	}
	return err
}

// SetActive implements orgs.Users: it deactivates or reactivates the user grant.
// It refuses the platform org and a grant that holds operator.
func (c *Client) SetActive(ctx context.Context, zitadelOrgID, userSub, grantID string, active bool) error {
	platform, err := c.PlatformOrg(ctx)
	if err != nil {
		return err
	}
	if zitadelOrgID == platform {
		return ErrRefused
	}
	if grantID == "" {
		if grantID, err = c.findGrant(ctx, zitadelOrgID, userSub); err != nil {
			return err
		}
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
	verb := "/_deactivate"
	if active {
		verb = "/_reactivate"
	}
	err = c.do(ctx, http.MethodPost, path+verb, zitadelOrgID, map[string]any{}, nil)
	if notChanged(err) || sameState(err) {
		return nil
	}
	return err
}

// projectGrant returns the id of the project grant of synthwerk-api to the org.
func (c *Client) projectGrant(ctx context.Context, zitadelOrgID, projectID string) (string, error) {
	var found struct {
		Result []struct {
			ProjectID string `json:"projectId"`
			GrantID   string `json:"grantId"`
		} `json:"result"`
	}
	if err := c.do(ctx, http.MethodPost, "/management/v1/granted_projects/_search", zitadelOrgID, map[string]any{}, &found); err != nil {
		return "", err
	}
	for _, p := range found.Result {
		if p.ProjectID == projectID && p.GrantID != "" {
			return p.GrantID, nil
		}
	}
	return "", fmt.Errorf("zitadel: org %s has no grant of project %s", zitadelOrgID, projectID)
}

// userInOrg returns the id of the user of the org with email (any case), or "".
// POST /v2/users is UserService.ListUsers in Zitadel v2 (create is
// /v2/users/human).
func (c *Client) userInOrg(ctx context.Context, zitadelOrgID, email string) (string, error) {
	var found struct {
		Result []struct {
			UserID string `json:"userId"`
		} `json:"result"`
	}
	err := c.do(ctx, http.MethodPost, "/v2/users", zitadelOrgID, map[string]any{"queries": []any{
		map[string]any{"organizationIdQuery": map[string]string{"organizationId": zitadelOrgID}},
		map[string]any{"emailQuery": map[string]string{"emailAddress": email, "method": "TEXT_QUERY_METHOD_EQUALS_IGNORE_CASE"}},
	}}, &found)
	if err != nil || len(found.Result) == 0 {
		return "", err
	}
	return found.Result[0].UserID, nil
}

// profileName is the local part of email, for the required Zitadel profile
// names. The invitee can change it later.
func profileName(email string) string {
	name, _, _ := strings.Cut(email, "@")
	if len(name) > 200 {
		name = strings.ToValidUTF8(name[:200], "")
	}
	if name == "" {
		name = "member"
	}
	return name
}

// exists reports a Zitadel "already exists" answer (HTTP 409, gRPC code 6).
func exists(err error) bool {
	var e *APIError
	return errors.As(err, &e) && (e.Status == http.StatusConflict || e.Code == 6)
}

// sameState reports Zitadel's answer to a deactivate of an inactive grant or a
// reactivate of an active one (gRPC code 9, failed precondition).
func sameState(err error) bool {
	var e *APIError
	if !errors.As(err, &e) || e.Code != 9 {
		return false
	}
	m := strings.ToLower(e.Message)
	return strings.Contains(m, "not active") || strings.Contains(m, "not inactive") || strings.Contains(m, "already")
}
