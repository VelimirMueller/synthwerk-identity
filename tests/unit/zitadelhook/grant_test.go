package zitadelhook_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"testing"

	"github.com/VelimirMueller/synthwerk-identity/internal/orgs"
	"github.com/VelimirMueller/synthwerk-identity/internal/zitadelhook"
)

type fakeMirror struct {
	known   bool
	changes []orgs.GrantChange
	names   []string
}

func (f *fakeMirror) OrgByZitadelID(context.Context, string) (orgs.Org, error) {
	if f.known {
		return orgs.Org{}, nil
	}
	return orgs.Org{}, orgs.ErrNotFound
}

func (f *fakeMirror) ApplyGrant(_ context.Context, c orgs.GrantChange, name string) (orgs.Outcome, error) {
	f.changes = append(f.changes, c)
	f.names = append(f.names, name)
	return orgs.OutcomeAdded, nil
}

// grantCall is a user grant event call; payload is the raw event_payload value.
func grantCall(eventType, payload string) string {
	return fmt.Sprintf(`{"aggregateID":"397000000000000001","aggregateType":"usergrant","resourceOwner":"396374393657324808","instanceID":"396374393657259272","version":"v1","sequence":2,"event_type":%q,"created_at":"2026-10-28T11:09:32Z","userID":"396374393657849096","event_payload":%s}`, eventType, payload)
}

func grantHandler(m *fakeMirror) *zitadelhook.Handler {
	h := handler(&fakeStore{}, &bytes.Buffer{})
	h.Grants = m
	h.ProjectID = "proj-1"
	h.OrgName = func(context.Context, string) (string, error) { return "Demo", nil }
	return h
}

func TestGrantEvents(t *testing.T) {
	t.Run("user.grant.added - project grant - mirrored with user, roles and org name", func(t *testing.T) {
		m := &fakeMirror{}
		body := grantCall(zitadelhook.ZitadelGrantAdded, `{"userId":"396374767738844424","projectId":"proj-1","roleKeys":["owner","end_user"]}`)
		if rec := post(grantHandler(m), body, zitadelhook.Sign([]byte(body), key, now)); rec.Code != http.StatusNoContent {
			t.Fatalf("status %d", rec.Code)
		}
		if len(m.changes) != 1 {
			t.Fatalf("changes %d", len(m.changes))
		}
		c := m.changes[0]
		if c.UserSub != "396374767738844424" || c.ZitadelOrgID != "396374393657324808" || c.GrantID != "397000000000000001" ||
			len(c.Roles) != 2 || c.Removed || c.Key != "396374393657259272:usergrant:397000000000000001:2" || m.names[0] != "Demo" {
			t.Fatalf("change %+v name %q", c, m.names[0])
		}
	})
	t.Run("user.grant.changed - base64 payload - decoded", func(t *testing.T) {
		m := &fakeMirror{known: true}
		payload := `"` + base64.StdEncoding.EncodeToString([]byte(`{"roleKeys":["admin"]}`)) + `"`
		body := grantCall(zitadelhook.ZitadelGrantChanged, payload)
		if rec := post(grantHandler(m), body, zitadelhook.Sign([]byte(body), key, now)); rec.Code != http.StatusNoContent {
			t.Fatalf("status %d", rec.Code)
		}
		if len(m.changes) != 1 || m.changes[0].Roles[0] != "admin" || m.changes[0].UserSub != "" || m.names[0] != "" {
			t.Fatalf("changes %+v", m.changes)
		}
	})
	t.Run("user.grant.removed - mirrored as removal", func(t *testing.T) {
		m := &fakeMirror{known: true}
		body := grantCall(zitadelhook.ZitadelGrantRemoved, `{"userId":"396374767738844424","projectId":"proj-1"}`)
		if rec := post(grantHandler(m), body, zitadelhook.Sign([]byte(body), key, now)); rec.Code != http.StatusNoContent {
			t.Fatalf("status %d", rec.Code)
		}
		if len(m.changes) != 1 || !m.changes[0].Removed {
			t.Fatalf("changes %+v", m.changes)
		}
	})
	t.Run("user.grant.added - other project - dropped", func(t *testing.T) {
		m := &fakeMirror{}
		body := grantCall(zitadelhook.ZitadelGrantAdded, `{"userId":"1","projectId":"proj-2","roleKeys":["owner"]}`)
		if rec := post(grantHandler(m), body, zitadelhook.Sign([]byte(body), key, now)); rec.Code != http.StatusNoContent || len(m.changes) != 0 {
			t.Fatalf("status %d changes %d", rec.Code, len(m.changes))
		}
	})
	t.Run("user.grant.added - unsigned - 401, nothing mirrored", func(t *testing.T) {
		m := &fakeMirror{}
		body := grantCall(zitadelhook.ZitadelGrantAdded, `{"userId":"1","projectId":"proj-1","roleKeys":["owner"]}`)
		if rec := post(grantHandler(m), body, ""); rec.Code != http.StatusUnauthorized || len(m.changes) != 0 {
			t.Fatalf("status %d changes %d", rec.Code, len(m.changes))
		}
	})
	t.Run("user.grant.added - payload not JSON - 400", func(t *testing.T) {
		m := &fakeMirror{}
		body := grantCall(zitadelhook.ZitadelGrantAdded, `"!!"`)
		if rec := post(grantHandler(m), body, zitadelhook.Sign([]byte(body), key, now)); rec.Code != http.StatusBadRequest {
			t.Fatalf("status %d", rec.Code)
		}
	})
}
