package zitadel_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/VelimirMueller/synthwerk-identity/internal/zitadel"
)

func TestDeleteUser(t *testing.T) {
	pat := func() (string, error) { return "pat", nil }
	for _, tc := range []struct {
		name    string
		status  int
		body    string
		wantErr bool
	}{
		{"DeleteUser - Zitadel removes the user - no error, DELETE /v2/users/<id> with host and PAT", http.StatusOK, `{}`, false},
		{"DeleteUser - user already gone (404) - no error", http.StatusNotFound, `{"code":5,"message":"User could not be found"}`, false},
		{"DeleteUser - no permission (403) - APIError", http.StatusForbidden, `{"code":7,"message":"No matching permissions found"}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var got string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Host != "auth.localhost:8080" || r.Header.Get("Authorization") != "Bearer pat" {
					http.Error(w, "bad headers", http.StatusBadRequest)
					return
				}
				got = r.Method + " " + r.URL.Path
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()
			c := &zitadel.Client{BaseURL: srv.URL, Host: "auth.localhost:8080", Token: pat}
			err := c.DeleteUser(t.Context(), "u-1")
			if got != "DELETE /v2/users/u-1" {
				t.Fatalf("sent %q", got)
			}
			var apiErr *zitadel.APIError
			if tc.wantErr != (err != nil) || (tc.wantErr && (!errors.As(err, &apiErr) || apiErr.Status != tc.status)) {
				t.Fatalf("err %v", err)
			}
		})
	}
	t.Run("DeleteUser - empty id - error, no call", func(t *testing.T) {
		c := &zitadel.Client{BaseURL: "http://127.0.0.1:1", Token: pat}
		if err := c.DeleteUser(t.Context(), ""); err == nil {
			t.Fatal("want an error")
		}
	})
}
