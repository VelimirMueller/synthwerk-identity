package zitadelhook_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/VelimirMueller/synthwerk-contracts/go/kit/cloudevents"

	"github.com/VelimirMueller/synthwerk-identity/internal/zitadelhook"
)

const key = "test-signing-key-0123456789abcdefghij"

var now = time.Date(2026, 10, 23, 11, 9, 40, 0, time.UTC)

// call is a user.human.added body as Zitadel v4.20.0 sends it (shape measured
// 2026-10-23; ids and names made up). event_payload holds personal data.
const call = `{"aggregateID":"396374767738844424","aggregateType":"user","resourceOwner":"396374393657324808","instanceID":"396374393657259272","version":"v2","sequence":1,"event_type":"user.human.added","created_at":"2026-10-23T11:09:32.299942Z","userID":"396374393657849096","event_payload":{"userName":"hook.probe","firstName":"Hook","lastName":"Probe","displayName":"Hook Probe","preferredLanguage":"und","gender":-1,"email":"hook.probe@example.test"}}`

type fakeStore struct {
	keys   []string
	events []cloudevents.Event
	seen   map[string]bool
	err    error
}

func (f *fakeStore) RecordOnce(_ context.Context, key string, e cloudevents.Event) (bool, error) {
	if f.err != nil {
		return false, f.err
	}
	if f.seen == nil {
		f.seen = map[string]bool{}
	}
	f.keys = append(f.keys, key)
	if f.seen[key] {
		return false, nil
	}
	f.seen[key] = true
	f.events = append(f.events, e)
	return true, nil
}

func handler(store zitadelhook.Store, logs *bytes.Buffer) *zitadelhook.Handler {
	return &zitadelhook.Handler{
		Store:      store,
		SigningKey: func() (string, error) { return key, nil },
		Source:     "/synthwerk/identity/local",
		Log:        slog.New(slog.NewJSONHandler(logs, nil)),
		Now:        func() time.Time { return now },
	}
}

func post(h http.Handler, body, sig string) *httptest.ResponseRecorder {
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, zitadelhook.Path, strings.NewReader(body))
	if sig != "" {
		req.Header.Set(zitadelhook.SignatureHeader, sig)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestUserAddedBecomesUserCreated(t *testing.T) {
	store, logs := &fakeStore{}, &bytes.Buffer{}
	rec := post(handler(store, logs), call, zitadelhook.Sign([]byte(call), key, now))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status %d, body %q", rec.Code, rec.Body)
	}
	if len(store.events) != 1 {
		t.Fatalf("events %d, want 1", len(store.events))
	}
	e := store.events[0]
	if e.Type != zitadelhook.UserCreated || e.Subject != "396374767738844424" || e.Actor != "system" ||
		e.DataSchema != zitadelhook.UserCreatedData || e.Source != "/synthwerk/identity/local" {
		t.Errorf("envelope: %+v", e)
	}
	if !e.Time.Equal(time.Date(2026, 10, 23, 11, 9, 32, 299942000, time.UTC)) {
		t.Errorf("time %v, want the Zitadel created_at", e.Time)
	}
	var data map[string]string
	if err := json.Unmarshal(e.Data, &data); err != nil {
		t.Fatal(err)
	}
	if len(data) != 2 || data["user_sub"] != "396374767738844424" || data["zitadel_org_id"] != "396374393657324808" {
		t.Errorf("data %v", data)
	}
	if store.keys[0] != "396374393657259272:user:396374767738844424:1" {
		t.Errorf("key %q", store.keys[0])
	}
	for _, pii := range []string{"example.test", "Probe", "hook.probe"} {
		if strings.Contains(logs.String(), pii) || strings.Contains(string(e.Data), pii) {
			t.Errorf("%q leaked into the logs or the event", pii)
		}
	}
}

func TestRepeatWritesOneEvent(t *testing.T) {
	store := &fakeStore{}
	h := handler(store, &bytes.Buffer{})
	for range 2 {
		if rec := post(h, call, zitadelhook.Sign([]byte(call), key, now)); rec.Code != http.StatusNoContent {
			t.Fatalf("status %d", rec.Code)
		}
	}
	if len(store.events) != 1 || len(store.keys) != 2 {
		t.Errorf("events %d (want 1), calls %d (want 2)", len(store.events), len(store.keys))
	}
}

func TestRejects(t *testing.T) {
	signed := zitadelhook.Sign([]byte(call), key, now)
	other := strings.Replace(call, `"user.human.added"`, `"user.human.changed"`, 1)
	noOrg := strings.Replace(call, `"resourceOwner":"396374393657324808"`, `"resourceOwner":""`, 1)
	noSeq := strings.Replace(call, `"sequence":1`, `"sequence":0`, 1)
	cases := []struct {
		name, body, sig string
		want            int
	}{
		{"no signature", call, "", http.StatusUnauthorized},
		{"wrong key", call, zitadelhook.Sign([]byte(call), "other-key", now), http.StatusUnauthorized},
		{"changed body", strings.Replace(call, "396374393657324808", "1", 1), signed, http.StatusUnauthorized},
		{"older than 300 s", call, zitadelhook.Sign([]byte(call), key, now.Add(-301*time.Second)), http.StatusUnauthorized},
		{"more than 300 s ahead", call, zitadelhook.Sign([]byte(call), key, now.Add(301*time.Second)), http.StatusUnauthorized},
		{"header without v1", call, "t=1792753772", http.StatusUnauthorized},
		{"two timestamps", call, "t=1," + signed, http.StatusUnauthorized},
		{"not JSON", "nope", zitadelhook.Sign([]byte("nope"), key, now), http.StatusBadRequest},
		{"no org id", noOrg, zitadelhook.Sign([]byte(noOrg), key, now), http.StatusBadRequest},
		{"no sequence", noSeq, zitadelhook.Sign([]byte(noSeq), key, now), http.StatusBadRequest},
		{"other event type", other, zitadelhook.Sign([]byte(other), key, now), http.StatusNoContent},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			store := &fakeStore{}
			if rec := post(handler(store, &bytes.Buffer{}), c.body, c.sig); rec.Code != c.want {
				t.Errorf("status %d, want %d", rec.Code, c.want)
			}
			if len(store.keys) != 0 {
				t.Errorf("store called %d times", len(store.keys))
			}
		})
	}
}

func TestSecondSignatureOfARotatedKeyPasses(t *testing.T) {
	old := zitadelhook.Sign([]byte(call), "old-key", now)
	cur := zitadelhook.Sign([]byte(call), key, now)
	header := old + ",v1=" + strings.SplitN(cur, "v1=", 2)[1]
	if err := zitadelhook.Verify([]byte(call), header, key, now); err != nil {
		t.Error(err)
	}
}

func TestOperationalErrors(t *testing.T) {
	t.Run("store fails - 500", func(t *testing.T) {
		rec := post(handler(&fakeStore{err: errors.New("db down")}, &bytes.Buffer{}), call, zitadelhook.Sign([]byte(call), key, now))
		if rec.Code != http.StatusInternalServerError {
			t.Errorf("status %d", rec.Code)
		}
	})
	t.Run("no key file yet - 503", func(t *testing.T) {
		h := handler(&fakeStore{}, &bytes.Buffer{})
		h.SigningKey = func() (string, error) { return "", errors.New("open: no such file") }
		if rec := post(h, call, zitadelhook.Sign([]byte(call), key, now)); rec.Code != http.StatusServiceUnavailable {
			t.Errorf("status %d", rec.Code)
		}
	})
	t.Run("body over 64 KiB - 413", func(t *testing.T) {
		big := strings.Repeat("x", zitadelhook.MaxBody+1)
		if rec := post(handler(&fakeStore{}, &bytes.Buffer{}), big, "t=1,v1=00"); rec.Code != http.StatusRequestEntityTooLarge {
			t.Errorf("status %d", rec.Code)
		}
	})
	t.Run("GET - 405", func(t *testing.T) {
		rec := httptest.NewRecorder()
		handler(&fakeStore{}, &bytes.Buffer{}).ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, zitadelhook.Path, nil))
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("status %d", rec.Code)
		}
	})
}
