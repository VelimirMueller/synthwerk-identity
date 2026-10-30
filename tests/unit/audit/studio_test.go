package audit_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"github.com/VelimirMueller/synthwerk-identity/internal/app"
	"github.com/VelimirMueller/synthwerk-identity/internal/audit"
)

const examplePage = "019a3e10-4b5c-7d6e-8f70-0a1b2c3d4e5f"

// studioExample is a contract example (synthwerk-contracts events/examples), copied.
func studioExample(t *testing.T, verb string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "dev.synthwerk.studio.page."+verb+".v1.json")) //nolint:gosec // fixed test data names

	if err != nil {
		t.Fatal(err)
	}
	return b
}

// studioEvent returns the example of verb with the envelope fields in env and the
// data fields in data set (a nil value removes the field).
func studioEvent(t *testing.T, verb string, env, data map[string]any) []byte {
	t.Helper()
	var ev map[string]any
	if err := json.Unmarshal(studioExample(t, verb), &ev); err != nil {
		t.Fatal(err)
	}
	d := ev["data"].(map[string]any)
	for k, v := range data {
		if v == nil {
			delete(d, k)
		} else {
			d[k] = v
		}
	}
	for k, v := range env {
		if v == nil {
			delete(ev, k)
		} else {
			ev[k] = v
		}
	}
	b, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// ParseStudioPage - the three contract examples - valid, type kept, ids from the envelope.
func TestParseStudioPageContractExamples(t *testing.T) {
	for verb, typ := range map[string]string{
		"created":     audit.StudioPageCreatedType,
		"published":   audit.StudioPagePublishedType,
		"rolled_back": audit.StudioPageRolledBackType,
	} {
		e, err := audit.ParseStudioPage(studioExample(t, verb))
		if err != nil {
			t.Fatalf("%s: %v", verb, err)
		}
		if e.Type != typ || e.OrgID != exampleOrg || e.Subject != examplePage || e.Actor != exampleActor || e.UserSub != exampleSub {
			t.Fatalf("%s: %+v", verb, e)
		}
		var d map[string]any
		if err := json.Unmarshal(e.Data, &d); err != nil || d["slug"] != "pricing" || d["page_id"] != examplePage {
			t.Fatalf("%s: data %s", verb, e.Data)
		}
	}
}

// ParseStudioPage - first publish (previous_version null), roll back from null, longest slug - valid.
func TestParseStudioPageEdges(t *testing.T) {
	cases := map[string][]byte{
		"first publish":       studioEvent(t, "published", nil, map[string]any{"version": 1, "previous_version": json.RawMessage("null")}),
		"roll back from none": studioEvent(t, "rolled_back", nil, map[string]any{"previous_version": json.RawMessage("null")}),
		"slug of 64 chars":    studioEvent(t, "created", nil, map[string]any{"slug": "a" + strings.Repeat("-b", 31) + "c"}),
		"one char slug":       studioEvent(t, "created", nil, map[string]any{"slug": "x"}),
		"locale en":           studioEvent(t, "published", nil, map[string]any{"locale": "en"}),
	}
	for name, raw := range cases {
		if _, err := audit.ParseStudioPage(raw); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// ParseStudioPage - each broken event - ErrMalformed, and the error holds no value of the event.
func TestParseStudioPageRejectsMalformed(t *testing.T) {
	other := "0199f3a0-5b6c-7d8e-9f0a-1b2c3d4e5f61"
	cases := map[string][]byte{
		"not json":                    []byte("{nope"),
		"bad envelope":                []byte(`{"specversion":"1.0","data":{}}`),
		"id not uuidv7":               studioEvent(t, "published", map[string]any{"id": "0199f3a0-5b6c-4d8e-9f0a-1b2c3d4e5f60"}, nil),
		"llm type":                    studioEvent(t, "published", map[string]any{"type": audit.AISettingsEventType}, nil),
		"unknown studio type":         studioEvent(t, "published", map[string]any{"type": "dev.synthwerk.studio.page.deleted.v1"}, nil),
		"service actor":               studioEvent(t, "published", map[string]any{"actor": "service:studio"}, nil),
		"no actor":                    studioEvent(t, "published", map[string]any{"actor": nil}, nil),
		"data not an object":          studioEvent(t, "published", map[string]any{"data": []int{1}}, nil),
		"unknown field (page title)":  studioEvent(t, "published", nil, map[string]any{"title": "Secret launch"}),
		"no org_id":                   studioEvent(t, "published", nil, map[string]any{"org_id": nil}),
		"upper case org_id":           studioEvent(t, "published", nil, map[string]any{"org_id": strings.ToUpper(exampleOrg)}),
		"no page_id":                  studioEvent(t, "published", nil, map[string]any{"page_id": nil}),
		"page_id not a uuid":          studioEvent(t, "published", map[string]any{"subject": "page-1"}, map[string]any{"page_id": "page-1"}),
		"orgid differs":               studioEvent(t, "published", map[string]any{"orgid": other}, nil),
		"subject differs":             studioEvent(t, "published", map[string]any{"subject": other}, nil),
		"no slug":                     studioEvent(t, "published", nil, map[string]any{"slug": nil}),
		"slug with a space":           studioEvent(t, "published", nil, map[string]any{"slug": "a b"}),
		"slug ends with -":            studioEvent(t, "published", nil, map[string]any{"slug": "pricing-"}),
		"slug of 65 chars":            studioEvent(t, "published", nil, map[string]any{"slug": strings.Repeat("a", 65)}),
		"no locale":                   studioEvent(t, "published", nil, map[string]any{"locale": nil}),
		"locale fr":                   studioEvent(t, "published", nil, map[string]any{"locale": "fr"}),
		"created with version":        studioEvent(t, "created", nil, map[string]any{"version": 1}),
		"created with previous":       studioEvent(t, "created", nil, map[string]any{"previous_version": 1}),
		"published without version":   studioEvent(t, "published", nil, map[string]any{"version": nil}),
		"published version 0":         studioEvent(t, "published", nil, map[string]any{"version": 0}),
		"published without previous":  studioEvent(t, "published", nil, map[string]any{"previous_version": nil}),
		"previous_version 0":          studioEvent(t, "rolled_back", nil, map[string]any{"previous_version": 0}),
		"previous_version a string":   studioEvent(t, "rolled_back", nil, map[string]any{"previous_version": "2"}),
		"rolled_back without version": studioEvent(t, "rolled_back", nil, map[string]any{"version": nil}),
	}
	for name, raw := range cases {
		_, err := audit.ParseStudioPage(raw)
		if !errors.Is(err, audit.ErrMalformed) {
			t.Errorf("%s: err %v, want ErrMalformed", name, err)
			continue
		}
		for _, v := range []string{"Secret launch", exampleSub, other, "pricing-", "a b"} {
			if strings.Contains(err.Error(), v) {
				t.Errorf("%s: error holds a value: %v", name, err)
			}
		}
	}
}

func newStudioConsumer(r audit.Recorder, logs *bytes.Buffer) *audit.Consumer {
	logger := slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	return audit.NewStudioConsumer(nil, r, logger, audit.ConsumerConfig{RetryMin: time.Second, RetryMax: 8 * time.Second})
}

// Handle - valid studio event - record with its type, then ack. Event id in the logs; no sub, no slug.
func TestHandleStudioPageRecordsThenAcks(t *testing.T) {
	var logs bytes.Buffer
	r := &fakeRecorder{inserted: true}
	m := &fakeMsg{data: studioExample(t, "rolled_back"), delivered: 1}
	newStudioConsumer(r, &logs).Handle(t.Context(), m)
	if r.calls != 1 || r.got.Type != audit.StudioPageRolledBackType || r.got.OrgID != exampleOrg || r.got.UserSub != exampleSub {
		t.Fatalf("recorder got %+v", r)
	}
	if !m.acked || m.termed || m.nakDelay != 0 {
		t.Fatalf("msg %+v", m)
	}
	l := logs.String()
	if !strings.Contains(l, `"identity.audit.studio_recorded"`) || !strings.Contains(l, "019a3e15-1a2b-7c3d-9e4f-5a6b7c8d9e0f") ||
		strings.Contains(l, exampleSub) || strings.Contains(l, "pricing") {
		t.Fatalf("logs: %s", l)
	}
}

// Handle - malformed studio event - Term, no record, WARN log with the studio event name.
func TestHandleStudioPageTermsMalformed(t *testing.T) {
	var logs bytes.Buffer
	r := &fakeRecorder{}
	m := &fakeMsg{data: studioEvent(t, "published", nil, map[string]any{"title": "Secret launch"}), delivered: 1}
	newStudioConsumer(r, &logs).Handle(t.Context(), m)
	if r.calls != 0 || !m.termed || m.acked {
		t.Fatalf("calls %d msg %+v", r.calls, m)
	}
	l := logs.String()
	if !strings.Contains(l, `"identity.audit.studio_rejected"`) || strings.Contains(l, "Secret launch") {
		t.Fatalf("logs: %s", l)
	}
}

// Handle - database error - Nak with a delay, studio failure log.
func TestHandleStudioPageNaksOnStoreError(t *testing.T) {
	var logs bytes.Buffer
	m := &fakeMsg{data: studioExample(t, "published"), delivered: 2}
	newStudioConsumer(&fakeRecorder{err: errors.New("db down")}, &logs).Handle(t.Context(), m)
	if m.acked || m.termed || m.nakDelay != 2*time.Second {
		t.Fatalf("msg %+v", m)
	}
	if !strings.Contains(logs.String(), `"identity.audit.studio_failed"`) {
		t.Fatalf("logs: %s", logs.String())
	}
}

// StudioJetStreamConfig - defaults - own durable on exactly the three page subjects.
func TestStudioConsumerConfig(t *testing.T) {
	c := audit.StudioJetStreamConfig(audit.ConsumerConfig{})
	want := []string{"evt.studio.page.created.v1", "evt.studio.page.published.v1", "evt.studio.page.rolled_back.v1"}
	if c.Durable != "identity-studio-pages" || c.FilterSubject != "" || !slices.Equal(c.FilterSubjects, want) ||
		c.AckPolicy != jetstream.AckExplicitPolicy || c.DeliverPolicy != jetstream.DeliverAllPolicy ||
		c.AckWait != 30*time.Second || c.MaxDeliver != -1 || c.MaxAckPending != 16 {
		t.Fatalf("%+v", c)
	}
}

// Ready - studio consumer not attached - /readyz degraded with the check studio_pages.
func TestStudioPagesReadyDegradesReadyz(t *testing.T) {
	c := newStudioConsumer(&fakeRecorder{}, &bytes.Buffer{})
	if err := c.Ready(t.Context()); err == nil || !strings.Contains(err.Error(), "studio page") {
		t.Fatalf("ready before Run: %v", err)
	}
	a, err := app.New(pinger{}, slog.New(slog.DiscardHandler), app.Config{Version: "0.1.0-dev", Commit: "0000000", Env: "ci", StudioPages: c.Ready})
	if err != nil {
		t.Fatal(err)
	}
	a.Health.MarkStarted()
	body := a.Health.Check(t.Context())
	var seen bool
	for _, ch := range body.Checks {
		seen = seen || (ch.Name == "studio_pages" && ch.Status == "degraded")
	}
	if body.Status != "degraded" || !seen {
		t.Fatalf("status %s checks %+v", body.Status, body.Checks)
	}
}
