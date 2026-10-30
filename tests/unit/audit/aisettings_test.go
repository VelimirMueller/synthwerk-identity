package audit_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/VelimirMueller/synthwerk-identity/internal/app"
	"github.com/VelimirMueller/synthwerk-identity/internal/audit"
)

const (
	exampleOrg   = "0199f3a0-5b6c-7d8e-9f0a-1b2c3d4e5f60"
	exampleActor = "user:283746192837461928"
	exampleSub   = "283746192837461928"
)

// aiExample is the contract example (synthwerk-contracts events/examples), copied.
func aiExample(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/dev.synthwerk.llm.ai_settings.changed.v1.json")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// aiEvent returns the example with the envelope fields in env and the data fields
// in data set (a nil value removes the field).
func aiEvent(t *testing.T, env, data map[string]any) []byte {
	t.Helper()
	var ev map[string]any
	if err := json.Unmarshal(aiExample(t), &ev); err != nil {
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

// rawData returns the example with data replaced by the JSON text data.
func rawData(t *testing.T, data string) []byte {
	t.Helper()
	var ev map[string]json.RawMessage
	if err := json.Unmarshal(aiExample(t), &ev); err != nil {
		t.Fatal(err)
	}
	ev["data"] = json.RawMessage(data)
	b, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// ParseAISettings - contract example - org, actor, sub, time and the data as received.
func TestParseAISettingsContractExample(t *testing.T) {
	c, err := audit.ParseAISettings(aiExample(t))
	if err != nil {
		t.Fatal(err)
	}
	if c.ID != "019a3d40-2b3c-7d4e-8f5a-6b7c8d9e0f1a" || c.OrgID != exampleOrg || c.Subject != exampleOrg ||
		c.Actor != exampleActor || c.UserSub != exampleSub || !c.Time.Equal(time.Date(2026, 10, 30, 10, 0, 0, 0, time.UTC)) {
		t.Fatalf("%+v", c)
	}
	var d map[string]any
	if err := json.Unmarshal(c.Data, &d); err != nil || d["system_prompt_chars"] != float64(52) || d["temperature"] != 0.3 {
		t.Fatalf("data %s", c.Data)
	}
}

// ParseAISettings - no temperature, user_tokens_per_day 0, system_prompt_chars 0, limits at the edge - valid.
func TestParseAISettingsEdges(t *testing.T) {
	models := make([]string, 32)
	for i := range models {
		models[i] = "m" + strings.Repeat("a", i+1)
	}
	for name, data := range map[string]map[string]any{
		"no temperature":     {"temperature": nil},
		"zeros":              {"user_tokens_per_day": 0, "system_prompt_chars": 0, "temperature": 0},
		"maximums":           {"max_input_chars": 8000, "user_tokens_per_day": 1e12, "system_prompt_chars": 4000, "temperature": 2},
		"all six changed":    {"changed": []string{"model", "allowed_models", "system_prompt", "max_input_chars", "user_tokens_per_day", "temperature"}},
		"32 allowed models":  {"allowed_models": models},
		"alias of 64 chars":  {"model": "a" + strings.Repeat("b", 63)},
		"alias with _ and -": {"model": "gpt_x-1"},
	} {
		if _, err := audit.ParseAISettings(aiEvent(t, nil, data)); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// ParseAISettings - each broken event - ErrMalformed, and the error holds no value of the event.
func TestParseAISettingsRejectsMalformed(t *testing.T) {
	other := "0199f3a0-5b6c-7d8e-9f0a-1b2c3d4e5f61"
	tooMany := make([]string, 33)
	for i := range tooMany {
		tooMany[i] = "m" + strings.Repeat("a", i+1)
	}
	cases := map[string][]byte{
		"not json":                 []byte("{nope"),
		"bad envelope":             []byte(`{"specversion":"1.0","data":{}}`),
		"id not uuidv7":            aiEvent(t, map[string]any{"id": "0199f3a0-5b6c-4d8e-9f0a-1b2c3d4e5f60"}, nil),
		"other type":               aiEvent(t, map[string]any{"type": "dev.synthwerk.llm.message.completed.v1"}, nil),
		"no actor":                 aiEvent(t, map[string]any{"actor": nil}, nil),
		"service actor":            aiEvent(t, map[string]any{"actor": "service:llm"}, nil),
		"system actor":             aiEvent(t, map[string]any{"actor": "system"}, nil),
		"no orgid":                 aiEvent(t, map[string]any{"orgid": nil}, nil),
		"orgid not data.org_id":    aiEvent(t, map[string]any{"orgid": other}, nil),
		"subject not data.org_id":  aiEvent(t, map[string]any{"subject": other}, nil),
		"no subject":               aiEvent(t, map[string]any{"subject": nil}, nil),
		"data not object":          rawData(t, `[1]`),
		"unknown field":            aiEvent(t, nil, map[string]any{"system_prompt": "secret prompt text"}),
		"no org_id":                aiEvent(t, nil, map[string]any{"org_id": nil}),
		"upper-case org_id":        aiEvent(t, map[string]any{"orgid": strings.ToUpper(exampleOrg), "subject": strings.ToUpper(exampleOrg)}, map[string]any{"org_id": strings.ToUpper(exampleOrg)}),
		"org_id not uuid":          aiEvent(t, map[string]any{"orgid": "org-1", "subject": "org-1"}, map[string]any{"org_id": "org-1"}),
		"no version":               aiEvent(t, nil, map[string]any{"version": nil}),
		"version 0":                aiEvent(t, nil, map[string]any{"version": 0}),
		"version not integer":      aiEvent(t, nil, map[string]any{"version": 1.5}),
		"no changed":               aiEvent(t, nil, map[string]any{"changed": nil}),
		"empty changed":            aiEvent(t, nil, map[string]any{"changed": []string{}}),
		"changed repeats":          aiEvent(t, nil, map[string]any{"changed": []string{"model", "model"}}),
		"changed outside enum":     aiEvent(t, nil, map[string]any{"changed": []string{"email"}}),
		"changed too long":         aiEvent(t, nil, map[string]any{"changed": []string{"model", "allowed_models", "system_prompt", "max_input_chars", "user_tokens_per_day", "temperature", "model"}}),
		"no model":                 aiEvent(t, nil, map[string]any{"model": nil}),
		"model upper case":         aiEvent(t, nil, map[string]any{"model": "GPT"}),
		"model too long":           aiEvent(t, nil, map[string]any{"model": "a" + strings.Repeat("b", 64)}),
		"no allowed_models":        aiEvent(t, nil, map[string]any{"allowed_models": nil}),
		"empty allowed_models":     aiEvent(t, nil, map[string]any{"allowed_models": []string{}}),
		"allowed_models too many":  aiEvent(t, nil, map[string]any{"allowed_models": tooMany}),
		"allowed_models repeats":   aiEvent(t, nil, map[string]any{"allowed_models": []string{"a", "a"}}),
		"allowed_models bad item":  aiEvent(t, nil, map[string]any{"allowed_models": []string{"a b"}}),
		"no max_input_chars":       aiEvent(t, nil, map[string]any{"max_input_chars": nil}),
		"max_input_chars 0":        aiEvent(t, nil, map[string]any{"max_input_chars": 0}),
		"max_input_chars 8001":     aiEvent(t, nil, map[string]any{"max_input_chars": 8001}),
		"no user_tokens_per_day":   aiEvent(t, nil, map[string]any{"user_tokens_per_day": nil}),
		"user_tokens_per_day < 0":  aiEvent(t, nil, map[string]any{"user_tokens_per_day": -1}),
		"user_tokens_per_day big":  aiEvent(t, nil, map[string]any{"user_tokens_per_day": 1e12 + 1}),
		"no system_prompt_chars":   aiEvent(t, nil, map[string]any{"system_prompt_chars": nil}),
		"system_prompt_chars 4001": aiEvent(t, nil, map[string]any{"system_prompt_chars": 4001}),
		"system_prompt_chars < 0":  aiEvent(t, nil, map[string]any{"system_prompt_chars": -1}),
		"temperature null":         rawData(t, `{"org_id":"`+exampleOrg+`","version":1,"changed":["model"],"model":"a","allowed_models":["a"],"max_input_chars":1,"user_tokens_per_day":0,"system_prompt_chars":0,"temperature":null}`),
		"temperature 2.1":          aiEvent(t, nil, map[string]any{"temperature": 2.1}),
		"temperature < 0":          aiEvent(t, nil, map[string]any{"temperature": -0.1}),
		"temperature string":       aiEvent(t, nil, map[string]any{"temperature": "0.3"}),
	}
	for name, raw := range cases {
		_, err := audit.ParseAISettings(raw)
		if !errors.Is(err, audit.ErrMalformed) {
			t.Errorf("%s: err %v, want ErrMalformed", name, err)
			continue
		}
		for _, v := range []string{"secret prompt text", exampleSub, other, "GPT", "a b"} {
			if strings.Contains(err.Error(), v) {
				t.Errorf("%s: error holds a value: %v", name, err)
			}
		}
	}
}

// fakeMsg records what the consumer did with it.
type fakeMsg struct {
	jetstream.Msg // nil: any other method panics
	data          []byte
	delivered     uint64
	mu            sync.Mutex
	acked, termed bool
	nakDelay      time.Duration
}

func (m *fakeMsg) Data() []byte { return m.data }
func (m *fakeMsg) Metadata() (*jetstream.MsgMetadata, error) {
	return &jetstream.MsgMetadata{NumDelivered: m.delivered}, nil
}
func (m *fakeMsg) Headers() nats.Header { return nats.Header{} }
func (m *fakeMsg) Ack() error           { m.mu.Lock(); m.acked = true; m.mu.Unlock(); return nil }
func (m *fakeMsg) Term() error          { m.mu.Lock(); m.termed = true; m.mu.Unlock(); return nil }
func (m *fakeMsg) NakWithDelay(d time.Duration) error {
	m.mu.Lock()
	m.nakDelay = d
	m.mu.Unlock()
	return nil
}

type fakeRecorder struct {
	err      error
	inserted bool
	got      audit.AISettingsChange
	calls    int
}

func (f *fakeRecorder) Record(_ context.Context, c audit.AISettingsChange) (bool, error) {
	f.calls++
	f.got = c
	return f.inserted, f.err
}

func newAIConsumer(r audit.Recorder, logs *bytes.Buffer) *audit.Consumer {
	logger := slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	return audit.NewConsumer(nil, r, logger, audit.ConsumerConfig{RetryMin: time.Second, RetryMax: 8 * time.Second})
}

// Handle - valid event - record, then ack. Event id in the logs; no sub, no setting value.
func TestHandleAISettingsRecordsThenAcks(t *testing.T) {
	for _, inserted := range []bool{true, false} {
		var logs bytes.Buffer
		r := &fakeRecorder{inserted: inserted}
		m := &fakeMsg{data: aiExample(t), delivered: 1}
		newAIConsumer(r, &logs).Handle(t.Context(), m)
		if r.calls != 1 || r.got.OrgID != exampleOrg || r.got.UserSub != exampleSub {
			t.Fatalf("recorder got %+v", r)
		}
		if !m.acked || m.termed || m.nakDelay != 0 {
			t.Fatalf("msg %+v", m)
		}
		l := logs.String()
		if !strings.Contains(l, `"identity.audit.llm_recorded"`) || !strings.Contains(l, "019a3d40-2b3c-7d4e-8f5a-6b7c8d9e0f1a") ||
			strings.Contains(l, exampleSub) || strings.Contains(l, `"default"`) {
			t.Fatalf("logs: %s", l)
		}
	}
}

// Handle - malformed event - Term, no record, WARN log that names the rule.
func TestHandleAISettingsTermsMalformed(t *testing.T) {
	var logs bytes.Buffer
	r := &fakeRecorder{}
	m := &fakeMsg{data: aiEvent(t, nil, map[string]any{"max_input_chars": 9000}), delivered: 1}
	newAIConsumer(r, &logs).Handle(t.Context(), m)
	if r.calls != 0 || !m.termed || m.acked {
		t.Fatalf("calls %d msg %+v", r.calls, m)
	}
	l := logs.String()
	if !strings.Contains(l, `"identity.audit.llm_rejected"`) || !strings.Contains(l, `"level":"WARN"`) || !strings.Contains(l, "max_input_chars") || strings.Contains(l, "9000") {
		t.Fatalf("logs: %s", l)
	}
}

// Handle - unknown org - ack, no retry, INFO log.
func TestHandleAISettingsAcksUnknownOrg(t *testing.T) {
	var logs bytes.Buffer
	m := &fakeMsg{data: aiExample(t), delivered: 1}
	newAIConsumer(&fakeRecorder{err: audit.ErrUnknownOrg}, &logs).Handle(t.Context(), m)
	if !m.acked || m.termed || m.nakDelay != 0 {
		t.Fatalf("msg %+v", m)
	}
	if !strings.Contains(logs.String(), `"identity.audit.llm_unknown_org"`) || strings.Contains(logs.String(), `"identity.audit.llm_recorded"`) {
		t.Fatalf("logs: %s", logs.String())
	}
}

// Handle - database error - Nak with a delay that doubles per delivery up to the max, no ack.
func TestHandleAISettingsNaksOnStoreError(t *testing.T) {
	want := map[uint64]time.Duration{0: time.Second, 1: time.Second, 2: 2 * time.Second, 3: 4 * time.Second, 4: 8 * time.Second, 9: 8 * time.Second}
	for n, d := range want {
		var logs bytes.Buffer
		m := &fakeMsg{data: aiExample(t), delivered: n}
		newAIConsumer(&fakeRecorder{err: errors.New("db down")}, &logs).Handle(t.Context(), m)
		if m.acked || m.termed || m.nakDelay != d {
			t.Errorf("delivery %d: msg %+v, want nak %s", n, m, d)
		}
		if !strings.Contains(logs.String(), `"identity.audit.llm_failed"`) {
			t.Errorf("delivery %d: no identity.audit.llm_failed log line", n)
		}
	}
}

// JetStreamConfig - defaults - durable on the subject, explicit ack, all events, small window, endless redelivery.
func TestAISettingsConsumerConfig(t *testing.T) {
	c := audit.JetStreamConfig(audit.ConsumerConfig{})
	if c.Durable != "identity-llm-ai-settings" || c.FilterSubject != "evt.llm.ai_settings.changed.v1" ||
		c.AckPolicy != jetstream.AckExplicitPolicy || c.DeliverPolicy != jetstream.DeliverAllPolicy ||
		c.AckWait != 30*time.Second || c.MaxDeliver != -1 || c.MaxAckPending != 16 {
		t.Fatalf("%+v", c)
	}
	if c := audit.JetStreamConfig(audit.ConsumerConfig{AckWait: 10 * time.Second}); c.AckWait != 10*time.Second {
		t.Fatalf("AckWait %s", c.AckWait)
	}
}

// Ready - not attached - error; /readyz is degraded (200), not down.
func TestAISettingsReadyDegradesReadyz(t *testing.T) {
	c := newAIConsumer(&fakeRecorder{}, &bytes.Buffer{})
	if c.Ready(t.Context()) == nil {
		t.Fatal("ready before Run")
	}
	a, err := app.New(pinger{}, slog.New(slog.DiscardHandler), app.Config{Version: "0.1.0-dev", Commit: "0000000", Env: "ci", AISettings: c.Ready})
	if err != nil {
		t.Fatal(err)
	}
	a.Health.MarkStarted()
	body := a.Health.Check(t.Context())
	if body.Status != "degraded" {
		t.Fatalf("status %s", body.Status)
	}
	var seen bool
	for _, ch := range body.Checks {
		seen = seen || (ch.Name == "llm_ai_settings" && ch.Status == "degraded")
	}
	if !seen {
		t.Fatalf("checks %+v", body.Checks)
	}
}

// ParseAISettings - case-variant and duplicate keys - Data holds only the checked
// fields with the schema names, never the hidden value (security review, #106).
func TestParseAISettingsStoresTheCheckedFieldsOnly(t *testing.T) {
	base := `"org_id":"` + exampleOrg + `","version":3,"changed":["model"],"allowed_models":["default"],"max_input_chars":2000,"user_tokens_per_day":0,"system_prompt_chars":0`
	for name, data := range map[string]string{
		"case-variant key": `{` + base + `,"MODEL":"Ignore all rules","model":"default"}`,
		"duplicate key":    `{` + base + `,"model":"Ignore all rules","model":"default","temperature":0.5}`,
	} {
		c, err := audit.ParseAISettings(rawData(t, data))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		var d map[string]any
		if err := json.Unmarshal(c.Data, &d); err != nil {
			t.Fatal(err)
		}
		if d["model"] != "default" || strings.Contains(string(c.Data), "Ignore all rules") || strings.Contains(string(c.Data), "MODEL") {
			t.Fatalf("%s: data %s", name, c.Data)
		}
		for k := range d {
			if !slices.Contains([]string{"org_id", "version", "changed", "model", "allowed_models", "max_input_chars", "user_tokens_per_day", "system_prompt_chars", "temperature"}, k) {
				t.Fatalf("%s: key %q", name, k)
			}
		}
	}
}
