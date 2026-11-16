package audit_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"github.com/VelimirMueller/synthwerk-identity/internal/app"
	"github.com/VelimirMueller/synthwerk-identity/internal/audit"
)

const exampleConversation = "019a8b0f-1a2b-7c3d-8e4f-5a6b7c8d9e0f"

// toolExample is the contract example (synthwerk-contracts events/examples), copied.
func toolExample(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/dev.synthwerk.llm.toolcall.executed.v3.json")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// toolEvent returns the example with the envelope fields in env and the data
// fields in data set (a nil value removes the field).
func toolEvent(t *testing.T, env, data map[string]any) []byte {
	t.Helper()
	var ev map[string]any
	if err := json.Unmarshal(toolExample(t), &ev); err != nil {
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

// ParseToolCall - contract example - valid, ids from the envelope, data as checked.
func TestParseToolCallContractExample(t *testing.T) {
	e, err := audit.ParseToolCall(toolExample(t))
	if err != nil {
		t.Fatal(err)
	}
	if e.Type != audit.ToolCallEventType || e.OrgID != exampleOrg || e.Subject != exampleConversation || e.Actor != exampleActor || e.UserSub != exampleSub {
		t.Fatalf("%+v", e)
	}
	want := `{"conversation_id":"` + exampleConversation + `","duration_ms":12,"org_id":"` + exampleOrg + `","outcome":"ok","scope":"org","tool":"llm_get_org_usage"}`
	if string(e.Data) != want {
		t.Fatalf("data %s", e.Data)
	}
	for _, outcome := range []string{"denied", "error"} {
		if _, err := audit.ParseToolCall(toolEvent(t, nil, map[string]any{"outcome": outcome})); err != nil {
			t.Fatalf("%s: %v", outcome, err)
		}
	}
	for _, ms := range []int{0, 600000} {
		if _, err := audit.ParseToolCall(toolEvent(t, nil, map[string]any{"duration_ms": ms})); err != nil {
			t.Fatalf("duration %d: %v", ms, err)
		}
	}
}

// ParseToolCall - each broken event - ErrMalformed, and the error holds no value of the event.
func TestParseToolCallRejectsMalformed(t *testing.T) {
	other := "0199f3a0-5b6c-7d8e-9f0a-1b2c3d4e5f61"
	cases := map[string][]byte{
		"not json":                   []byte("{nope"),
		"bad envelope":               []byte(`{"specversion":"1.0","data":{}}`),
		"v2 type":                    toolEvent(t, map[string]any{"type": "dev.synthwerk.llm.toolcall.executed.v2"}, nil),
		"service actor":              toolEvent(t, map[string]any{"actor": "service:llm"}, nil),
		"no actor":                   toolEvent(t, map[string]any{"actor": nil}, nil),
		"data not an object":         toolEvent(t, map[string]any{"data": []int{1}}, nil),
		"tool arguments":             toolEvent(t, nil, map[string]any{"arguments": `{"user_id":"Secret victim"}`}),
		"tool result":                toolEvent(t, nil, map[string]any{"result": "Secret victim"}),
		"no tool":                    toolEvent(t, nil, map[string]any{"tool": nil}),
		"tool not snake":             toolEvent(t, nil, map[string]any{"tool": "Secret victim"}),
		"tool of 65 chars":           toolEvent(t, nil, map[string]any{"tool": "llm_get_" + strings.Repeat("a", 57)}),
		"no scope":                   toolEvent(t, nil, map[string]any{"scope": nil}),
		"scope operator":             toolEvent(t, nil, map[string]any{"scope": "operator"}),
		"no org_id":                  toolEvent(t, nil, map[string]any{"org_id": nil}),
		"upper case org_id":          toolEvent(t, map[string]any{"orgid": strings.ToUpper(exampleOrg)}, map[string]any{"org_id": strings.ToUpper(exampleOrg)}),
		"zitadel org id":             toolEvent(t, map[string]any{"orgid": "283746192837461929"}, map[string]any{"org_id": "283746192837461929"}),
		"orgid differs":              toolEvent(t, map[string]any{"orgid": other}, nil),
		"no conversation_id":         toolEvent(t, nil, map[string]any{"conversation_id": nil}),
		"conversation_id not a uuid": toolEvent(t, map[string]any{"subject": "conv-1"}, map[string]any{"conversation_id": "conv-1"}),
		"subject differs":            toolEvent(t, map[string]any{"subject": other}, nil),
		"no outcome":                 toolEvent(t, nil, map[string]any{"outcome": nil}),
		"outcome unknown":            toolEvent(t, nil, map[string]any{"outcome": "maybe"}),
		"no duration":                toolEvent(t, nil, map[string]any{"duration_ms": nil}),
		"negative duration":          toolEvent(t, nil, map[string]any{"duration_ms": -1}),
		"duration above 10 min":      toolEvent(t, nil, map[string]any{"duration_ms": 600001}),
		"duration not an integer":    toolEvent(t, nil, map[string]any{"duration_ms": 1.5}),
	}
	for name, raw := range cases {
		_, err := audit.ParseToolCall(raw)
		if !errors.Is(err, audit.ErrMalformed) {
			t.Errorf("%s: err %v, want ErrMalformed", name, err)
			continue
		}
		for _, v := range []string{"Secret victim", exampleSub, other, "conv-1"} {
			if strings.Contains(err.Error(), v) {
				t.Errorf("%s: error holds a value: %v", name, err)
			}
		}
	}
}

// ParseToolCall - case-variant and duplicate keys - Data holds only the checked
// fields with the schema names (security review, #106).
func TestParseToolCallStoresTheCheckedFieldsOnly(t *testing.T) {
	ids := `"org_id":"` + exampleOrg + `","conversation_id":"` + exampleConversation + `","scope":"org","duration_ms":3`
	for name, data := range map[string]string{
		"case-variant key": `{` + ids + `,"TOOL":"Secret victim","tool":"llm_get_org_usage","outcome":"ok"}`,
		"duplicate key":    `{` + ids + `,"tool":"Secret victim","tool":"llm_get_org_usage","outcome":"ok"}`,
	} {
		var ev map[string]json.RawMessage
		if err := json.Unmarshal(toolExample(t), &ev); err != nil {
			t.Fatal(err)
		}
		ev["data"] = json.RawMessage(data)
		raw, _ := json.Marshal(ev)
		e, err := audit.ParseToolCall(raw)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if strings.Contains(string(e.Data), "Secret victim") || !strings.Contains(string(e.Data), `"tool":"llm_get_org_usage"`) {
			t.Fatalf("%s: data %s", name, e.Data)
		}
	}
}

func newToolCallConsumer(r audit.Recorder, logs *bytes.Buffer) *audit.Consumer {
	logger := slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	return audit.NewToolCallConsumer(nil, r, logger, audit.ConsumerConfig{RetryMin: time.Second, RetryMax: 8 * time.Second})
}

// Handle - valid tool call event - record, then ack. Event id in the logs; no sub.
func TestHandleToolCallRecordsThenAcks(t *testing.T) {
	var logs bytes.Buffer
	r := &fakeRecorder{inserted: true}
	m := &fakeMsg{data: toolExample(t), delivered: 1}
	newToolCallConsumer(r, &logs).Handle(t.Context(), m)
	if r.calls != 1 || r.got.Type != audit.ToolCallEventType || r.got.OrgID != exampleOrg || r.got.UserSub != exampleSub {
		t.Fatalf("recorder got %+v", r)
	}
	if !m.acked || m.termed || m.nakDelay != 0 {
		t.Fatalf("msg %+v", m)
	}
	l := logs.String()
	if !strings.Contains(l, `"identity.audit.toolcall_recorded"`) || !strings.Contains(l, "019a8b10-3c4d-7e5f-8a6b-7c8d9e0f1a2b") || strings.Contains(l, exampleSub) {
		t.Fatalf("logs: %s", l)
	}
}

// Handle - malformed and database error - Term without a record; Nak with a delay.
func TestHandleToolCallTermsMalformedAndNaksOnStoreError(t *testing.T) {
	var logs bytes.Buffer
	r := &fakeRecorder{}
	m := &fakeMsg{data: toolEvent(t, nil, map[string]any{"arguments": "Secret victim"}), delivered: 1}
	newToolCallConsumer(r, &logs).Handle(t.Context(), m)
	if r.calls != 0 || !m.termed || m.acked || !strings.Contains(logs.String(), `"identity.audit.toolcall_rejected"`) || strings.Contains(logs.String(), "Secret victim") {
		t.Fatalf("calls %d msg %+v logs %s", r.calls, m, logs.String())
	}
	logs.Reset()
	m = &fakeMsg{data: toolExample(t), delivered: 2}
	newToolCallConsumer(&fakeRecorder{err: errors.New("db down")}, &logs).Handle(t.Context(), m)
	if m.acked || m.termed || m.nakDelay != 2*time.Second || !strings.Contains(logs.String(), `"identity.audit.toolcall_failed"`) {
		t.Fatalf("msg %+v logs %s", m, logs.String())
	}
}

// ToolCallJetStreamConfig - defaults - own durable on exactly the v3 subject.
func TestToolCallConsumerConfig(t *testing.T) {
	c := audit.ToolCallJetStreamConfig(audit.ConsumerConfig{})
	if c.Durable != "identity-llm-toolcalls" || c.FilterSubject != "evt.llm.toolcall.executed.v3" || len(c.FilterSubjects) != 0 ||
		c.AckPolicy != jetstream.AckExplicitPolicy || c.DeliverPolicy != jetstream.DeliverAllPolicy || c.MaxDeliver != -1 {
		t.Fatalf("%+v", c)
	}
}

// Ready - tool call consumer not attached - /readyz degraded with the check llm_toolcalls.
func TestToolCallsReadyDegradesReadyz(t *testing.T) {
	c := newToolCallConsumer(&fakeRecorder{}, &bytes.Buffer{})
	if err := c.Ready(t.Context()); err == nil || !strings.Contains(err.Error(), "toolcall") {
		t.Fatalf("ready before Run: %v", err)
	}
	a, err := app.New(pinger{}, slog.New(slog.DiscardHandler), app.Config{Version: "0.1.0-dev", Commit: "0000000", Env: "ci", ToolCalls: c.Ready})
	if err != nil {
		t.Fatal(err)
	}
	a.Health.MarkStarted()
	body := a.Health.Check(t.Context())
	var seen bool
	for _, ch := range body.Checks {
		seen = seen || (ch.Name == "llm_toolcalls" && ch.Status == "degraded")
	}
	if body.Status != "degraded" || !seen {
		t.Fatalf("status %s checks %+v", body.Status, body.Checks)
	}
}
