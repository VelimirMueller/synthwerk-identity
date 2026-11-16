package audit

// The admin AI tool calls of llm in the audit list (synthwerk#53). llm writes
// dev.synthwerk.llm.toolcall.executed.v3 to its outbox for every call of an org
// tool; the kit relay publishes it on EVT_LLM. This JetStream durable consumer
// copies each valid event into identity.audit_events, with the rules of
// consumer.go. llm owns EVT_LLM: identity never creates it.

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"regexp"

	"github.com/nats-io/nats.go/jetstream"

	"github.com/VelimirMueller/synthwerk-contracts/go/kit/cloudevents"
)

// Names of the fact and its place on the bus (synthwerk-contracts events/catalog.yaml).
const (
	ToolCallEventType = "dev.synthwerk.llm.toolcall.executed.v3"
	ToolCallSubject   = "evt.llm.toolcall.executed.v3"
	// ToolCallsDurable is the consumer name. All replicas share it, so each event
	// reaches one replica.
	ToolCallsDurable = "identity-llm-toolcalls"
)

// Limits of the data schema (events/llm/toolcall.executed.v3.schema.json).
const (
	maxToolLen    = 64
	maxDurationMS = 600000
	toolCallScope = "org"
	outcomeOK     = "ok"
	outcomeDenied = "denied"
	outcomeFailed = "error"
)

var toolRe = regexp.MustCompile(`^[a-z]+_[a-z]+_[a-z_]+$`)

// toolCallData mirrors the data schema. Pointers find a missing field.
type toolCallData struct {
	Tool           *string `json:"tool"`
	Scope          *string `json:"scope"`
	OrgID          *string `json:"org_id"`
	ConversationID *string `json:"conversation_id"`
	Outcome        *string `json:"outcome"`
	DurationMS     *int64  `json:"duration_ms"`
}

// ParseToolCall decodes and checks one CloudEvent of type ToolCallEventType.
// Every error wraps ErrMalformed and names the rule, never a value.
func ParseToolCall(raw []byte) (Entry, error) {
	var ev cloudevents.Event
	if err := json.Unmarshal(raw, &ev); err != nil {
		return Entry{}, malformed("envelope is not JSON")
	}
	if err := ev.Validate(); err != nil {
		return Entry{}, malformed("envelope is not a valid CloudEvent")
	}
	if ev.Type != ToolCallEventType {
		return Entry{}, malformed("type is not " + ToolCallEventType)
	}
	if !actorRe.MatchString(ev.Actor) {
		return Entry{}, malformed("actor is not user:[A-Za-z0-9_-]{1,128}")
	}
	// The schema says additionalProperties: false. ev.Data is one JSON value: the
	// envelope decode checked that.
	dec := json.NewDecoder(bytes.NewReader(ev.Data))
	dec.DisallowUnknownFields()
	var d toolCallData
	if err := dec.Decode(&d); err != nil {
		return Entry{}, malformed("data does not match the schema")
	}
	if err := d.check(); err != nil {
		return Entry{}, err
	}
	if ev.OrgID != *d.OrgID {
		return Entry{}, malformed("orgid and data.org_id are not the same")
	}
	if ev.Subject != *d.ConversationID {
		return Entry{}, malformed("subject and data.conversation_id are not the same")
	}
	data, err := d.canonical()
	if err != nil {
		return Entry{}, malformed("data does not encode")
	}
	return Entry{
		ID: ev.ID, Type: ToolCallEventType, OrgID: *d.OrgID, Actor: ev.Actor, Subject: ev.Subject,
		Time: ev.Time.UTC(), Data: data, UserSub: ev.Actor[len("user:"):],
	}, nil
}

func (d toolCallData) check() error {
	if d.Tool == nil || len(*d.Tool) > maxToolLen || !toolRe.MatchString(*d.Tool) {
		return malformed("tool is missing or not <service>_<verb>_<noun>")
	}
	if d.Scope == nil || *d.Scope != toolCallScope {
		return malformed("scope is missing or not org")
	}
	if d.OrgID == nil || !lowerUUID(*d.OrgID) {
		return malformed("org_id is missing or not a lowercase UUID")
	}
	if d.ConversationID == nil || !lowerUUID(*d.ConversationID) {
		return malformed("conversation_id is missing or not a lowercase UUID")
	}
	if d.Outcome == nil || (*d.Outcome != outcomeOK && *d.Outcome != outcomeDenied && *d.Outcome != outcomeFailed) {
		return malformed("outcome is missing or not ok, denied or error")
	}
	if d.DurationMS == nil || *d.DurationMS < 0 || *d.DurationMS > maxDurationMS {
		return malformed("duration_ms is missing or not 0 to 600000")
	}
	return nil
}

// canonical encodes the checked fields only (call it after check), with the schema
// key names. The audit row stores this copy, never the received bytes (security
// review, synthwerk#106).
func (d toolCallData) canonical() (json.RawMessage, error) {
	return json.Marshal(map[string]any{
		"tool":            *d.Tool,
		"scope":           *d.Scope,
		"org_id":          *d.OrgID,
		"conversation_id": *d.ConversationID,
		"outcome":         *d.Outcome,
		"duration_ms":     *d.DurationMS,
	})
}

// toolCallSource is the EVT_LLM consumer of the admin AI tool calls.
var toolCallSource = source{
	name:        "toolcall",
	label:       "toolcall",
	stream:      LLMStreamName,
	durable:     ToolCallsDurable,
	description: "synthwerk-identity: copy the admin AI tool calls of llm to the audit list (synthwerk#53).",
	subjects:    []string{ToolCallSubject},
	parse:       ParseToolCall,
}

// ToolCallJetStreamConfig is the durable consumer identity creates or updates on
// EVT_LLM. Other llm subjects stay in the stream.
func ToolCallJetStreamConfig(c ConsumerConfig) jetstream.ConsumerConfig {
	return toolCallSource.jetStream(c)
}

// NewToolCallConsumer returns the admin AI tool call consumer on EVT_LLM. Call Run.
func NewToolCallConsumer(js jetstream.JetStream, rec Recorder, logger *slog.Logger, cfg ConsumerConfig) *Consumer {
	return newConsumer(toolCallSource, js, rec, logger, cfg)
}
