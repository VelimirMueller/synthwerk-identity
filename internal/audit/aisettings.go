package audit

// The llm AI settings changes in the audit list (synthwerk#39). llm owns the
// settings and writes dev.synthwerk.llm.ai_settings.changed.v1 to its outbox; the
// kit relay publishes it on EVT_LLM. This JetStream durable consumer copies each
// valid event into identity.audit_events.
//
//   - llm owns EVT_LLM. Identity never creates or changes it: while it is missing,
//     Run retries with backoff and logs WARN. The service keeps running.
//   - One event = one INSERT ... ON CONFLICT (id) DO NOTHING: a repeat adds no row.
//   - Ack after the commit. A database error: Nak with a delay, the event comes
//     back. A malformed event: Term, it never comes back. An unknown org (for
//     example a deleted one): ack, no row.
//   - Logs hold the event id. Never the user sub, never a setting value.

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"regexp"
	"slices"

	"github.com/google/uuid"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/VelimirMueller/synthwerk-contracts/go/kit/cloudevents"
)

// Names of the fact and its place on the bus (synthwerk-contracts events/catalog.yaml).
const (
	AISettingsEventType = "dev.synthwerk.llm.ai_settings.changed.v1"
	AISettingsSubject   = "evt.llm.ai_settings.changed.v1"
	LLMStreamName       = "EVT_LLM"
	// AISettingsDurable is the consumer name. All replicas share it, so each
	// event reaches one replica.
	AISettingsDurable = "identity-llm-ai-settings"
)

// Limits of the data schema (events/llm/ai_settings.changed.v1.schema.json).
const (
	maxAliasLen          = 64
	maxAllowedModels     = 32
	maxChanged           = 6
	maxInputChars        = 8000
	maxUserTokensPerDay  = 1_000_000_000_000
	maxSystemPromptChars = 4000
	maxTemperature       = 2
)

var (
	aliasRe = regexp.MustCompile(`^[a-z][a-z0-9_-]*$`)
	actorRe = regexp.MustCompile(`^user:[A-Za-z0-9_-]{1,128}$`)
	// changeable is the enum of data.changed.
	changeable = []string{"model", "allowed_models", "system_prompt", "max_input_chars", "user_tokens_per_day", "temperature"}
)

// AISettingsChange is one checked ai_settings.changed.v1 event. Its Data holds no
// prompt text.
type AISettingsChange = Entry

// aiSettingsData mirrors the data schema. Pointers find a missing field; raw
// temperature finds an explicit null.
type aiSettingsData struct {
	OrgID             *string         `json:"org_id"`
	Version           *int64          `json:"version"`
	Changed           *[]string       `json:"changed"`
	Model             *string         `json:"model"`
	AllowedModels     *[]string       `json:"allowed_models"`
	MaxInputChars     *int64          `json:"max_input_chars"`
	UserTokensPerDay  *int64          `json:"user_tokens_per_day"`
	SystemPromptChars *int64          `json:"system_prompt_chars"`
	Temperature       json.RawMessage `json:"temperature"`
}

// ParseAISettings decodes and checks one CloudEvent of type AISettingsEventType.
// Every error wraps ErrMalformed and names the rule, never a value.
func ParseAISettings(raw []byte) (AISettingsChange, error) {
	var ev cloudevents.Event
	if err := json.Unmarshal(raw, &ev); err != nil {
		return AISettingsChange{}, malformed("envelope is not JSON")
	}
	if err := ev.Validate(); err != nil {
		return AISettingsChange{}, malformed("envelope is not a valid CloudEvent")
	}
	if ev.Type != AISettingsEventType {
		return AISettingsChange{}, malformed("type is not " + AISettingsEventType)
	}
	if !actorRe.MatchString(ev.Actor) {
		return AISettingsChange{}, malformed("actor is not user:[A-Za-z0-9_-]{1,128}")
	}
	// The schema says additionalProperties: false. ev.Data is one JSON value: the
	// envelope decode checked that.
	dec := json.NewDecoder(bytes.NewReader(ev.Data))
	dec.DisallowUnknownFields()
	var d aiSettingsData
	if err := dec.Decode(&d); err != nil {
		return AISettingsChange{}, malformed("data does not match the schema")
	}
	if err := d.check(); err != nil {
		return AISettingsChange{}, err
	}
	if ev.OrgID != *d.OrgID || ev.Subject != *d.OrgID {
		return AISettingsChange{}, malformed("orgid, subject and data.org_id are not the same")
	}
	data, err := d.canonical()
	if err != nil {
		return AISettingsChange{}, malformed("data does not encode")
	}
	return AISettingsChange{
		ID: ev.ID, Type: AISettingsEventType, OrgID: *d.OrgID, Actor: ev.Actor, Subject: ev.Subject,
		Time: ev.Time.UTC(), Data: data, UserSub: ev.Actor[len("user:"):],
	}, nil
}

func (d aiSettingsData) check() error {
	if d.OrgID == nil {
		return malformed("org_id is missing")
	}
	if id, err := uuid.Parse(*d.OrgID); err != nil || id.String() != *d.OrgID {
		return malformed("org_id is not a lowercase UUID")
	}
	if d.Version == nil || *d.Version < 1 {
		return malformed("version is missing or below 1")
	}
	if d.Changed == nil || len(*d.Changed) < 1 || len(*d.Changed) > maxChanged {
		return malformed("changed is missing or not 1 to 6 items")
	}
	if !unique(*d.Changed) {
		return malformed("changed has a repeated item")
	}
	for _, c := range *d.Changed {
		if !slices.Contains(changeable, c) {
			return malformed("changed has an item outside the enum")
		}
	}
	if d.Model == nil || !alias(*d.Model) {
		return malformed("model is missing or not an alias")
	}
	if d.AllowedModels == nil || len(*d.AllowedModels) < 1 || len(*d.AllowedModels) > maxAllowedModels {
		return malformed("allowed_models is missing or not 1 to 32 items")
	}
	if !unique(*d.AllowedModels) {
		return malformed("allowed_models has a repeated item")
	}
	for _, m := range *d.AllowedModels {
		if !alias(m) {
			return malformed("allowed_models has an item that is not an alias")
		}
	}
	if d.MaxInputChars == nil || *d.MaxInputChars < 1 || *d.MaxInputChars > maxInputChars {
		return malformed("max_input_chars is missing or not 1 to 8000")
	}
	if d.UserTokensPerDay == nil || *d.UserTokensPerDay < 0 || *d.UserTokensPerDay > maxUserTokensPerDay {
		return malformed("user_tokens_per_day is missing or not 0 to 1e12")
	}
	if d.SystemPromptChars == nil || *d.SystemPromptChars < 0 || *d.SystemPromptChars > maxSystemPromptChars {
		return malformed("system_prompt_chars is missing or not 0 to 4000")
	}
	if d.Temperature != nil {
		var t float64
		if bytes.Equal(d.Temperature, []byte("null")) || json.Unmarshal(d.Temperature, &t) != nil || t < 0 || t > maxTemperature {
			return malformed("temperature is not a number from 0 to 2")
		}
	}
	return nil
}

// canonical encodes the checked fields only (call it after check), with the schema key names. The audit
// row stores this copy, never the received bytes: Go's decoder matches keys without
// case and keeps the last of two equal keys, so the raw data could hold a value
// the checks never saw (security review, synthwerk#106).
func (d aiSettingsData) canonical() (json.RawMessage, error) {
	out := map[string]any{
		"org_id":              *d.OrgID,
		"version":             *d.Version,
		"changed":             *d.Changed,
		"model":               *d.Model,
		"allowed_models":      *d.AllowedModels,
		"max_input_chars":     *d.MaxInputChars,
		"user_tokens_per_day": *d.UserTokensPerDay,
		"system_prompt_chars": *d.SystemPromptChars,
	}
	if d.Temperature != nil {
		var t float64
		if err := json.Unmarshal(d.Temperature, &t); err != nil {
			return nil, err
		}
		out["temperature"] = t
	}
	return json.Marshal(out)
}

func alias(s string) bool { return len(s) <= maxAliasLen && aliasRe.MatchString(s) }

func unique(items []string) bool {
	seen := make(map[string]struct{}, len(items))
	for _, s := range items {
		if _, ok := seen[s]; ok {
			return false
		}
		seen[s] = struct{}{}
	}
	return true
}

// aiSettingsSource is the EVT_LLM consumer of the AI settings changes.
var aiSettingsSource = source{
	name:        "llm",
	label:       "ai_settings",
	stream:      LLMStreamName,
	durable:     AISettingsDurable,
	description: "synthwerk-identity: copy the AI settings changes to the audit list (synthwerk#39).",
	subjects:    []string{AISettingsSubject},
	parse:       ParseAISettings,
}

// JetStreamConfig is the durable consumer identity creates or updates on EVT_LLM.
// MaxDeliver -1: a failing insert keeps coming back (with the Nak backoff) until
// it succeeds, so no change is lost. A malformed event is terminated instead.
func JetStreamConfig(c ConsumerConfig) jetstream.ConsumerConfig {
	return aiSettingsSource.jetStream(c)
}

// NewConsumer returns the AI settings consumer on EVT_LLM. Call Run.
func NewConsumer(js jetstream.JetStream, rec Recorder, logger *slog.Logger, cfg ConsumerConfig) *Consumer {
	return newConsumer(aiSettingsSource, js, rec, logger, cfg)
}
