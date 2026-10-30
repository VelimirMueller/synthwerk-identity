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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"slices"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/VelimirMueller/synthwerk-contracts/go/kit/cloudevents"

	"github.com/VelimirMueller/synthwerk-identity/internal/account"
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

// ErrMalformed means the event can never be processed. The consumer terminates it.
var ErrMalformed = errors.New("audit: malformed event")

// ErrUnknownOrg means the org of the event is not in identity.orgs.
var ErrUnknownOrg = errors.New("audit: unknown org")

// AISettingsChange is one checked ai_settings.changed.v1 event.
type AISettingsChange struct {
	ID      string
	OrgID   string
	Actor   string
	Subject string
	Time    time.Time
	// Data is the data object as received. It holds no prompt text.
	Data json.RawMessage
	// UserSub is the sub in Actor.
	UserSub string
}

func malformed(rule string) error { return fmt.Errorf("%w: %s", ErrMalformed, rule) }

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
	return AISettingsChange{
		ID: ev.ID, OrgID: *d.OrgID, Actor: ev.Actor, Subject: ev.Subject, Time: ev.Time.UTC(),
		Data: ev.Data, UserSub: ev.Actor[len("user:"):],
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

// Recorder writes one change to the audit list. *Writer implements it.
type Recorder interface {
	// Record returns inserted false for a repeat, ErrUnknownOrg when the org is
	// not in identity.orgs.
	Record(ctx context.Context, c AISettingsChange) (inserted bool, err error)
}

// Execer is the part of *pgxpool.Pool the writer needs.
type Execer interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// Writer inserts audit rows from other services (search_path=identity).
type Writer struct{ DB Execer }

// Record inserts c in one statement. A user who deleted the account (#41) is
// already "deleted-user": a late event never brings the sub back.
func (w *Writer) Record(ctx context.Context, c AISettingsChange) (bool, error) {
	var known, inserted bool
	err := w.DB.QueryRow(ctx, `WITH org AS (SELECT id FROM orgs WHERE id = $2::uuid),
		ins AS (
			INSERT INTO audit_events (id, org_id, type, actor, subject, time, data)
			SELECT $1::uuid, org.id, $3,
				CASE WHEN EXISTS (SELECT 1 FROM account_deletions WHERE user_sub_hash = $8) THEN 'user:' || $9 ELSE $4 END,
				$5, $6, $7::jsonb
			FROM org
			ON CONFLICT (id) DO NOTHING
			RETURNING 1)
		SELECT EXISTS (SELECT 1 FROM org), EXISTS (SELECT 1 FROM ins)`,
		c.ID, c.OrgID, AISettingsEventType, c.Actor, c.Subject, c.Time, string(c.Data),
		account.Hash(c.UserSub), account.DeletedUser).Scan(&known, &inserted)
	if err != nil {
		var pgErr *pgconn.PgError
		// The org went away between the read and the insert.
		if errors.As(err, &pgErr) && pgErr.Code == "23503" {
			return false, ErrUnknownOrg
		}
		return false, fmt.Errorf("audit: record: %w", err)
	}
	if !known {
		return false, ErrUnknownOrg
	}
	return inserted, nil
}

// ConsumerConfig of the AI settings consumer. Zero values take the defaults.
type ConsumerConfig struct {
	// AckWait is how long JetStream waits for the ack before it sends the event
	// again. Default 30 s. One insert gets AckWait minus 5 s.
	AckWait time.Duration
	// RetryMin and RetryMax bound the backoff of a Nak and of the wait for the
	// stream. Default 1 s and 1 min.
	RetryMin, RetryMax time.Duration
}

func (c ConsumerConfig) withDefaults() ConsumerConfig {
	if c.AckWait <= 0 {
		c.AckWait = 30 * time.Second
	}
	if c.RetryMin <= 0 {
		c.RetryMin = time.Second
	}
	if c.RetryMax < c.RetryMin {
		c.RetryMax = max(time.Minute, c.RetryMin)
	}
	return c
}

// JetStreamConfig is the durable consumer identity creates or updates on EVT_LLM.
// MaxDeliver -1: a failing insert keeps coming back (with the Nak backoff) until
// it succeeds, so no change is lost. A malformed event is terminated instead.
func JetStreamConfig(c ConsumerConfig) jetstream.ConsumerConfig {
	c = c.withDefaults()
	return jetstream.ConsumerConfig{
		Durable:       AISettingsDurable,
		Description:   "synthwerk-identity: copy the AI settings changes to the audit list (synthwerk#39).",
		FilterSubject: AISettingsSubject,
		DeliverPolicy: jetstream.DeliverAllPolicy,
		AckPolicy:     jetstream.AckExplicitPolicy,
		AckWait:       c.AckWait,
		MaxDeliver:    -1,
		MaxAckPending: 16,
	}
}

// Consumer runs the durable consumer.
type Consumer struct {
	js    jetstream.JetStream
	rec   Recorder
	log   *slog.Logger
	cfg   ConsumerConfig
	ready atomic.Bool
}

// NewConsumer returns the consumer. Call Run.
func NewConsumer(js jetstream.JetStream, rec Recorder, logger *slog.Logger, cfg ConsumerConfig) *Consumer {
	return &Consumer{js: js, rec: rec, log: logger, cfg: cfg.withDefaults()}
}

// Ready reports whether the consumer is attached to EVT_LLM. For /readyz, not
// critical: identity works without it, events wait in the stream.
func (c *Consumer) Ready(context.Context) error {
	if !c.ready.Load() {
		return errors.New("ai_settings consumer not attached")
	}
	return nil
}

// Run attaches the consumer and handles events until ctx ends. A missing stream
// or a lost consumer is retried with backoff. Run returns nil when ctx ends.
func (c *Consumer) Run(ctx context.Context) error {
	wait := c.cfg.RetryMin
	for {
		cons, err := c.js.CreateOrUpdateConsumer(ctx, LLMStreamName, JetStreamConfig(c.cfg))
		if err != nil {
			if ctx.Err() != nil {
				return nil //nolint:nilerr // shutdown, not a failure
			}
			reason := "consumer_create_failed"
			if errors.Is(err, jetstream.ErrStreamNotFound) {
				reason = "stream_missing"
			}
			c.log.WarnContext(ctx, "ai_settings consumer not attached, retrying",
				slog.String("event.name", "identity.audit.llm_waiting"),
				slog.String("synthwerk.reason", reason),
				slog.String("messaging.destination.name", LLMStreamName),
				slog.Duration("synthwerk.retry_in", wait))
			if !sleep(ctx, wait) {
				return nil
			}
			wait = min(wait*2, c.cfg.RetryMax)
			continue
		}
		cc, err := cons.Consume(func(m jetstream.Msg) { c.Handle(ctx, m) },
			jetstream.ConsumeErrHandler(func(_ jetstream.ConsumeContext, err error) {
				c.log.WarnContext(ctx, "ai_settings consumer error",
					slog.String("event.name", "identity.audit.llm_consume_error"),
					slog.String("exception.type", fmt.Sprintf("%T", err)))
			}))
		if err != nil {
			c.log.WarnContext(ctx, "ai_settings consumer does not start, retrying",
				slog.String("event.name", "identity.audit.llm_waiting"),
				slog.String("synthwerk.reason", "consume_failed"),
				slog.Duration("synthwerk.retry_in", wait))
			if !sleep(ctx, wait) {
				return nil
			}
			wait = min(wait*2, c.cfg.RetryMax)
			continue
		}
		wait = c.cfg.RetryMin
		c.ready.Store(true)
		c.log.InfoContext(ctx, "ai_settings consumer attached",
			slog.String("event.name", "identity.audit.llm_attached"),
			slog.String("messaging.destination.name", LLMStreamName),
			slog.String("messaging.consumer.group.name", AISettingsDurable))
		select {
		case <-ctx.Done():
			cc.Stop()
			c.ready.Store(false)
			return nil
		case <-cc.Closed():
			// The stream or the consumer went away (for example, llm re-created the
			// stream). Attach again.
			c.ready.Store(false)
		}
	}
}

// Handle processes one event: insert, then ack; Nak on a database error; Term on a
// malformed event; ack without a row for an unknown org.
func (c *Consumer) Handle(ctx context.Context, m jetstream.Msg) {
	ch, err := ParseAISettings(m.Data())
	if err != nil {
		c.log.WarnContext(ctx, "ai_settings event rejected",
			slog.String("event.name", "identity.audit.llm_rejected"),
			slog.String("error.type", "malformed"),
			slog.String("exception.message", err.Error())) // names the rule, never a value
		if err := m.Term(); err != nil {
			c.log.WarnContext(ctx, "term failed", slog.String("event.name", "identity.audit.llm_term_failed"))
		}
		return
	}
	rctx, cancel := context.WithTimeout(ctx, max(c.cfg.AckWait-5*time.Second, c.cfg.AckWait/2))
	defer cancel()
	inserted, err := c.rec.Record(rctx, ch)
	unknownOrg := errors.Is(err, ErrUnknownOrg)
	switch {
	case unknownOrg:
		c.log.InfoContext(ctx, "ai_settings event of an unknown org dropped",
			slog.String("event.name", "identity.audit.llm_unknown_org"),
			slog.String("cloudevents.event_id", ch.ID))
	case err != nil:
		delay := c.backoff(m)
		c.log.WarnContext(ctx, "ai_settings event not recorded, will retry",
			slog.String("event.name", "identity.audit.llm_failed"),
			slog.String("cloudevents.event_id", ch.ID),
			slog.Duration("synthwerk.retry_in", delay))
		if err := m.NakWithDelay(delay); err != nil {
			c.log.WarnContext(ctx, "nak failed", slog.String("event.name", "identity.audit.llm_nak_failed"))
		}
		return
	}
	if err := m.Ack(); err != nil {
		// The row is in; a redelivery inserts nothing and acks.
		c.log.WarnContext(ctx, "ack failed", slog.String("event.name", "identity.audit.llm_ack_failed"),
			slog.String("cloudevents.event_id", ch.ID))
		return
	}
	if !unknownOrg {
		c.log.InfoContext(ctx, "ai_settings change recorded",
			slog.String("event.name", "identity.audit.llm_recorded"),
			slog.String("cloudevents.event_id", ch.ID),
			slog.Bool("synthwerk.repeat", !inserted))
	}
}

// backoff doubles the Nak delay with each delivery, from RetryMin up to RetryMax.
func (c *Consumer) backoff(m jetstream.Msg) time.Duration {
	n := uint64(1)
	if md, err := m.Metadata(); err == nil && md.NumDelivered > 0 {
		n = md.NumDelivered
	}
	d := c.cfg.RetryMin
	for i := uint64(1); i < n && d < c.cfg.RetryMax; i++ {
		d *= 2
	}
	return min(d, c.cfg.RetryMax)
}

func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
