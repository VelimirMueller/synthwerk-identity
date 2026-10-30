package audit

// The audit list consumers of other services' streams: the llm AI settings
// changes (aisettings.go, synthwerk#39) and the studio page builder changes
// (studio.go, synthwerk#106). Each one is a JetStream durable consumer that
// copies every valid event into identity.audit_events. The rules are the same
// for every source:
//
//   - The producer owns its stream. Identity never creates or changes it: while it
//     is missing, Run retries with backoff and logs WARN. The service keeps running.
//   - One event = one INSERT ... ON CONFLICT (id) DO NOTHING: a repeat adds no row.
//   - Ack after the commit. A database error: Nak with a delay, the event comes
//     back. A malformed event: Term, it never comes back. An unknown org (for
//     example a deleted one): ack, no row.
//   - Logs hold the event id. Never the user sub, never a data value.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/VelimirMueller/synthwerk-identity/internal/account"
)

// ErrMalformed means the event can never be processed. The consumer terminates it.
var ErrMalformed = errors.New("audit: malformed event")

// ErrUnknownOrg means the org of the event is not in identity.orgs.
var ErrUnknownOrg = errors.New("audit: unknown org")

func malformed(rule string) error { return fmt.Errorf("%w: %s", ErrMalformed, rule) }

// Entry is one checked event of another service, ready for the audit list.
type Entry struct {
	ID string
	// Type is the CloudEvents type. The parser sets it.
	Type    string
	OrgID   string
	Actor   string
	Subject string
	Time    time.Time
	// Data is the data object as received. The schemas allow no personal text.
	Data json.RawMessage
	// UserSub is the sub in Actor.
	UserSub string
}

// Recorder writes one event to the audit list. *Writer implements it.
type Recorder interface {
	// Record returns inserted false for a repeat, ErrUnknownOrg when the org is
	// not in identity.orgs.
	Record(ctx context.Context, c Entry) (inserted bool, err error)
}

// Beginner is the part of *pgxpool.Pool the writer needs.
type Beginner interface {
	Begin(ctx context.Context) (pgx.Tx, error)
}

// Writer inserts audit rows from other services (search_path=identity).
type Writer struct{ DB Beginner }

// Record inserts c in one transaction. It first takes the account lock of the
// user (account.LockUser), so an account delete (#41) that runs at the same time
// either rewrites this row or is committed before the check: a user who deleted
// the account is "deleted-user", and a late event never brings the sub back.
func (w *Writer) Record(ctx context.Context, c Entry) (bool, error) {
	if c.Type == "" {
		return false, malformed("type is missing")
	}
	tx, err := w.DB.Begin(ctx)
	if err != nil {
		return false, fmt.Errorf("audit: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }() // no-op after Commit
	if err := account.LockUser(ctx, tx, c.UserSub); err != nil {
		return false, err
	}
	var known, inserted bool
	err = tx.QueryRow(ctx, `WITH org AS (SELECT id FROM orgs WHERE id = $2::uuid),
		ins AS (
			INSERT INTO audit_events (id, org_id, type, actor, subject, time, data)
			SELECT $1::uuid, org.id, $3,
				CASE WHEN EXISTS (SELECT 1 FROM account_deletions WHERE user_sub_hash = $8) THEN 'user:' || $9 ELSE $4 END,
				$5, $6, $7::jsonb
			FROM org
			ON CONFLICT (id) DO NOTHING
			RETURNING 1)
		SELECT EXISTS (SELECT 1 FROM org), EXISTS (SELECT 1 FROM ins)`,
		c.ID, c.OrgID, c.Type, c.Actor, c.Subject, c.Time, string(c.Data),
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
	if err := tx.Commit(ctx); err != nil {
		return false, fmt.Errorf("audit: commit: %w", err)
	}
	return inserted, nil
}

// ConsumerConfig of a consumer. Zero values take the defaults.
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

// source is one stream of another service that feeds the audit list.
type source struct {
	// name is the part of the log event names: identity.audit.<name>_recorded.
	name string
	// label starts the log messages: "<label> consumer attached".
	label       string
	stream      string
	durable     string
	description string
	// subjects are the NATS subjects the consumer reads. Other subjects of the
	// stream stay there and never reach the parser.
	subjects []string
	parse    func(raw []byte) (Entry, error)
}

// jetStream is the durable consumer config. MaxDeliver -1: a failing insert keeps
// coming back (with the Nak backoff) until it succeeds, so no event is lost. A
// malformed event is terminated instead.
func (s source) jetStream(c ConsumerConfig) jetstream.ConsumerConfig {
	c = c.withDefaults()
	cfg := jetstream.ConsumerConfig{
		Durable:       s.durable,
		Description:   s.description,
		DeliverPolicy: jetstream.DeliverAllPolicy,
		AckPolicy:     jetstream.AckExplicitPolicy,
		AckWait:       c.AckWait,
		MaxDeliver:    -1,
		MaxAckPending: 16,
	}
	if len(s.subjects) == 1 {
		cfg.FilterSubject = s.subjects[0]
	} else {
		cfg.FilterSubjects = s.subjects
	}
	return cfg
}

// Consumer runs one durable consumer.
type Consumer struct {
	src   source
	js    jetstream.JetStream
	rec   Recorder
	log   *slog.Logger
	cfg   ConsumerConfig
	ready atomic.Bool
}

func newConsumer(src source, js jetstream.JetStream, rec Recorder, logger *slog.Logger, cfg ConsumerConfig) *Consumer {
	return &Consumer{src: src, js: js, rec: rec, log: logger, cfg: cfg.withDefaults()}
}

func (c *Consumer) event(suffix string) slog.Attr {
	return slog.String("event.name", "identity.audit."+c.src.name+"_"+suffix)
}

// Ready reports whether the consumer is attached to its stream. For /readyz, not
// critical: identity works without it, events wait in the stream.
func (c *Consumer) Ready(context.Context) error {
	if !c.ready.Load() {
		return errors.New(c.src.label + " consumer not attached")
	}
	return nil
}

// Run attaches the consumer and handles events until ctx ends. A missing stream
// or a lost consumer is retried with backoff. Run returns nil when ctx ends.
func (c *Consumer) Run(ctx context.Context) error {
	wait := c.cfg.RetryMin
	for {
		cons, err := c.js.CreateOrUpdateConsumer(ctx, c.src.stream, c.src.jetStream(c.cfg))
		if err != nil {
			if ctx.Err() != nil {
				return nil //nolint:nilerr // shutdown, not a failure
			}
			reason := "consumer_create_failed"
			if errors.Is(err, jetstream.ErrStreamNotFound) {
				reason = "stream_missing"
			}
			c.log.WarnContext(ctx, c.src.label+" consumer not attached, retrying",
				c.event("waiting"),
				slog.String("synthwerk.reason", reason),
				slog.String("messaging.destination.name", c.src.stream),
				slog.Duration("synthwerk.retry_in", wait))
			if !sleep(ctx, wait) {
				return nil
			}
			wait = min(wait*2, c.cfg.RetryMax)
			continue
		}
		cc, err := cons.Consume(func(m jetstream.Msg) { c.Handle(ctx, m) },
			jetstream.ConsumeErrHandler(func(_ jetstream.ConsumeContext, err error) {
				c.log.WarnContext(ctx, c.src.label+" consumer error",
					c.event("consume_error"),
					slog.String("exception.type", fmt.Sprintf("%T", err)))
			}))
		if err != nil {
			c.log.WarnContext(ctx, c.src.label+" consumer does not start, retrying",
				c.event("waiting"),
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
		c.log.InfoContext(ctx, c.src.label+" consumer attached",
			c.event("attached"),
			slog.String("messaging.destination.name", c.src.stream),
			slog.String("messaging.consumer.group.name", c.src.durable))
		select {
		case <-ctx.Done():
			cc.Stop()
			c.ready.Store(false)
			return nil
		case <-cc.Closed():
			// The stream or the consumer went away (for example, the producer
			// re-created the stream). Attach again.
			c.ready.Store(false)
		}
	}
}

// Handle processes one event: insert, then ack; Nak on a database error; Term on a
// malformed event; ack without a row for an unknown org.
func (c *Consumer) Handle(ctx context.Context, m jetstream.Msg) {
	ch, err := c.src.parse(m.Data())
	if err != nil {
		c.log.WarnContext(ctx, c.src.label+" event rejected",
			c.event("rejected"),
			slog.String("error.type", "malformed"),
			slog.String("exception.message", err.Error())) // names the rule, never a value
		if err := m.Term(); err != nil {
			c.log.WarnContext(ctx, "term failed", c.event("term_failed"))
		}
		return
	}
	rctx, cancel := context.WithTimeout(ctx, max(c.cfg.AckWait-5*time.Second, c.cfg.AckWait/2))
	defer cancel()
	inserted, err := c.rec.Record(rctx, ch)
	unknownOrg := errors.Is(err, ErrUnknownOrg)
	switch {
	case unknownOrg:
		c.log.InfoContext(ctx, c.src.label+" event of an unknown org dropped",
			c.event("unknown_org"),
			slog.String("cloudevents.event_id", ch.ID))
	case err != nil:
		delay := c.backoff(m)
		c.log.WarnContext(ctx, c.src.label+" event not recorded, will retry",
			c.event("failed"),
			slog.String("cloudevents.event_id", ch.ID),
			slog.Duration("synthwerk.retry_in", delay))
		if err := m.NakWithDelay(delay); err != nil {
			c.log.WarnContext(ctx, "nak failed", c.event("nak_failed"))
		}
		return
	}
	if err := m.Ack(); err != nil {
		// The row is in; a redelivery inserts nothing and acks.
		c.log.WarnContext(ctx, "ack failed", c.event("ack_failed"),
			slog.String("cloudevents.event_id", ch.ID))
		return
	}
	if !unknownOrg {
		c.log.InfoContext(ctx, c.src.label+" event recorded",
			c.event("recorded"),
			slog.String("cloudevents.event_id", ch.ID),
			slog.String("cloudevents.event_type", ch.Type),
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
