package account

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
)

// Users removes a user in Zitadel. A user that is already gone is no error.
type Users interface {
	DeleteUser(ctx context.Context, userSub string) error
}

// Remover defaults.
const (
	DefaultRemoveInterval = 30 * time.Second
	removeBatch           = 10
	maxBackoff            = time.Hour
	maxErrorLen           = 512
)

// Remover removes the Zitadel user of each deleted account, with retries and a
// growing pause (1 min, 2 min, 4 min … at most 1 h). After success the clear sub
// leaves account_deletions; only its hash stays.
type Remover struct {
	DB    DB
	Users Users
	Log   *slog.Logger
	// Interval between two runs. Zero: DefaultRemoveInterval.
	Interval time.Duration
}

// Run works until ctx ends.
func (rm *Remover) Run(ctx context.Context) error {
	every := rm.Interval
	if every <= 0 {
		every = DefaultRemoveInterval
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		if _, err := rm.RunOnce(ctx); err != nil && ctx.Err() == nil {
			rm.Log.ErrorContext(ctx, "account remover: run failed", slog.String("event.name", "account.remover_failed"),
				slog.String("exception.message", err.Error()))
		}
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}

// RunOnce handles up to one batch of due rows and returns how many Zitadel users it
// removed. Two identity instances skip each other's rows.
func (rm *Remover) RunOnce(ctx context.Context) (int, error) {
	tx, err := rm.DB.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("account: remover begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	rows, err := tx.Query(ctx, `SELECT user_sub_hash, user_sub, attempts FROM account_deletions
		WHERE zitadel_removed_at IS NULL AND next_attempt_at <= now()
		ORDER BY next_attempt_at LIMIT $1 FOR UPDATE SKIP LOCKED`, removeBatch)
	if err != nil {
		return 0, fmt.Errorf("account: remover select: %w", err)
	}
	type due struct {
		hash     []byte
		sub      string
		attempts int
	}
	list, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (due, error) {
		var d due
		err := r.Scan(&d.hash, &d.sub, &d.attempts)
		return d, err
	})
	if err != nil {
		return 0, fmt.Errorf("account: remover select: %w", err)
	}
	removed := 0
	for _, d := range list {
		if err := rm.Users.DeleteUser(ctx, d.sub); err != nil {
			msg := err.Error()
			if len(msg) > maxErrorLen {
				msg = msg[:maxErrorLen]
			}
			wait := backoff(d.attempts + 1)
			if _, err := tx.Exec(ctx, `UPDATE account_deletions SET attempts = attempts + 1, last_error = $2,
				next_attempt_at = now() + $3::interval WHERE user_sub_hash = $1`, d.hash, msg, fmt.Sprintf("%d seconds", int(wait.Seconds()))); err != nil {
				return removed, fmt.Errorf("account: remover update: %w", err)
			}
			rm.Log.WarnContext(ctx, "account remover: zitadel refused", slog.String("event.name", "account.zitadel_remove_failed"),
				slog.String("enduser.id", d.sub), slog.Int("attempts", d.attempts+1), slog.String("exception.message", msg))
			continue
		}
		if _, err := tx.Exec(ctx, `UPDATE account_deletions SET zitadel_removed_at = now(), user_sub = NULL,
			attempts = attempts + 1, last_error = NULL WHERE user_sub_hash = $1`, d.hash); err != nil {
			return removed, fmt.Errorf("account: remover update: %w", err)
		}
		removed++
		rm.Log.InfoContext(ctx, "account remover: zitadel user removed", slog.String("event.name", "account.zitadel_removed"),
			slog.String("enduser.id", d.sub))
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("account: remover commit: %w", err)
	}
	return removed, nil
}

// backoff is the pause after the n-th failed attempt: 2^(n-1) minutes, at most 1 h.
func backoff(n int) time.Duration {
	if n < 1 {
		n = 1
	}
	if n > 7 {
		return maxBackoff
	}
	return min(time.Duration(1<<(n-1))*time.Minute, maxBackoff)
}
