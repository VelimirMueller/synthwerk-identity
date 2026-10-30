// Package app wires identity: the health probes, the org, app, entitlement and account routes and the HTTP router. The layout
// follows synthwerk-pulse, which starts from the example service of the
// synthwerk-contracts Go kit (go/examples/service).
package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"

	"github.com/VelimirMueller/synthwerk-contracts/go/kit/auth"
	"github.com/VelimirMueller/synthwerk-contracts/go/kit/health"
	kitlog "github.com/VelimirMueller/synthwerk-contracts/go/kit/log"

	"github.com/VelimirMueller/synthwerk-identity/internal/account"
	"github.com/VelimirMueller/synthwerk-identity/internal/apps"
	"github.com/VelimirMueller/synthwerk-identity/internal/audit"
	"github.com/VelimirMueller/synthwerk-identity/internal/entitlements"
	"github.com/VelimirMueller/synthwerk-identity/internal/orgs"
	"github.com/VelimirMueller/synthwerk-identity/migrations"
)

// Service is the short service name: env prefix SYNTHWERK_IDENTITY_, source /synthwerk/identity/<env>.
const Service = "identity"

// Config of the app.
type Config struct {
	Version string
	Commit  string
	// Env is SYNTHWERK_PLATFORM_ENV.
	Env string
	// Verifier checks the Bearer tokens of the org routes. Nil: probes only.
	Verifier *auth.Verifier
	// Orgs serves the org routes (synthwerk#29). Needs Verifier.
	Orgs *orgs.Handler
	// Apps serves the app routes and the widget token route (synthwerk#30). Needs Orgs.
	Apps *apps.Handler
	// NATS reports the bus connection for /readyz. Nil: no check.
	NATS func(ctx context.Context) error
	// Entitlements serves the entitlement routes (synthwerk#31). Needs Verifier.
	Entitlements *entitlements.Handler
	// Account serves the export and the delete of the own account (synthwerk#41). Needs Verifier.
	Account *account.Handler
	// Audit serves the audit list of an org (synthwerk#37). Needs Orgs.
	Audit *audit.Handler
	// AISettings reports the EVT_LLM consumer of the audit list for /readyz (not
	// critical, synthwerk#39). Nil: no check.
	AISettings func(ctx context.Context) error
}

// Pinger checks the database connection. *pgxpool.Pool satisfies it.
type Pinger interface {
	Ping(ctx context.Context) error
}

// App holds the dependencies of the service.
type App struct {
	Log     *slog.Logger
	Health  *health.Handler
	handler http.Handler
}

// New wires the app. Call Migrate, then Health.MarkStarted, then serve Handler.
func New(pinger Pinger, logger *slog.Logger, cfg Config) (*App, error) {
	checks := []health.Check{{Name: "postgres", Critical: true, Run: pinger.Ping, Detail: "postgres unreachable"}}
	if cfg.NATS != nil {
		checks = append(checks, health.Check{Name: "nats", Critical: true, Run: cfg.NATS, Detail: "nats not connected"})
	}
	if cfg.AISettings != nil {
		// Not critical: llm creates EVT_LLM; until then the events wait there.
		checks = append(checks, health.Check{Name: "llm_ai_settings", Run: cfg.AISettings, Detail: "ai_settings consumer not attached"})
	}
	if cfg.Verifier != nil {
		// Not critical: a token check fails closed (401/503) while the keys are away.
		checks = append(checks, health.Check{Name: "jwks", Run: cfg.Verifier.Ready, Detail: "token keys unavailable"})
	}
	h, err := health.New(cfg.Version, cfg.Commit, checks...)
	if err != nil {
		return nil, err
	}
	a := &App{Log: logger, Health: h}

	mux := http.NewServeMux()
	h.Register(mux)
	if cfg.Entitlements != nil {
		if cfg.Verifier == nil {
			return nil, errors.New("app: the entitlement routes need a token verifier")
		}
		cfg.Entitlements.Register(mux, func(next http.Handler) http.Handler { return auth.Middleware(cfg.Verifier, next) })
	}
	if cfg.Account != nil {
		if cfg.Verifier == nil {
			return nil, errors.New("app: the account routes need a token verifier")
		}
		cfg.Account.Register(mux, func(next http.Handler) http.Handler { return auth.Middleware(cfg.Verifier, next) })
	}
	if cfg.Orgs != nil {
		if cfg.Verifier == nil {
			return nil, errors.New("app: the org routes need a token verifier")
		}
		cfg.Orgs.Register(mux, func(next http.Handler) http.Handler { return auth.Middleware(cfg.Verifier, next) })
	}
	if cfg.Apps != nil {
		if cfg.Orgs == nil {
			return nil, errors.New("app: the app routes need the org routes")
		}
		cfg.Apps.Register(mux, func(next http.Handler) http.Handler { return auth.Middleware(cfg.Verifier, next) })
	}
	if cfg.Audit != nil {
		if cfg.Orgs == nil {
			return nil, errors.New("app: the audit route needs the org routes")
		}
		cfg.Audit.Register(mux, func(next http.Handler) http.Handler { return auth.Middleware(cfg.Verifier, next) })
	}
	// The log line sits inside the span. The probes create no span.
	a.handler = otelhttp.NewHandler(kitlog.HTTP(logger, mux), Service,
		otelhttp.WithFilter(func(r *http.Request) bool {
			return r.URL.Path != "/healthz" && r.URL.Path != "/readyz"
		}))
	return a, nil
}

// Handler is the HTTP handler of the service.
func (a *App) Handler() http.Handler { return a.handler }

// Migrate applies all SQL migrations of the service in file-name order.
func Migrate(ctx context.Context, db *pgxpool.Pool) error {
	all, err := migrations.All()
	if err != nil {
		return fmt.Errorf("app: migrate: %w", err)
	}
	for _, sql := range all {
		// The simple protocol runs a file with several statements in one call.
		if _, err := db.Exec(ctx, sql, pgx.QueryExecModeSimpleProtocol); err != nil {
			return fmt.Errorf("app: migrate: %w", err)
		}
	}
	return nil
}
