// Package app wires identity: the health probes and the HTTP router. The layout
// follows synthwerk-pulse, which starts from the example service of the
// synthwerk-contracts Go kit (go/examples/service).
package app

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"

	"github.com/VelimirMueller/synthwerk-contracts/go/kit/health"
	kitlog "github.com/VelimirMueller/synthwerk-contracts/go/kit/log"

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
	h, err := health.New(cfg.Version, cfg.Commit,
		health.Check{Name: "postgres", Critical: true, Run: pinger.Ping, Detail: "postgres unreachable"},
	)
	if err != nil {
		return nil, err
	}
	a := &App{Log: logger, Health: h}

	mux := http.NewServeMux()
	h.Register(mux)
	// The log line sits inside the span. The probes create no span.
	a.handler = otelhttp.NewHandler(kitlog.HTTP(logger, mux), Service,
		otelhttp.WithFilter(func(r *http.Request) bool {
			return r.URL.Path != "/healthz" && r.URL.Path != "/readyz"
		}))
	return a, nil
}

// Handler is the HTTP handler of the service.
func (a *App) Handler() http.Handler { return a.handler }

// Migrate applies the SQL migrations of the service, like pulse applies its schema.
func Migrate(ctx context.Context, db *pgxpool.Pool) error {
	if _, err := db.Exec(ctx, migrations.Schema); err != nil {
		return fmt.Errorf("app: migrate: %w", err)
	}
	return nil
}
