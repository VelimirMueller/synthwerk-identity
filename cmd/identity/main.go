// Command identity serves synthwerk-identity: health probes, migrations, the org
// routes (orgs, members, roles; synthwerk#29), the Zitadel Action hook and the
// outbox relay.
//
//	identity              run the service
//	identity healthcheck  exit 0 when /readyz answers 200 (container health check)
//
// Environment:
//
//	SYNTHWERK_PLATFORM_ENV               local (default), ci, dev, stg, prd
//	SYNTHWERK_IDENTITY_HTTP_ADDR         listen address, default :8080
//	SYNTHWERK_IDENTITY_DATABASE_URL      Postgres URL (required, secret)
//	SYNTHWERK_IDENTITY_HOOKS_ADDR        Zitadel Action listener, default :8081 (network zitadel-hooks only)
//	SYNTHWERK_IDENTITY_ZITADEL_SIGNING_KEY_FILE  file with the Action target signing key (secret).
//	                                     Unset = no Action listener.
//	SYNTHWERK_IDENTITY_OIDC_ISSUER        token issuer, for example http://auth.localhost:8080. Unset = no org routes.
//	SYNTHWERK_IDENTITY_OIDC_AUDIENCE     accepted audiences, comma-separated, default synthwerk-api
//	SYNTHWERK_IDENTITY_JWKS_URL          key set URL. Unset = from the issuer discovery document.
//	SYNTHWERK_IDENTITY_PLATFORM_ORG_ID   Zitadel org that grants operator. Unset = nobody is operator.
//	SYNTHWERK_IDENTITY_NATS_URL          NATS with credentials (secret). Unset = no relay; events stay in the outbox.
//	SYNTHWERK_IDENTITY_ZITADEL_API_URL   Zitadel API inside the stack, for example http://zitadel:8080.
//	SYNTHWERK_IDENTITY_ZITADEL_HOST      instance host Zitadel expects, for example auth.localhost:8080.
//	SYNTHWERK_IDENTITY_ZITADEL_PAT_FILE  file with the PAT of the machine user that manages user grants (secret).
//	                                     Unset (or no API URL) = role changes stay in identity, Zitadel is not written.
//	SYNTHWERK_IDENTITY_ZITADEL_PROJECT_ID  project synthwerk-api; grants of other projects are dropped.
//	SYNTHWERK_IDENTITY_LOG_LEVEL         DEBUG, INFO (default), WARN, ERROR
//	SYNTHWERK_IDENTITY_LOG_FORMAT        json (default) or console (local only)
//	OTEL_EXPORTER_OTLP_ENDPOINT          collector (gRPC), for example http://telemetry:4317. Unset = no export.
//
// Build with the release data:
//
//	go build -ldflags "-X main.version=0.1.0 -X main.commit=$(git rev-parse HEAD)" ./cmd/identity
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"golang.org/x/sync/errgroup"

	"github.com/VelimirMueller/synthwerk-contracts/go/kit/auth"
	"github.com/VelimirMueller/synthwerk-contracts/go/kit/cloudevents"
	"github.com/VelimirMueller/synthwerk-contracts/go/kit/env"
	kitlog "github.com/VelimirMueller/synthwerk-contracts/go/kit/log"
	kitotel "github.com/VelimirMueller/synthwerk-contracts/go/kit/otel"
	"github.com/VelimirMueller/synthwerk-contracts/go/kit/outbox"

	"github.com/VelimirMueller/synthwerk-identity/internal/app"
	"github.com/VelimirMueller/synthwerk-identity/internal/orgs"
	"github.com/VelimirMueller/synthwerk-identity/internal/zitadel"
	"github.com/VelimirMueller/synthwerk-identity/internal/zitadelhook"
)

// Set by -ldflags at build time.
var (
	version = "0.1.0-dev"
	commit  = "0000000"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		if err := healthcheck(env.Get(app.Service, "HTTP_ADDR", ":8080")); err != nil {
			fmt.Fprintln(os.Stderr, "healthcheck:", err)
			os.Exit(1)
		}
		return
	}
	if err := start(); err != nil {
		slog.Error("service stopped", slog.String("event.name", "service.failed"), slog.String("exception.message", err.Error()))
		os.Exit(1)
	}
}

func start() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return run(ctx)
}

func run(ctx context.Context) error {
	// 1. Logger without the OTel bridge, for the setup lines.
	logOpts, err := kitlog.OptionsFromEnv(app.Service, version)
	if err != nil {
		return err
	}
	logger, err := kitlog.New(logOpts)
	if err != nil {
		return err
	}
	slog.SetDefault(logger)

	// 2. Telemetry, then the final logger that also writes to OTLP.
	tel, err := kitotel.Setup(ctx, kitotel.Config{ServiceName: logOpts.ServiceName, Version: version, Env: logOpts.Env}, logger)
	if err != nil {
		return err
	}
	defer func() {
		sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = tel.Shutdown(sctx)
	}()
	logOpts.LoggerProvider = tel.LoggerProvider
	if logger, err = kitlog.New(logOpts); err != nil {
		return err
	}
	slog.SetDefault(logger)

	// 3. Dependencies.
	dbURL := env.Get(app.Service, "DATABASE_URL", "")
	if dbURL == "" {
		return errors.New(env.Key(app.Service, "DATABASE_URL") + " is not set")
	}
	poolCfg, err := pgxpool.ParseConfig(dbURL)
	if err != nil {
		return errors.New("database url does not parse") // the error text may hold the password
	}
	// The kit outbox uses the unqualified table name; it must resolve to identity.synthwerk_outbox.
	poolCfg.ConnConfig.RuntimeParams["search_path"] = "identity"
	db, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		return errors.New("database pool does not start")
	}
	defer db.Close()

	source, err := cloudevents.Source(app.Service, logOpts.Env)
	if err != nil {
		return err
	}
	zc := zitadelClient()
	store := &orgs.Store{DB: db, Source: source}
	if zc != nil {
		store.Grants = zc
	} else {
		logger.WarnContext(ctx, "zitadel client off: role changes stay in identity", slog.String("event.name", "zitadel.client_off"))
	}
	appCfg := app.Config{Version: version, Commit: commit, Env: logOpts.Env}
	if issuer := env.Get(app.Service, "OIDC_ISSUER", ""); issuer != "" {
		v, err := auth.NewVerifier(auth.Config{
			Issuer:    issuer,
			Audiences: splitList(env.Get(app.Service, "OIDC_AUDIENCE", "synthwerk-api")),
			JWKSURL:   env.Get(app.Service, "JWKS_URL", ""),
			Mapper:    auth.ZitadelMapper{PlatformOrgID: env.Get(app.Service, "PLATFORM_ORG_ID", "")},
		})
		if err != nil {
			return err
		}
		appCfg.Verifier = v
		appCfg.Orgs = &orgs.Handler{Repo: store, Log: logger}
	} else {
		logger.WarnContext(ctx, "no token issuer: org routes off", slog.String("event.name", "orgs.off"))
	}

	// Outbox relay to EVT_IDENTITY, when NATS is set.
	var relay *outbox.Relay
	if natsURL := env.Get(app.Service, "NATS_URL", ""); natsURL != "" {
		nc, err := nats.Connect(natsURL, nats.Name("synthwerk-"+app.Service), nats.MaxReconnects(-1))
		if err != nil {
			return errors.New("nats does not connect") // the error text may hold credentials
		}
		defer nc.Close()
		js, err := jetstream.New(nc)
		if err != nil {
			return fmt.Errorf("jetstream: %w", err)
		}
		if err := app.EnsureStream(ctx, js); err != nil {
			return err
		}
		if relay, err = outbox.NewRelay(db, js, logger, outbox.Config{}); err != nil {
			return err
		}
		appCfg.NATS = func(context.Context) error {
			if !nc.IsConnected() {
				return errors.New("nats not connected")
			}
			return nil
		}
	}

	// 4. App and migrations. /readyz answers 503 until here.
	a, err := app.New(db, logger, appCfg)
	if err != nil {
		return err
	}
	if err := app.Migrate(ctx, db); err != nil {
		return err
	}

	// 5. HTTP server.
	srv := &http.Server{
		Addr:              env.Get(app.Service, "HTTP_ADDR", ":8080"),
		Handler:           a.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}
	a.Health.MarkStarted()
	logger.InfoContext(ctx, "service started",
		slog.String("event.name", "service.started"),
		slog.String("server.address", srv.Addr))

	servers := []*http.Server{srv}
	if hooks := hookServer(db, store, zc, logger, source); hooks != nil {
		servers = append(servers, hooks)
		logger.InfoContext(ctx, "zitadel hook listening",
			slog.String("event.name", "zitadel_hook.started"),
			slog.String("server.address", hooks.Addr))
	}

	g, gctx := errgroup.WithContext(ctx)
	if relay != nil {
		g.Go(func() error { return relay.Run(gctx) })
	}
	for _, s := range servers {
		g.Go(func() error {
			if err := s.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				return err
			}
			return nil
		})
		g.Go(func() error {
			<-gctx.Done()
			sctx, cancel := context.WithTimeout(context.WithoutCancel(gctx), 10*time.Second)
			defer cancel()
			return s.Shutdown(sctx)
		})
	}
	return g.Wait()
}

// hookServer is the Zitadel Action listener on its own address, or nil when no
// signing key file is set. It serves only zitadelhook.Path.
func hookServer(db *pgxpool.Pool, store *orgs.Store, zc *zitadel.Client, logger *slog.Logger, source string) *http.Server {
	keyFile := env.Get(app.Service, "ZITADEL_SIGNING_KEY_FILE", "")
	if keyFile == "" {
		return nil
	}
	h := &zitadelhook.Handler{
		Grants:    store,
		ProjectID: env.Get(app.Service, "ZITADEL_PROJECT_ID", ""),
		Store:     zitadelhook.Postgres{DB: db},
		SigningKey: func() (string, error) {
			b, err := os.ReadFile(keyFile) //nolint:gosec // G304: path from our own config
			if err != nil {
				return "", err
			}
			return strings.TrimSpace(string(b)), nil
		},
		Source: source,
		Log:    logger,
		Now:    time.Now,
	}
	if zc != nil {
		h.OrgName = zc.OrgName
		h.PlatformOrg = zc.PlatformOrg
	}
	mux := http.NewServeMux()
	mux.Handle(zitadelhook.Path, h)
	return &http.Server{
		Addr:              env.Get(app.Service, "HOOKS_ADDR", ":8081"),
		Handler:           kitlog.HTTP(logger, mux),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}
}

// zitadelClient is the Zitadel API client, or nil when the API URL or PAT file is unset.
func zitadelClient() *zitadel.Client {
	apiURL := env.Get(app.Service, "ZITADEL_API_URL", "")
	patFile := env.Get(app.Service, "ZITADEL_PAT_FILE", "")
	if apiURL == "" || patFile == "" {
		return nil
	}
	return &zitadel.Client{
		BaseURL:   apiURL,
		Host:      env.Get(app.Service, "ZITADEL_HOST", ""),
		ProjectID: env.Get(app.Service, "ZITADEL_PROJECT_ID", ""),
		Token: func() (string, error) {
			b, err := os.ReadFile(patFile) //nolint:gosec // G304: path from our own config
			if err != nil {
				return "", err
			}
			return strings.TrimSpace(string(b)), nil
		},
	}
}

func splitList(v string) []string {
	var out []string
	for _, s := range strings.Split(v, ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func healthcheck(addr string) error {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("address %q: %w", addr, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	url := "http://" + net.JoinHostPort("127.0.0.1", port) + "/readyz"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	_ = res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("readyz: status %d", res.StatusCode)
	}
	return nil
}
