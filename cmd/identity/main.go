// Command identity serves synthwerk-identity: health probes, migrations, the org
// routes (orgs, members, roles; synthwerk#29), apps and widget tokens (synthwerk#30),
// the export and delete of the own account (synthwerk#41), the Zitadel Action hook,
// the outbox relay and the Zitadel user remover.
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
//	SYNTHWERK_IDENTITY_WIDGET_SIGNING_KEY_FILE  file with the ECDSA P-256 private key (PEM) that signs
//	                                     widget tokens (secret). Unset = no widget token route, no key set.
//	SYNTHWERK_IDENTITY_WIDGET_ISSUER     iss of widget tokens: the public URL of identity. Required with the key.
//	SYNTHWERK_IDENTITY_WIDGET_AUDIENCE   aud of widget tokens, comma-separated, default synthwerk-api
//	SYNTHWERK_IDENTITY_WIDGET_TOKEN_TTL  widget token lifetime, 1m to 15m, default 10m
//	SYNTHWERK_IDENTITY_NATS_URL          NATS with credentials (secret). Unset = no relay; events stay in the outbox.
//	SYNTHWERK_IDENTITY_ZITADEL_API_URL   Zitadel API inside the stack, for example http://zitadel:8080.
//	SYNTHWERK_IDENTITY_ZITADEL_HOST      instance host Zitadel expects, for example auth.localhost:8080.
//	SYNTHWERK_IDENTITY_ZITADEL_PAT_FILE  file with the PAT of the machine user that manages user grants (secret).
//	                                     Unset (or no API URL) = role changes stay in identity, Zitadel is not written.
//	SYNTHWERK_IDENTITY_ZITADEL_PROJECT_ID  project synthwerk-api; grants of other projects are dropped.
//	SYNTHWERK_IDENTITY_MFA_GATE_KEY_FILE      file with the signing key of the MFA gate target (secret).
//	                                     Set = the gate listens on the hook address; it needs the Zitadel client.
//	SYNTHWERK_IDENTITY_TOKEN_CLAIMS_KEY_FILE  file with the signing key of the pre-access-token target (secret).
//	SYNTHWERK_IDENTITY_MFA_EVIDENCE_MAX_AGE   how long a gated sign-in gives tokens amr, default 12h.
//	SYNTHWERK_IDENTITY_FREE_LLM_TOKENS_PER_USER_PER_DAY  free plan: LLM tokens per user per UTC day, default 50000, 0 = no limit
//	SYNTHWERK_IDENTITY_FREE_LLM_TOKENS_PER_ORG_PER_DAY   free plan: LLM tokens per org per UTC day, default 500000, 0 = no limit
//	SYNTHWERK_IDENTITY_FREE_APPS_PER_ORG                 free plan: apps per org, default 3, 0 = no limit
//	                                     A change moves every free org at the next start and emits org.entitlements_changed.
//	SYNTHWERK_IDENTITY_EXPORT_SOURCES    services asked for the own-data export, name=url comma list, for example
//	                                     llm=http://llm:8080. Unset = the export holds identity rows only.
//	SYNTHWERK_IDENTITY_ACCOUNT_DELETE_MFA_MAX_AGE  how old the newest sign-in with MFA may be for an
//	                                     account delete, default 15m.
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

	"github.com/VelimirMueller/synthwerk-identity/internal/account"
	"github.com/VelimirMueller/synthwerk-identity/internal/app"
	"github.com/VelimirMueller/synthwerk-identity/internal/apps"
	"github.com/VelimirMueller/synthwerk-identity/internal/entitlements"
	"github.com/VelimirMueller/synthwerk-identity/internal/mfagate"
	"github.com/VelimirMueller/synthwerk-identity/internal/orgs"
	"github.com/VelimirMueller/synthwerk-identity/internal/widget"
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
	free, err := entitlements.FreePlan(func(name string) string { return env.Get(app.Service, name, "") })
	if err != nil {
		return err
	}
	plans := &entitlements.Store{DB: db, Source: source, Default: free}
	store := &orgs.Store{DB: db, Source: source, Plans: plans}
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
		wi, err := widgetIssuer()
		if err != nil {
			return err
		}
		if wi == nil {
			logger.WarnContext(ctx, "no widget signing key: widget token route off", slog.String("event.name", "widget.off"))
		}
		appCfg.Apps = &apps.Handler{Repo: &apps.Store{DB: db, Source: source}, Orgs: appCfg.Orgs, Widget: wi, Log: logger}
		appCfg.Entitlements = &entitlements.Handler{Orgs: store, Repo: plans, Log: logger}
		if appCfg.Account, err = accountHandler(db, source, logger); err != nil {
			return err
		}
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
	// Every active org has a plan with the configured limits before the first request.
	rec, err := plans.Reconcile(ctx)
	if err != nil {
		return err
	}
	logger.InfoContext(ctx, "entitlements reconciled", slog.String("event.name", "entitlements.reconciled"),
		slog.Int("assigned", rec.Assigned), slog.Int("updated", rec.Updated),
		slog.Int64("free.llm_tokens_per_user_per_day", free.Limits.LLMTokensPerUserPerDay),
		slog.Int64("free.llm_tokens_per_org_per_day", free.Limits.LLMTokensPerOrgPerDay),
		slog.Int("free.apps_per_org", int(free.Limits.AppsPerOrg)))

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
	hooks, err := hookServer(db, store, zc, logger, source)
	if err != nil {
		return err
	}
	if hooks != nil {
		servers = append(servers, hooks)
		logger.InfoContext(ctx, "zitadel hook listening",
			slog.String("event.name", "zitadel_hook.started"),
			slog.String("server.address", hooks.Addr))
	}

	g, gctx := errgroup.WithContext(ctx)
	if relay != nil {
		g.Go(func() error { return relay.Run(gctx) })
	}
	if zc != nil {
		rm := &account.Remover{DB: db, Users: zc, Log: logger}
		g.Go(func() error { return rm.Run(gctx) })
	} else {
		logger.WarnContext(ctx, "zitadel client off: deleted accounts keep their Zitadel user", slog.String("event.name", "account.remover_off"))
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
// signing key file is set. It serves zitadelhook.Path and, when their key files are
// set, the MFA gate and the token claims (synthwerk#94).
func hookServer(db *pgxpool.Pool, store *orgs.Store, zc *zitadel.Client, logger *slog.Logger, source string) (*http.Server, error) {
	keyFile := env.Get(app.Service, "ZITADEL_SIGNING_KEY_FILE", "")
	if keyFile == "" {
		for _, k := range []string{"MFA_GATE_KEY_FILE", "TOKEN_CLAIMS_KEY_FILE"} {
			if env.Get(app.Service, k, "") != "" {
				return nil, errors.New(env.Key(app.Service, k) + " needs the hook listener (ZITADEL_SIGNING_KEY_FILE)")
			}
		}
		return nil, nil
	}
	h := &zitadelhook.Handler{
		Grants:     store,
		ProjectID:  env.Get(app.Service, "ZITADEL_PROJECT_ID", ""),
		Store:      zitadelhook.Postgres{DB: db},
		SigningKey: readKey(keyFile),
		Source:     source,
		Log:        logger,
		Now:        time.Now,
	}
	if zc != nil {
		h.OrgName = zc.OrgName
		h.PlatformOrg = zc.PlatformOrg
	}
	mux := http.NewServeMux()
	mux.Handle(zitadelhook.Path, h)
	if err := mfaRoutes(mux, db, zc, logger); err != nil {
		return nil, err
	}
	return &http.Server{
		Addr:              env.Get(app.Service, "HOOKS_ADDR", ":8081"),
		Handler:           kitlog.HTTP(logger, mux),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}, nil
}

// mfaRoutes adds the MFA gate and the token claims to the hook listener when their
// key files are set. The gate reads sessions with the Zitadel client: without it,
// identity does not start (a gate that cannot read sessions refuses every sign-in).
func mfaRoutes(mux *http.ServeMux, db *pgxpool.Pool, zc *zitadel.Client, logger *slog.Logger) error {
	evidence := mfagate.Postgres{DB: db}
	if f := env.Get(app.Service, "MFA_GATE_KEY_FILE", ""); f != "" {
		if zc == nil {
			return errors.New(env.Key(app.Service, "MFA_GATE_KEY_FILE") + " needs the Zitadel client (ZITADEL_API_URL and ZITADEL_PAT_FILE)")
		}
		mux.Handle(mfagate.GatePath, &mfagate.Gate{Sessions: zc, Store: evidence, SigningKey: readKey(f), Log: logger, Now: time.Now})
	}
	if f := env.Get(app.Service, "TOKEN_CLAIMS_KEY_FILE", ""); f != "" {
		maxAge := mfagate.DefaultMaxAge
		if v := env.Get(app.Service, "MFA_EVIDENCE_MAX_AGE", ""); v != "" {
			d, err := time.ParseDuration(v)
			if err != nil || d <= 0 {
				return fmt.Errorf("%s %q: want a positive duration", env.Key(app.Service, "MFA_EVIDENCE_MAX_AGE"), v)
			}
			maxAge = d
		}
		mux.Handle(mfagate.ClaimsPath, &mfagate.Claims{Store: evidence, SigningKey: readKey(f), Log: logger, Now: time.Now, MaxAge: maxAge})
	}
	return nil
}

// accountHandler serves the export and the delete of the own account (synthwerk#41).
func accountHandler(db *pgxpool.Pool, source string, logger *slog.Logger) (*account.Handler, error) {
	sources, err := account.ParseSources(env.Get(app.Service, "EXPORT_SOURCES", ""))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", env.Key(app.Service, "EXPORT_SOURCES"), err)
	}
	maxAge := account.DefaultMFAMaxAge
	if v := env.Get(app.Service, "ACCOUNT_DELETE_MFA_MAX_AGE", ""); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d <= 0 || d > mfagate.DefaultMaxAge {
			return nil, fmt.Errorf("%s %q: want a positive duration up to %s", env.Key(app.Service, "ACCOUNT_DELETE_MFA_MAX_AGE"), v, mfagate.DefaultMaxAge)
		}
		maxAge = d
	}
	return &account.Handler{
		Repo:      &account.Store{DB: db, Source: source},
		Evidence:  mfagate.Postgres{DB: db},
		Fetcher:   &account.Fetcher{Sources: sources},
		Log:       logger,
		Now:       time.Now,
		MFAMaxAge: maxAge,
	}, nil
}

// readKey returns a function that reads a target signing key per call, so a key
// written after the start works.
func readKey(path string) func() (string, error) {
	return func() (string, error) {
		b, err := os.ReadFile(path) //nolint:gosec // G304: path from our own config
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(b)), nil
	}
}

// widgetIssuer signs widget tokens, or is nil when no signing key file is set. The
// key is read once at start: a new key needs a restart.
func widgetIssuer() (*widget.Issuer, error) {
	keyFile := env.Get(app.Service, "WIDGET_SIGNING_KEY_FILE", "")
	if keyFile == "" {
		return nil, nil
	}
	b, err := os.ReadFile(keyFile) //nolint:gosec // G304: path from our own config
	if err != nil {
		return nil, fmt.Errorf("%s: %w", env.Key(app.Service, "WIDGET_SIGNING_KEY_FILE"), err)
	}
	key, err := widget.ParseKey(b)
	if err != nil {
		return nil, err
	}
	var ttl time.Duration
	if v := env.Get(app.Service, "WIDGET_TOKEN_TTL", ""); v != "" {
		if ttl, err = time.ParseDuration(v); err != nil {
			return nil, fmt.Errorf("%s: %w", env.Key(app.Service, "WIDGET_TOKEN_TTL"), err)
		}
	}
	return widget.NewIssuer(widget.Config{
		Issuer:    env.Get(app.Service, "WIDGET_ISSUER", ""),
		Audiences: splitList(env.Get(app.Service, "WIDGET_AUDIENCE", widget.DefaultAudience)),
		TTL:       ttl,
		Key:       key,
	})
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
