//go:build integration

// Component tests of the llm AI settings changes in the audit list (synthwerk#39):
// the EVT_LLM consumer against Postgres as a non-superuser role and NATS JetStream.
// Names follow "method - condition - outcome".
package audit_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/VelimirMueller/synthwerk-contracts/go/identity"
	"github.com/VelimirMueller/synthwerk-contracts/go/kit/auth"
	"github.com/VelimirMueller/synthwerk-contracts/go/kit/auth/authtest"

	"github.com/VelimirMueller/synthwerk-identity/internal/account"
	"github.com/VelimirMueller/synthwerk-identity/internal/app"
	"github.com/VelimirMueller/synthwerk-identity/internal/audit"
	"github.com/VelimirMueller/synthwerk-identity/internal/entitlements"
	"github.com/VelimirMueller/synthwerk-identity/internal/orgs"
	"github.com/VelimirMueller/synthwerk-identity/tests/support/containers"
)

var env *containers.Env

func TestMain(m *testing.M) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	e, err := containers.Start(ctx)
	if err == nil {
		if err = e.StartNATS(ctx); err != nil {
			e.Stop()
		}
	}
	cancel()
	if err != nil {
		fmt.Fprintln(os.Stderr, "containers:", err)
		os.Exit(1)
	}
	env = e
	code := m.Run()
	e.Stop()
	os.Exit(code)
}

const (
	zorg   = "300000000000000001"
	owner  = "100000000000000001"
	admin  = "100000000000000002"
	source = "/synthwerk/identity/dev"
)

// logBuf is a log sink that the consumer goroutine and the test share.
type logBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *logBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *logBuf) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// aiEvent is an ai_settings.changed.v1 event of org by admin, as llm writes it.
func aiEvent(t *testing.T, org string, version, maxInput int) (id string, raw []byte) {
	t.Helper()
	id = uuid.Must(uuid.NewV7()).String()
	ev := map[string]any{
		"specversion": "1.0", "id": id, "source": "/synthwerk/llm/dev",
		"type": audit.AISettingsEventType, "subject": org, "orgid": org,
		"time": time.Now().UTC().Format(time.RFC3339Nano), "datacontenttype": "application/json",
		"dataschema": "https://schemas.synthwerk.dev/events/llm/ai_settings.changed.v1.json",
		"actor":      "user:" + admin,
		"data": map[string]any{
			"org_id": org, "version": version, "changed": []string{"max_input_chars", "system_prompt"},
			"model": "default", "allowed_models": []string{"default", "small"},
			"max_input_chars": maxInput, "user_tokens_per_day": 20000, "system_prompt_chars": 52, "temperature": 0.3,
		},
	}
	b, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	return id, b
}

func count(t *testing.T, db *pgxpool.Pool, sql string, args ...any) int {
	t.Helper()
	var n int
	if err := db.QueryRow(t.Context(), sql, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// handled waits until the consumer acked or terminated n stream messages.
func handled(t *testing.T, js jetstream.JetStream, n uint64) {
	t.Helper()
	waitFor(t, fmt.Sprintf("%d events handled", n), func() bool {
		c, err := js.Consumer(t.Context(), audit.LLMStreamName, audit.AISettingsDurable)
		if err != nil {
			return false
		}
		info, err := c.Info(t.Context())
		return err == nil && info.AckFloor.Stream == n && info.NumAckPending == 0 && info.NumPending == 0
	})
}

// list reads the audit list of org with tok.
func list(t *testing.T, url, tok string) identity.AuditEventPage {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	body, _ := io.ReadAll(res.Body)
	var page identity.AuditEventPage
	if res.StatusCode != http.StatusOK || json.Unmarshal(body, &page) != nil {
		t.Fatalf("audit list: %d %s", res.StatusCode, body)
	}
	return page
}

// Consumer - EVT_LLM missing at start - waits with WARN and never creates it, attaches
// once llm creates it; a change is the newest audit event; a repeat, a malformed
// event and an unknown org add no row and leave nothing pending; after an account
// delete the change and a late change show deleted-user.
func TestAISettingsConsumerEndToEnd(t *testing.T) {
	db := env.Database(t)
	if err := app.Migrate(t.Context(), db); err != nil {
		t.Fatal(err)
	}
	plans := &entitlements.Store{DB: db, Source: source, Default: entitlements.Plan{Name: entitlements.Free, Limits: entitlements.FreeDefaults}}
	st := &orgs.Store{DB: db, Source: source, Plans: plans}
	for i, g := range []struct{ sub, role string }{{owner, "owner"}, {admin, "admin"}} {
		if _, err := st.ApplyGrant(t.Context(), orgs.GrantChange{
			Key: fmt.Sprintf("i:usergrant:g-%s:%d", g.sub, i), ZitadelOrgID: zorg, GrantID: "g-" + g.sub, UserSub: g.sub, Roles: []string{g.role},
		}, "Acme Labs"); err != nil {
			t.Fatal(err)
		}
	}
	org, err := st.OrgByZitadelID(t.Context(), zorg)
	if err != nil {
		t.Fatal(err)
	}

	// The audit list over HTTP, as cmd/identity serves it.
	iss := authtest.NewIssuer(t)
	cfg := iss.Config()
	cfg.Mapper = auth.ZitadelMapper{}
	v, err := auth.NewVerifier(cfg)
	if err != nil {
		t.Fatal(err)
	}
	oh := &orgs.Handler{Repo: st, Members: st, Log: slog.New(slog.DiscardHandler)}
	a, err := app.New(db, slog.New(slog.DiscardHandler), app.Config{Version: "0.1.0-dev", Commit: "0000000", Env: "ci",
		Verifier: v, Orgs: oh, Audit: &audit.Handler{Repo: &audit.Store{DB: db}, Orgs: oh}})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(a.Handler())
	t.Cleanup(srv.Close)
	url := srv.URL + "/v1/orgs/" + org.ID + "/audit-events"
	ownerTok := iss.Mint(t, authtest.Claims(owner, zorg, "owner"))

	js, err := jetstream.New(env.NATS(t))
	if err != nil {
		t.Fatal(err)
	}
	_ = js.DeleteStream(t.Context(), audit.LLMStreamName) // from an earlier run

	var logs logBuf
	c := audit.NewConsumer(js, &audit.Writer{DB: db}, slog.New(slog.NewJSONHandler(&logs, nil)),
		audit.ConsumerConfig{RetryMin: 100 * time.Millisecond, RetryMax: 300 * time.Millisecond, AckWait: 10 * time.Second})
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- c.Run(ctx) }()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("run: %v", err)
		}
	}()

	waitFor(t, "a WARN about the missing stream", func() bool {
		l := logs.String()
		return strings.Contains(l, `"stream_missing"`) && strings.Contains(l, `"level":"WARN"`)
	})
	if c.Ready(t.Context()) == nil {
		t.Fatal("ready without the stream")
	}
	if _, err := js.Stream(t.Context(), audit.LLMStreamName); err == nil {
		t.Fatal("identity created EVT_LLM")
	}

	// llm creates its stream.
	if _, err := js.CreateStream(t.Context(), jetstream.StreamConfig{Name: audit.LLMStreamName, Subjects: []string{"evt.llm.>"}}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = js.DeleteStream(context.Background(), audit.LLMStreamName) })
	waitFor(t, "the consumer to attach", func() bool { return c.Ready(t.Context()) == nil })

	publish := func(b []byte) {
		t.Helper()
		if _, err := js.Publish(t.Context(), audit.AISettingsSubject, b); err != nil {
			t.Fatal(err)
		}
	}
	rows := func() int {
		return count(t, db, `SELECT count(*) FROM audit_events WHERE type = $1`, audit.AISettingsEventType)
	}

	goodID, good := aiEvent(t, org.ID, 3, 2000)
	_, bad := aiEvent(t, org.ID, 4, 9000) // max_input_chars above 8000
	unknownID, unknown := aiEvent(t, uuid.Must(uuid.NewV7()).String(), 1, 2000)

	t.Run("Consumer - valid change - newest event of the audit list with actor, subject and data", func(t *testing.T) {
		publish(good)
		handled(t, js, 1)
		page := list(t, url+"?limit=1", ownerTok)
		if len(page.Items) != 1 {
			t.Fatalf("%+v", page)
		}
		e := page.Items[0]
		if e.Id.String() != goodID || e.Type != audit.AISettingsEventType || e.Actor != "user:"+admin ||
			e.Subject == nil || *e.Subject != org.ID || e.Data["org_id"] != org.ID || e.Data["version"] != float64(3) ||
			e.Data["max_input_chars"] != float64(2000) || e.Data["system_prompt_chars"] != float64(52) {
			t.Fatalf("got %+v", e)
		}
	})
	t.Run("Consumer - repeat, malformed, unknown org - one row, nothing pending", func(t *testing.T) {
		publish(good)
		publish(bad)
		publish(unknown)
		handled(t, js, 4)
		if n := rows(); n != 1 {
			t.Fatalf("%d ai_settings rows, want 1", n)
		}
		if n := count(t, db, `SELECT count(*) FROM audit_events WHERE id = $1`, unknownID); n != 0 {
			t.Fatal("row of an unknown org")
		}
		l := logs.String()
		if !strings.Contains(l, `"identity.audit.llm_rejected"`) || !strings.Contains(l, `"identity.audit.llm_unknown_org"`) ||
			strings.Count(l, `"identity.audit.llm_recorded"`) != 2 {
			t.Fatalf("logs: %s", l)
		}
	})
	t.Run("Account delete - actor of a change and of a late change - deleted-user", func(t *testing.T) {
		if _, err := (&account.Store{DB: db, Source: source}).Delete(t.Context(), admin); err != nil {
			t.Fatal(err)
		}
		lateID, late := aiEvent(t, org.ID, 5, 1000)
		publish(late)
		handled(t, js, 5)
		page := list(t, url+"?limit=2", ownerTok)
		if len(page.Items) != 2 || page.Items[0].Id.String() != lateID || page.Items[1].Id.String() != goodID {
			t.Fatalf("%+v", page)
		}
		for _, e := range page.Items {
			if e.Actor != "user:"+account.DeletedUser {
				t.Fatalf("actor %q", e.Actor)
			}
		}
		if n := count(t, db, `SELECT count(*) FROM audit_events WHERE actor = $1`, "user:"+admin); n != 0 {
			t.Fatalf("%d rows still name the deleted user", n)
		}
	})
	if strings.Contains(logs.String(), admin) {
		t.Fatal("the user sub is in the logs")
	}
}

// Record and account Delete - run at the same time, 20 users - no row keeps the
// clear actor: the shared user lock orders them (security review, synthwerk#39).
func TestRecordRacesAccountDelete(t *testing.T) {
	db := env.Database(t)
	if err := app.Migrate(t.Context(), db); err != nil {
		t.Fatal(err)
	}
	plans := &entitlements.Store{DB: db, Source: source, Default: entitlements.Plan{Name: entitlements.Free, Limits: entitlements.FreeDefaults}}
	st := &orgs.Store{DB: db, Source: source, Plans: plans}
	grant := func(n int, sub, role string) {
		t.Helper()
		if _, err := st.ApplyGrant(t.Context(), orgs.GrantChange{
			Key: fmt.Sprintf("i:usergrant:g-%s:%d", sub, n), ZitadelOrgID: zorg, GrantID: "g-" + sub, UserSub: sub, Roles: []string{role},
		}, "Acme Labs"); err != nil {
			t.Fatal(err)
		}
	}
	grant(0, owner, "owner")
	org, err := st.OrgByZitadelID(t.Context(), zorg)
	if err != nil {
		t.Fatal(err)
	}
	w := &audit.Writer{DB: db}
	acc := &account.Store{DB: db, Source: source}
	for i := range 20 {
		sub := fmt.Sprintf("2000000000000000%02d", i)
		grant(i+1, sub, "admin")
		_, raw := aiEvent(t, org.ID, 1, 2000)
		ch, err := audit.ParseAISettings(raw)
		if err != nil {
			t.Fatal(err)
		}
		ch.Actor, ch.UserSub = "user:"+sub, sub
		var wg sync.WaitGroup
		var recErr, delErr error
		start := make(chan struct{})
		wg.Go(func() { <-start; _, recErr = w.Record(context.WithoutCancel(t.Context()), ch) })
		wg.Go(func() { <-start; _, delErr = acc.Delete(context.WithoutCancel(t.Context()), sub) })
		close(start)
		wg.Wait()
		if recErr != nil || delErr != nil {
			t.Fatalf("run %d: record %v, delete %v", i, recErr, delErr)
		}
		if n := count(t, db, `SELECT count(*) FROM audit_events WHERE actor = $1`, "user:"+sub); n != 0 {
			t.Fatalf("run %d: %d rows keep the clear actor", i, n)
		}
		if n := count(t, db, `SELECT count(*) FROM audit_events WHERE id = $1 AND actor = $2`, ch.ID, "user:"+account.DeletedUser); n != 1 {
			t.Fatalf("run %d: the change is not stored as deleted-user", i)
		}
	}
}
