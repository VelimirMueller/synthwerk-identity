//go:build integration

package audit_test

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/VelimirMueller/synthwerk-contracts/go/kit/auth"
	"github.com/VelimirMueller/synthwerk-contracts/go/kit/auth/authtest"

	"github.com/VelimirMueller/synthwerk-identity/internal/app"
	"github.com/VelimirMueller/synthwerk-identity/internal/audit"
	"github.com/VelimirMueller/synthwerk-identity/internal/entitlements"
	"github.com/VelimirMueller/synthwerk-identity/internal/orgs"
)

// toolEvent is an admin AI tool call of org by admin, as the llm relay publishes it.
func toolEvent(t *testing.T, org, conversation, outcome string, durationMS int) (id string, raw []byte) {
	t.Helper()
	id = uuid.Must(uuid.NewV7()).String()
	ev := map[string]any{
		"specversion": "1.0", "id": id, "source": "/synthwerk/llm/dev",
		"type": audit.ToolCallEventType, "subject": conversation, "orgid": org,
		"time": time.Now().UTC().Format(time.RFC3339Nano), "datacontenttype": "application/json",
		"dataschema": "https://schemas.synthwerk.dev/events/llm/toolcall.executed.v3.json",
		"actor":      "user:" + admin,
		"data": map[string]any{
			"tool": "llm_get_org_usage", "scope": "org", "org_id": org, "conversation_id": conversation,
			"outcome": outcome, "duration_ms": durationMS,
		},
	}
	b, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	return id, b
}

// toolCallsHandled waits until the tool call consumer acked or terminated every
// message up to stream sequence n.
func toolCallsHandled(t *testing.T, js jetstream.JetStream, n uint64) {
	t.Helper()
	waitFor(t, fmt.Sprintf("tool call events up to seq %d handled", n), func() bool {
		c, err := js.Consumer(t.Context(), audit.LLMStreamName, audit.ToolCallsDurable)
		if err != nil {
			return false
		}
		info, err := c.Info(t.Context())
		return err == nil && info.AckFloor.Stream == n && info.NumAckPending == 0 && info.NumPending == 0
	})
}

// Consumer - admin AI tool calls on EVT_LLM - each call is the newest audit event
// with actor, conversation and outcome; a repeat, a malformed event, an unknown org
// and an ai_settings event add no tool call row (synthwerk#53).
func TestToolCallsConsumerEndToEnd(t *testing.T) {
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
	_ = js.DeleteStream(t.Context(), audit.LLMStreamName) // from an earlier test
	// llm creates its stream.
	if _, err := js.CreateStream(t.Context(), jetstream.StreamConfig{Name: audit.LLMStreamName, Subjects: []string{"evt.llm.>"}}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = js.DeleteStream(context.Background(), audit.LLMStreamName) })

	var logs logBuf
	c := audit.NewToolCallConsumer(js, &audit.Writer{DB: db}, slog.New(slog.NewJSONHandler(&logs, nil)),
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
	waitFor(t, "the consumer to attach", func() bool { return c.Ready(t.Context()) == nil })

	publish := func(subject string, b []byte) {
		t.Helper()
		if _, err := js.Publish(t.Context(), subject, b); err != nil {
			t.Fatal(err)
		}
	}
	rows := func() int {
		return count(t, db, `SELECT count(*) FROM audit_events WHERE type = $1`, audit.ToolCallEventType)
	}

	conv := uuid.Must(uuid.NewV7()).String()
	okID, ok := toolEvent(t, org.ID, conv, "ok", 12)
	deniedID, denied := toolEvent(t, org.ID, conv, "denied", 1)

	t.Run("Consumer - an allowed and a refused admin tool call - both in the audit list, newest first", func(t *testing.T) {
		publish(audit.ToolCallSubject, ok)
		publish(audit.ToolCallSubject, denied)
		toolCallsHandled(t, js, 2)
		page := list(t, url+"?limit=2", ownerTok)
		if len(page.Items) != 2 || page.Items[0].Id.String() != deniedID || page.Items[1].Id.String() != okID {
			t.Fatalf("%+v", page)
		}
		e := page.Items[1]
		if e.Type != audit.ToolCallEventType || e.Actor != "user:"+admin || e.Subject == nil || *e.Subject != conv ||
			e.Data["tool"] != "llm_get_org_usage" || e.Data["outcome"] != "ok" || e.Data["org_id"] != org.ID || e.Data["scope"] != "org" {
			t.Fatalf("got %+v", e)
		}
		if page.Items[0].Data["outcome"] != "denied" {
			t.Fatalf("got %+v", page.Items[0])
		}
	})
	t.Run("Consumer - repeat, malformed, unknown org, other llm subject - no new row, nothing pending", func(t *testing.T) {
		_, bad := toolEvent(t, org.ID, conv, "ok", 600001)
		unknownID, unknown := toolEvent(t, uuid.Must(uuid.NewV7()).String(), conv, "ok", 3)
		publish(audit.ToolCallSubject, ok)
		publish(audit.ToolCallSubject, bad)
		publish(audit.ToolCallSubject, unknown)
		// The ai_settings durable reads this one; the tool call consumer never sees it.
		_, settings := aiEvent(t, org.ID, 1, 2000)
		publish(audit.AISettingsSubject, settings)
		publish(audit.ToolCallSubject, denied) // repeat; seq 7 moves the ack floor past seq 6
		toolCallsHandled(t, js, 7)
		if n := rows(); n != 2 {
			t.Fatalf("%d tool call rows, want 2", n)
		}
		if n := count(t, db, `SELECT count(*) FROM audit_events WHERE id = $1`, unknownID); n != 0 {
			t.Fatal("row of an unknown org")
		}
		if n := count(t, db, `SELECT count(*) FROM audit_events WHERE type = $1`, audit.AISettingsEventType); n != 0 {
			t.Fatal("the tool call consumer recorded an ai_settings event")
		}
		l := logs.String()
		if !strings.Contains(l, `"identity.audit.toolcall_rejected"`) || !strings.Contains(l, `"identity.audit.toolcall_unknown_org"`) {
			t.Fatalf("logs: %s", l)
		}
	})
	if strings.Contains(logs.String(), admin) {
		t.Fatal("the user sub is in the logs")
	}
}
