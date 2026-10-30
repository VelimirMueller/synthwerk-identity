//go:build integration

// Component tests of the studio page builder changes in the audit list
// (synthwerk#106): the EVT_STUDIO consumer against Postgres as a non-superuser role
// and NATS JetStream. Names follow "method - condition - outcome".
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

	"github.com/VelimirMueller/synthwerk-identity/internal/account"
	"github.com/VelimirMueller/synthwerk-identity/internal/app"
	"github.com/VelimirMueller/synthwerk-identity/internal/audit"
	"github.com/VelimirMueller/synthwerk-identity/internal/entitlements"
	"github.com/VelimirMueller/synthwerk-identity/internal/orgs"
)

// pageEvent is a studio page event of org by admin, as the studio relay publishes it.
// previous is nil for page.created.
func pageEvent(t *testing.T, verb, org, page string, version int, previous *int) (id string, raw []byte) {
	t.Helper()
	id = uuid.Must(uuid.NewV7()).String()
	data := map[string]any{"org_id": org, "page_id": page, "slug": "pricing", "locale": "de"}
	if verb != "created" {
		data["version"] = version
		data["previous_version"] = previous
	}
	ev := map[string]any{
		"specversion": "1.0", "id": id, "source": "/synthwerk/studio/dev",
		"type": "dev.synthwerk.studio.page." + verb + ".v1", "subject": page, "orgid": org,
		"time": time.Now().UTC().Format(time.RFC3339Nano), "datacontenttype": "application/json",
		"dataschema": "https://schemas.synthwerk.dev/events/studio/page." + verb + ".v1.json",
		"actor":      "user:" + admin,
		"data":       data,
	}
	b, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	return id, b
}

// studioHandled waits until the studio consumer acked or terminated n stream messages.
func studioHandled(t *testing.T, js jetstream.JetStream, n uint64) {
	t.Helper()
	waitFor(t, fmt.Sprintf("%d studio events handled", n), func() bool {
		c, err := js.Consumer(t.Context(), audit.StudioStreamName, audit.StudioPagesDurable)
		if err != nil {
			return false
		}
		info, err := c.Info(t.Context())
		return err == nil && info.AckFloor.Stream == n && info.NumAckPending == 0 && info.NumPending == 0
	})
}

// Consumer - EVT_STUDIO missing at start - waits and never creates it, attaches once
// studio creates it; create, publish and roll back are the newest audit events; a
// repeat, a malformed event, an unknown org and another studio subject add no row;
// after an account delete the rows and a late event show deleted-user.
func TestStudioPagesConsumerEndToEnd(t *testing.T) {
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
	_ = js.DeleteStream(t.Context(), audit.StudioStreamName) // from an earlier run

	var logs logBuf
	c := audit.NewStudioConsumer(js, &audit.Writer{DB: db}, slog.New(slog.NewJSONHandler(&logs, nil)),
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
		return strings.Contains(l, `"stream_missing"`) && strings.Contains(l, `"identity.audit.studio_waiting"`)
	})
	if _, err := js.Stream(t.Context(), audit.StudioStreamName); err == nil {
		t.Fatal("identity created EVT_STUDIO")
	}

	// studio creates its stream.
	if _, err := js.CreateStream(t.Context(), jetstream.StreamConfig{Name: audit.StudioStreamName, Subjects: []string{"evt.studio.>"}}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = js.DeleteStream(context.Background(), audit.StudioStreamName) })
	waitFor(t, "the consumer to attach", func() bool { return c.Ready(t.Context()) == nil })

	publish := func(verb string, b []byte) {
		t.Helper()
		if _, err := js.Publish(t.Context(), "evt.studio.page."+verb+".v1", b); err != nil {
			t.Fatal(err)
		}
	}
	rows := func() int {
		return count(t, db, `SELECT count(*) FROM audit_events WHERE type LIKE 'dev.synthwerk.studio.page.%'`)
	}

	page := uuid.NewString()
	one, two := 1, 2
	createdID, created := pageEvent(t, "created", org.ID, page, 0, nil)
	publishedID, published := pageEvent(t, "published", org.ID, page, 2, &one)
	rolledID, rolled := pageEvent(t, "rolled_back", org.ID, page, 1, &two)

	t.Run("Consumer - create, publish, roll back - newest events of the audit list in order", func(t *testing.T) {
		publish("created", created)
		publish("published", published)
		publish("rolled_back", rolled)
		studioHandled(t, js, 3)
		got := list(t, url+"?limit=3", ownerTok)
		if len(got.Items) != 3 || got.Items[0].Id.String() != rolledID || got.Items[1].Id.String() != publishedID || got.Items[2].Id.String() != createdID {
			t.Fatalf("%+v", got)
		}
		e := got.Items[0]
		if e.Type != audit.StudioPageRolledBackType || e.Actor != "user:"+admin || e.Subject == nil || *e.Subject != page ||
			e.Data["org_id"] != org.ID || e.Data["slug"] != "pricing" || e.Data["version"] != float64(1) || e.Data["previous_version"] != float64(2) {
			t.Fatalf("got %+v", e)
		}
	})
	t.Run("Consumer - repeat, malformed, unknown org, other subject - no new row, nothing pending", func(t *testing.T) {
		_, bad := pageEvent(t, "published", org.ID, page, 0, &one) // version 0
		unknownID, unknown := pageEvent(t, "published", uuid.Must(uuid.NewV7()).String(), page, 3, &two)
		publish("published", published)
		publish("published", bad)
		publish("published", unknown)
		// A later studio type the consumer does not read stays in the stream.
		if _, err := js.Publish(t.Context(), "evt.studio.page.deleted.v1", []byte(`{}`)); err != nil {
			t.Fatal(err)
		}
		studioHandled(t, js, 6)
		if n := rows(); n != 3 {
			t.Fatalf("%d studio rows, want 3", n)
		}
		if n := count(t, db, `SELECT count(*) FROM audit_events WHERE id = $1`, unknownID); n != 0 {
			t.Fatal("row of an unknown org")
		}
		l := logs.String()
		if !strings.Contains(l, `"identity.audit.studio_rejected"`) || !strings.Contains(l, `"identity.audit.studio_unknown_org"`) ||
			strings.Count(l, `"identity.audit.studio_recorded"`) != 4 {
			t.Fatalf("logs: %s", l)
		}
	})
	t.Run("Account delete - actor of the page events and of a late one - deleted-user", func(t *testing.T) {
		if _, err := (&account.Store{DB: db, Source: source}).Delete(t.Context(), admin); err != nil {
			t.Fatal(err)
		}
		lateID, late := pageEvent(t, "published", org.ID, page, 3, &one)
		publish("published", late)
		studioHandled(t, js, 8) // seq 7 is the deleted subject, never delivered
		got := list(t, url+"?limit=4", ownerTok)
		if len(got.Items) != 4 || got.Items[0].Id.String() != lateID {
			t.Fatalf("%+v", got)
		}
		for _, e := range got.Items {
			if e.Actor != "user:"+account.DeletedUser {
				t.Fatalf("actor %q", e.Actor)
			}
		}
	})
	if strings.Contains(logs.String(), admin) {
		t.Fatal("the user sub is in the logs")
	}
}
