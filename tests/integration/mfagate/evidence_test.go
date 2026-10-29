//go:build integration

package mfagate_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/VelimirMueller/synthwerk-identity/internal/app"
	"github.com/VelimirMueller/synthwerk-identity/internal/mfagate"
	"github.com/VelimirMueller/synthwerk-identity/tests/support/containers"
)

var env *containers.Env

func TestMain(m *testing.M) {
	e, err := containers.Start(context.Background())
	if err != nil {
		fmt.Fprintln(os.Stderr, "containers:", err)
		os.Exit(1)
	}
	env = e
	code := m.Run()
	e.Stop()
	os.Exit(code)
}

func TestEvidence(t *testing.T) {
	db := env.Database(t)
	if err := app.Migrate(t.Context(), db); err != nil {
		t.Fatal(err)
	}
	st := mfagate.Postgres{DB: db}
	t0 := time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)

	t.Run("Latest - no row - ErrNoEvidence", func(t *testing.T) {
		if _, err := st.Latest(t.Context(), "u-none"); !errors.Is(err, mfagate.ErrNoEvidence) {
			t.Fatalf("err %v", err)
		}
	})
	t.Run("Record twice - newer replaces older; an older check never replaces a newer one", func(t *testing.T) {
		ctx := t.Context()
		for _, e := range []mfagate.Evidence{
			{UserSub: "u-1", SessionID: "s-1", AMR: []string{"pwd", "otp", "mfa"}, CheckedAt: t0},
			{UserSub: "u-1", SessionID: "s-2", AMR: []string{"user", "mfa"}, CheckedAt: t0.Add(time.Minute)},
			{UserSub: "u-1", SessionID: "s-0", AMR: []string{"pwd", "otp", "mfa"}, CheckedAt: t0.Add(-time.Minute)},
		} {
			if err := st.Record(ctx, e); err != nil {
				t.Fatal(err)
			}
		}
		got, err := st.Latest(ctx, "u-1")
		if err != nil {
			t.Fatal(err)
		}
		if got.SessionID != "s-2" || !slices.Equal(got.AMR, []string{"user", "mfa"}) || !got.CheckedAt.Equal(t0.Add(time.Minute)) {
			t.Fatalf("evidence %+v", got)
		}
	})
}
