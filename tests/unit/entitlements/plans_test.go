package entitlements_test

import (
	"strings"
	"testing"

	"github.com/VelimirMueller/synthwerk-identity/internal/entitlements"
)

func lookup(m map[string]string) func(string) string {
	return func(name string) string { return m[name] }
}

func TestFreePlan(t *testing.T) {
	t.Run("FreePlan - nothing set - placeholder defaults", func(t *testing.T) {
		p, err := entitlements.FreePlan(lookup(nil))
		if err != nil {
			t.Fatal(err)
		}
		want := entitlements.Limits{LLMTokensPerUserPerDay: 50000, LLMTokensPerOrgPerDay: 500000, AppsPerOrg: 3}
		if p.Name != entitlements.Free || p.Limits != want {
			t.Fatalf("got %+v", p)
		}
	})

	t.Run("FreePlan - all set, 0 included - config wins", func(t *testing.T) {
		p, err := entitlements.FreePlan(lookup(map[string]string{
			entitlements.EnvUserTokens: "1000", entitlements.EnvOrgTokens: "0", entitlements.EnvApps: "10000",
		}))
		if err != nil {
			t.Fatal(err)
		}
		if p.Limits != (entitlements.Limits{LLMTokensPerUserPerDay: 1000, LLMTokensPerOrgPerDay: 0, AppsPerOrg: 10000}) {
			t.Fatalf("got %+v", p.Limits)
		}
	})

	for _, tc := range []struct{ name, key, val, want string }{
		{"negative user tokens", entitlements.EnvUserTokens, "-1", "per user"},
		{"negative org tokens", entitlements.EnvOrgTokens, "-5", "per org"},
		{"apps above the contract", entitlements.EnvApps, "10001", "apps per org"},
		{"negative apps", entitlements.EnvApps, "-1", "apps per org"},
		{"not a number", entitlements.EnvUserTokens, "50k", entitlements.EnvUserTokens},
		{"apps not an int32", entitlements.EnvApps, "99999999999", entitlements.EnvApps},
	} {
		t.Run("FreePlan - "+tc.name+" - error names the setting", func(t *testing.T) {
			_, err := entitlements.FreePlan(lookup(map[string]string{tc.key: tc.val}))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err %v, want it to name %q", err, tc.want)
			}
		})
	}
}
