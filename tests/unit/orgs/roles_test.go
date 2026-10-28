package orgs_test

import (
	"errors"
	"testing"

	"github.com/VelimirMueller/synthwerk-contracts/go/kit/auth"

	"github.com/VelimirMueller/synthwerk-identity/internal/orgs"
)

func TestAuthorize(t *testing.T) {
	o, a, m := orgs.Owner, orgs.Admin, orgs.Member
	for _, tc := range []struct {
		name              string
		actor, target, to orgs.Role
		self              bool
		want              error
	}{
		{"Authorize - member changes role - denied", m, m, a, false, orgs.ErrForbidden},
		{"Authorize - member changes own role - denied", m, m, a, true, orgs.ErrForbidden},
		{"Authorize - admin sets admin on a member - allowed", a, m, a, false, nil},
		{"Authorize - admin sets member on an admin - allowed", a, a, m, false, nil},
		{"Authorize - admin grants owner - denied", a, m, o, false, orgs.ErrForbidden},
		{"Authorize - admin changes an owner - denied", a, o, a, false, orgs.ErrForbidden},
		{"Authorize - owner grants owner - allowed", o, a, o, false, nil},
		{"Authorize - owner demotes another owner - allowed", o, o, a, false, nil},
		{"Authorize - owner demotes self as last owner - conflict", o, o, a, true, orgs.ErrOwnRole},
		{"Authorize - admin changes own role - conflict", a, a, m, true, orgs.ErrOwnRole},
		{"Authorize - operator as actor - denied", orgs.Role(auth.RoleOperator), m, a, false, orgs.ErrForbidden},
		{"Authorize - operator as new role - denied", o, m, orgs.Role(auth.RoleOperator), false, orgs.ErrForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := orgs.Authorize(tc.actor, tc.target, tc.to, tc.self); !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

func TestRoles(t *testing.T) {
	t.Run("Claims - roles claim with several roles - highest role wins", func(t *testing.T) {
		if got := orgs.Highest([]string{"member", "end_user", "owner", "admin"}); got != orgs.Owner {
			t.Fatalf("got %q", got)
		}
	})
	t.Run("Operator - is_operator - never an org role", func(t *testing.T) {
		if orgs.Role(auth.RoleOperator).Valid() || orgs.Highest([]string{"operator", "end_user"}) != "" {
			t.Fatal("operator counts as an org role")
		}
		p := &auth.Principal{Roles: []string{"operator"}}
		if !p.IsOperator() || orgs.TokenRole(p).Valid() {
			t.Fatal("operator token has an org role")
		}
	})
	t.Run("AtLeast - invalid role - never enough", func(t *testing.T) {
		if orgs.Role("").AtLeast(orgs.Member) || !orgs.Admin.AtLeast(orgs.Admin) || orgs.Member.AtLeast(orgs.Admin) {
			t.Fatal("AtLeast")
		}
	})
	t.Run("Slug - names - URL-safe slugs", func(t *testing.T) {
		for in, want := range map[string]string{"Acme Labs": "acme-labs", "demo": "demo", "42 Things!": "o-42-things", "": "o-", "x": "x-o"} {
			if got := orgs.Slug(in); got != want {
				t.Fatalf("Slug(%q) = %q, want %q", in, got, want)
			}
		}
	})
}
