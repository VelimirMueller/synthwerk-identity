// Package orgs holds orgs, their members and the org roles (synthwerk#29).
//
// An org is a Zitadel org. Zitadel holds the user grants; identity keeps a mirror in
// identity.memberships for the last-owner rule, fast checks and the events. The org
// roles are owner, admin and member. operator is a platform role: it comes only from
// the token and is never a membership.
//
// Check order of every org route: token (auth.Middleware) → org from the path → role
// from the token (first gate) → stored membership (wins over a stale token) → rule.
package orgs

import (
	"errors"

	"github.com/VelimirMueller/synthwerk-contracts/go/kit/auth"
)

// Role is an org role.
type Role string

// Org roles, highest first.
const (
	Owner  Role = auth.RoleOwner
	Admin  Role = auth.RoleAdmin
	Member Role = auth.RoleMember
)

// rank orders the org roles. 0 = not an org role.
func (r Role) rank() int {
	switch r {
	case Owner:
		return 3
	case Admin:
		return 2
	case Member:
		return 1
	}
	return 0
}

// Valid reports whether r is an org role. operator is not.
func (r Role) Valid() bool { return r.rank() > 0 }

// AtLeast reports whether r is floor or higher. An invalid role is never enough.
func (r Role) AtLeast(floor Role) bool { return r.Valid() && r.rank() >= floor.rank() }

// Highest returns the highest org role in keys, or "" when keys hold none. Other
// keys (operator, end_user) are skipped.
func Highest(keys []string) Role {
	var best Role
	for _, k := range keys {
		if r := Role(k); r.rank() > best.rank() {
			best = r
		}
	}
	return best
}

// TokenRole is the highest org role of the token in its own org.
func TokenRole(p *auth.Principal) Role { return Highest(p.Roles) }

// Refusals of a role change.
var (
	// ErrForbidden: the role of the caller does not allow the change (403).
	ErrForbidden = errors.New("orgs: forbidden")
	// ErrOwnRole: the caller tried to change their own role (409 own_role).
	ErrOwnRole = errors.New("orgs: own role")
	// ErrLastOwner: the org would lose its last owner (409 last_owner).
	ErrLastOwner = errors.New("orgs: last owner")
	// ErrNotFound: unknown org or member, or no access to the org (404).
	ErrNotFound = errors.New("orgs: not found")
	// ErrUpstream: Zitadel did not take the change; nothing changed (502).
	ErrUpstream = errors.New("orgs: zitadel did not take the change")
	// ErrNotReady: identity does not know the Zitadel project id yet; the Zitadel
	// setup (zitadel-bootstrap) has not finished. Nothing changed (503, retry).
	ErrNotReady = errors.New("orgs: zitadel project id not known yet")
)

// Authorize applies the rule table of spec #29 to a role change. actor is the
// stored role of the caller, target the stored role of the member, to the new role.
// self is true when the caller changes their own row. The last-owner rule needs the
// owner count and is checked by the store.
func Authorize(actor, target, to Role, self bool) error {
	if !actor.AtLeast(Admin) || !target.Valid() || !to.Valid() {
		return ErrForbidden
	}
	if self {
		return ErrOwnRole
	}
	if (target == Owner || to == Owner) && actor != Owner {
		return ErrForbidden
	}
	return nil
}
