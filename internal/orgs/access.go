package orgs

import (
	"net/http"

	"github.com/VelimirMueller/synthwerk-contracts/go/kit/auth"
)

// Access is the result of the org gate, for routes of other packages under
// /v1/orgs/{orgId} (apps, synthwerk#30).
type Access struct {
	Principal *auth.Principal
	Org       Org
	// Own: the token acts in this org and has an org role in it. Else the caller is
	// an operator (read only).
	Own bool
}

// Gate resolves the org of the path value orgId with the same rules as the org
// routes: unknown, pending or foreign org → 404; operator passes with Own false.
// It writes the refusal and returns false.
func (h *Handler) Gate(w http.ResponseWriter, r *http.Request) (Access, bool) {
	a, ok := h.gate(w, r)
	return Access{Principal: a.p, Org: a.org, Own: a.own}, ok
}

// WriteProblem writes an RFC 9457 body with the problem codes of openapi/identity.
func WriteProblem(w http.ResponseWriter, r *http.Request, status int, code, detail string) {
	writeProblem(w, r, status, code, detail)
}

// Fail logs err and answers 500 internal_error.
func (h *Handler) Fail(w http.ResponseWriter, r *http.Request, err error) { h.fail(w, r, err) }

// Problem codes for routes of other packages.
const (
	CodeInvalidRequest   = codeInvalidRequest
	CodeNotFound         = codeNotFound
	CodeOriginNotAllowed = codeOriginNotAllowed
)
