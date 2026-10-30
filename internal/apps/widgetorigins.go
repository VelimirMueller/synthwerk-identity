package apps

import (
	"net/http"

	"github.com/VelimirMueller/synthwerk-identity/internal/orgs"
)

// WidgetOriginsPath is the internal route that tells whether an origin is in the
// allow-list of any app of an active org. llm asks it before it answers CORS for
// the widget chat routes (infra#21). The answer is yes or no only: no app, no org.
const WidgetOriginsPath = "/internal/v1/widget-origins"

// widgetOrigin answers GET /internal/v1/widget-origins?origin=<origin>: 204 when
// an app of an active org lists the canonical origin, 404 when none does, 400 for
// a missing, repeated or invalid origin. Every answer sends Cache-Control: no-store.
func (h *Handler) widgetOrigin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	values := r.URL.Query()["origin"]
	if len(values) != 1 {
		orgs.WriteProblem(w, r, http.StatusBadRequest, orgs.CodeInvalidRequest, "Send exactly one origin query parameter.")
		return
	}
	origin, err := CanonicalOrigin(values[0])
	if err != nil {
		orgs.WriteProblem(w, r, http.StatusBadRequest, orgs.CodeInvalidRequest, "origin is not a valid origin. Use scheme://host[:port]; http only for localhost.")
		return
	}
	listed, err := h.Repo.OriginListed(r.Context(), origin)
	if err != nil {
		h.Orgs.Fail(w, r, err)
		return
	}
	if !listed {
		orgs.WriteProblem(w, r, http.StatusNotFound, orgs.CodeNotFound, "No app lists this origin.")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
