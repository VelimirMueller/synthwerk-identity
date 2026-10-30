package apps

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/VelimirMueller/synthwerk-contracts/go/identity"
	"github.com/VelimirMueller/synthwerk-contracts/go/kit/auth"

	"github.com/VelimirMueller/synthwerk-identity/internal/orgs"
	"github.com/VelimirMueller/synthwerk-identity/internal/widget"
)

// Repo is the part of Store the handlers use.
type Repo interface {
	ByID(ctx context.Context, id string) (App, error)
	Get(ctx context.Context, orgID, id string) (App, error)
	List(ctx context.Context, orgID, after string, limit int) ([]App, error)
	Create(ctx context.Context, org orgs.Org, actorSub, name string, origins []string) (App, error)
	Update(ctx context.Context, org orgs.Org, actorSub, id string, c Change) (App, error)
	Delete(ctx context.Context, org orgs.Org, actorSub, id string) error
	OriginListed(ctx context.Context, origin string) (bool, error)
}

// Handler serves the app routes and the widget token route of openapi/identity.
type Handler struct {
	Repo Repo
	// Orgs gives the org gate and the org and membership lookups.
	Orgs *orgs.Handler
	// Widget signs widget tokens. Nil: the widget token route and the key set are off.
	Widget *widget.Issuer
	Log    *slog.Logger
}

// Page sizes of listApps and the body limit.
const (
	DefaultPageSize = 50
	MaxPageSize     = 100
	maxNameLen      = 128
	maxBody         = 16 << 10
	preflightMaxAge = "600"
)

// Register adds the routes to mux. authn must be auth.Middleware: every route but
// the CORS preflight and the key set needs a verified user token.
func (h *Handler) Register(mux *http.ServeMux, authn func(http.Handler) http.Handler) {
	mux.Handle("GET /v1/orgs/{orgId}/apps", authn(http.HandlerFunc(h.listApps)))
	mux.Handle("POST /v1/orgs/{orgId}/apps", authn(http.HandlerFunc(h.createApp)))
	mux.Handle("GET /v1/orgs/{orgId}/apps/{appId}", authn(http.HandlerFunc(h.getApp)))
	mux.Handle("PATCH /v1/orgs/{orgId}/apps/{appId}", authn(http.HandlerFunc(h.updateApp)))
	mux.Handle("DELETE /v1/orgs/{orgId}/apps/{appId}", authn(http.HandlerFunc(h.deleteApp)))
	// Public: a signed-out visitor's widget reads its look (synthwerk#38, widgets#34).
	mux.Handle("GET /v1/apps/{appId}/widget-settings", h.cors(http.HandlerFunc(h.getWidgetSettings)))
	mux.Handle("OPTIONS /v1/apps/{appId}/widget-settings", h.cors(preflight(http.MethodGet, "")))
	// Internal, no token: llm asks it for the CORS answer of the widget chat
	// routes (infra#21). The edge refuses /identity/internal/*.
	mux.HandleFunc("GET "+WidgetOriginsPath, h.widgetOrigin)
	if h.Widget != nil {
		mux.Handle("POST /v1/apps/{appId}/widget-tokens", h.cors(authn(http.HandlerFunc(h.createWidgetToken))))
		mux.Handle("OPTIONS /v1/apps/{appId}/widget-tokens", h.cors(preflight(http.MethodPost, "Authorization, Content-Type")))
		mux.Handle("GET "+widget.JWKSPath, h.Widget.JWKSHandler())
	}
}

func (h *Handler) listApps(w http.ResponseWriter, r *http.Request) {
	a, ok := h.Orgs.Gate(w, r)
	if !ok {
		return
	}
	limit, after, ok := pageParams(r)
	if !ok {
		orgs.WriteProblem(w, r, http.StatusBadRequest, orgs.CodeInvalidRequest, "limit must be 1 to 100; cursor must come from next_cursor.")
		return
	}
	list, err := h.Repo.List(r.Context(), a.Org.ID, after, limit+1)
	if err != nil {
		h.Orgs.Fail(w, r, err)
		return
	}
	page := identity.AppPage{Items: []identity.App{}}
	if len(list) > limit {
		list = list[:limit]
		next := base64.RawURLEncoding.EncodeToString([]byte(list[len(list)-1].ID))
		page.NextCursor = &next
	}
	for _, app := range list {
		page.Items = append(page.Items, appBody(app))
	}
	writeJSON(w, http.StatusOK, page)
}

func (h *Handler) getApp(w http.ResponseWriter, r *http.Request) {
	a, ok := h.Orgs.Gate(w, r)
	if !ok {
		return
	}
	app, err := h.Repo.Get(r.Context(), a.Org.ID, r.PathValue("appId"))
	if h.refusal(w, r, err) {
		return
	}
	writeJSON(w, http.StatusOK, appBody(app))
}

func (h *Handler) createApp(w http.ResponseWriter, r *http.Request) {
	a, ok := h.writer(w, r)
	if !ok {
		return
	}
	var body identity.CreateAppRequest
	if !decode(w, r, &body) {
		return
	}
	name, ok := validName(body.Name)
	if !ok {
		orgs.WriteProblem(w, r, http.StatusBadRequest, orgs.CodeInvalidRequest, "name must be 1 to 128 characters.")
		return
	}
	origins, ok := validOrigins(w, r, body.AllowedOrigins)
	if !ok {
		return
	}
	app, err := h.Repo.Create(r.Context(), a.Org, a.Principal.Subject, name, origins)
	if limit, ok := errors.AsType[LimitError](err); ok {
		h.Log.InfoContext(r.Context(), "app refused", slog.String("event.name", "apps.limit_reached"),
			slog.String("org.id", a.Org.ID), slog.Int("limit", int(limit.Limit)))
		orgs.WriteProblem(w, r, http.StatusForbidden, orgs.CodeAppLimitReached, fmt.Sprintf("The plan of this org allows %d apps.", limit.Limit))
		return
	}
	if h.refusal(w, r, err) {
		return
	}
	h.Log.InfoContext(r.Context(), "app created", slog.String("event.name", "apps.created"),
		slog.String("org.id", a.Org.ID), slog.String("app.id", app.ID), slog.Int("origins", len(app.AllowedOrigins)))
	w.Header().Set("Location", "/v1/orgs/"+a.Org.ID+"/apps/"+app.ID)
	writeJSON(w, http.StatusCreated, appBody(app))
}

func (h *Handler) updateApp(w http.ResponseWriter, r *http.Request) {
	a, ok := h.writer(w, r)
	if !ok {
		return
	}
	var body identity.UpdateAppRequest
	if !decode(w, r, &body) {
		return
	}
	if body.Name == nil && body.AllowedOrigins == nil && body.WidgetSettings == nil {
		orgs.WriteProblem(w, r, http.StatusBadRequest, orgs.CodeInvalidRequest, "Set name, allowed_origins, widget_settings or more of them.")
		return
	}
	var change Change
	if body.WidgetSettings != nil {
		ws, err := WidgetSettingsFrom(*body.WidgetSettings)
		if err != nil {
			orgs.WriteProblem(w, r, http.StatusBadRequest, orgs.CodeInvalidRequest,
				fmt.Sprintf("widget_settings: every field needs an allowed value; greeting is plain text, %d characters or less.", MaxGreetingLen))
			return
		}
		change.Settings = &ws
	}
	var name *string
	if body.Name != nil {
		n, ok := validName(*body.Name)
		if !ok {
			orgs.WriteProblem(w, r, http.StatusBadRequest, orgs.CodeInvalidRequest, "name must be 1 to 128 characters.")
			return
		}
		name = &n
	}
	var origins []string
	if body.AllowedOrigins != nil {
		if origins, ok = validOrigins(w, r, *body.AllowedOrigins); !ok {
			return
		}
	}
	change.Name, change.Origins = name, origins
	app, err := h.Repo.Update(r.Context(), a.Org, a.Principal.Subject, r.PathValue("appId"), change)
	if h.refusal(w, r, err) {
		return
	}
	h.Log.InfoContext(r.Context(), "app updated", slog.String("event.name", "apps.updated"),
		slog.String("org.id", a.Org.ID), slog.String("app.id", app.ID), slog.Int("origins", len(app.AllowedOrigins)),
		slog.Bool("widget_settings", change.Settings != nil))
	writeJSON(w, http.StatusOK, appBody(app))
}

// getWidgetSettings answers the widget of an app without a token. Check order:
// app → org active → Origin in the allow-list. The answer holds the settings
// only. The route is registered through h.cors, which sets Vary: Origin on
// every answer and Access-Control-Allow-Origin only for a listed origin;
// refusals are no-store (WriteProblem).
func (h *Handler) getWidgetSettings(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	app, err := h.Repo.ByID(ctx, r.PathValue("appId"))
	if h.refusal(w, r, err) {
		return
	}
	org, err := h.Orgs.Repo.OrgByID(ctx, app.OrgID)
	if err != nil && !errors.Is(err, orgs.ErrNotFound) {
		h.Orgs.Fail(w, r, err)
		return
	}
	if err != nil || org.Status != "active" {
		orgs.WriteProblem(w, r, http.StatusNotFound, orgs.CodeNotFound, "")
		return
	}
	if _, ok := MatchOrigin(app.AllowedOrigins, singleOrigin(r)); !ok {
		orgs.WriteProblem(w, r, http.StatusForbidden, orgs.CodeOriginNotAllowed, "")
		return
	}
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(app.WidgetSettings.API()); err != nil {
		h.Orgs.Fail(w, r, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	// no-cache, not no-store: a cache may keep it but must ask again, so a studio
	// change shows on the next page load.
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(buf.Bytes())
}

func (h *Handler) deleteApp(w http.ResponseWriter, r *http.Request) {
	a, ok := h.writer(w, r)
	if !ok {
		return
	}
	id := r.PathValue("appId")
	if h.refusal(w, r, h.Repo.Delete(r.Context(), a.Org, a.Principal.Subject, id)) {
		return
	}
	h.Log.InfoContext(r.Context(), "app deleted", slog.String("event.name", "apps.deleted"),
		slog.String("org.id", a.Org.ID), slog.String("app.id", id))
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}

// writer is the gate of the app writes: own org, token role owner or admin. The
// store then checks the stored role (it wins over a stale token). Operator: 403.
func (h *Handler) writer(w http.ResponseWriter, r *http.Request) (orgs.Access, bool) {
	a, ok := h.Orgs.Gate(w, r)
	if !ok {
		return a, false
	}
	if !a.Own || !orgs.TokenRole(a.Principal).AtLeast(orgs.Admin) {
		orgs.WriteProblem(w, r, http.StatusForbidden, auth.CodeForbidden, "")
		return a, false
	}
	return a, true
}

// refusal writes the answer for a store error and returns true, or returns false
// when err is nil.
func (h *Handler) refusal(w http.ResponseWriter, r *http.Request, err error) bool {
	switch {
	case err == nil:
		return false
	case errors.Is(err, ErrNotFound):
		orgs.WriteProblem(w, r, http.StatusNotFound, orgs.CodeNotFound, "")
	case errors.Is(err, ErrForbidden):
		orgs.WriteProblem(w, r, http.StatusForbidden, auth.CodeForbidden, "")
	default:
		h.Orgs.Fail(w, r, err)
	}
	return true
}

// createWidgetToken issues a widget token. Check order: user token (auth.Middleware)
// → app → org of the app is the token's org → stored membership → Origin in the
// allow-list. Every refusal before the origin check answers 404, the same as an
// unknown app.
func (h *Handler) createWidgetToken(w http.ResponseWriter, r *http.Request) {
	p, ok := auth.FromContext(r.Context())
	if !ok { // auth.Middleware never lets this through
		orgs.WriteProblem(w, r, http.StatusUnauthorized, auth.CodeUnauthenticated, "")
		return
	}
	if _, isWidget := p.Raw[auth.ClaimOrigin]; isWidget {
		// A widget token never gets a new widget token.
		orgs.WriteProblem(w, r, http.StatusForbidden, auth.CodeForbidden, "")
		return
	}
	app, org, ok := h.memberApp(w, r, p)
	if !ok {
		return
	}
	origin, ok := MatchOrigin(app.AllowedOrigins, singleOrigin(r))
	if !ok {
		h.Log.InfoContext(r.Context(), "widget token refused", slog.String("event.name", "apps.widget_token_refused"),
			slog.String("org.id", org.ID), slog.String("app.id", app.ID), slog.String("reason", orgs.CodeOriginNotAllowed))
		orgs.WriteProblem(w, r, http.StatusForbidden, orgs.CodeOriginNotAllowed, "")
		return
	}
	tok, err := h.Widget.Issue(widget.Subject{UserSub: p.Subject, ZitadelOrgID: org.ZitadelOrgID, AppID: app.ID, Origin: origin})
	if err != nil {
		h.Orgs.Fail(w, r, err)
		return
	}
	h.Log.InfoContext(r.Context(), "widget token issued", slog.String("event.name", "apps.widget_token_issued"),
		slog.String("org.id", org.ID), slog.String("app.id", app.ID), slog.String("enduser.id", p.Subject),
		slog.Int("expires_in", tok.ExpiresIn))
	writeJSON(w, http.StatusCreated, identity.WidgetToken{
		AccessToken: tok.Raw,
		TokenType:   identity.WidgetTokenTokenTypeBearer,
		ExpiresIn:   tok.ExpiresIn,
		ExpiresAt:   tok.ExpiresAt.UTC(),
		AppId:       uuid.MustParse(app.ID),
		Origin:      origin,
	})
}

// memberApp loads the app of the path and checks that the caller is a member of its
// org (token org, token role and stored membership). Any miss answers 404.
func (h *Handler) memberApp(w http.ResponseWriter, r *http.Request, p *auth.Principal) (App, orgs.Org, bool) {
	ctx := r.Context()
	app, err := h.Repo.ByID(ctx, r.PathValue("appId"))
	if h.refusal(w, r, err) {
		return App{}, orgs.Org{}, false
	}
	org, err := h.Orgs.Repo.OrgByID(ctx, app.OrgID)
	if err != nil && !errors.Is(err, orgs.ErrNotFound) {
		h.Orgs.Fail(w, r, err)
		return App{}, orgs.Org{}, false
	}
	if err != nil || org.Status != "active" || org.ZitadelOrgID != p.OrgID || !orgs.TokenRole(p).Valid() {
		orgs.WriteProblem(w, r, http.StatusNotFound, orgs.CodeNotFound, "")
		return App{}, orgs.Org{}, false
	}
	stored, err := h.Orgs.Repo.MemberRole(ctx, org.ID, p.Subject)
	if err != nil && !errors.Is(err, orgs.ErrNotFound) {
		h.Orgs.Fail(w, r, err)
		return App{}, orgs.Org{}, false
	}
	if !stored.Valid() {
		orgs.WriteProblem(w, r, http.StatusNotFound, orgs.CodeNotFound, "")
		return App{}, orgs.Org{}, false
	}
	return app, org, true
}

// singleOrigin is the Origin header, or "" when it is missing or sent twice.
func singleOrigin(r *http.Request) string {
	if v := r.Header.Values("Origin"); len(v) == 1 {
		return v[0]
	}
	return ""
}

// cors sets the CORS headers of the widget token route. Only an origin in the
// allow-list of the app gets Access-Control-Allow-Origin; every other origin gets
// none, so the browser hides the answer. The handler checks the origin again.
func (h *Handler) cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Vary", "Origin")
		if origin := singleOrigin(r); origin != "" {
			if app, err := h.Repo.ByID(r.Context(), r.PathValue("appId")); err == nil {
				if _, ok := MatchOrigin(app.AllowedOrigins, origin); ok {
					// The header value passed the strict parser: no CR, LF or space.
					w.Header().Set("Access-Control-Allow-Origin", origin)
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

// preflight answers the CORS preflight for method: 204 for an allowed origin
// (cors set the header and Vary: Origin), else 403 without CORS headers. headers
// is the Access-Control-Allow-Headers value, "" for none.
func preflight(method, headers string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if w.Header().Get("Access-Control-Allow-Origin") == "" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.Header().Set("Access-Control-Allow-Methods", method)
		if headers != "" {
			w.Header().Set("Access-Control-Allow-Headers", headers)
		}
		w.Header().Set("Access-Control-Max-Age", preflightMaxAge)
		w.WriteHeader(http.StatusNoContent)
	})
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil || dec.More() {
		orgs.WriteProblem(w, r, http.StatusBadRequest, orgs.CodeInvalidRequest, "Body is not valid JSON for this route.")
		return false
	}
	return true
}

// validName trims the name and checks 1 to 128 characters of valid UTF-8.
func validName(s string) (string, bool) {
	s = strings.TrimSpace(s)
	return s, s != "" && utf8.ValidString(s) && utf8.RuneCountInString(s) <= maxNameLen
}

// validOrigins canonicalizes the allow-list or writes 400. The detail names the
// index, never the value.
func validOrigins(w http.ResponseWriter, r *http.Request, in []string) ([]string, bool) {
	out, bad, err := CanonicalOrigins(in)
	if err == nil {
		return out, true
	}
	detail := fmt.Sprintf("allowed_origins must hold 1 to %d origins.", MaxOrigins)
	if bad >= 0 {
		detail = fmt.Sprintf("allowed_origins[%d] is not a valid origin or is a duplicate. Use scheme://host[:port]; http only for localhost.", bad)
	}
	orgs.WriteProblem(w, r, http.StatusBadRequest, orgs.CodeInvalidRequest, detail)
	return nil, false
}

func pageParams(r *http.Request) (limit int, after string, ok bool) {
	q := r.URL.Query()
	limit = DefaultPageSize
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > MaxPageSize {
			return 0, "", false
		}
		limit = n
	}
	if c := q.Get("cursor"); c != "" {
		if len(c) > 256 {
			return 0, "", false
		}
		b, err := base64.RawURLEncoding.DecodeString(c)
		if err != nil {
			return 0, "", false
		}
		id, ok := parseID(string(b))
		if !ok {
			return 0, "", false
		}
		after = id
	}
	return limit, after, true
}

func appBody(a App) identity.App {
	return identity.App{
		Id:             uuid.MustParse(a.ID),
		OrgId:          uuid.MustParse(a.OrgID),
		Name:           a.Name,
		AllowedOrigins: a.AllowedOrigins,
		WidgetSettings: a.WidgetSettings.API(),
		CreatedAt:      a.CreatedAt.UTC(),
		UpdatedAt:      a.UpdatedAt.UTC(),
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(v); err != nil {
		http.Error(w, "encode", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}
