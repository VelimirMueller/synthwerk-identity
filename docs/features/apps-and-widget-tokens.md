---
title: Apps and widget tokens
slug: apps-and-widget-tokens
status: beta
epic: E2
owner: identity
paths: ["internal/apps/**", "internal/widget/**", "migrations/0004_apps.sql", "migrations/0007_app_widget_settings.sql", "migrations/0010_apps_origin_index.sql", "cmd/identity/main.go"]
api: ["GET /v1/orgs/{orgId}/apps", "POST /v1/orgs/{orgId}/apps", "GET /v1/orgs/{orgId}/apps/{appId}", "PATCH /v1/orgs/{orgId}/apps/{appId}", "DELETE /v1/orgs/{orgId}/apps/{appId}", "POST /v1/apps/{appId}/widget-tokens", "GET /v1/apps/{appId}/widget-settings", "GET /internal/v1/widget-origins"]
events: ["dev.synthwerk.identity.app.created.v1"]
mcp: []
updated: 2026-10-30
---

# Apps and widget tokens

> **In 30 seconds**
> - An org registers apps. Each app has an origin allow-list (synthwerk#30).
> - A widget gets a widget token only for a signed-in member of the org, and only on a listed origin.
> - The token is a JWT signed by identity. It lives 10 minutes by default, 15 minutes at most.
> - Each app has widget settings. The widget reads them without a token, only from a listed origin (synthwerk#38).
> - An org gets at most `apps_per_org` apps from its plan (synthwerk#38).
> - An internal route tells llm if any app lists an origin. llm then answers CORS for the widget chat (infra#21).

## What it does

- `GET|POST /v1/orgs/{orgId}/apps`, `GET|PATCH|DELETE /v1/orgs/{orgId}/apps/{appId}` manage apps (table `identity.apps`).
- Creating an app writes `app.created` to the outbox in the same transaction. Update and delete write no event yet.
- `POST /v1/apps/{appId}/widget-tokens` issues a widget token. The caller sends the Zitadel user token and the browser sends `Origin`.
- `GET /.well-known/jwks.json` serves the public key of the widget tokens. No token needed.
- The widget token route answers the CORS preflight (`OPTIONS`) for every origin in canonical form. The trade then decides: a listed origin gets the token, any other origin gets a readable `403 origin_not_allowed` (widgets#41).
- `PATCH /v1/orgs/{orgId}/apps/{appId}` also sets `widget_settings`: position, theme, mode, language, accent group, greeting. New settings replace the old ones (column `apps.widget_settings`, migration 0007).
- `GET /v1/apps/{appId}/widget-settings` returns the settings without a token, only to a listed `Origin`. The answer holds the settings only. It has a CORS preflight too (GET, no extra headers).
- `GET /internal/v1/widget-origins?origin=<origin>` answers 204 when an app of an active org lists the origin. Else 404.
- The internal route needs no token. It tells only yes or no: no app id, no org. The edge refuses `/identity/internal/*`.
- llm asks the internal route before it answers CORS for the widget chat routes (infra#21).
- `POST /v1/orgs/{orgId}/apps` counts the apps of the org under a row lock on its entitlements. At `apps_per_org` it answers 403 `app_limit_reached`.

## How to use

1. Make a P-256 key: `openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out widget-key.pem`. Keep it out of git.
2. Set `SYNTHWERK_IDENTITY_WIDGET_SIGNING_KEY_FILE` to the key file and `SYNTHWERK_IDENTITY_WIDGET_ISSUER` to the public URL of identity. Unset key: the widget token route and the key set are off (warning at start). The app routes stay on.
3. Optional: `SYNTHWERK_IDENTITY_WIDGET_AUDIENCE` (default `synthwerk-api`), `SYNTHWERK_IDENTITY_WIDGET_TOKEN_TTL` (`1m` to `15m`, default `10m`).
4. A service that accepts widget tokens uses kit `auth.NewVerifier` with the widget issuer and `JWKS_URL` = `<identity>/.well-known/jwks.json`. It must compare `synthwerk:origin` with the `Origin` header (llm does).

## Rules and limits

| Rule | Value |
|---|---|
| Read apps | Any member of the org, or operator |
| Write apps | Token role owner or admin, then the stored role (row share lock in the write transaction). Operator: 403 |
| Origin form | `scheme://host[:port]`. `https`; `http` only for `localhost`, `127.0.0.1`, `[::1]` |
| Refused in an origin | Path (also `/`), query, fragment, user info, wildcard, percent-encoding, backslash, white space, non-ASCII, trailing dot, port with a leading zero |
| Canonical form | Lower-case scheme and host, default port removed, short IPv6 form |
| Origin match | Exact string compare of canonical forms. No prefix, suffix, subdomain or wildcard match |
| Allow-list size | 1 to 20, no duplicates after the canonical form |
| Widget token check order | user token → app → app org = token org, token org role → stored membership → `Origin` in the list |
| Refusal before the origin check | 404, same as an unknown app |
| Non-listed origin in canonical form | 403 `origin_not_allowed` with `Access-Control-Allow-Origin` of that origin, so the widget can show "not allowed" (widgets#41). No token, no app data |
| Missing, `null`, malformed or non-canonical origin, two `Origin` headers | 403 `origin_not_allowed`, no CORS header |
| Token preflight | 204 for every origin in canonical form, the same answer for every app id. `POST`, `Authorization, Content-Type`, max age 600. Else 403 without CORS headers |
| Readable answers of the trade for a non-listed origin | Only 403 `origin_not_allowed`. 401, 404 and 5xx carry no CORS header. Never `Access-Control-Allow-Credentials`: the trade takes a bearer token, not cookies |
| Token | JWT, `typ` `at+jwt`, `ES256`, `kid` = RFC 7638 thumbprint |
| Token claims | `iss`, `aud`, `sub`, `urn:zitadel:iam:user:resourceowner:id`, `client_id` (app id), `synthwerk:origin`, `iat`, `nbf`, `exp`, `jti`. No roles |
| Lifetime | Default 10 min, max 15 min; start refuses a longer `WIDGET_TOKEN_TTL` |
| Change or delete of an app | Tokens issued before stay valid until they expire |
| App limit | `apps_per_org` of the org's entitlements, `0` = no limit. Row lock on `org_entitlements`: parallel creates count one after the other. No entitlements row: 500, never "no limit" |
| Widget settings | `position` `bottom-right`/`bottom-left`, `theme` `default`/`contrast`, `mode` `system`/`light`/`dark`, `lang` `auto`/`de`/`en`, `accent` `flagship`/`lab`/`ops`/`venture`, `greeting` 0 to 280 characters, plain text, line breaks only as control characters, no bidi embedding, override or isolate (U+202A to U+202E, U+2066 to U+2069; the widget refuses the same set) |
| Stored settings | jsonb, object, 4 KiB at most. A missing or unknown stored value reads as its default. A stored greeting with a bidi control reads as no greeting |
| Widget settings read | No token. App → org active → `Origin` in the list. Unknown app or inactive org: 404 |
| CORS caching | Both widget routes send `Vary: Origin` on every answer, preflight and refusals included. Refusals and tokens: `Cache-Control: no-store`. Settings: `no-cache` |
| Internal origin lookup | `GET /internal/v1/widget-origins`, port 8080, no token. Exactly one `origin` query parameter |
| Lookup compare | Canonical form, exact match. Only apps of an org with status `active` count |
| Lookup answers | 204 listed, 404 not listed, 400 invalid origin, 500 database error. Always `Cache-Control: no-store` |
| Lookup index | GIN index `apps_allowed_origins` on `apps.allowed_origins` (migration 0010) |
| Signing key | Read once at start; a new key needs a restart. One key in the key set |

## Events

| Type | When |
|---|---|
| `dev.synthwerk.identity.app.created.v1` | An owner or admin created an app. `app_id`, `org_id`, `name`; actor `user:<sub>`. No origins. |

## Errors

| Status | Problem type | Cause |
|---|---|---|
| 400 | `invalid_request` | Bad JSON, name, origin (detail names the index, never the value) or paging. Internal lookup: missing, repeated or invalid `origin`. |
| 401 | `unauthenticated` | User token missing or not valid. A widget token is not a user token. |
| 403 | `forbidden` | Role does not allow the write. Generic body. |
| 403 | `origin_not_allowed` | `Origin` is missing or not in the allow-list. |
| 403 | `app_limit_reached` | The org has `apps_per_org` apps already. The detail names the limit. |
| 404 | `not_found` | Unknown app or org, or the caller is not a member. Internal lookup: no app of an active org lists the origin. |

## Tests

- `tests/unit/apps/origin_test.go` — `CanonicalOrigin - <case> - refused` (40 tricks), `MatchOrigin - suffix trick`, `MatchOrigin - subdomain`, `MatchOrigin - other port`, `CanonicalOrigins - same origin twice after canonical form - refused at index 1`
- `tests/unit/widget/widget_test.go` — `Issue - default lifetime - 10 minutes, verified by the kit verifier with Zitadel claim names`, `Verify - token issued 16 minutes ago with the max lifetime - expired`, `NewIssuer - lifetime 1h0m0s - refused`, `ParseKey - RSA key - refused`
- `tests/unit/apps/http_test.go` — `CreateWidgetToken - suffix of a listed origin - 403 origin_not_allowed readable to that origin, no token`, `CreateWidgetToken - null origin - 403 origin_not_allowed, no CORS header`, `CreateWidgetToken - token of another org, origin not listed - 404 unreadable, no CORS header`, `Preflight - unknown app - 204 with CORS headers, no credentials, no-store`, `Preflight - origin with a path - 403 without CORS headers`, `CreateApp - admin token, stored role member - 403`
- `tests/unit/apps/http_test.go` — `GetWidgetSettings - new app, listed origin, no token - 200 defaults, CORS, Vary, no-cache, settings only`, `GetWidgetSettings - origin not listed - 403 origin_not_allowed, no CORS header, Vary, no-store`, `UpdateApp - free colour as accent - 400 invalid_request, nothing stored`, `CreateApp - org at its app limit - 403 app_limit_reached with the limit`
- `tests/unit/apps/settings_test.go` — `Refused - free colour - ErrSettings`, `Greeting - 280 characters with a line break - accepted, trimmed`, `Refused - greeting with RLO U+202E - ErrSettings`, `Greeting - שלום - accepted`
- `tests/integration/apps/apps_test.go` — `Create - org at apps_per_org - LimitError, no row, no event`, `Create - eight parallel creates, one slot left - exactly one app made`, `Create - org without an entitlements row - error, never no limit`, `Settings - new app defaults, update replaces them, row from before 0007 reads as defaults`, `GetWidgetSettings - listed origin, no token - 200 stored settings, CORS, Vary, no-cache`
- `tests/unit/apps/widgetorigins_test.go` — `WidgetOrigin - listed origin in upper case with the default port - 204, store gets the canonical form`, `WidgetOrigin - null origin - 400 invalid_request, no lookup`, `WidgetOrigin - store fails - 500, never 204`
- `tests/integration/apps/widgetorigins_test.go` — `WidgetOrigin - origin of no app, subdomain and other port - 404`, `WidgetOrigin - org of the only app not active - 404`, `Migration - GIN index on allowed_origins - present`
- `tests/integration/apps/apps_test.go` — `Create - owner - app row and app.created in one commit, no origins in the event`, `CreateWidgetToken - member on a listed origin - 201, verified with the key set, bound to user, org, app and origin`, `UpdateApp - origin removed - widget token on that origin 403`, `CreateWidgetToken - member left the org, old token - 404`

## Changes

| Date | Change |
|---|---|
| 2026-10-29 | First version (synthwerk#30). |
| 2026-10-30 | Widget settings, the public settings route, `apps_per_org` enforced, `Vary: Origin` on every widget route answer (synthwerk#38). |
| 2026-10-30 | `cmd/identity/main.go` also starts the `EVT_LLM` consumer of the audit list (synthwerk#39). No change to this feature. |
| 2026-10-30 | Internal route `GET /internal/v1/widget-origins` and GIN index 0010: llm answers CORS for the widget chat (infra#21). |
| 2026-10-30 | Token preflight open to every canonical origin, readable 403 `origin_not_allowed` (widgets#41). Greeting refuses bidi controls like the widget. |
