---
title: Apps and widget tokens
slug: apps-and-widget-tokens
status: beta
epic: E2
owner: identity
paths: ["internal/apps/**", "internal/widget/**", "migrations/0004_apps.sql", "cmd/identity/main.go"]
api: ["GET /v1/orgs/{orgId}/apps", "POST /v1/orgs/{orgId}/apps", "GET /v1/orgs/{orgId}/apps/{appId}", "PATCH /v1/orgs/{orgId}/apps/{appId}", "DELETE /v1/orgs/{orgId}/apps/{appId}", "POST /v1/apps/{appId}/widget-tokens"]
events: ["dev.synthwerk.identity.app.created.v1"]
mcp: []
updated: 2026-10-29
---

# Apps and widget tokens

> **In 30 seconds**
> - An org registers apps. Each app has an origin allow-list (synthwerk#30).
> - A widget gets a widget token only for a signed-in member of the org, and only on a listed origin.
> - The token is a JWT signed by identity. It lives 10 minutes by default, 15 minutes at most.

## What it does

- `GET|POST /v1/orgs/{orgId}/apps`, `GET|PATCH|DELETE /v1/orgs/{orgId}/apps/{appId}` manage apps (table `identity.apps`).
- Creating an app writes `app.created` to the outbox in the same transaction. Update and delete write no event yet.
- `POST /v1/apps/{appId}/widget-tokens` issues a widget token. The caller sends the Zitadel user token and the browser sends `Origin`.
- `GET /.well-known/jwks.json` serves the public key of the widget tokens. No token needed.
- The widget token route answers the CORS preflight (`OPTIONS`). Only a listed origin gets `Access-Control-Allow-Origin`.

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
| Non-listed or missing origin, two `Origin` headers | 403 `origin_not_allowed`, no CORS header |
| Token | JWT, `typ` `at+jwt`, `ES256`, `kid` = RFC 7638 thumbprint |
| Token claims | `iss`, `aud`, `sub`, `urn:zitadel:iam:user:resourceowner:id`, `client_id` (app id), `synthwerk:origin`, `iat`, `nbf`, `exp`, `jti`. No roles |
| Lifetime | Default 10 min, max 15 min; start refuses a longer `WIDGET_TOKEN_TTL` |
| Change or delete of an app | Tokens issued before stay valid until they expire |
| Signing key | Read once at start; a new key needs a restart. One key in the key set |

## Events

| Type | When |
|---|---|
| `dev.synthwerk.identity.app.created.v1` | An owner or admin created an app. `app_id`, `org_id`, `name`; actor `user:<sub>`. No origins. |

## Errors

| Status | Problem type | Cause |
|---|---|---|
| 400 | `invalid_request` | Bad JSON, name, origin (detail names the index, never the value) or paging. |
| 401 | `unauthenticated` | User token missing or not valid. A widget token is not a user token. |
| 403 | `forbidden` | Role does not allow the write. Generic body. |
| 403 | `origin_not_allowed` | `Origin` is missing or not in the allow-list. |
| 404 | `not_found` | Unknown app or org, or the caller is not a member. |

## Tests

- `tests/unit/apps/origin_test.go` — `CanonicalOrigin - <case> - refused` (40 tricks), `MatchOrigin - suffix trick`, `MatchOrigin - subdomain`, `MatchOrigin - other port`, `CanonicalOrigins - same origin twice after canonical form - refused at index 1`
- `tests/unit/widget/widget_test.go` — `Issue - default lifetime - 10 minutes, verified by the kit verifier with Zitadel claim names`, `Verify - token issued 16 minutes ago with the max lifetime - expired`, `NewIssuer - lifetime 1h0m0s - refused`, `ParseKey - RSA key - refused`
- `tests/unit/apps/http_test.go` — `CreateWidgetToken - suffix of a listed origin - 403 origin_not_allowed, no CORS header`, `CreateWidgetToken - token of another org - 404 even on a listed origin`, `Preflight - origin not listed - 403 without CORS headers`, `CreateApp - admin token, stored role member - 403`
- `tests/integration/apps/apps_test.go` — `Create - owner - app row and app.created in one commit, no origins in the event`, `CreateWidgetToken - member on a listed origin - 201, verified with the key set, bound to user, org, app and origin`, `UpdateApp - origin removed - widget token on that origin 403`, `CreateWidgetToken - member left the org, old token - 404`

## Changes

| Date | Change |
|---|---|
| 2026-10-29 | First version (synthwerk#30). |
