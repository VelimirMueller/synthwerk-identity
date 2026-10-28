---
title: Orgs and roles
slug: orgs-and-roles
status: beta
epic: E2
owner: identity
paths: ["internal/orgs/**", "internal/zitadel/**", "internal/app/**", "migrations/0003_orgs_members.sql", "cmd/identity/main.go"]
api: ["GET /v1/me", "GET /v1/orgs/{orgId}", "GET /v1/orgs/{orgId}/members", "PATCH /v1/orgs/{orgId}/members/{userId}"]
events: ["dev.synthwerk.identity.org.created.v1", "dev.synthwerk.identity.member.role_changed.v1"]
mcp: []
updated: 2026-10-28
---

# Orgs and roles

> **In 30 seconds**
> - An org is a Zitadel org. Its members have one org role: `owner`, `admin` or `member`. `operator` is a platform role, never a member row.
> - Owner and admin change roles; a member gets 403. An active org always has an owner.
> - Identity writes `org.created` and `member.role_changed` to the outbox in the same transaction as the change (synthwerk#29).

## What it does

- Mirrors the Zitadel user grants of project `synthwerk-api` into `identity.memberships` (hook events `user.grant.added|changed|removed|cascade.removed`).
- An org row appears with its first grant. It stays `pending` until its first owner; then it turns `active` and identity writes `org.created`.
- `PATCH /v1/orgs/{orgId}/members/{userId}` changes a role: membership, outbox row and Zitadel user grant in one transaction. Zitadel refuses: rollback, 502.
- A grant changed directly in Zitadel updates the mirror and writes `member.role_changed` with actor `system`.
- The outbox relay publishes to stream `EVT_IDENTITY` (`evt.identity.>`), which identity creates at start.

## How to use

1. Set `SYNTHWERK_IDENTITY_OIDC_ISSUER` (and `OIDC_AUDIENCE`, `JWKS_URL`). Unset: the org routes are off.
2. Set `SYNTHWERK_IDENTITY_ZITADEL_API_URL`, `ZITADEL_HOST`, `ZITADEL_PAT_FILE`, `ZITADEL_PROJECT_ID` so role changes reach Zitadel. Unset: changes stay in identity (warning at start).
3. Set `SYNTHWERK_IDENTITY_PLATFORM_ORG_ID` to the Zitadel org that grants `operator`.
4. Set `SYNTHWERK_IDENTITY_NATS_URL` to publish the outbox. Unset: rows stay in the outbox.

## Rules and limits

| Rule | Value |
|---|---|
| Check order | token → org from path → token role (first gate) → stored role (wins) → rule table |
| Stale token | Writes and `listMembers` check the stored role: a demoted admin gets 403 with the old token |
| Set `admin`/`member` | owner or admin; target is not an owner |
| Grant `owner`, change an owner | owner only |
| Own role | 409 `own_role` |
| Last owner | 409 `last_owner`; a deferred trigger guards the commit too |
| Operator | GET any active org and its members; PATCH 403 |
| Org not visible to the caller | 404, same as unknown |
| Page size | 1 to 100, default 50, cursor = base64url of the last `user_id` |

## Events

| Type | When |
|---|---|
| `dev.synthwerk.identity.org.created.v1` | An org got its first owner. |
| `dev.synthwerk.identity.member.role_changed.v1` | A member's org role changed (API: actor `user:<sub>`; Zitadel: actor `system`). Refusals write nothing. |

## Errors

| Status | Problem type | Cause |
|---|---|---|
| 400 | `invalid_request` | Body is not `{"role": owner|admin|member}`, or bad paging. |
| 401 | `unauthenticated` | Token missing or not valid. |
| 403 | `forbidden` | Role does not allow the call. Generic body. |
| 404 | `not_found` | Unknown org or member, or no access to the org. |
| 409 | `own_role`, `last_owner` | Rule refused the change. |
| 502 | `upstream_unavailable` | Zitadel did not take the change. Nothing changed. |

## Tests

- `tests/unit/orgs/roles_test.go` — `Authorize - member changes role - denied`, `Authorize - admin grants owner - denied`, `Authorize - owner grants owner - allowed`, `Authorize - owner demotes self as last owner - conflict`, `Claims - roles claim with several roles - highest role wins`, `Operator - is_operator - never an org role`
- `tests/integration/orgs/orgs_test.go` — `ChangeRole - success - membership and outbox row in one commit, Zitadel grant written`, `ChangeRole - Zitadel fake fails - mirror rolled back, no event`, `ChangeRole - last owner demoted - rejected, row unchanged`, `ChangeRole - two parallel demotions of two owners - one succeeds`, `Action org created - same event twice - one org, one owner`
- `tests/integration/orgs/orgs_test.go` — `PATCH member - member token - 403 generic body`, `PATCH member - owner token - 200`, `PATCH member - token of other org - 404`, `PATCH member - forged token - 401`, `ListMembers - admin demoted, old admin token - 403`
- `tests/unit/zitadelhook/grant_test.go`, `tests/unit/zitadel/client_test.go`

## Changes

| Date | Change |
|---|---|
| 2026-10-28 | First version (synthwerk#29). |
