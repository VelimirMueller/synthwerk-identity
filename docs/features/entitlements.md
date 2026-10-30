---
title: Entitlements
slug: entitlements
status: beta
epic: E2
owner: identity
paths: ["internal/entitlements/**", "migrations/0006_entitlements.sql", "cmd/identity/main.go"]
api: ["GET /v1/me/entitlements", "GET /v1/orgs/{orgId}/entitlements"]
events: ["dev.synthwerk.identity.org.entitlements_changed.v1"]
mcp: []
updated: 2026-10-30
---

# Entitlements

> **In 30 seconds**
> - Every active org has a plan and the limits it gives. A new org gets the plan `free`. Paid plans come in M5 (synthwerk#50).
> - Other services read the limits over HTTP. llm forwards the caller's token to `GET /v1/me/entitlements`.
> - Every change writes `org.entitlements_changed.v1` with the full new state, in the same transaction (synthwerk#31).

## What it does

- Table `identity.org_entitlements`: one row per active org with `plan`, the resolved limits, `version` and `updated_at`.
- An org turns active (first owner): identity writes the free plan, `org.created` and `org.entitlements_changed` (reason `plan_assigned`) in one transaction. A failed plan write rolls the activation back.
- At start, before the first request, `Reconcile` gives every active org without a plan the free plan (orgs from before #31), and moves every free org to the configured limits (reason `plan_defaults_changed`, `version` + 1).
- `GET /v1/me/entitlements`: the org the token acts in. `GET /v1/orgs/{orgId}/entitlements`: one org.

## How to use

1. Set the free plan limits, or keep the defaults: `SYNTHWERK_IDENTITY_FREE_LLM_TOKENS_PER_USER_PER_DAY`, `_FREE_LLM_TOKENS_PER_ORG_PER_DAY`, `_FREE_APPS_PER_ORG`.
2. Restart identity after a change. Each free org whose limits differ gets the new limits and one event.
3. A service that acts for a user calls `GET /v1/me/entitlements` with the caller's token and caches the answer per org. It may refresh the cache from the event; it keeps the highest `version`.

## Rules and limits

| Rule | Value |
|---|---|
| Default plan | `free` |
| Free limits (placeholders, product decides) | 50000 LLM tokens per user per UTC day, 500000 per org per UTC day, 3 apps per org |
| `0` | No limit |
| Bad config | Negative value, apps above 10000 or not a whole number: the service does not start |
| Read access | Any org role of the token in the org, or `operator`. Everything else: 404 |
| Pending org | No plan yet; the API answers 404 |
| Version | Starts at 1, goes up by one on every change; the event has the same value |
| Two replicas start at once | Reconcile skips rows another replica holds; each change is written once |
| Enforcement | llm enforces the token limits. Identity enforces `apps_per_org` on app create (403 `app_limit_reached`, synthwerk#38, [apps](apps-and-widget-tokens.md)) |

## Events

| Type | When |
|---|---|
| `dev.synthwerk.identity.org.entitlements_changed.v1` | An org got its first plan (`plan_assigned`), or the limits of its plan changed (`plan_defaults_changed`). Actor `system`. |

## Errors

| Status | Problem type | Cause |
|---|---|---|
| 401 | `unauthenticated` | Token missing or not valid. |
| 404 | `not_found` | Unknown or pending org, no org role in the org, or no access. Same body. |
| 500 | `internal_error` | Database error, or an active org without a plan (a bug). |

## Tests

- `tests/unit/entitlements/plans_test.go` — `FreePlan - nothing set - placeholder defaults`, `FreePlan - all set, 0 included - config wins`, `FreePlan - negative user tokens - error names the setting` (and 5 more)
- `tests/unit/entitlements/http_test.go` — `GET /v1/me/entitlements - member token - 200 contract body`, `me - token without an org role - 404 not_found` (and 7 more 404 cases), `org - operator of another org - 200`, `me - active org without a row - 500, never a 404`
- `tests/unit/entitlements/http_test.go` — `ChangedData - marshal - exactly the fields of the contract schema` (contract test)
- `tests/integration/entitlements/entitlements_test.go` — `ApplyGrant - first owner - org gets plan free and one entitlements_changed`, `ApplyGrant - plan write fails - org stays pending, no org.created`
- `tests/integration/entitlements/entitlements_test.go` — `Reconcile - active org from before #31 - gets plan free once`, `Reconcile - free limits changed in config - version 2 and plan_defaults_changed`, `Reconcile - 450 orgs from before #31 - all assigned over 3 batches`
- `tests/integration/entitlements/entitlements_test.go` — `GET /v1/me/entitlements - member token - plan free and its limits`, `GET /v1/orgs/{orgId}/entitlements - operator - 200`

## Changes

| Date | Change |
|---|---|
| 2026-10-29 | First version: free plan per org, two read routes, `org.entitlements_changed.v1` (synthwerk#31). |
| 2026-10-30 | `apps_per_org` is enforced on app create (synthwerk#38). |
| 2026-10-30 | `cmd/identity/main.go` also starts the `EVT_LLM` consumer of the audit list (synthwerk#39). No change to this feature. |
