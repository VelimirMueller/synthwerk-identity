---
title: Export own data and delete own account
slug: account-export-delete
status: beta
epic: E4
owner: identity
paths: ["internal/account/**", "internal/zitadel/client.go", "internal/orgs/store.go", "migrations/0008_account_deletions.sql", "cmd/identity/main.go"]
api: ["GET /v1/me/export", "DELETE /v1/me"]
events: ["dev.synthwerk.identity.user.deleted.v1"]
mcp: []
updated: 2026-10-30
---

# Export own data and delete own account

> **In 30 seconds**
> - `GET /v1/me/export` gives the caller one JSON file with every row Synthwerk keeps about them: identity rows plus the export of each service that keeps user rows (today llm).
> - `DELETE /v1/me` deletes the account. It needs a sign-in with MFA in the last 15 minutes. Identity deletes its rows and publishes `user.deleted.v1`; the other services delete theirs. Zitadel removes the user next, with retries (synthwerk#41).

## What it does

- Export: the memberships of the caller in every org (org id, name, slug, role, joined, updated) and the newest MFA evidence (session id, `amr`, time; never a session token).
- Export: asks every source of `SYNTHWERK_IDENTITY_EXPORT_SOURCES` at `GET /v1/me/export` with the caller's own access token, and puts each answer unchanged into `services[].data`. A source that fails gives `status: unavailable` and `complete: false`; the answer stays 200.
- Delete, in one transaction: a row in `account_deletions` (key sha256 of the sub), the memberships, the MFA evidence, the seen keys of the user's Zitadel events, the orgs where the user is the only member (with their apps and plan), and the outbox row of `user.deleted.v1`.
- Remover: every 30 s it removes the Zitadel user of each new deletion (UserService v2 `DeleteUser`). Failure: retry after 1, 2, 4 … 60 minutes. Success: the clear sub leaves `account_deletions`; only the hash stays.
- The Zitadel hook drops a grant event of a deleted user (hash lookup), so a late event never brings a membership back.

## How to use

1. Studio calls `GET /v1/me/export` with the user's token and saves the body (`Content-Disposition: attachment`).
2. Studio asks the user to sign in again with MFA, then calls `DELETE /v1/me`. On 409 `last_owner` it shows the orgs from `detail` and asks for a new owner first.
3. Set `SYNTHWERK_IDENTITY_EXPORT_SOURCES=llm=http://llm:8080` in the stack. The machine user `identity-sync` needs the permission to delete users (synthwerk-infra), else the remover retries and logs WARN.

## Rules and limits

| Rule | Value |
|---|---|
| Recent MFA | Token `amr` has `mfa`, and the newest gated sign-in is at most `SYNTHWERK_IDENTITY_ACCOUNT_DELETE_MFA_MAX_AGE` old (default 15m, max 12h). Else 403 `recent_mfa_required`. |
| Operator | 403 `forbidden`. Platform users are never removed here. |
| Last owner | Only owner of an active org with other members: 409 `last_owner`, nothing changes. The org row lock and the deferred owner trigger guard parallel deletes and role changes. |
| Only member | The org closes with the account: org, apps, plan deleted. Its ids go into `deleted_org_ids` and the event. The Zitadel org stays. |
| Repeat | 202 with the first `requested_at`, empty `deleted_org_ids`, no new event, no MFA check. |
| Old tokens | Stay valid until they expire. Identity has no rows for them; other services delete theirs on the event. |
| Export source | 10 s timeout, 32 MiB, `application/json` object, status 200. No redirects: the token goes only to the configured host. |
| Export source config | `name=url` list. http(s) URL without user info, query or fragment. A bad value stops the start. |
| Logs | `enduser.id` and reason. Never a token, never export content. |
| Bus retention | `EVT_IDENTITY` keeps older events with the sub up to 30 days; published outbox rows go after the kit retention. |

## Events

| Type | When |
|---|---|
| `dev.synthwerk.identity.user.deleted.v1` | A user deleted the own account. `user_sub`, `deleted_orgs` (`org_id`, `zitadel_org_id`). No `orgid` extension. Consumer: llm. |

## Errors

| Status | Problem type | Cause |
|---|---|---|
| 401 | `unauthenticated` | Token missing or not valid. |
| 403 | `recent_mfa_required` | No sign-in with MFA in the last 15 minutes. |
| 403 | `forbidden` | Caller is an operator. |
| 409 | `last_owner` | Only owner of an org with other members. `detail` names the orgs. |
| 500 | `internal_error` | Database error. Nothing changed. |

## Tests

- `tests/unit/account/http_test.go` — `DeleteMe - token with mfa, gated sign-in 5 min old - 202 with the closed org`
- `tests/unit/account/http_test.go` — `DeleteMe - token without amr mfa / no gated sign-in stored / gated sign-in 16 min old / evidence from the future / evidence without mfa - 403 recent_mfa_required, nothing deleted`
- `tests/unit/account/http_test.go` — `DeleteMe - operator - 403 forbidden`; `last owner of an org with members - 409 last_owner naming the org`; `repeat with the old token - 202 with the first time`
- `tests/unit/account/http_test.go` — `ExportMe - identity rows, evidence and the llm part - 200 attachment, data unchanged, token forwarded`
- `tests/unit/account/http_test.go` — `ExportMe - source answers 503 / HTML / a JSON array / broken JSON / redirects - 200, service unavailable, complete false`
- `tests/unit/account/http_test.go` — `ParseSources - …`
- `tests/unit/zitadel/delete_user_test.go` — `DeleteUser - Zitadel removes the user / already gone (404) / no permission (403)`
- `tests/integration/account/account_test.go` — `Delete - member of a shared org, only member of another - rows gone, solo org closed, one event`
- `tests/integration/account/account_test.go` — `Delete - repeat`; `only owner of an org with a member - ErrLastOwner`; `two owners delete at the same time - one wins`
- `tests/integration/account/account_test.go` — `ApplyGrant - grant of a deleted user arrives late - ignored, no membership`
- `tests/integration/account/account_test.go` — `RunOnce - Zitadel removes the user - clear sub gone, hash stays`; `Zitadel refuses - retry after a pause`

## Changes

| Date | Change |
|---|---|
| 2026-10-30 | First version (synthwerk#41). |
