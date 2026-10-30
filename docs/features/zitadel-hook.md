---
title: Zitadel Action hook
slug: zitadel-hook
status: beta
epic: E2
owner: identity
paths: ["internal/zitadelhook/**", "migrations/0002_zitadel_event_seen.sql", "cmd/identity/main.go"]
api: []
events: ["dev.synthwerk.identity.user.created.v1", "dev.synthwerk.identity.org.created.v1", "dev.synthwerk.identity.member.role_changed.v1"]
mcp: []
updated: 2026-10-30
---

# Zitadel Action hook

> **In 30 seconds**
> - Zitadel calls identity when it creates a human user. Identity checks the signature and writes `dev.synthwerk.identity.user.created.v1` to the outbox.
> - A repeated call writes nothing new (synthwerk#28 task 5).

## What it does

- Serves `POST /internal/zitadel/actions` on its own address (`SYNTHWERK_IDENTITY_HOOKS_ADDR`, default `:8081`), not on the API port.
- Checks `ZITADEL-Signature`: HMAC-SHA256 over `<t>.<body>`, max 300 s old or ahead.
- Reads the signing key from `SYNTHWERK_IDENTITY_ZITADEL_SIGNING_KEY_FILE` on every call, so a key written after the start works.
- Turns `user.human.added` into `user.created`: `user_sub` = Zitadel user id, `zitadel_org_id` = resource owner, `time` = Zitadel `created_at`.
- Stores the key `<instance>:<aggregate type>:<aggregate id>:<sequence>` and the outbox row in one transaction.
- Never decodes or logs the `event_payload` of user events (email, names).
- Shares its listener with the MFA gate and the token claims ([mfa-gate](mfa-gate.md), synthwerk#94). Each target has its own signing key file.
- Mirrors user grant events (`user.grant.added|changed|removed|cascade.removed`) of project `synthwerk-api` into memberships; see [orgs-and-roles](orgs-and-roles.md). Their payload holds ids and role keys only.
- The project id comes from `SYNTHWERK_IDENTITY_ZITADEL_PROJECT_ID`, or from the file `SYNTHWERK_IDENTITY_ZITADEL_PROJECT_ID_FILE` that `zitadel-bootstrap` writes after identity starts. identity reads the file per call until it holds an id, then keeps it.
- Mirrors `user.grant.deactivated` and `user.grant.reactivated` into the member status (synthwerk#37). These events have no payload: identity finds the member by grant id in the org of the event.

## How to use

1. Set `SYNTHWERK_IDENTITY_ZITADEL_SIGNING_KEY_FILE`. Without it, the listener does not start.
2. Register the target and the execution in Zitadel. synthwerk-infra `zitadel-bootstrap` does this and writes the key file.

## Rules and limits

| Rule | Value |
|---|---|
| Body | 64 KiB max |
| Signature age | 300 s, both directions |
| Grants of another project | 204, ignored |
| Grant event that names a project before the project id is known | 503, nothing changes |
| Deactivate of an active member | Status `deactivated`, `member.deactivated` with actor `system`, audit row |
| Reactivate of a deactivated member | Only when Zitadel confirms the grant is active now. Then status `active`, `member.reactivated` with actor `system`. Else 204, WARN log, member stays deactivated. A failed read answers 500 and the event is not marked seen. |
| Deactivate or reactivate of an unknown grant, a grant of another org, an invited member, a member in that status already | 204, ignored, no event (idempotent: the echo of an identity change writes nothing) |
| Deactivate of the last active owner | 204, mirror keeps the owner active, WARN log. Zitadel tokens carry no org role for that grant, so the org gate refuses the owner anyway. |
| Grant that would remove the last owner | 204, mirror keeps the owner, WARN log |
| Grant of a deleted account (synthwerk#41) | 204, ignored: no membership comes back |
| Other event types | 204, ignored |
| Exposure | Only the compose network `zitadel-hooks` (alias `identity-hooks`). The edge routes `/identity/*` to `:8080`. |

## Events

| Type | When |
|---|---|
| `dev.synthwerk.identity.user.created.v1` | Zitadel created a human user. |
| `dev.synthwerk.identity.org.created.v1` | A grant gave a pending org its first owner. |
| `dev.synthwerk.identity.member.role_changed.v1` | A grant changed in Zitadel changed a member's org role (actor `system`). |

## Errors

| Status | Problem type | Cause |
|---|---|---|
| 401 | `unauthorized` | Signature missing, wrong, or older than 300 s. |
| 400 | `bad request` | Body is not a Zitadel event, or ids are missing. |
| 413 | `body too large` | Body over 64 KiB. |
| 503 | `unavailable` | The key file is not there yet. |
| 500 | `store failed` | Postgres write failed; Zitadel can retry. |

## Tests

- `tests/unit/zitadelhook/hook_test.go` — `user.human.added - signed - one user.created event, no personal data in logs or event`
- `tests/unit/zitadelhook/hook_test.go` — `same call twice - one event`
- `tests/unit/zitadelhook/hook_test.go` — `unsigned, wrong key, changed body, old or future timestamp - 401, no write`
- `tests/unit/zitadelhook/grant_test.go` — `user.grant.added - project grant - mirrored with user, roles and org name`, `user.grant.changed - base64 payload - decoded`, `user.grant.added - other project - dropped`, `user.grant.added - project id not known yet - 503, nothing mirrored`
- `tests/unit/zitadelhook/grant_test.go` — `TestGrantStatusEvents`: deactivated and reactivated with no payload, platform org dropped, wrong aggregate 400, unsigned 401, store error 500
- `tests/integration/orgs/grantstatus_test.go` — `TestApplyGrantStatus`: deactivate with audit row, repeat and echo, confirmed and unconfirmed reactivate, read error rolled back, last owner, unknown grant, invited member, deleted account
- `tests/unit/zitadel/project_test.go` — `Resolve - file written after the start - ErrNotReady first, then the id, then kept`
- synthwerk-infra `tests/stack/stack_test.sh` — `test users from the bootstrap - user.created rows in the outbox; hook path through the edge - 404`

## Changes

| Date | Change |
|---|---|
| 2026-10-23 | First version (synthwerk#28 task 5). |
| 2026-10-28 | Mirror user grant events into memberships (synthwerk#29). |
| 2026-10-29 | The listener also serves the MFA gate (synthwerk#94). |
| 2026-10-30 | Grant events of a deleted account are ignored (synthwerk#41). |
| 2026-10-30 | `cmd/identity/main.go` also starts the `EVT_LLM` consumer of the audit list (synthwerk#39). No change to this feature. |
| 2026-10-30 | Project id from a file written by the bootstrap; grant deactivate and reactivate events set the member status (synthwerk#37). |
| 2026-10-30 | `cmd/identity/main.go` also starts the `EVT_STUDIO` consumer of the audit list (synthwerk#106). No change to this feature. |
