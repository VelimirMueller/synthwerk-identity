---
title: Zitadel Action hook
slug: zitadel-hook
status: beta
epic: E2
owner: identity
paths: ["internal/zitadelhook/**", "migrations/0002_zitadel_event_seen.sql", "cmd/identity/main.go"]
api: []
events: ["dev.synthwerk.identity.user.created.v1"]
mcp: []
updated: 2026-10-23
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
- Never decodes or logs `event_payload` (email, names).

## How to use

1. Set `SYNTHWERK_IDENTITY_ZITADEL_SIGNING_KEY_FILE`. Without it, the listener does not start.
2. Register the target and the execution in Zitadel. synthwerk-infra `zitadel-bootstrap` does this and writes the key file.

## Rules and limits

| Rule | Value |
|---|---|
| Body | 64 KiB max |
| Signature age | 300 s, both directions |
| Other event types | 204, ignored |
| Exposure | Only the compose network `zitadel-hooks` (alias `identity-hooks`). The edge routes `/identity/*` to `:8080`. |

## Events

| Type | When |
|---|---|
| `dev.synthwerk.identity.user.created.v1` | Zitadel created a human user. |

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
- synthwerk-infra `tests/stack/stack_test.sh` — `test users from the bootstrap - user.created rows in the outbox; hook path through the edge - 404`

## Changes

| Date | Change |
|---|---|
| 2026-10-23 | First version (synthwerk#28 task 5). |
