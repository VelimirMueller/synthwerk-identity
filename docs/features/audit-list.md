---
title: Audit list
slug: audit-list
status: beta
epic: E4
owner: identity
paths: ["internal/audit/**", "migrations/0009_member_status_audit.sql", "internal/app/app.go", "cmd/identity/main.go", "tests/support/containers/**", "tests/unit/audit/**", "tests/integration/audit/**"]
api: ["GET /v1/orgs/{orgId}/audit-events"]
events: ["dev.synthwerk.llm.ai_settings.changed.v1", "dev.synthwerk.studio.page.created.v1", "dev.synthwerk.studio.page.published.v1", "dev.synthwerk.studio.page.rolled_back.v1"]
mcp: []
updated: 2026-10-30
---

# Audit list

> **In 30 seconds**
> - The audit list shows the admin actions of an org, newest first (synthwerk#37).
> - It is built on the outbox: every identity event of an org is also copied to `identity.audit_events`, in the same transaction.
> - It also shows the AI settings changes of llm (synthwerk#39). Identity reads them from the stream `EVT_LLM`; they show a few seconds after the change.
> - It also shows the page builder changes of studio: create, publish, roll back (synthwerk#106). Identity reads them from `EVT_STUDIO`, the same way.
> - Owner and admin of the org read it. A member and an operator get 403.

## What it does

- A trigger on `identity.synthwerk_outbox` copies each new row to `identity.audit_events` when the event type starts with `dev.synthwerk.identity.` and its `orgid` is a known org.
- The copy holds the event id, type, actor, subject, time and data. The data follows the event schema: ids and roles, no email.
- The outbox deletes published rows after 7 days. The audit rows stay.
- Each start with migration 0007 copies the outbox rows that still exist; a bad row is skipped with a warning.
- A JetStream consumer copies each valid `dev.synthwerk.llm.ai_settings.changed.v1` from `EVT_LLM` to `identity.audit_events` (synthwerk#39). The row holds the event id, the full type, actor, subject (the org id), time and `data` as received. The data has no prompt text: only its length.
- llm owns `EVT_LLM`. Identity never creates or changes it. While it is missing, the consumer retries (1 s to 1 min), logs WARN, and `/readyz` shows `llm_ai_settings` degraded. Identity keeps running. The consumer attaches when llm creates the stream, and reads every event from the start.
- A second consumer copies `dev.synthwerk.studio.page.created.v1`, `page.published.v1` and `page.rolled_back.v1` from `EVT_STUDIO` (synthwerk#106). Same rules as the llm consumer (`internal/audit/consumer.go`). The subject is the page id; `data` holds org id, page id, slug, locale and the versions, never page content. Studio owns `EVT_STUDIO`; `/readyz` shows `studio_pages` degraded until studio creates it.
- `GET /v1/orgs/{orgId}/audit-events` reads the list, newest first, with cursor paging.

## How to use

1. Call `GET /v1/orgs/{orgId}/audit-events?limit=50` with the token of an owner or admin.
2. Pass `next_cursor` as `cursor` for the next, older page.
3. Show unknown event types with type, time and actor. New identity events appear without a change here.
4. Set `SYNTHWERK_IDENTITY_NATS_URL` to get the llm AI settings changes and the studio page changes. Unset: the list shows identity events only. The NATS user needs consumer rights on `EVT_LLM` and `EVT_STUDIO`.

## Rules and limits

| Rule | Value |
|---|---|
| Access | Token role owner or admin in the org, then the stored membership: active owner or admin |
| Operator | 403 |
| Other org | 404, same as unknown |
| Order | Newest first (`seq`, the insert order). An llm change gets its `seq` when it arrives, a few seconds after the change |
| Page size | 1 to 100, default 50; cursor = base64url of the last `seq` |
| `member.invited`, `member.invite_revoked` | Invitation id and role only: the same for a new email and for a user of another org |
| Events | `org.created`, `member.invited`, `member.invite_revoked`, `member.role_changed`, `member.deactivated`, `member.reactivated`, `app.created`, `org.entitlements_changed`, later org events of identity, `dev.synthwerk.llm.ai_settings.changed.v1`, and `dev.synthwerk.studio.page.{created,published,rolled_back}.v1` |
| llm consumer | Durable `identity-llm-ai-settings` on `EVT_LLM`, filter `evt.llm.ai_settings.changed.v1`, deliver all, explicit ack, ack wait 30 s, max 16 pending. Replicas share it |
| studio consumer | Durable `identity-studio-pages` on `EVT_STUDIO`, filters `evt.studio.page.created.v1`, `evt.studio.page.published.v1`, `evt.studio.page.rolled_back.v1` (other studio subjects stay in the stream), same delivery settings |
| studio event checks | Kit envelope rules; one of the three types; `data` strict per type (`page.created` has no version; publish and roll back need `version` ≥ 1 and `previous_version` null or ≥ 1); slug and locale as the schema; `orgid` = `data.org_id`, `subject` = `data.page_id`; `actor` = `user:<sub>` |
| Stored `data` | A new JSON object of the checked fields with the schema key names, never the received bytes: Go's decoder matches keys without case and keeps the last duplicate, so the raw data could hold a value no check saw (llm and studio) |
| llm event checks | Kit envelope rules; exact type; `data` strict (no unknown field, every schema rule); `orgid` = `subject` = `data.org_id`; `actor` = `user:[A-Za-z0-9_-]{1,128}` |
| Malformed llm event | Terminated, no row, WARN that names the rule, never a value |
| llm event of an unknown org | Acked, no row, INFO. A deleted org is unknown |
| Database error | Nak with a delay that doubles per delivery, 1 s to 1 min. The event comes back until it is stored |
| Repeat llm event | Acked, no new row (`ON CONFLICT (id) DO NOTHING`) |
| llm consumer logs | Event id only. No user sub, no setting value |
| Refusals | Not listed: a refused change writes no event |
| Org delete | The audit rows go with the org (`ON DELETE CASCADE`) |
| Account delete (#41) | Rows of other orgs stay; the user becomes `deleted-user` in `actor`, `subject`, `data.user_sub` and `data.owner_sub`. This includes llm and studio rows. An llm or studio event of a deleted user that arrives later is stored with actor `user:deleted-user`. Both consumers and the delete take the same user lock (`account.LockUser`): a row written during a delete never keeps the clear sub |
| Retention | No end yet (follow-up) |

## Errors

| Status | Problem type | Cause |
|---|---|---|
| 400 | `invalid_request` | Bad `limit` or `cursor`. |
| 401 | `unauthenticated` | Token missing or not valid. |
| 403 | `forbidden` | Not an active owner or admin of the org. |
| 404 | `not_found` | Unknown org, or not the caller's org. |

## Tests

- `tests/unit/audit/audit_test.go` — `ListAuditEvents - owner, two pages - newest first, cursor walks back`, `ListAuditEvents - operator - Forbidden`, `ListAuditEvents - admin token, stored role member - Forbidden`, `ListAuditEvents - cursor=MA - 400`
- `tests/unit/audit/aisettings_test.go` — `ParseAISettings - contract example - org, actor, sub, time and the data as received`, `ParseAISettings - each broken event - ErrMalformed, and the error holds no value of the event`, `Handle - valid event - record, then ack`, `Handle - malformed event - Term`, `Handle - unknown org - ack`, `Handle - database error - Nak with a delay that doubles per delivery`, `JetStreamConfig - defaults`, `Ready - not attached - /readyz is degraded`
- `tests/unit/audit/studio_test.go` — `ParseStudioPage - the three contract examples - valid`, `ParseStudioPage - each broken event - ErrMalformed, and the error holds no value of the event`, `Handle - valid studio event - record with its type, then ack`, `Handle - malformed studio event - Term`, `Handle - database error - Nak with a delay`, `StudioJetStreamConfig - defaults - own durable on exactly the three page subjects`, `Ready - studio consumer not attached - /readyz degraded`
- `tests/integration/audit/studio_test.go` — `Consumer - EVT_STUDIO missing at start - waits and never creates it, attaches once studio creates it; create, publish and roll back are the newest audit events; a repeat, a malformed event, an unknown org and another studio subject add no row; after an account delete the rows and a late event show deleted-user`
- `tests/integration/audit/aisettings_test.go` — `Consumer - EVT_LLM missing at start - waits with WARN and never creates it, attaches once llm creates it; a change is the newest audit event; a repeat, a malformed event and an unknown org add no row and leave nothing pending; after an account delete the change and a late change show deleted-user`, `Record and account Delete - run at the same time, 20 users - no row keeps the clear actor`
- `tests/integration/orgs/members_test.go` — `Migrate - outbox row with a bad time - skipped with a warning, start not blocked`, `Audit - admin changes a role - change is the newest audit event with actor and old and new role`, `Invite - new email and user of another org - same answer, same members list, same invitation, same audit event`

## Changes

| Date | Change |
|---|---|
| 2026-10-30 | First version (synthwerk#37). |
| 2026-10-30 | The list also shows `llm.ai_settings.changed.v1`, read from `EVT_LLM` by a durable consumer; `/readyz` check `llm_ai_settings` (synthwerk#39). |
| 2026-10-30 | The list also shows the studio page events `page.created`, `page.published`, `page.rolled_back`, read from `EVT_STUDIO` by the durable consumer `identity-studio-pages`; `/readyz` check `studio_pages`; one consumer code for every source (synthwerk#106). |
| 2026-10-30 | Both consumers store a re-encoded copy of the checked `data`, not the received bytes (security review, synthwerk#106). |
