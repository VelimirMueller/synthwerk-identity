---
title: Audit list
slug: audit-list
status: beta
epic: E4
owner: identity
paths: ["internal/audit/**", "migrations/0009_member_status_audit.sql"]
api: ["GET /v1/orgs/{orgId}/audit-events"]
events: []
mcp: []
updated: 2026-10-30
---

# Audit list

> **In 30 seconds**
> - The audit list shows the admin actions of an org, newest first (synthwerk#37).
> - It is built on the outbox: every identity event of an org is also copied to `identity.audit_events`, in the same transaction.
> - Owner and admin of the org read it. A member and an operator get 403.

## What it does

- A trigger on `identity.synthwerk_outbox` copies each new row to `identity.audit_events` when the event type starts with `dev.synthwerk.identity.` and its `orgid` is a known org.
- The copy holds the event id, type, actor, subject, time and data. The data follows the event schema: ids and roles, no email.
- The outbox deletes published rows after 7 days. The audit rows stay.
- Each start with migration 0007 copies the outbox rows that still exist; a bad row is skipped with a warning.
- `GET /v1/orgs/{orgId}/audit-events` reads the list, newest first, with cursor paging.

## How to use

1. Call `GET /v1/orgs/{orgId}/audit-events?limit=50` with the token of an owner or admin.
2. Pass `next_cursor` as `cursor` for the next, older page.
3. Show unknown event types with type, time and actor. New identity events appear without a change here.

## Rules and limits

| Rule | Value |
|---|---|
| Access | Token role owner or admin in the org, then the stored membership: active owner or admin |
| Operator | 403 |
| Other org | 404, same as unknown |
| Order | Newest first (`seq`, the insert order) |
| Page size | 1 to 100, default 50; cursor = base64url of the last `seq` |
| `member.invited`, `member.invite_revoked` | Invitation id and role only: the same for a new email and for a user of another org |
| Events | `org.created`, `member.invited`, `member.invite_revoked`, `member.role_changed`, `member.deactivated`, `member.reactivated`, `app.created`, `org.entitlements_changed`, and later org events of identity |
| Refusals | Not listed: a refused change writes no event |
| Retention | No end yet. Delete per user (#41) is open |

## Errors

| Status | Problem type | Cause |
|---|---|---|
| 400 | `invalid_request` | Bad `limit` or `cursor`. |
| 401 | `unauthenticated` | Token missing or not valid. |
| 403 | `forbidden` | Not an active owner or admin of the org. |
| 404 | `not_found` | Unknown org, or not the caller's org. |

## Tests

- `tests/unit/audit/audit_test.go` — `ListAuditEvents - owner, two pages - newest first, cursor walks back`, `ListAuditEvents - operator - Forbidden`, `ListAuditEvents - admin token, stored role member - Forbidden`, `ListAuditEvents - cursor=MA - 400`
- `tests/integration/orgs/members_test.go` — `Migrate - outbox row with a bad time - skipped with a warning, start not blocked`, `Audit - admin changes a role - change is the newest audit event with actor and old and new role`, `Invite - new email and user of another org - same answer, same members list, same invitation, same audit event`

## Changes

| Date | Change |
|---|---|
| 2026-10-30 | First version (synthwerk#37). |
