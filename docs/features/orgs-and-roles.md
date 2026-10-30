---
title: Orgs and roles
slug: orgs-and-roles
status: beta
epic: E2
owner: identity
paths: ["internal/orgs/**", "internal/zitadel/**", "internal/app/**", "migrations/0003_orgs_members.sql", "migrations/0009_member_status_audit.sql", "cmd/identity/main.go"]
api: ["GET /v1/me", "GET /v1/orgs/{orgId}", "GET /v1/orgs/{orgId}/members", "POST /v1/orgs/{orgId}/members", "GET /v1/orgs/{orgId}/invitations", "DELETE /v1/orgs/{orgId}/invitations/{invitationId}", "PATCH /v1/orgs/{orgId}/members/{userId}", "POST /v1/orgs/{orgId}/members/{userId}:deactivate", "POST /v1/orgs/{orgId}/members/{userId}:reactivate"]
events: ["dev.synthwerk.identity.org.created.v1", "dev.synthwerk.identity.member.role_changed.v1", "dev.synthwerk.identity.member.invited.v1", "dev.synthwerk.identity.member.invite_revoked.v1", "dev.synthwerk.identity.member.deactivated.v1", "dev.synthwerk.identity.member.reactivated.v1"]
mcp: []
updated: 2026-10-30
---

# Orgs and roles

> **In 30 seconds**
> - An org is a Zitadel org. Its members have one org role: `owner`, `admin` or `member`. `operator` is a platform role, never a member row.
> - Owner and admin change roles; a member gets 403. An active org always has an owner.
> - Identity writes `org.created` and `member.role_changed` to the outbox in the same transaction as the change (synthwerk#29).
> - Owner and admin invite members by email and deactivate or reactivate them (synthwerk#37). A deactivated member keeps the row and the role, but has no access.

## What it does

- Mirrors the Zitadel user grants of project `synthwerk-api` into `identity.memberships` (hook events `user.grant.added|changed|removed|cascade.removed`).
- An org row appears with its first grant. It stays `pending` until its first owner; then it turns `active` and identity writes `org.created` and the free plan (`docs/features/entitlements.md`) in the same transaction.
- `PATCH /v1/orgs/{orgId}/members/{userId}` changes a role: membership, outbox row and Zitadel user grant in one transaction. Zitadel refuses: rollback, 502.
- A grant changed directly in Zitadel updates the mirror and writes `member.role_changed` with actor `system`.
- `POST /v1/orgs/{orgId}/members` invites by email and answers 202 with a pending invitation (`identity.invitations`, with the typed email) and `member.invited` (invitation id, no email, no subject id).
- New email: identity also creates the Zitadel user and its grant, and Zitadel sends the invite mail. The member row is `invited`: not listed, no stored role.
- User of another org: only the invitation; it stays pending (cross-org join is not supported yet). Answer, invitation list, audit event and members list look the same as for a new email: no account enumeration.
- The first call of the invitee with a token of the org (org route or `GET /v1/me`) makes the row `active` and the invitation no longer pending.
- `GET /v1/orgs/{orgId}/invitations` lists pending invitations (owner or admin).
- A repeat invite of an email with a pending invitation (any case) answers 202 with that invitation, unchanged. No Zitadel call, no event: the answer never shows whether the first invite made a user.
- `DELETE /v1/orgs/{orgId}/invitations/{invitationId}` revokes a pending invitation (owner or admin; only owner for an `owner` invitation): `revoked_at` is set, the `invited` row is deleted, the Zitadel user identity made for it is deleted, `member.invite_revoked` is written. A revoked invitation is never accepted. When the invitee is an active or deactivated member by now, only the invitation is revoked: the member row and the Zitadel user stay, and only an owner revokes when that member is an owner.
- `POST /v1/orgs/{orgId}/members/{userId}:deactivate` and `:reactivate` set `status` on the row, write `member.deactivated` or `member.reactivated` and switch the Zitadel user grant off or on, in one transaction.
- A deactivated member fails every stored-role check (members list, role change, apps, widget token, audit list). Every route behind the org gate (`GET /v1/orgs/{orgId}`, apps, audit list) and both entitlements routes also need an active stored membership: a deactivated member with a token that still has the role gets 404, the same as an unknown org.
- The outbox relay publishes to stream `EVT_IDENTITY` (`evt.identity.>`), which identity creates at start.

## How to use

1. Set `SYNTHWERK_IDENTITY_OIDC_ISSUER` (and `OIDC_AUDIENCE`, `JWKS_URL`). Unset: the org routes are off.
2. Set `SYNTHWERK_IDENTITY_ZITADEL_API_URL`, `ZITADEL_HOST`, `ZITADEL_PAT_FILE`, `ZITADEL_PROJECT_ID` so role changes reach Zitadel. Unset: changes stay in identity (warning at start).
3. Set `SYNTHWERK_IDENTITY_PLATFORM_ORG_ID` to the Zitadel org that grants `operator`.
4. Set `SYNTHWERK_IDENTITY_NATS_URL` to publish the outbox. Unset: rows stay in the outbox.
5. Invites need the Zitadel client and, for `identity-sync`, the org role `ORG_USER_MANAGER` in each customer org (user create and invite code). `PROJECT_GRANT_OWNER` (ADR-0003) covers the user grant and deactivate only. Without it, an invite answers 502 and nothing changes.

## Rules and limits

| Rule | Value |
|---|---|
| Check order | token → org from path → token role (first gate) → stored role (wins) → rule table |
| Stale token | Writes and `listMembers` check the stored role: a demoted admin gets 403 with the old token |
| Set `admin`/`member` | owner or admin; target is not an owner |
| Grant `owner`, change an owner | owner only |
| Own role | 409 `own_role` |
| Last owner | 409 `last_owner`; a deferred trigger guards the commit too. Only active owners count |
| Invite | owner or admin; only owner invites `owner`; active or deactivated member: 409 `member_exists`; pending invitation for the email: 202 with it; a user of the org without a membership: pending invitation like a foreign email; 10 per caller and 30 per org per hour, per process: 429 `rate_limited` with `Retry-After` |
| Failed commit after a Zitadel write | Fail closed. Deactivation and downgrade stay in Zitadel; a retry repairs the row. Reactivation and upgrade are undone only when a re-read shows the old row. Invite deletes the new Zitadel user only when the invitation is not stored. Revoke deletes the Zitadel user before the commit (fail closed; `orgs.revoke_drift`). Drift is logged at WARN (`orgs.status_drift`, `orgs.role_drift`, `orgs.invite_drift`) |
| Deactivate, reactivate | owner or admin; only owner on an owner; own membership: 409 `own_membership`; last active owner: 409 `last_owner`; same status again: 200, no event |
| Deactivated member | Row and role stay; Zitadel grant inactive; no stored role for any check |
| Operator | GET any active org and its members; PATCH 403 |
| Org not visible to the caller | 404, same as unknown |
| Zitadel writes | Machine user `identity-sync`, `PROJECT_GRANT_OWNER` per project grant, no instance role. Never the platform org, never a grant with `operator`, never the role `operator` (refused before any write). |
| Page size | 1 to 100, default 50, cursor = base64url of the last `user_id` |

## Events

| Type | When |
|---|---|
| `dev.synthwerk.identity.org.created.v1` | An org got its first owner. |
| `dev.synthwerk.identity.member.role_changed.v1` | A member's org role changed (API: actor `user:<sub>`; Zitadel: actor `system`). Refusals write nothing. |
| `dev.synthwerk.identity.member.invited.v1` | An owner or admin invited an email. Invitation id and role, no email, no subject id. |
| `dev.synthwerk.identity.member.invite_revoked.v1` | An owner or admin revoked a pending invitation. Invitation id and role. |
| `dev.synthwerk.identity.member.deactivated.v1` | An owner or admin deactivated a member. |
| `dev.synthwerk.identity.member.reactivated.v1` | An owner or admin reactivated a member. |

## Errors

| Status | Problem type | Cause |
|---|---|---|
| 400 | `invalid_request` | Body is not `{"role": owner, admin or member}`, an invite body is not `{"email", "role"}`, or bad paging. |
| 401 | `unauthenticated` | Token missing or not valid. |
| 403 | `forbidden` | Role does not allow the call. Generic body. |
| 404 | `not_found` | Unknown org or member, or no access to the org. |
| 409 | `own_role`, `last_owner`, `own_membership`, `member_exists` | Rule refused the change. |
| 429 | `rate_limited` | Too many invites. |
| 502 | `upstream_unavailable` | Zitadel did not take the change, or no Zitadel client for an invite. Nothing changed. |

## Tests

- `tests/unit/apps/http_test.go` — `CreateWidgetToken - deactivated member, token still has the role - 404 even on a listed origin`, `ListApps - deactivated member, token still has the role - 404`; `tests/unit/entitlements/http_test.go` — `<route> - deactivated member, token still has the role - 404 not_found`; `tests/integration/apps/apps_test.go` — `Deactivated member, token still has the role - widget token, ListApps, GetApp and GetOrg 404`
- `tests/unit/orgs/roles_test.go` — `Authorize - member changes role - denied`, `Authorize - admin grants owner - denied`, `Authorize - owner grants owner - allowed`, `Authorize - owner demotes self as last owner - conflict`, `Claims - roles claim with several roles - highest role wins`, `Operator - is_operator - never an org role`
- `tests/integration/orgs/orgs_test.go` — `ChangeRole - success - membership and outbox row in one commit, Zitadel grant written`, `ChangeRole - Zitadel fake fails - mirror rolled back, no event`, `ChangeRole - last owner demoted - rejected, row unchanged`, `ChangeRole - two parallel demotions of two owners - one succeeds`, `Action org created - same event twice - one org, one owner`
- `tests/integration/orgs/orgs_test.go` — `PATCH member - member token - 403 generic body`, `PATCH member - owner token - 200`, `PATCH member - token of other org - 404`, `PATCH member - forged token - 401`, `ListMembers - admin demoted, old admin token - 403`
- `tests/unit/zitadelhook/grant_test.go` — `user.grant.added - platform org - dropped, platform users are never members`
- `tests/unit/zitadel/client_test.go` — `SetRole - platform org, operator grant or operator role - refused, no write`
- `tests/unit/orgs/members_test.go` — `AuthorizeStatus - admin deactivates owner - denied`, `AuthorizeInvite - admin invites owner - denied`, `InviteMember - admin, valid body - 202 with the pending invitation, no subject id`, `InviteMember - 11th invite of one caller in an hour - 429 rate_limited with Retry-After, no write`, `Member writes - store says <code> - <status>`
- `tests/unit/zitadel/client_test.go` — `Invite - new email - user, invite mail, grant of the project grant with the role`, `Invite - email of a user of this org - ErrMemberExists with the user id, no invite mail`, `Uninvite - user gone already (404) - no error`, `SetActive - grant with operator or platform org - refused, no write`
- `tests/integration/orgs/members_test.go` — `Invite - repeat invite of a pending new and a pending foreign email - same invitation back, no Zitadel call, no event`, `Invite - active or deactivated member - member_exists, nothing written`, `Revoke - new email - invitation revoked, invited row deleted, Zitadel user deleted, event and audit, never accepted`, `Revoke - invitee is now an active owner - admin forbidden; owner revokes the invitation only, row and Zitadel user kept`, `Revoke - admin on an owner invitation, member, deactivated admin - forbidden, still pending`, `Revoke - Zitadel refuses - upstream error, invitation and invited row kept, no event`, `Invite - new email and user of another org - same answer, same members list, same invitation, same audit event`, `Invite - invitee signs in and calls the org - active, listed, invitation no longer pending`, `Deactivate - commit lost - Zitadel grant stays deactivated, row still active`, `Reactivate - commit error after the commit - row active, Zitadel grant not switched back`, `ChangeRole - upgrade, commit lost - Zitadel set back; downgrade, commit lost - Zitadel keeps the lower role`, `Deactivate - admin deactivates member - row kept with role, no stored role, event, audit, Zitadel grant off`, `Trigger - deactivate the only owner directly in SQL - commit refused`, `Migrate - second start - no error, audit backfill adds no duplicate, owner guard counts active owners`

## Changes

| Date | Change |
|---|---|
| 2026-10-28 | First version (synthwerk#29). |
| 2026-10-28 | Least privilege: org name from the grant, platform org and operator refused before any Zitadel write. |
| 2026-10-29 | The org gate and the problem writer are exported for the app routes (`internal/orgs/access.go`, synthwerk#30). |
| 2026-10-29 | Activation also writes the free plan and `org.entitlements_changed` (synthwerk#31). |
| 2026-10-30 | Invite, deactivate and reactivate members; member `status`; owner guard counts active owners (synthwerk#37). |
| 2026-10-30 | Pending invitations, no account enumeration, invite rate limit, fail-closed repair after a failed commit (synthwerk#37 security review). |
| 2026-10-30 | Repeat invite returns the pending invitation; revoke a pending invitation; `member_exists` only for listed members (synthwerk#37 security review). |
| 2026-10-30 | The org gate and the entitlements routes need an active stored membership: a deactivated member with an old token gets 404 (synthwerk#37 security review). |
| 2026-10-30 | `/readyz` has the not-critical check `llm_ai_settings`: the `EVT_LLM` consumer of the audit list (synthwerk#39, `docs/features/audit-list.md`). |
