---
title: MFA gate
slug: mfa-gate
status: beta
epic: E2
owner: identity
paths: ["internal/mfagate/**", "internal/zitadel/client.go", "migrations/0005_mfa_evidence.sql", "cmd/identity/main.go"]
api: []
events: []
mcp: []
updated: 2026-10-29
---

# MFA gate

> **In 30 seconds**
> - Zitadel asks identity before it finishes a sign-in. Identity refuses a session without a second factor, so no token exists for it.
> - Access tokens of gated sign-ins carry `amr`, so `kit/auth` `RequireMFA` works on Zitadel tokens (synthwerk#94, synthwerk-infra ADR-0004).

## What it does

- Serves `POST /internal/zitadel/mfa-gate` on the hook address: a Zitadel request execution on every call that finishes a sign-in (`mfagate.GatedMethods`: OIDC v2 and v2beta `CreateCallback`, device authorization, SAML `CreateResponse`).
- Reads the session with its token: `SessionService/GetSession` over Connect (POST body, so the token is in no URL), as `identity-sync`.
- Maps the factors to `amr` with Zitadel's own rule: passkey with user verification = 2 factors, every other check = 1; 2 or more = `mfa`.
- No `mfa`: answers `{"forwardedStatusCode":403,"forwardedErrorMessage":"mfa_required: …"}`. Zitadel returns 403 to the caller and issues no code.
- `mfa`: stores the evidence (user, session id, `amr`, time) in `identity.mfa_evidence` and answers 204.
- An error callback or a device deny passes: it ends the flow without a token. Any other call without a session, or an unknown method, is refused.
- Serves `POST /internal/zitadel/token-claims`: the `preaccesstoken` function. It adds `amr` from the user's newest evidence when it is at most `SYNTHWERK_IDENTITY_MFA_EVIDENCE_MAX_AGE` old (default 12 h).

## How to use

1. Set `SYNTHWERK_IDENTITY_MFA_GATE_KEY_FILE`, `SYNTHWERK_IDENTITY_TOKEN_CLAIMS_KEY_FILE` and the Zitadel client (`ZITADEL_API_URL`, `ZITADEL_PAT_FILE`). The gate needs the hook listener (`ZITADEL_SIGNING_KEY_FILE`).
2. synthwerk-infra `zitadel-bootstrap` with `SYNTHWERK_ZITADEL_MFA_GATE=true` creates both targets, the executions and the key files.
3. Mount `auth.RequireMFA()` on routes that need a sign-in with MFA.

## Rules and limits

| Rule | Value |
|---|---|
| Fail closed | Gate key missing, signature wrong, Zitadel unreachable: no 2xx answer, Zitadel refuses the sign-in. |
| Gate key set, no Zitadel client | identity does not start. |
| Evidence write fails | Sign-in passes, the token gets no `amr`, ERROR log `mfa_gate.store_failed`. |
| `amr` binding | The `amr` of the user's newest gated sign-in, not of the exact session behind the token: Zitadel shows no session to the function. The gate refuses every sign-in without a second factor. |
| Refresh tokens | `amr` only while the newest gated sign-in is at most 12 h old. |
| Machine users | No evidence, no `amr`. |
| Identity provider | Zitadel's rule counts an IdP sign-in (intent) as one factor: password plus IdP = `["pwd","mfa"]`. No IdP is set up today. |
| Zitadel answers 401 to identity-sync | Config error: 503, not a refusal per user. |
| Logs | Never the session token. `enduser.id`, method, `amr`, reason. |
| Body | 256 KiB max. Signature as in [zitadel-hook](zitadel-hook.md), own key per target. |

## Events

| Type | When |
|---|---|
| None. | |

## Errors

| Status | Problem type | Cause |
|---|---|---|
| 200 + forwarded 403 | `mfa_required` | Session without a second factor, refused or missing session, unknown method. |
| 401 | `unauthorized` | Signature missing, wrong, or older than 300 s. |
| 400 | `bad request` | Body is not a Zitadel call. |
| 503 | `unavailable` | Key file missing, or the session could not be read. Zitadel refuses the sign-in. |

## Tests

- `tests/unit/mfagate/mfagate_test.go` — `AMR - password only, password and TOTP, passkey, U2F, TOTP only, identity provider only`
- `tests/unit/mfagate/mfagate_test.go` — `CreateCallback - password-only session - refused with 403, no evidence, no token in logs`; `passkey / password and TOTP session - passes unchanged, evidence stored`
- `tests/unit/mfagate/mfagate_test.go` — `every gated method - refused`; `error callback or device deny - passes`; `no session, unknown method, wrong token - refused`; `Zitadel unreachable - 503`; `unsigned, wrong key, old signature, GET - no session read`
- `tests/unit/mfagate/mfagate_test.go` — `pre-access-token - fresh evidence - amr appended; none, old, store error, pre-userinfo, other user - no amr`
- `tests/unit/zitadel/session_test.go` — `Session - factors read, token in the body; wrong token or no verified user - ErrSessionRefused`
- `tests/integration/mfagate/evidence_test.go` — `Record twice - newer replaces older; an older check never replaces a newer one`
- synthwerk-e2e `tests/auth/mfa-gate.spec.ts` — `session API - password only - no token; plus TOTP - token with amr mfa`

## Changes

| Date | Change |
|---|---|
| 2026-10-29 | First version (synthwerk#94). |
