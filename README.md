<p>
<picture>
  <source media="(prefers-color-scheme: light)" srcset="assets/banner/hero-v2-light.svg">
  <img alt="SYNTHWERK-IDENTITY. It knows who you are. And what you paid for. Orgs, roles, entitlements. Status: rewrite." src="assets/banner/hero-v2-dark.svg" width="100%">
</picture>
</p>

<p>
<picture>
  <source media="(prefers-color-scheme: light)" srcset="assets/readme/lead-v2-light.svg">
  <img alt="synthwerk-identity owns organisations, roles, entitlements and the paywall for the synthwerk services. Zitadel says who you are. This service decides what that is worth." src="assets/readme/lead-v2-dark.svg" width="100%">
</picture>
</p>

<p>
<picture>
  <source media="(prefers-color-scheme: light)" srcset="assets/readme/stats-v2-light.svg">
  <img alt="0 LOGIN FORMS WRITTEN HERE. 1 ENTITLEMENTS TABLE FROM STRIPE. 3 CALLERS: STUDIO, WIDGETS, SDK. E2 REWRITE EPIC ON THE MAP" src="assets/readme/stats-v2-dark.svg" width="100%">
</picture>
</p>

## Status

- **Decision:** the rewrite happens in this repo. No restore from `legacy-final`, no archive.
- **Today:** rewrite in progress, epic E2 ([synthwerk#28](https://github.com/VelimirMueller/synthwerk/issues/28)). `main` holds the Go service: orgs, members, roles and the Zitadel user hook. Entitlements and the paywall are planned.
- **Old code:** tag `legacy-final` holds the Kotlin/Quarkus prototype, for history only.

<br>

<p>
<img alt="01 WHAT IT DOES. FRONT DOOR. ALSO THE CASH REGISTER." src="assets/readme/divider-what-v2.svg" width="100%">
</p>

<p>
<picture>
  <source media="(prefers-color-scheme: light)" srcset="assets/readme/features-v2-light.svg">
  <img alt="WHO GETS IN: Organisations, roles and entitlements, owned here. Zitadel v4 does the login: OIDC, passkeys, MFA. WHAT THEY PAID FOR: Stripe events become one entitlements table. The paywall reads that table. WHO ASKS: Studio, widgets and SDK apps call this service. It answers with identity events on the NATS bus" src="assets/readme/features-v2-dark.svg" width="100%">
</picture>
</p>

<p>
<picture>
  <source media="(prefers-color-scheme: light)" srcset="assets/readme/what-v2-light.svg">
  <img alt="Owns the model: Owns organisations, roles and entitlements for every synthwerk service. Login by Zitadel v4: OIDC, passkeys, MFA. No login form lives here. Stripe in, entitlements out: Turns Stripe events into one entitlements table. The paywall reads that table. Identity events: Emits identity events on the NATS bus. The other services trust them" src="assets/readme/what-v2-dark.svg" width="100%">
</picture>
</p>

<br>

<p>
<img alt="02 QUICK START. CLONE. TEST. RUN." src="assets/readme/divider-start-v2.svg" width="100%">
</p>

<p>
<picture>
  <source media="(prefers-color-scheme: light)" srcset="assets/readme/start-v2-light.svg">
  <img alt="Terminal: $ gh repo clone VelimirMueller/synthwerk-identity | $ cd synthwerk-identity | $ just test | # unit and integration tests | # then: go run ./cmd/identity" src="assets/readme/start-v2-dark.svg" width="100%">
</picture>
</p>

<details>
<summary><picture><source media="(prefers-color-scheme: light)" srcset="assets/readme/links-6-v2-light.svg"><img alt="Plain text" src="assets/readme/links-6-v2-dark.svg" width="32%"></picture></summary>

```bash
gh repo clone VelimirMueller/synthwerk-identity
cd synthwerk-identity
just test   # unit and integration tests
```

</details>

## Run locally

The scaffold is Go 1.27. It needs a Postgres URL; migrations apply at startup.

```bash
export SYNTHWERK_IDENTITY_DATABASE_URL="postgres://synthwerk:synthwerk@127.0.0.1:5432/identity"
just test              # go test -race ./...
go run ./cmd/identity  # serves :8080
```

| Variable | Default | Purpose |
| --- | --- | --- |
| `SYNTHWERK_IDENTITY_DATABASE_URL` | none, required | Postgres URL (secret) |
| `SYNTHWERK_IDENTITY_HTTP_ADDR` | `:8080` | Listen address |
| `SYNTHWERK_IDENTITY_EXPORT_SOURCES` | unset | Services asked for the own-data export, `name=url` list, for example `llm=http://llm:8080` |
| `SYNTHWERK_IDENTITY_ACCOUNT_DELETE_MFA_MAX_AGE` | `15m` | Max age of the sign-in with MFA for `DELETE /v1/me` |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | unset | OTLP gRPC collector. Unset = no export |
| `SYNTHWERK_IDENTITY_LOG_LEVEL` | `INFO` | `DEBUG`, `INFO`, `WARN`, `ERROR` |
| `SYNTHWERK_IDENTITY_LOG_FORMAT` | `json` | `console` only in env `local` |

Probes: `GET /healthz` (liveness) and `GET /readyz` (readiness, pings Postgres).
<p>
<picture>
  <source media="(prefers-color-scheme: light)" srcset="assets/readme/startnotes-v2-light.svg">
  <img alt="Go on main: main holds the Go service: orgs, members, roles and the Zitadel user hook. Needs Postgres: SYNTHWERK_IDENTITY_DATABASE_URL is required. Migrations apply at startup. Epic E2 Identity: The rewrite is epic E2 Identity on the synthwerk map (https://github.com/VelimirMueller/synthwerk). It is in progress" src="assets/readme/startnotes-v2-dark.svg" width="100%">
</picture>
</p>

<p align="center">
<a href="https://github.com/VelimirMueller/synthwerk"><picture><source media="(prefers-color-scheme: light)" srcset="assets/readme/links-1-v2-light.svg"><img alt="synthwerk (https://github.com/VelimirMueller/synthwerk)" src="assets/readme/links-1-v2-dark.svg" width="32%"></picture></a>
<a href="https://github.com/VelimirMueller/synthwerk-blueprint"><picture><source media="(prefers-color-scheme: light)" srcset="assets/readme/links-2-v2-light.svg"><img alt="Blueprint (https://github.com/VelimirMueller/synthwerk-blueprint)" src="assets/readme/links-2-v2-dark.svg" width="32%"></picture></a>
<a href="https://github.com/VelimirMueller/synthwerk-identity/tree/legacy-final"><picture><source media="(prefers-color-scheme: light)" srcset="assets/readme/links-3-v2-light.svg"><img alt="legacy-final (https://github.com/VelimirMueller/synthwerk-identity/tree/legacy-final)" src="assets/readme/links-3-v2-dark.svg" width="32%"></picture></a>
</p>

<br>

<p>
<img alt="03 HOW IT WORKS. WHO CHECKS WHOM, IN ORDER." src="assets/readme/divider-how-v2.svg" width="100%">
</p>

<p>
<picture>
  <source media="(prefers-color-scheme: light)" srcset="assets/readme/flow-v2-light.svg">
  <img alt="CLIENTS -&gt; IDENTITY -&gt; ZITADEL V4 -&gt; POSTGRES · NATS. Stripe webhooks come in. One entitlements table comes out." src="assets/readme/flow-v2-dark.svg" width="100%">
</picture>
</p>

<p>
<picture>
  <source media="(prefers-color-scheme: light)" srcset="assets/readme/calls-v2-light.svg">
  <img alt="ZITADEL V4: The login: OIDC, passkeys, MFA. POSTGRES: Orgs, roles, entitlements. NATS BUS: Identity events for the other services" src="assets/readme/calls-v2-dark.svg" width="100%">
</picture>
</p>

<p>
<picture>
  <source media="(prefers-color-scheme: light)" srcset="assets/readme/paywall-v2-light.svg">
  <img alt="STRIPE EVENTS -&gt; ENTITLEMENTS -&gt; THE PAYWALL" src="assets/readme/paywall-v2-dark.svg" width="100%">
</picture>
</p>

<p>
<picture>
  <source media="(prefers-color-scheme: light)" srcset="assets/readme/hownotes-v2-light.svg">
  <img alt="Clients: Clients are synthwerk-studio, synthwerk-widgets and the SDK apps. They ask, identity answers. Stack: Go 1.27" src="assets/readme/hownotes-v2-dark.svg" width="100%">
</picture>
</p>

<br>

<p>
<img alt="04 USAGE. SHORT ON PURPOSE." src="assets/readme/divider-usage-v2.svg" width="100%">
</p>

<p>
<picture>
  <source media="(prefers-color-scheme: light)" srcset="assets/readme/usage-v2-light.svg">
  <img alt="Ecosystem map: synthwerk (https://github.com/VelimirMueller/synthwerk). One repo per role. Start there. Blueprint: Shared CI, lint configs and templates: synthwerk-blueprint (https://github.com/VelimirMueller/synthwerk-blueprint). Renamed: This repo was renamed. The old URL still redirects here. Legacy code: The tag legacy-final keeps the old service: a Kotlin/Quarkus prototype with hard-coded users and no tokens. Branching: main deploys to dev, a vX.Y.Z tag to stg, an approved digest to prd. License: MIT. Copyright 2025 Velimir Müller" src="assets/readme/usage-v2-dark.svg" width="100%">
</picture>
</p>

<br>

<p>
<img alt="05 STATUS. HALF BUILT. CLEARLY LABELLED." src="assets/readme/divider-status-v2.svg" width="100%">
</p>

<p>
<picture>
  <source media="(prefers-color-scheme: light)" srcset="assets/readme/status-v2-light.svg">
  <img alt="Rewrite (epic E2 Identity): in progress. Orgs, members, roles: on main. Zitadel user hook: on main. Entitlements, paywall: planned. legacy-final tag: Kotlin/Quarkus prototype" src="assets/readme/status-v2-dark.svg" width="100%">
</picture>
</p>

<p>
<picture>
  <source media="(prefers-color-scheme: light)" srcset="assets/readme/statuslog-v2-light.svg">
  <img alt="[ STATUS ]: Rewrite in progress, epic E2 identity. [ WORKS ]: Orgs, members, roles. The Zitadel user hook. [ NEXT ]: Entitlements and the paywall" src="assets/readme/statuslog-v2-dark.svg" width="100%">
</picture>
</p>

<p>
<picture>
  <source media="(prefers-color-scheme: light)" srcset="assets/readme/honest-v2-light.svg">
  <img alt="Tests: just test runs unit and integration tests. Changelog: No CHANGELOG yet. Numbers later: Coverage and latency numbers come with the first release" src="assets/readme/honest-v2-dark.svg" width="100%">
</picture>
</p>

<p align="center">
<a href="LICENSE"><picture><source media="(prefers-color-scheme: light)" srcset="assets/readme/links-4-v2-light.svg"><img alt="License (LICENSE)" src="assets/readme/links-4-v2-dark.svg" width="32%"></picture></a>
<a href="https://github.com/VelimirMueller"><picture><source media="(prefers-color-scheme: light)" srcset="assets/readme/links-5-v2-light.svg"><img alt="VM. flagship (https://github.com/VelimirMueller)" src="assets/readme/links-5-v2-dark.svg" width="32%"></picture></a>
</p>

<p>
<picture>
  <source media="(prefers-color-scheme: light)" srcset="assets/readme/footer-v2-light.svg">
  <img alt="VM. studio / flagship · open source · look per vm-brand playbook · MIT © 2025 Velimir Müller · -- EOF -- access granted, eventually --" src="assets/readme/footer-v2-dark.svg" width="100%">
</picture>
</p>
