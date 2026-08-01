# @absolutejs/compliance changelog

## 0.7.0 — 2026-08-01

- Require the unified Dispatch 0.7 messaging contract.
- Include the BSL-1.1 license artifact explicitly in npm releases.

## 0.6.0 — 2026-08-01

- Derive the consent transport type from Dispatch's extensible transport
  registry so adapter-owned channels participate in the same evidence ledger
  and policy without a Compliance release.

## 0.5.0 — 2026-08-01

- Consume Dispatch's provider-neutral `MessagingMessage` contract.
- Derive every consent transport from the primary and fallback routes instead
  of trusting a caller-maintained transport list.
- Move the policy boundary from the legacy SMS channel to messaging.

## 0.4.0 — 2026-08-01

- Scope consent by stable program, purpose, tenant, transport, and recipient.
- Add bounded evidence export and purge contracts for memory and PostgreSQL.

## 0.3.2 — 2026-08-01

- Canonicalize required-RCS recipient addresses to E.164 for consent lookup.

## 0.3.1 — 2026-08-01

- Make consent ingestion idempotent with stable upstream event keys.
- Return consent history newest-first across memory and PostgreSQL stores.

## 0.3.0 — 2026-08-01

- Add an immutable, provider-neutral messaging consent evidence ledger.
- Add memory and Postgres consent stores with an installable SQL schema.
- Add a dispatch authorization policy that blocks missing or revoked consent.
- Scope evidence by tenant, sender, topic, transport, and recipient.

## 0.1.0 — 2026-05-31

Initial release. Closes G14 from the second-pass PaaS audit — the
substrate now has a framework-agnostic compliance layer. SOC2,
HIPAA, ISO 27001, and GDPR all map onto the same primitives; the
specific framework controls live in the control plane, not here.

### Added

- **`createCompliancePolicy({ classifications, tenantOverrides? })`**
  — declarative policy: per-class retention + residency + erasure-
  exempt flag + open `flags` bag. Tenant overrides merge over class
  defaults so GDPR-strict tenants can ride a default-US platform.
- **`createResidencyGuard(policy)`** — pure check function. Throws
  `ResidencyViolation` on mismatch; `inspect()` is the non-throwing
  variant. Unknown classes pass through (caller can opt in to
  strict mode by listing every class).
- **`runRetention({ policy, scanners, deleters, audit?, ... })`** —
  streams expired records through deleters in batches (default
  500). Per-scanner failure isolation. `dryRun: true` counts
  without deleting. Optional audit broker logs a
  `'compliance.retention.swept'` event per class. `Infinity`
  retention is skipped entirely (no scan).
- **`runSubjectAccess({ subject, collectors })`** — composes
  collectors across packages into one bundle. Collectors return
  arrays, async iterables, or single objects (auto-wrapped).
  Per-collector failure isolation.
- **`runErasure({ policy, subject, erasers, audit?, ... })`** —
  routes to `eraser.erase` for normal classes, to
  `eraser.anonymize` for `erasureExempt` classes. Skipped when
  neither is provided. Audit broker logs the erasure with subject +
  mode breakdown. `dryRun` returns the plan without mutation.
- **`collectEvidence({ policy, period, sources })`** — bundles
  arbitrary JSON-serializable evidence into a single auditor-ready
  structure. Ships with `auditEvidenceSource(broker)` for the
  typical "all audit events in the period" case.

### Design notes

- Substrate is intentionally framework-agnostic. Mapping
  classifications + audit kinds onto SOC2 CC6.1 / HIPAA 164.316 /
  ISO 27001 A.18.1 / GDPR Art. 32 lives in the control plane.
- All orchestrators isolate per-adapter failures into `report.errors`
  rather than aborting — a SAR over five collectors shouldn't fail
  because one table is offline.
- All audit-broker calls are wrapped in try/catch so a broken broker
  doesn't break the sweep / erasure / SAR.
- Tenant override resolution is shared across guard / retention /
  erasure so the same policy expression behaves consistently
  everywhere.

### Tests

37 covering: policy validation (id-key match, retentionMs bounds,
Infinity); override resolution (base, tenant-scoped, unknown);
residency guard (throw on mismatch, pass on match, tenant flip,
no-constraint passthrough, unknown-class no-op, inspect variant,
tenant in violation message); retention (batching, Infinity skip,
unknown class, missing deleter, scanner failure isolation, dryRun,
audit broker emission, tenant-override cutoff); SAR (sync + async +
iterable returns, failure isolation, singleton wrap); erasure
(erase + anonymize routing, exempt-no-anonymize → skipped, audit
emission, eraser failure isolation, dryRun, tenant-override flip);
evidence (bySource keying, source failure isolation, policy +
period passthrough); auditEvidenceSource (read filtering, missing-
read error).

### License

BSL-1.1 with named carveout against hosted compliance / GRC SaaS
(Vanta, Drata, Secureframe, OneTrust, TrustCloud, Sprinto). Change
date: 2030-05-31 (Apache 2.0).
