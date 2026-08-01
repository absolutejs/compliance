# `@absolutejs/compliance`

> Framework-agnostic compliance substrate for the AbsoluteJS PaaS.

`@absolutejs/compliance` gives a control plane composable
primitives. None of them know about a specific framework — SOC2,
HIPAA, ISO 27001, and GDPR all map onto the same shape.

## Messaging consent

The messaging consent ledger records immutable grant/revocation evidence at an
exact tenant, program, purpose, transport, and recipient scope. Memory and
Postgres stores are included. Its dispatch policy blocks messages before an
adapter or provider call when evidence is missing or revoked.

```ts
const store = createPostgresMessagingConsentStore(postgres);
const consent = createMessagingConsentLedger({ audit, store });

await consent.grant(
  {
    recipient: "+12025550100",
    programId: "acme-incident-alerts",
    purpose: "incident-alerts",
    tenant: "tenant-a",
    transport: "sms",
  },
  { at: Date.now(), reference: "signup-42", source: "signup-form" },
);

const dispatcher = createDispatcher({
  policies: [createMessagingConsentDispatchPolicy({ ledger: consent })],
  sms,
});
```

Apply `MESSAGING_CONSENT_POSTGRES_SCHEMA` once before using the Postgres
store. Provider adapters can write signed opt-in/opt-out callbacks into the
same ledger.

## Primitives

### 1. `createCompliancePolicy({ classifications, tenantOverrides? })`

Declarative shape. Each classification gets a stable id,
retention window, optional residency region, optional
`erasureExempt` flag, and an open `flags` bag.

```ts
const policy = createCompliancePolicy({
  classifications: {
    pii:       { id: 'pii', retentionMs: 730 * DAY, residency: 'eu' },
    'audit-log': {
      id: 'audit-log',
      retentionMs: Infinity,
      erasureExempt: true,  // SOX / many regulators require 7+ years
      flags: { immutable: true },
    },
    operational: { id: 'operational', retentionMs: 90 * DAY },
  },
  tenantOverrides: {
    'gdpr-strict-tenant': { pii: { retentionMs: 90 * DAY } },
  },
});
```

### 2. `createResidencyGuard(policy)`

Pure check. The runtime, sync, queue, and blob layers call
`guard.check({ classification, region, tenant? })` before letting
data move. Mismatches throw `ResidencyViolation`.

```ts
guard.check({ classification: 'pii', region: 'us-east' });
// throws ResidencyViolation if policy says 'eu'

// non-throwing variant
const v = guard.inspect({ classification: 'pii', region: 'eu', tenant: 'acme' });
if (v !== null) return new Response(v.message, { status: 451 });
```

### 3. `runRetention({ policy, scanners, deleters, audit?, ... })`

Orchestrator. Each scanner streams expired records for a
classification; each deleter removes them (batched). Per-scanner
failures are isolated. Optional audit broker logs a
`'compliance.retention.swept'` event per class. `dryRun: true`
counts without deleting.

```ts
const report = await runRetention({
  policy,
  audit: broker,
  scanners: [
    { classification: 'audit-log', scan: auditTable.scan },
    { classification: 'pii',       scan: userTable.scan  },
  ],
  deleters: {
    'audit-log': (rows) => auditTable.delete(rows.map(r => r.id)),
    'pii':       (rows) => userTable.delete(rows.map(r => r.id)),
  },
});
// report = { byClassification: { pii: { scanned, deleted, durationMs }, ... }, errors }
```

### 4. `runSubjectAccess({ subject, collectors })` + `runErasure({ subject, erasers, ... })`

Compose a "find / forget everything about user X" pipeline across
packages. Each package provides a collector / eraser pair. The
substrate runs them and returns a structured bundle.

`runErasure` automatically routes to `eraser.anonymize` for
`erasureExempt` classifications (typical: anonymize audit-log
subject references rather than delete the log itself). Records the
erasure to audit if a broker is provided.

```ts
const bundle = await runSubjectAccess({
  subject: { tenant: 'acme', subjectId: 'u-1' },
  collectors: [
    { name: 'profile',    classification: 'pii',         collect: userTable.findBySubject },
    { name: 'audit',      classification: 'audit-log',   collect: auditTable.findBySubject },
    { name: 'sync-packs', classification: 'sync-packs',  collect: syncPacks.findBySubject },
  ],
});

await runErasure({
  policy, audit: broker,
  subject: { tenant: 'acme', subjectId: 'u-1' },
  erasers: [
    { name: 'profile', classification: 'pii',       erase: userTable.deleteBySubject },
    { name: 'audit',   classification: 'audit-log', anonymize: auditTable.anonymizeSubject },
  ],
});
```

### 5. `collectEvidence({ policy, period, sources })`

Bundles per-source JSON evidence into a single structure an
external auditor can read. Each source returns arbitrary JSON-
serializable evidence for the period; the bundler doesn't
interpret the shape. Ships with `auditEvidenceSource(broker)`
for the typical "all audit events in the period" case.

```ts
const bundle = await collectEvidence({
  policy,
  period: { start: lastQuarter, end: now },
  sources: [
    auditEvidenceSource(broker, { kindPrefix: 'compliance.' }),
    { name: 'access-log',     collect: () => accessLog.dump(period) },
    { name: 'config-snapshot',collect: () => config.snapshot() },
  ],
});
// Write `bundle` to disk → hand to your SOC2 / ISO / HIPAA auditor.
```

## Tenant overrides

A per-tenant override wins over the class default. GDPR-strict
tenants riding a default-US-East platform get their own residency,
retention, and erasure-exempt behavior without forking the policy.

## License

BSL-1.1 with named carveout against hosted compliance / GRC SaaS
(Vanta, Drata, Secureframe, OneTrust, TrustCloud, Sprinto,
Tugboat Logic). See `LICENSE`. Change date: **2030-05-31** →
Apache 2.0.
