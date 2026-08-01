import type {
  DispatchPolicy,
  DispatchPolicyDecision,
  MessagingMessage,
} from "@absolutejs/dispatch";
import type { ComplianceAuditLike } from "./index";

export type MessagingConsentTransport = "mms" | "rcs" | "sms" | "whatsapp";

export type MessagingConsentScope = {
  programId: string;
  purpose: string;
  recipient: string;
  tenant?: string;
  transport: MessagingConsentTransport;
};

export type MessagingConsentEvidence = {
  /** When and how the recipient granted or revoked consent. */
  at: number;
  /** Stable upstream event id used to make webhook retries idempotent. */
  idempotencyKey?: string;
  metadata?: Record<string, unknown>;
  reference?: string;
  source: string;
};

export type MessagingConsentRecord = MessagingConsentScope & {
  evidence: MessagingConsentEvidence;
  id: string;
  status: "granted" | "revoked";
};

export type MessagingConsentStore = {
  readonly durability: "durable" | "memory";
  /** Returns false when this record id was already stored. */
  append: (record: MessagingConsentRecord) => Promise<boolean>;
  history: (scope: MessagingConsentScope) => Promise<MessagingConsentRecord[]>;
  latest: (
    scope: MessagingConsentScope,
  ) => Promise<MessagingConsentRecord | undefined>;
  /** Exports consent evidence for a recipient access request. */
  exportRecipient: (input: {
    recipient: string;
    tenant?: string;
  }) => Promise<MessagingConsentRecord[]>;
  /** Purges historical evidence while retaining the current decision per scope by default. */
  purge: (input: {
    before: number;
    preserveCurrent?: boolean;
    recipient?: string;
    tenant?: string;
  }) => Promise<number>;
};

const scopeKey = (scope: MessagingConsentScope) =>
  JSON.stringify([
    scope.tenant ?? null,
    scope.programId,
    scope.purpose,
    scope.transport,
    scope.recipient,
  ]);

export const createMemoryMessagingConsentStore = (): MessagingConsentStore => {
  const records = new Map<string, MessagingConsentRecord[]>();
  const ids = new Set<string>();
  return {
    append: async (record) => {
      if (ids.has(record.id)) return false;
      const key = scopeKey(record);
      records.set(key, [...(records.get(key) ?? []), structuredClone(record)]);
      ids.add(record.id);
      return true;
    },
    durability: "memory",
    exportRecipient: async (input) =>
      [...records.values()]
        .flat()
        .filter(
          (record) =>
            record.recipient === input.recipient &&
            (input.tenant === undefined || record.tenant === input.tenant),
        )
        .sort((left, right) => right.evidence.at - left.evidence.at)
        .map((record) => structuredClone(record)),
    history: async (scope) =>
      [...(records.get(scopeKey(scope)) ?? [])]
        .reverse()
        .map((record) => structuredClone(record)),
    latest: async (scope) => {
      const history = records.get(scopeKey(scope));
      const record = history?.at(-1);
      return record === undefined ? undefined : structuredClone(record);
    },
    purge: async (input) => {
      let purged = 0;
      for (const [key, history] of records) {
        const scoped = history.filter(
          (record) =>
            (input.recipient === undefined ||
              record.recipient === input.recipient) &&
            (input.tenant === undefined || record.tenant === input.tenant),
        );
        if (scoped.length === 0) continue;
        const currentId = history.at(-1)?.id;
        const kept = history.filter((record) => {
          const preserveCurrent =
            input.preserveCurrent !== false && record.id === currentId;
          const remove =
            !preserveCurrent &&
            record.evidence.at < input.before &&
            scoped.some(({ id }) => id === record.id);
          if (remove) {
            ids.delete(record.id);
            purged += 1;
          }
          return !remove;
        });
        if (kept.length === 0) records.delete(key);
        else records.set(key, kept);
      }
      return purged;
    },
  };
};

export type MessagingConsentPostgresClient = {
  query: (
    text: string,
    values?: ReadonlyArray<unknown>,
  ) => Promise<{ rows: Array<Record<string, unknown>> }>;
};

export const MESSAGING_CONSENT_POSTGRES_SCHEMA = `
CREATE TABLE IF NOT EXISTS absolute_messaging_consent_v2 (
  id text PRIMARY KEY,
  tenant text,
  program_id text NOT NULL,
  purpose text NOT NULL,
  transport text NOT NULL,
  recipient text NOT NULL,
  status text NOT NULL CHECK (status IN ('granted', 'revoked')),
  evidence jsonb NOT NULL,
  recorded_at_ms bigint NOT NULL
);
CREATE INDEX IF NOT EXISTS absolute_messaging_consent_scope_idx
  ON absolute_messaging_consent_v2
  (tenant, program_id, purpose, transport, recipient, recorded_at_ms DESC, id DESC);
CREATE INDEX IF NOT EXISTS absolute_messaging_consent_recipient_idx
  ON absolute_messaging_consent_v2
  (recipient, tenant, recorded_at_ms DESC, id DESC);
`;

const fromRow = (row: Record<string, unknown>): MessagingConsentRecord => ({
  evidence: row.evidence as MessagingConsentEvidence,
  id: String(row.id),
  programId: String(row.program_id),
  purpose: String(row.purpose),
  recipient: String(row.recipient),
  status: row.status as MessagingConsentRecord["status"],
  ...(row.tenant === null || row.tenant === undefined
    ? {}
    : { tenant: String(row.tenant) }),
  transport: row.transport as MessagingConsentTransport,
});

export const createPostgresMessagingConsentStore = (
  client: MessagingConsentPostgresClient,
): MessagingConsentStore => {
  const select = `
    SELECT id, tenant, program_id, purpose, transport, recipient, status, evidence
    FROM absolute_messaging_consent_v2
    WHERE tenant IS NOT DISTINCT FROM $1 AND program_id = $2 AND purpose = $3
      AND transport = $4 AND recipient = $5
    ORDER BY recorded_at_ms DESC, id DESC`;
  const values = (scope: MessagingConsentScope) => [
    scope.tenant ?? null,
    scope.programId,
    scope.purpose,
    scope.transport,
    scope.recipient,
  ];
  return {
    append: async (record) => {
      const result = await client.query(
        `INSERT INTO absolute_messaging_consent_v2
          (id, tenant, program_id, purpose, transport, recipient, status, evidence, recorded_at_ms)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9)
         ON CONFLICT (id) DO NOTHING
         RETURNING id`,
        [
          record.id,
          record.tenant ?? null,
          record.programId,
          record.purpose,
          record.transport,
          record.recipient,
          record.status,
          JSON.stringify(record.evidence),
          record.evidence.at,
        ],
      );
      return result.rows.length === 1;
    },
    durability: "durable",
    exportRecipient: async (input) => {
      const result = await client.query(
        `SELECT id, tenant, program_id, purpose, transport, recipient, status, evidence
         FROM absolute_messaging_consent_v2
         WHERE recipient = $1 AND ($2::text IS NULL OR tenant = $2)
         ORDER BY recorded_at_ms DESC, id DESC`,
        [input.recipient, input.tenant ?? null],
      );
      return result.rows.map(fromRow);
    },
    history: async (scope) => {
      const result = await client.query(select, values(scope));
      return result.rows.map(fromRow);
    },
    latest: async (scope) => {
      const result = await client.query(`${select} LIMIT 1`, values(scope));
      return result.rows[0] === undefined ? undefined : fromRow(result.rows[0]);
    },
    purge: async (input) => {
      const result = await client.query(
        `WITH ranked AS (
           SELECT id,
             row_number() OVER (
               PARTITION BY tenant, program_id, purpose, transport, recipient
               ORDER BY recorded_at_ms DESC, id DESC
             ) AS scope_rank
           FROM absolute_messaging_consent_v2
           WHERE ($2::text IS NULL OR recipient = $2)
             AND ($3::text IS NULL OR tenant = $3)
         ), deleted AS (
           DELETE FROM absolute_messaging_consent_v2 AS consent
           USING ranked
           WHERE consent.id = ranked.id
             AND consent.recorded_at_ms < $1
             AND ($4::boolean = false OR ranked.scope_rank > 1)
           RETURNING consent.id
         ) SELECT id FROM deleted`,
        [
          input.before,
          input.recipient ?? null,
          input.tenant ?? null,
          input.preserveCurrent !== false,
        ],
      );
      return result.rows.length;
    },
  };
};

export type MessagingConsentDecision =
  | { allowed: true; record: MessagingConsentRecord }
  | {
      allowed: false;
      code: "missing-consent" | "revoked";
      record?: MessagingConsentRecord;
    };

export type MessagingConsentLedger = {
  readonly store: MessagingConsentStore;
  decision: (scope: MessagingConsentScope) => Promise<MessagingConsentDecision>;
  grant: (
    scope: MessagingConsentScope,
    evidence: MessagingConsentEvidence,
  ) => Promise<MessagingConsentRecord>;
  history: (scope: MessagingConsentScope) => Promise<MessagingConsentRecord[]>;
  revoke: (
    scope: MessagingConsentScope,
    evidence: MessagingConsentEvidence,
  ) => Promise<MessagingConsentRecord>;
};

export const createMessagingConsentLedger = (input: {
  audit?: ComplianceAuditLike;
  id?: () => string;
  store: MessagingConsentStore;
}): MessagingConsentLedger => {
  const record = async (
    status: MessagingConsentRecord["status"],
    scope: MessagingConsentScope,
    evidence: MessagingConsentEvidence,
  ) => {
    if (!Number.isFinite(evidence.at) || evidence.at < 0) {
      throw new TypeError(
        "compliance: consent evidence at must be a timestamp",
      );
    }
    for (const [name, value] of Object.entries({
      recipient: scope.recipient,
      programId: scope.programId,
      purpose: scope.purpose,
      source: evidence.source,
    })) {
      if (value.trim().length === 0) {
        throw new TypeError(`compliance: consent ${name} must not be empty`);
      }
    }
    if (
      !(["mms", "rcs", "sms", "whatsapp"] as const).includes(scope.transport)
    ) {
      throw new TypeError("compliance: consent transport is unsupported");
    }
    const result: MessagingConsentRecord = {
      ...scope,
      evidence: structuredClone(evidence),
      id: evidence.idempotencyKey ?? input.id?.() ?? crypto.randomUUID(),
      status,
    };
    const inserted = await input.store.append(result);
    if (inserted)
      await input.audit?.append({
        kind: `compliance.messaging-consent.${status}`,
        ...(scope.tenant === undefined ? {} : { actor: scope.tenant }),
        metadata: {
          reference: evidence.reference,
          programId: scope.programId,
          purpose: scope.purpose,
          source: evidence.source,
          transport: scope.transport,
        },
        target: scope.recipient,
      });
    return result;
  };
  return {
    decision: async (scope) => {
      const latest = await input.store.latest(scope);
      if (latest === undefined)
        return { allowed: false, code: "missing-consent" };
      return latest.status === "granted"
        ? { allowed: true, record: latest }
        : { allowed: false, code: "revoked", record: latest };
    },
    grant: (scope, evidence) => record("granted", scope, evidence),
    history: input.store.history,
    revoke: (scope, evidence) => record("revoked", scope, evidence),
    store: input.store,
  };
};

export const createMessagingConsentDispatchPolicy = (input: {
  ledger: MessagingConsentLedger;
}): DispatchPolicy => ({
  evaluate: async (context): Promise<DispatchPolicyDecision> => {
    if (context.channel !== "messaging") return { allowed: true };
    const message = context.message as MessagingMessage;
    if (message.consent === undefined) {
      return {
        allowed: false,
        code: "missing-consent-scope",
        reason: "messaging sends require a stable program and purpose",
      };
    }
    const recipient = message.to.address;
    const transports = [
      ...new Set([
        message.to.transport,
        ...(message.fallbacks ?? []).map(({ transport }) => transport),
      ]),
    ];
    for (const transport of transports) {
      const decision = await input.ledger.decision({
        programId: message.consent.programId,
        purpose: message.consent.purpose,
        recipient,
        ...(message.tenant === undefined ? {} : { tenant: message.tenant }),
        transport,
      });
      if (!decision.allowed) {
        return {
          allowed: false,
          code: decision.code,
          reason:
            decision.code === "revoked"
              ? `recipient revoked consent for ${transport} delivery in this program`
              : `no consent evidence exists for ${transport} delivery in this program`,
        };
      }
    }
    return { allowed: true };
  },
  name: "messaging-consent",
});
