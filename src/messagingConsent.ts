import type {
  DispatchPolicy,
  DispatchPolicyDecision,
  SmsMessage,
} from "@absolutejs/dispatch";
import type { ComplianceAuditLike } from "./index";

export type MessagingConsentTransport = "mms" | "rcs" | "sms" | "whatsapp";

export type MessagingConsentScope = {
  recipient: string;
  senderId: string;
  tenant?: string;
  topic: string;
  transport: MessagingConsentTransport;
};

export type MessagingConsentEvidence = {
  /** When and how the recipient granted or revoked consent. */
  at: number;
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
  append: (record: MessagingConsentRecord) => Promise<void>;
  history: (scope: MessagingConsentScope) => Promise<MessagingConsentRecord[]>;
  latest: (
    scope: MessagingConsentScope,
  ) => Promise<MessagingConsentRecord | undefined>;
};

const scopeKey = (scope: MessagingConsentScope) =>
  JSON.stringify([
    scope.tenant ?? null,
    scope.senderId,
    scope.topic,
    scope.transport,
    scope.recipient,
  ]);

export const createMemoryMessagingConsentStore = (): MessagingConsentStore => {
  const records = new Map<string, MessagingConsentRecord[]>();
  return {
    append: async (record) => {
      const key = scopeKey(record);
      records.set(key, [...(records.get(key) ?? []), structuredClone(record)]);
    },
    durability: "memory",
    history: async (scope) =>
      (records.get(scopeKey(scope)) ?? []).map((record) =>
        structuredClone(record),
      ),
    latest: async (scope) => {
      const history = records.get(scopeKey(scope));
      const record = history?.at(-1);
      return record === undefined ? undefined : structuredClone(record);
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
CREATE TABLE IF NOT EXISTS absolute_messaging_consent (
  id text PRIMARY KEY,
  tenant text,
  sender_id text NOT NULL,
  topic text NOT NULL,
  transport text NOT NULL,
  recipient text NOT NULL,
  status text NOT NULL CHECK (status IN ('granted', 'revoked')),
  evidence jsonb NOT NULL,
  recorded_at_ms bigint NOT NULL
);
CREATE INDEX IF NOT EXISTS absolute_messaging_consent_scope_idx
  ON absolute_messaging_consent
  (tenant, sender_id, topic, transport, recipient, recorded_at_ms DESC, id DESC);
`;

const fromRow = (row: Record<string, unknown>): MessagingConsentRecord => ({
  evidence: row.evidence as MessagingConsentEvidence,
  id: String(row.id),
  recipient: String(row.recipient),
  senderId: String(row.sender_id),
  status: row.status as MessagingConsentRecord["status"],
  ...(row.tenant === null || row.tenant === undefined
    ? {}
    : { tenant: String(row.tenant) }),
  topic: String(row.topic),
  transport: row.transport as MessagingConsentTransport,
});

export const createPostgresMessagingConsentStore = (
  client: MessagingConsentPostgresClient,
): MessagingConsentStore => {
  const select = `
    SELECT id, tenant, sender_id, topic, transport, recipient, status, evidence
    FROM absolute_messaging_consent
    WHERE tenant IS NOT DISTINCT FROM $1 AND sender_id = $2 AND topic = $3
      AND transport = $4 AND recipient = $5
    ORDER BY recorded_at_ms DESC, id DESC`;
  const values = (scope: MessagingConsentScope) => [
    scope.tenant ?? null,
    scope.senderId,
    scope.topic,
    scope.transport,
    scope.recipient,
  ];
  return {
    append: async (record) => {
      await client.query(
        `INSERT INTO absolute_messaging_consent
          (id, tenant, sender_id, topic, transport, recipient, status, evidence, recorded_at_ms)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9)`,
        [
          record.id,
          record.tenant ?? null,
          record.senderId,
          record.topic,
          record.transport,
          record.recipient,
          record.status,
          JSON.stringify(record.evidence),
          record.evidence.at,
        ],
      );
    },
    durability: "durable",
    history: async (scope) => {
      const result = await client.query(select, values(scope));
      return result.rows.map(fromRow);
    },
    latest: async (scope) => {
      const result = await client.query(`${select} LIMIT 1`, values(scope));
      return result.rows[0] === undefined ? undefined : fromRow(result.rows[0]);
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
      senderId: scope.senderId,
      source: evidence.source,
      topic: scope.topic,
    })) {
      if (value.trim().length === 0) {
        throw new TypeError(`compliance: consent ${name} must not be empty`);
      }
    }
    const result: MessagingConsentRecord = {
      ...scope,
      evidence: structuredClone(evidence),
      id: input.id?.() ?? crypto.randomUUID(),
      status,
    };
    await input.store.append(result);
    await input.audit?.append({
      kind: `compliance.messaging-consent.${status}`,
      ...(scope.tenant === undefined ? {} : { actor: scope.tenant }),
      metadata: {
        reference: evidence.reference,
        senderId: scope.senderId,
        source: evidence.source,
        topic: scope.topic,
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
    if (context.channel !== "sms") return { allowed: true };
    const message = context.message as SmsMessage;
    if (message.consent === undefined) {
      return {
        allowed: false,
        code: "missing-consent-scope",
        reason: "messaging sends require consent.senderId and consent.topic",
      };
    }
    const decision = await input.ledger.decision({
      recipient: message.to,
      senderId: message.consent.senderId,
      ...(message.tenant === undefined ? {} : { tenant: message.tenant }),
      topic: message.consent.topic,
      transport: message.channel ?? "sms",
    });
    return decision.allowed
      ? { allowed: true }
      : {
          allowed: false,
          code: decision.code,
          reason:
            decision.code === "revoked"
              ? "recipient revoked consent for this sender and topic"
              : "no consent evidence exists for this sender and topic",
        };
  },
  name: "messaging-consent",
});
