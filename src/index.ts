/**
 * @absolutejs/compliance — framework-agnostic compliance substrate.
 *
 * The package gives a control plane five composable primitives, none
 * of which know about a specific framework (SOC2 / HIPAA / ISO /
 * GDPR are all expressible on top):
 *
 *   1. `createCompliancePolicy(...)` — declarative shape:
 *      classifications (tags + retention + residency + flags) and
 *      tenant overrides.
 *
 *   2. `createResidencyGuard(policy)` — pure check function. The
 *      runtime / sync / queue call `guard.checkWrite({ classification,
 *      tenant, region })` before letting data move; mismatches throw
 *      a `ResidencyViolation`.
 *
 *   3. `runRetention({ policy, scanners, deleters, audit?, ... })` —
 *      orchestrator. Each scanner returns a list of expired records
 *      for a class; each deleter removes them. Per-scanner failures
 *      are isolated. Optional audit + onError hooks.
 *
 *   4. `runSubjectAccess({ subject, collectors })` and
 *      `runErasure({ subject, deleters / anonymizers, audit? })` —
 *      compose a "find / forget everything about user X" pipeline
 *      across multiple packages. Each package provides a collector
 *      / deleter pair; the substrate runs them and returns a
 *      structured bundle.
 *
 *   5. `collectEvidence({ policy, period, sources })` — bundles
 *      audit excerpts + retention sweep proofs + config snapshots
 *      into a single JSON structure an external auditor can read.
 *
 * The substrate is INTENTIONALLY framework-agnostic: it provides
 * the primitives; the framework mapping (which audit kinds count
 * as "access events" for SOC2 CC6.1, which retention proof maps
 * to HIPAA 164.316) lives in the control plane.
 */

// =============================================================================
// Audit interface — same narrow shape as @absolutejs/errors etc.
// =============================================================================

export type ComplianceAuditLike = {
	append: (event: {
		kind: string;
		actor?: string;
		target?: string;
		metadata?: Record<string, unknown>;
	}) => Promise<void> | void;
	/**
	 * Optional reader — required only for `collectEvidence`. Returns
	 * audit events in the period bounded by `since` / `until` (inclusive
	 * / exclusive). Implementations stream large windows page-by-page.
	 */
	read?: (filter: {
		since: number;
		until: number;
		kindPrefix?: string;
	}) => AsyncIterable<{
		kind: string;
		at?: number;
		actor?: string;
		target?: string;
		metadata?: Record<string, unknown>;
	}>;
};

export * from './messagingConsent';

// =============================================================================
// Policy
// =============================================================================

export type Classification = {
	/**
	 * Stable id (`'pii'`, `'phi'`, `'audit-log'`, `'operational'`).
	 * The substrate doesn't interpret it — callers tag data, runners
	 * look up policy by id.
	 */
	id: string;
	/** Human label for the evidence bundle / dashboards. */
	label?: string;
	/**
	 * Retention window in milliseconds. After this duration, scanners
	 * report records as expired. `Infinity` = retain indefinitely;
	 * `0` = delete immediately on next sweep.
	 */
	retentionMs: number;
	/**
	 * Required residency region. ResidencyGuard throws on any write
	 * whose region differs. `undefined` = no residency constraint.
	 */
	residency?: string;
	/**
	 * Right-to-erasure exemption flag. When `true`, runErasure leaves
	 * data of this class in place (typical for `audit-log` — many
	 * jurisdictions require audit retention even after a user is
	 * erased; we anonymize the subject reference instead).
	 */
	erasureExempt?: boolean;
	/**
	 * Open metadata bag — `{ encrypted: true, immutable: true,
	 * regulator: 'sec' }`. Substrate doesn't act on it; the control
	 * plane reads it for evidence bundles.
	 */
	flags?: Record<string, string | number | boolean>;
};

export type CompliancePolicy = {
	classifications: Record<string, Classification>;
	/**
	 * Tenant-scoped overrides. Per-tenant retention / residency wins
	 * over the class default. Useful for GDPR-EU tenants riding a
	 * default-US-East platform.
	 */
	tenantOverrides?: Record<
		string,
		Partial<
			Record<
				string,
				Partial<Pick<Classification, 'retentionMs' | 'residency' | 'erasureExempt'>>
			>
		>
	>;
};

export const createCompliancePolicy = (
	policy: CompliancePolicy
): CompliancePolicy => {
	for (const [id, cls] of Object.entries(policy.classifications)) {
		if (cls.id !== id) {
			throw new Error(
				`compliance: classification key '${id}' must match its id '${cls.id}'`
			);
		}
		if (
			cls.retentionMs < 0 ||
			(!Number.isFinite(cls.retentionMs) && cls.retentionMs !== Infinity)
		) {
			throw new Error(
				`compliance: classification '${id}' has invalid retentionMs ${cls.retentionMs}`
			);
		}
	}
	return policy;
};

/** Resolve the effective class for a tenant (overrides merged in). */
export const resolveClassification = (
	policy: CompliancePolicy,
	classId: string,
	tenant?: string
): Classification | undefined => {
	const base = policy.classifications[classId];
	if (base === undefined) return undefined;
	if (tenant === undefined) return base;
	const override = policy.tenantOverrides?.[tenant]?.[classId];
	if (override === undefined) return base;
	return { ...base, ...override };
};

// =============================================================================
// Residency guard
// =============================================================================

export class ResidencyViolation extends Error {
	classification: string;
	required: string;
	got: string;
	tenant?: string;
	constructor(args: {
		classification: string;
		required: string;
		got: string;
		tenant?: string;
	}) {
		super(
			`residency: ${args.classification} requires '${args.required}' but got '${args.got}'${args.tenant !== undefined ? ` (tenant ${args.tenant})` : ''}`
		);
		this.name = 'ResidencyViolation';
		this.classification = args.classification;
		this.required = args.required;
		this.got = args.got;
		if (args.tenant !== undefined) this.tenant = args.tenant;
	}
}

export type ResidencyCheck = {
	classification: string;
	region: string;
	tenant?: string;
};

export type ResidencyGuard = {
	/**
	 * Throws `ResidencyViolation` if `region` doesn't match the
	 * required region for `classification` (after tenant override
	 * resolution). Pass-through when the class has no residency
	 * constraint or doesn't exist in the policy.
	 */
	check: (input: ResidencyCheck) => void;
	/** Non-throwing variant — returns `null` on pass, the violation on fail. */
	inspect: (input: ResidencyCheck) => ResidencyViolation | null;
};

export const createResidencyGuard = (
	policy: CompliancePolicy
): ResidencyGuard => {
	const inspect = (input: ResidencyCheck): ResidencyViolation | null => {
		const cls = resolveClassification(
			policy,
			input.classification,
			input.tenant
		);
		if (cls === undefined || cls.residency === undefined) return null;
		if (cls.residency !== input.region) {
			return new ResidencyViolation({
				classification: input.classification,
				got: input.region,
				required: cls.residency,
				...(input.tenant !== undefined ? { tenant: input.tenant } : {})
			});
		}
		return null;
	};
	return {
		check: (input) => {
			const violation = inspect(input);
			if (violation !== null) throw violation;
		},
		inspect
	};
};

// =============================================================================
// Retention runner
// =============================================================================

export type ExpiredRecord = {
	/** Stable id the deleter can use to remove this record. */
	id: string;
	/** Optional `Date.now()` timestamp the scanner used for the cutoff. */
	createdAt?: number;
	/** Optional tenant scope for audit + per-tenant retention sweeps. */
	tenant?: string;
	/** Opaque payload the scanner wants the deleter to receive. */
	metadata?: Record<string, unknown>;
};

export type RetentionScanner = {
	/** Class id this scanner walks. */
	classification: string;
	/** Optional descriptor for evidence + logs. */
	description?: string;
	/**
	 * Find records older than the cutoff. Implementations stream so
	 * large tables don't pin memory. `cutoff` = current time minus
	 * the class's `retentionMs`.
	 */
	scan: (input: {
		cutoff: number;
		now: number;
		classification: Classification;
		tenant?: string;
	}) => AsyncIterable<ExpiredRecord>;
};

export type RetentionDeleter = (
	records: ExpiredRecord[],
	context: { classification: string; tenant?: string }
) => Promise<{ deleted: number }> | { deleted: number };

export type RetentionReport = {
	startedAt: number;
	endedAt: number;
	durationMs: number;
	byClassification: Record<
		string,
		{
			scanned: number;
			deleted: number;
			durationMs: number;
		}
	>;
	errors: Array<{ classification: string; error: Error }>;
};

export type RunRetentionInput = {
	policy: CompliancePolicy;
	scanners: RetentionScanner[];
	/** Keyed by classification id. */
	deleters: Record<string, RetentionDeleter>;
	/** Optional audit broker — appends `'compliance.retention.swept'` events. */
	audit?: ComplianceAuditLike;
	/** Optional tenant scope — only sweeps records for this tenant. */
	tenant?: string;
	/** Batch size handed to the deleter. Default 500. */
	batchSize?: number;
	/** Override `Date.now()` for tests. */
	now?: () => number;
	/** Optional dry-run — scan + count but never call deleters. */
	dryRun?: boolean;
	/** Per-error hook. */
	onError?: (e: { classification: string; error: Error }) => void;
};

export const runRetention = async (
	input: RunRetentionInput
): Promise<RetentionReport> => {
	const now = input.now ?? Date.now;
	const startedAt = now();
	const batchSize = input.batchSize ?? 500;
	const byClassification: RetentionReport['byClassification'] = {};
	const errors: RetentionReport['errors'] = [];

	for (const scanner of input.scanners) {
		const cls = resolveClassification(
			input.policy,
			scanner.classification,
			input.tenant
		);
		if (cls === undefined) {
			errors.push({
				classification: scanner.classification,
				error: new Error(
					`compliance: no classification '${scanner.classification}' in policy`
				)
			});
			continue;
		}
		const classStartedAt = now();
		const cutoff = cls.retentionMs === Infinity
			? -Infinity
			: classStartedAt - cls.retentionMs;
		const stats = { deleted: 0, scanned: 0 };
		const batch: ExpiredRecord[] = [];

		const flush = async (): Promise<void> => {
			if (batch.length === 0) return;
			if (input.dryRun) {
				batch.length = 0;
				return;
			}
			const deleter = input.deleters[scanner.classification];
			if (deleter === undefined) {
				throw new Error(
					`compliance: no deleter for classification '${scanner.classification}'`
				);
			}
			const result = await deleter([...batch], {
				classification: scanner.classification,
				...(input.tenant !== undefined ? { tenant: input.tenant } : {})
			});
			stats.deleted += result.deleted;
			batch.length = 0;
		};

		try {
			if (cls.retentionMs !== Infinity) {
				for await (const record of scanner.scan({
					classification: cls,
					cutoff,
					now: classStartedAt,
					...(input.tenant !== undefined ? { tenant: input.tenant } : {})
				})) {
					stats.scanned += 1;
					batch.push(record);
					if (batch.length >= batchSize) await flush();
				}
				await flush();
			}
		} catch (e) {
			const error = e instanceof Error ? e : new Error(String(e));
			errors.push({ classification: scanner.classification, error });
			input.onError?.({ classification: scanner.classification, error });
		}

		const classEndedAt = now();
		byClassification[scanner.classification] = {
			deleted: stats.deleted,
			durationMs: classEndedAt - classStartedAt,
			scanned: stats.scanned
		};

		if (input.audit !== undefined && !input.dryRun) {
			try {
				await input.audit.append({
					kind: 'compliance.retention.swept',
					metadata: {
						classification: scanner.classification,
						deleted: stats.deleted,
						scanned: stats.scanned,
						...(input.tenant !== undefined ? { tenant: input.tenant } : {})
					},
					...(input.tenant !== undefined ? { actor: input.tenant } : {})
				});
			} catch (e) {
				const error = e instanceof Error ? e : new Error(String(e));
				errors.push({ classification: scanner.classification, error });
				input.onError?.({ classification: scanner.classification, error });
			}
		}
	}

	const endedAt = now();
	return {
		byClassification,
		durationMs: endedAt - startedAt,
		endedAt,
		errors,
		startedAt
	};
};

// =============================================================================
// Subject Access Request (SAR) + erasure
// =============================================================================

export type Subject = {
	/** Tenant the subject belongs to. */
	tenant?: string;
	/** Stable user / subject id. */
	subjectId: string;
};

export type SubjectAccessCollector = {
	/** Name surfaced in the bundle (`'audit'`, `'profile'`, `'sync-packs'`). */
	name: string;
	/** Classification this collector returns — drives erasure-exempt filtering. */
	classification: string;
	/**
	 * Returns all records the subject is reachable through. Array,
	 * async iterable, or single object (wrapped automatically).
	 */
	collect: (
		subject: Subject
	) =>
		| Promise<unknown[]>
		| unknown[]
		| AsyncIterable<unknown>
		| Promise<unknown>
		| unknown;
};

export type SubjectAccessBundle = {
	subject: Subject;
	collectedAt: number;
	byCollector: Record<
		string,
		{
			classification: string;
			records: unknown[];
			durationMs: number;
		}
	>;
	errors: Array<{ collector: string; error: Error }>;
};

export const runSubjectAccess = async (input: {
	subject: Subject;
	collectors: SubjectAccessCollector[];
	now?: () => number;
}): Promise<SubjectAccessBundle> => {
	const now = input.now ?? Date.now;
	const collectedAt = now();
	const byCollector: SubjectAccessBundle['byCollector'] = {};
	const errors: SubjectAccessBundle['errors'] = [];

	for (const collector of input.collectors) {
		const start = now();
		try {
			const raw = await collector.collect(input.subject);
			const records: unknown[] = [];
			if (Array.isArray(raw)) {
				records.push(...raw);
			} else if (raw !== null && typeof raw === 'object' && Symbol.asyncIterator in raw) {
				for await (const record of raw as AsyncIterable<unknown>) {
					records.push(record);
				}
			} else if (raw !== undefined) {
				records.push(raw);
			}
			byCollector[collector.name] = {
				classification: collector.classification,
				durationMs: now() - start,
				records
			};
		} catch (e) {
			errors.push({
				collector: collector.name,
				error: e instanceof Error ? e : new Error(String(e))
			});
		}
	}

	return { byCollector, collectedAt, errors, subject: input.subject };
};

export type SubjectEraser = {
	classification: string;
	name: string;
	/**
	 * Remove all records belonging to the subject. Returns `{ deleted }`
	 * count. If the classification is `erasureExempt`, runErasure
	 * routes to `anonymize` instead.
	 */
	erase?: (
		subject: Subject
	) => Promise<{ deleted: number }> | { deleted: number };
	/**
	 * Anonymize-in-place fallback. Required when the classification
	 * is `erasureExempt`; ignored otherwise.
	 */
	anonymize?: (
		subject: Subject
	) => Promise<{ anonymized: number }> | { anonymized: number };
};

export type ErasureReport = {
	subject: Subject;
	startedAt: number;
	endedAt: number;
	durationMs: number;
	byEraser: Record<
		string,
		{
			classification: string;
			deleted: number;
			anonymized: number;
			mode: 'erase' | 'anonymize' | 'skipped';
			durationMs: number;
		}
	>;
	errors: Array<{ eraser: string; error: Error }>;
};

export const runErasure = async (input: {
	policy: CompliancePolicy;
	subject: Subject;
	erasers: SubjectEraser[];
	audit?: ComplianceAuditLike;
	now?: () => number;
	dryRun?: boolean;
	onError?: (e: { eraser: string; error: Error }) => void;
}): Promise<ErasureReport> => {
	const now = input.now ?? Date.now;
	const startedAt = now();
	const byEraser: ErasureReport['byEraser'] = {};
	const errors: ErasureReport['errors'] = [];

	for (const eraser of input.erasers) {
		const cls = resolveClassification(
			input.policy,
			eraser.classification,
			input.subject.tenant
		);
		const start = now();
		const exempt = cls?.erasureExempt === true;
		const mode: 'erase' | 'anonymize' | 'skipped' = exempt
			? eraser.anonymize !== undefined
				? 'anonymize'
				: 'skipped'
			: eraser.erase !== undefined
				? 'erase'
				: 'skipped';

		let deleted = 0;
		let anonymized = 0;
		try {
			if (!input.dryRun) {
				if (mode === 'erase' && eraser.erase !== undefined) {
					const result = await eraser.erase(input.subject);
					deleted = result.deleted;
				} else if (mode === 'anonymize' && eraser.anonymize !== undefined) {
					const result = await eraser.anonymize(input.subject);
					anonymized = result.anonymized;
				}
			}
		} catch (e) {
			const error = e instanceof Error ? e : new Error(String(e));
			errors.push({ eraser: eraser.name, error });
			input.onError?.({ eraser: eraser.name, error });
		}

		byEraser[eraser.name] = {
			anonymized,
			classification: eraser.classification,
			deleted,
			durationMs: now() - start,
			mode
		};
	}

	if (input.audit !== undefined && !input.dryRun) {
		try {
			await input.audit.append({
				kind: 'compliance.subject.erased',
				metadata: {
					byEraser,
					...(input.subject.tenant !== undefined
						? { tenant: input.subject.tenant }
						: {})
				},
				target: input.subject.subjectId,
				...(input.subject.tenant !== undefined
					? { actor: input.subject.tenant }
					: {})
			});
		} catch (e) {
			const error = e instanceof Error ? e : new Error(String(e));
			errors.push({ eraser: 'audit', error });
			input.onError?.({ eraser: 'audit', error });
		}
	}

	const endedAt = now();
	return {
		byEraser,
		durationMs: endedAt - startedAt,
		endedAt,
		errors,
		startedAt,
		subject: input.subject
	};
};

// =============================================================================
// Evidence bundler
// =============================================================================

export type EvidenceSource = {
	/** Surface name (`'audit'`, `'access-log'`, `'config-snapshot'`). */
	name: string;
	/**
	 * Return arbitrary JSON-serializable evidence for the period. The
	 * bundler doesn't interpret the shape; it's plumbed straight into
	 * the output bundle for an auditor.
	 */
	collect: (
		period: { start: number; end: number },
		policy: CompliancePolicy
	) => Promise<unknown> | unknown;
};

export type EvidenceBundle = {
	period: { start: number; end: number };
	generatedAt: number;
	policy: CompliancePolicy;
	bySource: Record<string, unknown>;
	errors: Array<{ source: string; error: Error }>;
};

export const collectEvidence = async (input: {
	policy: CompliancePolicy;
	period: { start: number; end: number };
	sources: EvidenceSource[];
	now?: () => number;
	onError?: (e: { source: string; error: Error }) => void;
}): Promise<EvidenceBundle> => {
	const now = input.now ?? Date.now;
	const bySource: EvidenceBundle['bySource'] = {};
	const errors: EvidenceBundle['errors'] = [];

	for (const source of input.sources) {
		try {
			bySource[source.name] = await source.collect(input.period, input.policy);
		} catch (e) {
			const error = e instanceof Error ? e : new Error(String(e));
			errors.push({ source: source.name, error });
			input.onError?.({ source: source.name, error });
		}
	}

	return {
		bySource,
		errors,
		generatedAt: now(),
		period: input.period,
		policy: input.policy
	};
};

/**
 * Convenience evidence source that streams audit events in the
 * period (optionally filtered by kind prefix) into the bundle.
 */
export const auditEvidenceSource = (
	audit: ComplianceAuditLike,
	options: { name?: string; kindPrefix?: string } = {}
): EvidenceSource => ({
	collect: async (period) => {
		if (audit.read === undefined) {
			throw new Error(
				'compliance: auditEvidenceSource needs a broker with `read`'
			);
		}
		const events: unknown[] = [];
		for await (const event of audit.read({
			since: period.start,
			until: period.end,
			...(options.kindPrefix !== undefined
				? { kindPrefix: options.kindPrefix }
				: {})
		})) {
			events.push(event);
		}
		return events;
	},
	name: options.name ?? 'audit'
});
