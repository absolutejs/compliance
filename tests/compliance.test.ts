import { describe, expect, test } from 'bun:test';
import {
	auditEvidenceSource,
	collectEvidence,
	createCompliancePolicy,
	createMemoryMessagingConsentStore,
	createMessagingConsentDispatchPolicy,
	createMessagingConsentLedger,
	createResidencyGuard,
	ResidencyViolation,
	resolveClassification,
	runErasure,
	runRetention,
	runSubjectAccess,
	type ComplianceAuditLike,
	type ExpiredRecord,
	type RetentionScanner,
	type SubjectAccessCollector,
	type SubjectEraser
} from '../src/index';

describe('messaging consent', () => {
	const scope = {
		recipient: '+12025550100',
		senderId: 'acme',
		tenant: 'tenant-a',
		topic: 'incident-alerts',
		transport: 'sms' as const
	};

	test('records grant and revocation evidence chronologically', async () => {
		const ledger = createMessagingConsentLedger({
			id: (() => {
				let next = 0;
				return () => `consent-${++next}`;
			})(),
			store: createMemoryMessagingConsentStore()
		});
		expect(await ledger.decision(scope)).toEqual({
			allowed: false,
			code: 'missing-consent'
		});
		await ledger.grant(scope, { at: 100, source: 'signup-form' });
		expect((await ledger.decision(scope)).allowed).toBe(true);
		await ledger.revoke(scope, { at: 200, source: 'twilio-stop' });
		expect(await ledger.decision(scope)).toMatchObject({
			allowed: false,
			code: 'revoked'
		});
		expect(await ledger.history(scope)).toHaveLength(2);
	});

	test('supplies a dispatch policy that enforces the exact scope', async () => {
		const ledger = createMessagingConsentLedger({
			store: createMemoryMessagingConsentStore()
		});
		const policy = createMessagingConsentDispatchPolicy({ ledger });
		const context = {
			adapter: 'twilio',
			channel: 'sms' as const,
			message: {
				body: 'Alert',
				consent: { senderId: scope.senderId, topic: scope.topic },
				tenant: scope.tenant,
				to: scope.recipient
			}
		};
		expect(await policy.evaluate(context)).toMatchObject({ allowed: false });
		await ledger.grant(scope, { at: 100, source: 'signup-form' });
		expect(await policy.evaluate(context)).toEqual({ allowed: true });
	});
});

// =============================================================================
// Audit mock
// =============================================================================

const makeAudit = (): {
	audit: ComplianceAuditLike;
	events: Array<{
		kind: string;
		actor?: string;
		target?: string;
		metadata?: Record<string, unknown>;
	}>;
} => {
	const events: Array<{
		kind: string;
		actor?: string;
		target?: string;
		metadata?: Record<string, unknown>;
	}> = [];
	return {
		audit: { append: async (e) => void events.push(e) },
		events
	};
};

// =============================================================================
// createCompliancePolicy
// =============================================================================

describe('createCompliancePolicy', () => {
	test('returns the policy when valid', () => {
		const policy = createCompliancePolicy({
			classifications: {
				pii: { id: 'pii', residency: 'eu', retentionMs: 1000 }
			}
		});
		expect(policy.classifications.pii?.residency).toBe('eu');
	});

	test('rejects mismatched key/id', () => {
		expect(() =>
			createCompliancePolicy({
				classifications: {
					pii: { id: 'wrong', retentionMs: 1000 }
				}
			})
		).toThrow('must match its id');
	});

	test('rejects negative retentionMs', () => {
		expect(() =>
			createCompliancePolicy({
				classifications: {
					pii: { id: 'pii', retentionMs: -1 }
				}
			})
		).toThrow('invalid retentionMs');
	});

	test('rejects NaN retentionMs but accepts Infinity', () => {
		expect(() =>
			createCompliancePolicy({
				classifications: {
					pii: { id: 'pii', retentionMs: NaN }
				}
			})
		).toThrow('invalid retentionMs');
		expect(() =>
			createCompliancePolicy({
				classifications: {
					'audit-log': { id: 'audit-log', retentionMs: Infinity }
				}
			})
		).not.toThrow();
	});
});

// =============================================================================
// resolveClassification — overrides
// =============================================================================

describe('resolveClassification', () => {
	const policy = createCompliancePolicy({
		classifications: {
			pii: { id: 'pii', residency: 'us-east', retentionMs: 1000 }
		},
		tenantOverrides: {
			acme: { pii: { residency: 'eu', retentionMs: 500 } }
		}
	});

	test('returns base class for tenants with no override', () => {
		const c = resolveClassification(policy, 'pii', 'someone-else');
		expect(c?.residency).toBe('us-east');
		expect(c?.retentionMs).toBe(1000);
	});

	test('tenant override merges over base', () => {
		const c = resolveClassification(policy, 'pii', 'acme');
		expect(c?.residency).toBe('eu');
		expect(c?.retentionMs).toBe(500);
	});

	test('unknown class returns undefined', () => {
		expect(resolveClassification(policy, 'nope')).toBeUndefined();
	});
});

// =============================================================================
// Residency guard
// =============================================================================

describe('createResidencyGuard', () => {
	const policy = createCompliancePolicy({
		classifications: {
			'audit-log': { id: 'audit-log', retentionMs: Infinity },
			pii: { id: 'pii', residency: 'us-east', retentionMs: 1000 }
		},
		tenantOverrides: {
			acme: { pii: { residency: 'eu' } }
		}
	});

	test('throws ResidencyViolation on region mismatch', () => {
		const guard = createResidencyGuard(policy);
		expect(() =>
			guard.check({ classification: 'pii', region: 'eu' })
		).toThrow(ResidencyViolation);
	});

	test('passes when regions match', () => {
		const guard = createResidencyGuard(policy);
		expect(() =>
			guard.check({ classification: 'pii', region: 'us-east' })
		).not.toThrow();
	});

	test('tenant override flips required region', () => {
		const guard = createResidencyGuard(policy);
		expect(() =>
			guard.check({
				classification: 'pii',
				region: 'us-east',
				tenant: 'acme'
			})
		).toThrow(ResidencyViolation);
		expect(() =>
			guard.check({ classification: 'pii', region: 'eu', tenant: 'acme' })
		).not.toThrow();
	});

	test('class with no residency constraint passes through', () => {
		const guard = createResidencyGuard(policy);
		expect(() =>
			guard.check({ classification: 'audit-log', region: 'antarctica' })
		).not.toThrow();
	});

	test('unknown class is a no-op (lets the data through)', () => {
		const guard = createResidencyGuard(policy);
		expect(() =>
			guard.check({ classification: 'nope', region: 'eu' })
		).not.toThrow();
	});

	test('inspect returns the violation without throwing', () => {
		const guard = createResidencyGuard(policy);
		const v = guard.inspect({ classification: 'pii', region: 'eu' });
		expect(v).toBeInstanceOf(ResidencyViolation);
		expect(v?.classification).toBe('pii');
		expect(v?.required).toBe('us-east');
		expect(v?.got).toBe('eu');
	});

	test('ResidencyViolation includes tenant id when present', () => {
		const guard = createResidencyGuard(policy);
		const v = guard.inspect({
			classification: 'pii',
			region: 'us-east',
			tenant: 'acme'
		});
		expect(v?.tenant).toBe('acme');
		expect(v?.message).toContain('tenant acme');
	});
});

// =============================================================================
// runRetention
// =============================================================================

describe('runRetention', () => {
	const policy = createCompliancePolicy({
		classifications: {
			'audit-log': { id: 'audit-log', retentionMs: Infinity },
			operational: { id: 'operational', retentionMs: 90 * 86_400_000 },
			pii: { id: 'pii', retentionMs: 730 * 86_400_000 }
		}
	});

	const makeScanner = (
		classification: string,
		records: ExpiredRecord[]
	): RetentionScanner => ({
		classification,
		scan: async function* () {
			for (const r of records) yield r;
		}
	});

	test('streams expired records through the deleter in batches', async () => {
		const deleted: ExpiredRecord[][] = [];
		const records = Array.from({ length: 1200 }, (_, i) => ({ id: `r-${i}` }));
		const report = await runRetention({
			batchSize: 500,
			deleters: {
				operational: (batch) => {
					deleted.push(batch);
					return { deleted: batch.length };
				}
			},
			policy,
			scanners: [makeScanner('operational', records)]
		});
		expect(deleted.map((b) => b.length)).toEqual([500, 500, 200]);
		expect(report.byClassification.operational?.scanned).toBe(1200);
		expect(report.byClassification.operational?.deleted).toBe(1200);
		expect(report.errors).toEqual([]);
	});

	test('Infinity retention skips the scanner entirely', async () => {
		const scanned: number[] = [];
		const report = await runRetention({
			deleters: {
				'audit-log': () => ({ deleted: 0 })
			},
			policy,
			scanners: [
				{
					classification: 'audit-log',
					scan: async function* () {
						scanned.push(1);
						yield { id: 'a' };
					}
				}
			]
		});
		expect(scanned).toEqual([]);
		expect(report.byClassification['audit-log']?.scanned).toBe(0);
	});

	test('unknown classification ends up in errors, not throws', async () => {
		const report = await runRetention({
			deleters: {},
			policy,
			scanners: [makeScanner('mystery', [{ id: '1' }])]
		});
		expect(report.errors[0]?.classification).toBe('mystery');
		expect(report.errors[0]?.error.message).toContain('no classification');
	});

	test('missing deleter for a discovered class surfaces as an error', async () => {
		const report = await runRetention({
			deleters: {}, // <-- missing
			policy,
			scanners: [makeScanner('pii', [{ id: '1' }])]
		});
		expect(report.errors[0]?.error.message).toContain('no deleter');
	});

	test('scanner failure is isolated to that classification', async () => {
		const report = await runRetention({
			deleters: {
				operational: () => ({ deleted: 1 }),
				pii: () => ({ deleted: 1 })
			},
			policy,
			scanners: [
				{
					classification: 'pii',
					scan: async function* () {
						throw new Error('db down');
					}
				},
				makeScanner('operational', [{ id: 'op-1' }])
			]
		});
		expect(report.errors).toHaveLength(1);
		expect(report.errors[0]?.classification).toBe('pii');
		expect(report.byClassification.operational?.deleted).toBe(1);
	});

	test('dryRun never calls the deleter', async () => {
		let called = 0;
		await runRetention({
			deleters: {
				operational: () => {
					called += 1;
					return { deleted: 1 };
				}
			},
			dryRun: true,
			policy,
			scanners: [makeScanner('operational', [{ id: '1' }, { id: '2' }])]
		});
		expect(called).toBe(0);
	});

	test('audit broker receives a sweep event per classification', async () => {
		const { audit, events } = makeAudit();
		await runRetention({
			audit,
			deleters: {
				operational: (b) => ({ deleted: b.length }),
				pii: (b) => ({ deleted: b.length })
			},
			policy,
			scanners: [
				makeScanner('pii', [{ id: 'p-1' }]),
				makeScanner('operational', [{ id: 'op-1' }])
			]
		});
		expect(events.map((e) => e.kind)).toEqual([
			'compliance.retention.swept',
			'compliance.retention.swept'
		]);
		expect(events[0]?.metadata?.classification).toBe('pii');
		expect(events[0]?.metadata?.deleted).toBe(1);
	});

	test('tenant override drives retention cutoff', async () => {
		const overridden = createCompliancePolicy({
			classifications: {
				pii: { id: 'pii', retentionMs: 1_000_000_000 } // ~11.5 days
			},
			tenantOverrides: {
				strict: { pii: { retentionMs: 1 } }
			}
		});
		const seenCutoffs: number[] = [];
		await runRetention({
			deleters: { pii: () => ({ deleted: 0 }) },
			now: () => 5_000_000_000,
			policy: overridden,
			scanners: [
				{
					classification: 'pii',
					scan: async function* ({ cutoff }) {
						seenCutoffs.push(cutoff);
					}
				}
			],
			tenant: 'strict'
		});
		// With override applied: cutoff ≈ now - 1 = 4999999999
		expect(seenCutoffs[0]).toBe(4_999_999_999);
	});
});

// =============================================================================
// runSubjectAccess
// =============================================================================

describe('runSubjectAccess', () => {
	test('collects sync + async + iterable returns into one bundle', async () => {
		const collectors: SubjectAccessCollector[] = [
			{
				classification: 'pii',
				collect: () => [{ row: 1 }, { row: 2 }],
				name: 'profile'
			},
			{
				classification: 'audit-log',
				collect: async () => [{ at: 100 }],
				name: 'audit'
			},
			{
				classification: 'sync-packs',
				collect: async function* () {
					yield { pack: 'comments' };
					yield { pack: 'favorites' };
				} as never,
				name: 'sync'
			}
		];
		const bundle = await runSubjectAccess({
			collectors,
			subject: { subjectId: 'u-1', tenant: 'acme' }
		});
		expect(bundle.byCollector.profile?.records).toHaveLength(2);
		expect(bundle.byCollector.audit?.records).toHaveLength(1);
		expect(bundle.byCollector.sync?.records).toHaveLength(2);
		expect(bundle.errors).toEqual([]);
	});

	test('one collector throwing → error captured, others continue', async () => {
		const bundle = await runSubjectAccess({
			collectors: [
				{
					classification: 'pii',
					collect: () => {
						throw new Error('lost');
					},
					name: 'broken'
				},
				{
					classification: 'pii',
					collect: () => [{ ok: true }],
					name: 'fine'
				}
			],
			subject: { subjectId: 'u-1' }
		});
		expect(bundle.errors).toHaveLength(1);
		expect(bundle.errors[0]?.collector).toBe('broken');
		expect(bundle.byCollector.fine?.records).toHaveLength(1);
	});

	test('non-array, non-iterable single value is wrapped', async () => {
		const bundle = await runSubjectAccess({
			collectors: [
				{
					classification: 'pii',
					collect: () => ({ singleton: true }),
					name: 'one'
				}
			],
			subject: { subjectId: 'u-1' }
		});
		expect(bundle.byCollector.one?.records).toEqual([{ singleton: true }]);
	});
});

// =============================================================================
// runErasure
// =============================================================================

describe('runErasure', () => {
	const policy = createCompliancePolicy({
		classifications: {
			'audit-log': {
				erasureExempt: true,
				id: 'audit-log',
				retentionMs: Infinity
			},
			pii: { id: 'pii', retentionMs: 1000 }
		}
	});

	test('non-exempt class is erased', async () => {
		const erasers: SubjectEraser[] = [
			{
				classification: 'pii',
				erase: async () => ({ deleted: 3 }),
				name: 'profile'
			}
		];
		const report = await runErasure({
			erasers,
			policy,
			subject: { subjectId: 'u-1' }
		});
		expect(report.byEraser.profile?.mode).toBe('erase');
		expect(report.byEraser.profile?.deleted).toBe(3);
	});

	test('exempt class routes to anonymize when provided', async () => {
		const erasers: SubjectEraser[] = [
			{
				anonymize: async () => ({ anonymized: 7 }),
				classification: 'audit-log',
				erase: async () => ({ deleted: 99 }),
				name: 'audit'
			}
		];
		const report = await runErasure({
			erasers,
			policy,
			subject: { subjectId: 'u-1' }
		});
		expect(report.byEraser.audit?.mode).toBe('anonymize');
		expect(report.byEraser.audit?.anonymized).toBe(7);
		expect(report.byEraser.audit?.deleted).toBe(0);
	});

	test('exempt class with no anonymize → skipped', async () => {
		const report = await runErasure({
			erasers: [
				{
					classification: 'audit-log',
					erase: async () => ({ deleted: 99 }),
					name: 'audit'
				}
			],
			policy,
			subject: { subjectId: 'u-1' }
		});
		expect(report.byEraser.audit?.mode).toBe('skipped');
	});

	test('audit event records the erasure with subject + mode breakdown', async () => {
		const { audit, events } = makeAudit();
		await runErasure({
			audit,
			erasers: [
				{
					classification: 'pii',
					erase: async () => ({ deleted: 1 }),
					name: 'profile'
				}
			],
			policy,
			subject: { subjectId: 'u-1', tenant: 'acme' }
		});
		expect(events[0]?.kind).toBe('compliance.subject.erased');
		expect(events[0]?.target).toBe('u-1');
		expect(events[0]?.actor).toBe('acme');
	});

	test('eraser throwing → captured in errors, others continue', async () => {
		const report = await runErasure({
			erasers: [
				{
					classification: 'pii',
					erase: async () => {
						throw new Error('locked');
					},
					name: 'broken'
				},
				{
					classification: 'pii',
					erase: async () => ({ deleted: 2 }),
					name: 'fine'
				}
			],
			policy,
			subject: { subjectId: 'u-1' }
		});
		expect(report.errors).toHaveLength(1);
		expect(report.byEraser.fine?.deleted).toBe(2);
	});

	test('dryRun returns the plan without calling erase/anonymize', async () => {
		let called = 0;
		const report = await runErasure({
			dryRun: true,
			erasers: [
				{
					classification: 'pii',
					erase: () => {
						called += 1;
						return { deleted: 1 };
					},
					name: 'profile'
				}
			],
			policy,
			subject: { subjectId: 'u-1' }
		});
		expect(called).toBe(0);
		expect(report.byEraser.profile?.mode).toBe('erase');
		expect(report.byEraser.profile?.deleted).toBe(0);
	});

	test('tenant override flips erasureExempt for one tenant only', async () => {
		const overridden = createCompliancePolicy({
			classifications: {
				'audit-log': {
					erasureExempt: true,
					id: 'audit-log',
					retentionMs: Infinity
				}
			},
			tenantOverrides: {
				'no-exempt-tenant': { 'audit-log': { erasureExempt: false } }
			}
		});
		const erasers: SubjectEraser[] = [
			{
				anonymize: async () => ({ anonymized: 1 }),
				classification: 'audit-log',
				erase: async () => ({ deleted: 5 }),
				name: 'audit'
			}
		];
		const reportA = await runErasure({
			erasers,
			policy: overridden,
			subject: { subjectId: 'u', tenant: 'normal' }
		});
		expect(reportA.byEraser.audit?.mode).toBe('anonymize');
		const reportB = await runErasure({
			erasers,
			policy: overridden,
			subject: { subjectId: 'u', tenant: 'no-exempt-tenant' }
		});
		expect(reportB.byEraser.audit?.mode).toBe('erase');
	});
});

// =============================================================================
// collectEvidence
// =============================================================================

describe('collectEvidence', () => {
	const policy = createCompliancePolicy({
		classifications: {
			pii: { id: 'pii', retentionMs: 1000 }
		}
	});

	test('returns bySource keyed by source name', async () => {
		const bundle = await collectEvidence({
			period: { end: 200, start: 100 },
			policy,
			sources: [
				{ collect: () => ({ count: 4 }), name: 'audit' },
				{ collect: async () => ({ ok: true }), name: 'access' }
			]
		});
		expect(bundle.bySource.audit).toEqual({ count: 4 });
		expect(bundle.bySource.access).toEqual({ ok: true });
	});

	test('source failure captured in errors, others continue', async () => {
		const bundle = await collectEvidence({
			period: { end: 200, start: 100 },
			policy,
			sources: [
				{
					collect: () => {
						throw new Error('S3 unreachable');
					},
					name: 'broken'
				},
				{ collect: () => ({ ok: true }), name: 'fine' }
			]
		});
		expect(bundle.errors).toHaveLength(1);
		expect(bundle.errors[0]?.source).toBe('broken');
		expect(bundle.bySource.fine).toEqual({ ok: true });
	});

	test('policy + period flow through unchanged', async () => {
		const bundle = await collectEvidence({
			period: { end: 999, start: 1 },
			policy,
			sources: []
		});
		expect(bundle.policy).toBe(policy);
		expect(bundle.period).toEqual({ end: 999, start: 1 });
	});
});

// =============================================================================
// auditEvidenceSource
// =============================================================================

describe('auditEvidenceSource', () => {
	test('reads broker events in the period', async () => {
		const events = [
			{ at: 100, kind: 'compliance.retention.swept', metadata: { x: 1 } },
			{ at: 200, kind: 'compliance.subject.erased' }
		];
		const audit: ComplianceAuditLike = {
			append: () => {},
			read: async function* ({ since, until }) {
				for (const e of events) {
					const at = e.at;
					if (at >= since && at < until) yield e;
				}
			}
		};
		const policy = createCompliancePolicy({
			classifications: { pii: { id: 'pii', retentionMs: 1 } }
		});
		const bundle = await collectEvidence({
			period: { end: 250, start: 50 },
			policy,
			sources: [auditEvidenceSource(audit)]
		});
		expect((bundle.bySource.audit as unknown[]).length).toBe(2);
	});

	test('throws when broker lacks `read`', async () => {
		const audit: ComplianceAuditLike = { append: () => {} };
		const policy = createCompliancePolicy({
			classifications: { pii: { id: 'pii', retentionMs: 1 } }
		});
		const bundle = await collectEvidence({
			period: { end: 200, start: 100 },
			policy,
			sources: [auditEvidenceSource(audit)]
		});
		expect(bundle.errors[0]?.error.message).toContain('needs a broker');
	});
});
