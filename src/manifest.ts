import { defineManifest, toolFactory } from '@absolutejs/manifest';
import { Type } from '@sinclair/typebox';
import {
	createResidencyGuard,
	runErasure,
	runSubjectAccess,
	type CompliancePolicy,
	type SubjectAccessCollector,
	type SubjectEraser
} from './index';

/* Composite runtime (v1 convention): the SAR/erasure tools need the policy
 * plus the host-registered collector/eraser pairs, so TRuntime is a
 * structural object of the pieces. */
type ComplianceRuntime = {
	policy: CompliancePolicy;
	collectors: SubjectAccessCollector[];
	erasers: SubjectEraser[];
};

const tool = toolFactory<ComplianceRuntime>();

const DAY_MS = 24 * 60 * 60 * 1000;
const GDPR_PII_RETENTION_DAYS = 730;
const OPERATIONAL_RETENTION_DAYS = 90;
const AUDIT_RETENTION_DAYS = 2555;

/* Serializable subset of CompliancePolicy: the classification table itself.
 * Collectors, erasers, scanners, deleters, and audit brokers are
 * function-valued → wiring concerns. */
export const manifest = defineManifest<CompliancePolicy, ComplianceRuntime>()({
	contract: 2,
	identity: {
		accent: '#0d9488',
		category: 'compliance',
		description:
			'Framework-agnostic compliance substrate: declarative data classification with retention windows, residency regions, and erasure exemptions; orchestrators for retention sweeps, Subject Access Requests, right-to-erasure (auto-routing exempt classes to anonymization), and auditor evidence bundles. SOC2, HIPAA, ISO 27001, and GDPR map onto the same five primitives.',
		docsUrl: 'https://github.com/absolutejs/compliance',
		name: '@absolutejs/compliance',
		tagline: "Follow privacy rules for keeping and erasing people's data.",
	},
	presets: [
		{
			description:
				'Personal data kept 2 years, operational data 90 days, audit logs 7 years (anonymized on erasure instead of deleted).',
			id: 'gdpr-baseline',
			title: 'GDPR baseline',
			values: {
				classifications: {
					'audit-log': {
						erasureExempt: true,
						id: 'audit-log',
						label: 'Audit logs',
						retentionMs: AUDIT_RETENTION_DAYS * DAY_MS
					},
					operational: {
						id: 'operational',
						label: 'Operational data',
						retentionMs: OPERATIONAL_RETENTION_DAYS * DAY_MS
					},
					pii: {
						id: 'pii',
						label: 'Personal data',
						retentionMs: GDPR_PII_RETENTION_DAYS * DAY_MS
					}
				}
			}
		}
	],
	settings: Type.Object({
		classifications: Type.Optional(
			Type.Record(
				Type.String(),
				Type.Object(
					{
						erasureExempt: Type.Optional(
							Type.Boolean({
								description:
									'Keep this data even when a person asks to be erased (required for audit logs in many jurisdictions). Their identity is anonymized instead.',
								title: 'Exempt from erasure'
							})
						),
						id: Type.String({
							description:
								'Stable id — must match the entry key.',
							title: 'Id'
						}),
						label: Type.Optional(
							Type.String({ title: 'Display name' })
						),
						residency: Type.Optional(
							Type.String({
								description:
									'Region this data must stay in. Leave empty for no constraint.',
								examples: ['eu'],
								title: 'Required region'
							})
						),
						retentionMs: Type.Number({
							description:
								'How long this data is kept before retention sweeps delete it, in milliseconds. 0 deletes on the next sweep.',
							minimum: 0,
							title: 'Keep for (ms)'
						})
					},
					{ title: 'Classification' }
				),
				{
					description:
						'Each kind of data your site stores, with its retention window, residency, and erasure behavior.',
					title: 'Data classifications'
				}
			)
		)
	}),
	tools: {
		check_residency: tool.runtime({
			annotations: { readOnlyHint: true },
			authorization: {
				approval: 'never',
				audience: 'admin',
				effects: ['read'],
				requiredScopes: ['compliance:read']
			},
			description:
				'Check whether storing data of a classification in a region would violate the residency policy. Pure policy check — touches no data.',
			handler: ({ classification, region, tenant }, runtime) => {
				const violation = createResidencyGuard(
					runtime.policy
				).inspect({ classification, region, tenant });

				return violation === null
					? `ok — '${classification}' may be stored in '${region}'`
					: violation.message;
			},
			input: Type.Object({
				classification: Type.String({ minLength: 1 }),
				region: Type.String({ minLength: 1 }),
				tenant: Type.Optional(Type.String({ minLength: 1 }))
			})
		}),
		erase_subject: tool.runtime({
			annotations: { destructiveHint: true, idempotentHint: true },
			authorization: {
				approval: 'always',
				audience: 'admin',
				effects: ['delete', 'write'],
				idempotency: { mode: 'resource' },
				requiredScopes: ['compliance:erase'],
				resource: {
					idField: 'subjectId',
					tenantIdField: 'tenant',
					type: 'data-subject'
				},
				reversible: false
			},
			description:
				'Execute a right-to-erasure request: every registered eraser deletes the subject’s records (erasure-exempt classes are anonymized in place instead). THIS DELETES DATA — run erasure_dry_run first.',
			handler: async ({ subjectId, tenant }, runtime) => {
				if (runtime.erasers.length === 0)
					return 'no erasers registered — wire subjectErasers first';
				const report = await runErasure({
					erasers: runtime.erasers,
					policy: runtime.policy,
					subject: { subjectId, tenant }
				});

				return JSON.stringify({
					byEraser: report.byEraser,
					errors: report.errors.map(
						({ eraser, error }) => `${eraser}: ${error.message}`
					)
				});
			},
			input: Type.Object({
				subjectId: Type.String({ minLength: 1 }),
				tenant: Type.Optional(Type.String({ minLength: 1 }))
			})
		}),
		erasure_dry_run: tool.runtime({
			annotations: { readOnlyHint: true },
			authorization: {
				approval: 'never',
				audience: 'admin',
				effects: ['read'],
				requiredScopes: ['compliance:read'],
				resource: {
					idField: 'subjectId',
					tenantIdField: 'tenant',
					type: 'data-subject'
				}
			},
			description:
				'Preview a right-to-erasure request: which erasers would delete and which would anonymize (erasure-exempt classes) for this subject, without touching any data.',
			handler: async ({ subjectId, tenant }, runtime) => {
				if (runtime.erasers.length === 0)
					return 'no erasers registered — wire subjectErasers first';
				const report = await runErasure({
					dryRun: true,
					erasers: runtime.erasers,
					policy: runtime.policy,
					subject: { subjectId, tenant }
				});

				return JSON.stringify(
					Object.fromEntries(
						Object.entries(report.byEraser).map(
							([name, entry]) => [
								name,
								{
									classification: entry.classification,
									mode: entry.mode
								}
							]
						)
					)
				);
			},
			input: Type.Object({
				subjectId: Type.String({ minLength: 1 }),
				tenant: Type.Optional(Type.String({ minLength: 1 }))
			})
		}),
		subject_access_preview: tool.runtime({
			annotations: { readOnlyHint: true },
			authorization: {
				approval: 'never',
				audience: 'admin',
				effects: ['read'],
				requiredScopes: ['compliance:read'],
				resource: {
					idField: 'subjectId',
					tenantIdField: 'tenant',
					type: 'data-subject'
				}
			},
			description:
				'Run a Subject Access Request across every registered collector and report how many records each holds for the subject. Returns counts, not the records themselves.',
			handler: async ({ subjectId, tenant }, runtime) => {
				if (runtime.collectors.length === 0)
					return 'no collectors registered — wire subjectCollectors first';
				const bundle = await runSubjectAccess({
					collectors: runtime.collectors,
					subject: { subjectId, tenant }
				});

				return JSON.stringify({
					byCollector: Object.fromEntries(
						Object.entries(bundle.byCollector).map(
							([name, entry]) => [
								name,
								{
									classification: entry.classification,
									records: entry.records.length
								}
							]
						)
					),
					errors: bundle.errors.map(
						({ collector, error }) =>
							`${collector}: ${error.message}`
					)
				});
			},
			input: Type.Object({
				subjectId: Type.String({ minLength: 1 }),
				tenant: Type.Optional(Type.String({ minLength: 1 }))
			})
		})
	},
	wiring: [
		{
			description:
				'Create the policy from your classification table, guard writes with the residency check, and register a collector + eraser per data store for SAR/erasure requests.',
			id: 'default',
			server: {
				code: [
					'const compliancePolicy = createCompliancePolicy({',
					'\tclassifications: {},',
					'\t...${settings}',
					'});',
					'',
					'// Call residencyGuard.check({ classification, region, tenant })',
					'// before letting classified data move.',
					'const residencyGuard = createResidencyGuard(compliancePolicy);',
					'',
					'// Each place that stores personal data contributes a collector',
					"// ('find everything about subject X') and an eraser ('forget it').",
					'// TODO: register a collector + eraser pair per data store.',
					'const subjectCollectors: SubjectAccessCollector[] = [];',
					'const subjectErasers: SubjectEraser[] = [];',
					'',
					'// Sweep expired data on your own schedule (cron / queue):',
					'//   await runRetention({ deleters, policy: compliancePolicy, scanners });'
				].join('\n'),
				imports: [
					{
						from: '@absolutejs/compliance',
						names: [
							'createCompliancePolicy',
							'createResidencyGuard'
						]
					},
					{
						from: '@absolutejs/compliance',
						names: ['SubjectAccessCollector', 'SubjectEraser'],
						typeOnly: true
					}
				],
				placement: 'module-scope'
			},
			title: 'Define the policy and the SAR/erasure pipeline'
		}
	]
});
