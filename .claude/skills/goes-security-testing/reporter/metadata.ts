/**
 * Security Reporter Helper — Metadata Collector
 * ───────────────────────────────────────────────
 * Collects metadata (epic, feature, story, severity, tags, parameters, steps, evidence)
 * per test and writes it to a temp JSON file that the custom SecurityHtmlReporter reads.
 *
 * Compatible with allure-js-commons API for zero-migration from existing Allure tests.
 *
 * Usage:
 *   import { report } from './reporter/metadata';
 *
 *   it('test name', async () => {
 *     const t = report();
 *     t.epic('Input Validation');
 *     t.severity('critical');
 *     t.parameter('email', 'test@goes.gob.sv');
 *     t.step('Validate DTO');
 *     // ... test logic ...
 *     t.evidence('Validation Result', { payload, errors });
 *     await t.flush();
 *   });
 */

import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import * as crypto from 'crypto';

// ─── Temp directory for metadata files ─────────────────────────
//
// Concurrency: when Jest runs in parallel (--maxWorkers > 1) or when several
// CI jobs share the same machine, every worker process must scope its
// metadata to a unique subdirectory; otherwise the reporter would merge
// unrelated runs.
//
// Resolution order:
//   1. SECURITY_REPORTER_TEMP_DIR  (full override)
//   2. SECURITY_REPORTER_RUN_ID    (subdir scoped to this run)
//   3. fallback: $TMPDIR/security-html-reporter
function resolveTempDir(): string {
  if (process.env.SECURITY_REPORTER_TEMP_DIR) {
    return path.resolve(process.env.SECURITY_REPORTER_TEMP_DIR);
  }
  const runId = process.env.SECURITY_REPORTER_RUN_ID;
  if (runId) {
    return path.resolve(path.join(os.tmpdir(), 'security-html-reporter', runId));
  }
  return path.resolve(path.join(os.tmpdir(), 'security-html-reporter'));
}

const TEMP_DIR = resolveTempDir();

// Ensure temp directory exists
if (!fs.existsSync(TEMP_DIR)) {
  fs.mkdirSync(TEMP_DIR, { recursive: true });
}

// ─── Interfaces ─────────────────────────────────────────────────

/**
 * Actionable remediation info. Use it.remediation({...}) so the HTML modal
 * shows a prominent "Como arreglar" block when the test fails.
 *
 * All fields are optional — fill the ones you have. The modal renders only
 * the populated fields, in this order:
 *   file/line  →  expected vs received diff  →  howToFix  →  references
 */
export interface Remediation {
  /**
   * Plain-language summary (1-2 sentences) of what failed and what the impact is.
   * Avoid jargon — write for a dev who is new to security.
   * Example: "El sistema esta enviando informacion extra en los mensajes de error que un
   *          atacante puede usar para mapear la API."
   */
  summary?: string;

  /**
   * Ordered chain of verification steps the test followed to reach its conclusion.
   * Each item is one step. Helps the dev trace the reasoning, not just see the result.
   * Example: [
   *   "Forzamos un error enviando { malformed: true } a POST /api/auth/login",
   *   "Esperabamos un body con solo { statusCode, message }",
   *   "Encontramos tambien los campos `path` y `timestamp` con precision de milisegundos"
   * ]
   */
  howWeChecked?: string[];

  /**
   * Plain-language explanation of WHY this matters — the business / security impact
   * in terms a non-expert can understand. Used in the modal as a "Por que importa" callout.
   * Example: "El campo path deja ver rutas internas que un atacante puede enumerar.
   *          El timestamp con ms permite ataques de temporizacion."
   */
  whyItMatters?: string;

  /** Source file path relative to project root, e.g. "src/auth/auth.service.ts" */
  file?: string;
  /** Line number inside the file */
  line?: number;
  /** Function/symbol name (e.g. "validateDui()") */
  symbol?: string;
  /** What the test expected to find (concrete, copy-pasteable if possible) */
  expected?: string;
  /** What the test actually found in the code/runtime */
  received?: string;
  /** Step-by-step fix in plain text or markdown. Can be multi-line. */
  howToFix?: string;
  /** External references (docs, OWASP, GOES guide section) */
  references?: Array<{ url?: string; title: string }>;
  /** Snippet of correct code that the dev should aim for */
  exampleCode?: string;
}

export interface TestMetadata {
  testName: string;
  testPath: string;
  epic?: string;
  feature?: string;
  story?: string;
  severity?: string;
  owner?: string;
  tags: string[];
  labels: Record<string, string>;
  suite?: string;
  parentSuite?: string;
  links: Array<{ url: string; name: string }>;
  description?: string;
  parameters: Array<{ name: string; value: string }>;
  steps: string[];
  evidences: Array<{ name: string; data: unknown }>;
  /**
   * Actionable fix info shown prominently in the modal when the test fails.
   * Set via t.remediation({...}). See Remediation interface above.
   */
  remediation?: Remediation;
  /**
   * If set, the reporter overrides the test status to "skipped" and renders a
   * Not Applicable badge with this reason. Use it when a checklist item does
   * not apply to the project under test (e.g. R57-R60 file upload rules on a
   * backend that does not accept uploads).
   */
  naReason?: string;

  /**
   * If set, the reporter overrides the test status to "skipped" and renders a
   * "Riesgo Aceptado" (violet) badge — distinct from N/A (yellow).
   *
   * Use cases:
   * - Internal-only system where the surface exists but exposure to public
   *   internet is gated (VPN, IP allowlist).
   * - Legacy library that requires unsafe CSP and migration is scheduled.
   * - Risk evaluated by the team and consciously accepted with compensating
   *   controls.
   *
   * Should NEVER be used to silently skip failing tests without justification —
   * the doctor validates that every accepted_risk has:
   *   - reason (non-empty)
   *   - approved_by (@user)
   *   - approved_at (ISO date)
   *   - review_at (future date — once it expires, the risk must be re-evaluated)
   */
  acceptedRisk?: {
    rid: string;
    reason: string;
    approvedBy: string;
    approvedAt: string;
    reviewAt: string;
    compensatingControls?: string[];
  };
}

// ─── Reporter Class ─────────────────────────────────────────────
class SecurityTestReporter {
  private meta: TestMetadata = {
    testName: '',
    testPath: '',
    tags: [],
    labels: {},
    links: [],
    parameters: [],
    steps: [],
    evidences: [],
  };

  epic(name: string): this {
    this.meta.epic = name;
    return this;
  }

  feature(name: string): this {
    this.meta.feature = name;
    return this;
  }

  story(name: string): this {
    this.meta.story = name;
    return this;
  }

  severity(level: string): this {
    this.meta.severity = level.toLowerCase();
    return this;
  }

  owner(name: string): this {
    this.meta.owner = name;
    return this;
  }

  tag(...tags: string[]): this {
    this.meta.tags.push(...tags);
    return this;
  }

  label(key: string, value: string): this {
    this.meta.labels[key] = value;
    return this;
  }

  suite(name: string): this {
    this.meta.suite = name;
    return this;
  }

  parentSuite(name: string): this {
    this.meta.parentSuite = name;
    return this;
  }

  link(url: string, name?: string): this {
    this.meta.links.push({ url, name: name || url });
    return this;
  }

  descriptionHtml(html: string): this {
    this.meta.description = html;
    return this;
  }

  parameter(name: string, value: unknown): this {
    let strValue: string;
    if (value == null) {
      strValue = String(value);
    } else if (typeof value === 'string') {
      strValue = value;
    } else {
      strValue = JSON.stringify(value);
    }
    this.meta.parameters.push({ name, value: strValue });
    return this;
  }

  step(name: string, fn?: () => any): any {
    this.meta.steps.push(name);
    if (fn) {
      return fn();
    }
    return this;
  }

  evidence(name: string, data: unknown): this {
    this.meta.evidences.push({ name, data });
    return this;
  }

  /**
   * Attach actionable fix info that the modal renders prominently when this
   * test fails. Use it for tests that detect a specific code smell or missing
   * config — the dev sees exactly which file to open and what to change.
   *
   * Example:
   *   t.remediation({
   *     file: 'src/admin-reports/admin-reports.service.ts',
   *     line: 42,
   *     expected: 'prisma.$queryRaw\`SELECT ... WHERE id = ${id}\` (parametrized)',
   *     received: 'prisma.$queryRawUnsafe(\`SELECT ... WHERE id = ${id}\`)',
   *     howToFix: 'Reemplazar $queryRawUnsafe por $queryRaw con template tag.',
   *     references: [{ title: 'Prisma raw queries', url: 'https://prisma.io/docs' }],
   *   });
   */
  remediation(info: Remediation): this {
    this.meta.remediation = info;
    return this;
  }

  /**
   * Mark this test as Accepted Risk based on the project's snapshot.
   *
   * Reads `security.snapshot.json` (the project-level config approved by
   * CODEOWNERS) and looks up the given R-ID in `accepted_risks`. If found,
   * marks the test as skipped with a violet "Riesgo Aceptado" badge that
   * shows the reason + approver + review date.
   *
   * If the R-ID is NOT in accepted_risks, the method returns false and the
   * test continues normally (so the test runs its real assertions and fails
   * if the defense is missing).
   *
   * Example usage at the start of a test:
   *
   *   it('R6 — robots.txt accessible', async () => {
   *     const t = report();
   *     t.epic('Configuracion').feature('Public Site Config').story('robots.txt');
   *     t.tag('GOES Checklist R6');
   *
   *     if (await t.acceptedRiskIfDeclared('R6')) {
   *       await t.flush();
   *       return; // skip the real assertions, the snapshot accepts the risk
   *     }
   *
   *     // normal test body if the risk is NOT accepted...
   *   });
   *
   * Returns: true if the risk was found and accepted, false otherwise.
   */
  async acceptedRiskIfDeclared(rid: string, snapshotPath?: string): Promise<boolean> {
    const fsModule = fs;
    const pathModule = path;
    const candidates = [
      snapshotPath,
      'test/security/security.snapshot.json',
      './security.snapshot.json',
    ].filter(Boolean) as string[];

    for (const candidate of candidates) {
      try {
        const resolved = pathModule.resolve(process.cwd(), candidate);
        if (!fsModule.existsSync(resolved)) continue;
        const snap = JSON.parse(fsModule.readFileSync(resolved, 'utf-8'));
        const risks = Array.isArray(snap.accepted_risks) ? snap.accepted_risks : [];
        const found = risks.find((r: any) => r.rid === rid);
        if (found) {
          // Validar que tenga los campos minimos (sino, NO aceptamos — falla seguro)
          if (!found.reason || !found.approved_by || !found.review_at) {
            return false;
          }
          // Validar que review_at no haya expirado
          const reviewDate = new Date(found.review_at);
          if (isNaN(reviewDate.getTime()) || reviewDate < new Date()) {
            return false;
          }
          // Aceptar el riesgo
          this.meta.acceptedRisk = {
            rid: found.rid,
            reason: found.reason,
            approvedBy: found.approved_by,
            approvedAt: found.approved_at || '',
            reviewAt: found.review_at,
            compensatingControls: found.compensating_controls,
          };
          return true;
        }
      } catch (e) {
        // Si el snapshot no se puede parsear, no aceptamos riesgo (falla seguro)
        return false;
      }
    }
    return false;
  }

  /**
   * Mark this test as Not Applicable. The reporter overrides the test status
   * to "skipped" and renders a Not Applicable badge with the given reason.
   *
   * Use it.skip() also works but loses metadata. notApplicable() keeps the
   * test body running (so metadata is captured) and reports as skipped.
   *
   * Example:
   *   it('R57-R60 — File upload rules', async () => {
   *     const t = report();
   *     t.epic('Archivos').feature('File Upload Security');
   *     t.notApplicable('Backend does not accept uploads (no multer, no FileInterceptor)');
   *     await t.flush();
   *   });
   */
  notApplicable(reason: string): this {
    this.meta.naReason = reason;
    return this;
  }

  /**
   * Flush metadata to a temp JSON file.
   * The custom reporter reads these files in onRunComplete.
   */
  async flush(): Promise<void> {
    // Get current test name and path from Jest's global state
    try {
      const state = expect.getState();
      this.meta.testName = state.currentTestName || '';
      this.meta.testPath = state.testPath || '';
    } catch {
      // Fallback if expect.getState() is not available
    }

    const id = crypto.randomBytes(8).toString('hex');
    const filePath = path.join(TEMP_DIR, `meta-${id}.json`);
    fs.writeFileSync(filePath, JSON.stringify(this.meta, null, 2));
  }
}

// ─── Factory Function ───────────────────────────────────────────
export function report(): SecurityTestReporter {
  return new SecurityTestReporter();
}

/**
 * Compatibility layer: mirrors allure-js-commons API.
 * Use this for minimal migration effort from existing allure-based tests.
 */
export class AllureCompat {
  private reporter = new SecurityTestReporter();

  epic(name: string) { this.reporter.epic(name); }
  feature(name: string) { this.reporter.feature(name); }
  story(name: string) { this.reporter.story(name); }
  severity(level: string) { this.reporter.severity(level); }
  owner(name: string) { this.reporter.owner(name); }
  tag(...tags: string[]) { this.reporter.tag(...tags); }
  label(key: string, value: string) { this.reporter.label(key, value); }
  suite(name: string) { this.reporter.suite(name); }
  parentSuite(name: string) { this.reporter.parentSuite(name); }
  link(url: string, name?: string) { this.reporter.link(url, name); }
  descriptionHtml(html: string) { this.reporter.descriptionHtml(html); }
  // allure-js-commons exposes description() (markdown). We keep both names so
  // patterns migrated from the legacy Allure API still type-check.
  description(text: string) { this.reporter.descriptionHtml(text); }
  parameter(name: string, value: unknown) { this.reporter.parameter(name, value); }
  notApplicable(reason: string) { this.reporter.notApplicable(reason); }
  remediation(info: Remediation) { this.reporter.remediation(info); }
  async acceptedRiskIfDeclared(rid: string, snapshotPath?: string) {
    return this.reporter.acceptedRiskIfDeclared(rid, snapshotPath);
  }

  step<T = unknown>(name: string, fn?: () => T): T extends void ? this : T {
    return this.reporter.step(name, fn);
  }

  async attachment(name: string, data: unknown, _options?: any) {
    if (typeof data === 'string') {
      try {
        this.reporter.evidence(name, JSON.parse(data));
      } catch {
        this.reporter.evidence(name, data);
      }
    } else {
      this.reporter.evidence(name, data);
    }
  }

  async flush() {
    await this.reporter.flush();
  }
}

/**
 * Convenience helper used by legacy `attach('name', data)` calls in the test
 * patterns. Wires through to AllureCompat#attachment so callers do not need to
 * stringify their evidence manually.
 *
 * Usage in a spec:
 *   import { AllureCompat, attachFor } from '@security-reporter/metadata';
 *   const allure = new AllureCompat();
 *   const attach = attachFor(allure);
 *   await attach('payload (input)', { foo: 'bar' });
 */
export function attachFor(allure: AllureCompat) {
  return async (name: string, data: unknown) => {
    await allure.attachment(name, data);
  };
}

/**
 * Get the temp directory path (used by the custom reporter to read metadata files).
 */
export function getMetadataTempDir(): string {
  return TEMP_DIR;
}
