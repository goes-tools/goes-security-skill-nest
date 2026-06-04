/**
 * Smoke test del reporter universal — Node puro, sin runner.
 * ─────────────────────────────────────────────────────────────────────────────
 * Protege el reporter de regresiones cuando la skill evoluciona. Valida, contra
 * el MISMO archivo html-reporter.js:
 *   1. Camino Jest (onRunComplete): test verde + archivo que falla al cargar → rojo.
 *   2. Camino Vitest (onFinished):  test verde + archivo que falla a colección → rojo.
 *   3. Cruce de metadata runner-agnostic (Vitest une nombres con " > ").
 *
 * Uso:  node .claude/skills/goes-security-testing/reporter/smoke.js
 * Sale con código ≠ 0 si algo se rompe. Pensado para correr antes de commitear
 * cambios al reporter.
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const Reporter = require('./html-reporter.js');

const tmpRoot = path.join(os.tmpdir(), 'security-reporter-smoke');
fs.rmSync(tmpRoot, { recursive: true, force: true });
fs.mkdirSync(tmpRoot, { recursive: true });

let failures = 0;
function check(name, cond) {
  if (cond) {
    console.log(`  ✓ ${name}`);
  } else {
    console.error(`  ✗ ${name}`);
    failures++;
  }
}

function readReport(p) {
  return fs.readFileSync(p, 'utf-8');
}

async function run() {
  // ── Caso Jest ──────────────────────────────────────────────────────────────
  const metaDir = path.join(tmpRoot, 'meta-jest');
  fs.mkdirSync(metaDir, { recursive: true });
  process.env.SECURITY_REPORTER_TEMP_DIR = metaDir;

  // metadata escrita por metadata.ts (separador Jest = espacio)
  fs.writeFileSync(
    path.join(metaDir, 'meta-1.json'),
    JSON.stringify({
      testName: 'AuthService rechaza SQLi',
      testPath: path.join(tmpRoot, 'auth.security-html.spec.ts'),
      epic: 'Seguridad',
      feature: 'Input Validation',
      tags: ['Pentest', 'OWASP A03'],
      evidences: [
        { name: 'Attacker payload (input)', data: { q: "' OR 1=1" } },
        { name: 'Defense response (output)', data: { valid: false } },
      ],
    }),
  );

  const jestOut = path.join(tmpRoot, 'jest.html');
  const jr = new Reporter({ rootDir: tmpRoot, testMatch: ['x'] }, { outputPath: jestOut });
  await jr.onRunComplete(
    {},
    {
      testResults: [
        {
          testFilePath: path.join(tmpRoot, 'auth.security-html.spec.ts'),
          perfStats: { start: 0, end: 5 },
          testResults: [
            {
              title: 'rechaza SQLi',
              fullName: 'AuthService rechaza SQLi',
              status: 'passed',
              duration: 5,
              failureMessages: [],
            },
          ],
        },
        // Archivo que NO compila: sin assertions, con testExecError.
        {
          testFilePath: path.join(tmpRoot, 'broken.security-html.spec.ts'),
          perfStats: { start: 0, end: 0 },
          testResults: [],
          testExecError: { message: 'Cannot find module x' },
        },
      ],
    },
  );
  const jh = readReport(jestOut);
  console.log('Jest:');
  check('render contiene el test', jh.includes('rechaza SQLi'));
  check('metadata cruzó (feature presente)', jh.includes('Input Validation'));
  check('evidencia presente', jh.includes("' OR 1=1"));
  check('archivo roto aparece como fallo', jh.includes('no se pudo cargar') && jh.includes('Cannot find module x'));

  // ── Caso Vitest ──────────────────────────────────────────────────────────────
  const metaDirV = path.join(tmpRoot, 'meta-vitest');
  fs.mkdirSync(metaDirV, { recursive: true });
  process.env.SECURITY_REPORTER_TEMP_DIR = metaDirV;

  // metadata con separador Vitest (" > ") — debe cruzar igual tras normalizar.
  fs.writeFileSync(
    path.join(metaDirV, 'meta-1.json'),
    JSON.stringify({
      testName: 'AuthService > rechaza IDOR',
      testPath: path.join(tmpRoot, 'idor.security-html.spec.ts'),
      epic: 'Seguridad',
      feature: 'IDOR Prevention',
      tags: ['OWASP API1'],
      evidences: [
        { name: 'Request (input)', data: { id: 99 } },
        { name: 'Response (output)', data: { status: 403 } },
      ],
    }),
  );

  const vitestOut = path.join(tmpRoot, 'vitest.html');
  const vr = new Reporter({ outputPath: vitestOut });
  vr.onInit({ config: { root: tmpRoot } });
  await vr.onFinished([
    {
      filepath: path.join(tmpRoot, 'idor.security-html.spec.ts'),
      result: { duration: 3, state: 'pass' },
      tasks: [
        {
          type: 'suite',
          name: 'AuthService',
          tasks: [
            {
              type: 'test',
              name: 'rechaza IDOR',
              suite: { name: 'AuthService', suite: { filepath: path.join(tmpRoot, 'idor.security-html.spec.ts') } },
              result: { state: 'pass', duration: 3, errors: [] },
            },
          ],
        },
      ],
    },
    // Archivo que falla a colección: sin tasks, file.result.state = 'fail'.
    {
      filepath: path.join(tmpRoot, 'broken.security-html.spec.ts'),
      result: { state: 'fail', duration: 0, errors: [{ message: 'SyntaxError: bad import' }] },
      tasks: [],
    },
  ]);
  const vh = readReport(vitestOut);
  console.log('Vitest:');
  check('render contiene el test', vh.includes('rechaza IDOR'));
  check('metadata cruzó pese al separador ">"', vh.includes('IDOR Prevention'));
  check('evidencia presente', vh.includes('403'));
  check('archivo roto aparece como fallo', vh.includes('no se pudo cargar') && vh.includes('SyntaxError: bad import'));

  // ── Limpieza ──────────────────────────────────────────────────────────────
  fs.rmSync(tmpRoot, { recursive: true, force: true });

  console.log('');
  if (failures > 0) {
    console.error(`SMOKE FAIL — ${failures} aserción(es) rotas`);
    process.exit(1);
  }
  console.log('SMOKE OK — reporter universal Jest+Vitest válido');
  process.exit(0);
}

run().catch((e) => {
  console.error('SMOKE ERROR:', e);
  process.exit(1);
});
