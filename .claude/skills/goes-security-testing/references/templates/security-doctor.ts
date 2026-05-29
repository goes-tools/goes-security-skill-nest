// scripts/security-doctor.ts
//
// Auditor de la skill goes-security-testing aplicada al proyecto actual.
// Falla con codigo 1 si CUALQUIER pieza obligatoria esta ausente o mal
// configurada. La skill lo ejecuta como ultimo paso del PASO 8 — si no
// pasa, la skill marca FAILURE y NO se considera aplicada al proyecto.
//
// Tambien se puede correr manualmente en cualquier momento:
//   npm run security:doctor
//
// Genera reports/security/doctor-report.json con el detalle.

import * as fs from 'fs';
import * as path from 'path';
import * as yaml from 'js-yaml';
import * as glob from 'glob';

interface DoctorCheck {
  id: string;
  description: string;
  passed: boolean;
  details?: string;
  missing?: string[];
}

const ROOT = path.resolve(__dirname, '..');
const checks: DoctorCheck[] = [];

function exists(p: string): boolean {
  return fs.existsSync(path.join(ROOT, p));
}

function read(p: string): string {
  return fs.readFileSync(path.join(ROOT, p), 'utf-8');
}

// ============================================================
// 1. Archivos canonicos de la skill
// ============================================================
const REQUIRED_FILES = [
  'test/security/jest-security-html.config.ts',
  'test/security/security.snapshot.json',
  '.github/workflows/security-gate.yml',
  '.github/CODEOWNERS',
];
const missingFiles = REQUIRED_FILES.filter((f) => !exists(f));
checks.push({
  id: 'CANONICAL_FILES',
  description: 'Archivos canonicos de la skill presentes',
  passed: missingFiles.length === 0,
  missing: missingFiles,
});

// ============================================================
// 2. Cobertura del checklist GOES (57 items)
// ============================================================
const specs = glob.sync('test/security/**/*.security-html.spec.ts', { cwd: ROOT, absolute: true });
const specContents = specs.map((f) => fs.readFileSync(f, 'utf-8')).join('\n');

const checklistItems: string[] = [];
for (let n = 3; n <= 63; n++) {
  if ([7, 12, 36, 56].includes(n)) continue; // gaps por categorias
  checklistItems.push(`R${n}`);
}
const missingChecklist = checklistItems.filter((r) => {
  const tag = `GOES Checklist ${r}`;
  return !specContents.includes(tag);
});
checks.push({
  id: 'CHECKLIST_COVERAGE',
  description: '57 items del checklist GOES cubiertos con al menos 1 test',
  passed: missingChecklist.length === 0,
  details: `${checklistItems.length - missingChecklist.length}/${checklistItems.length} cubiertos`,
  missing: missingChecklist,
});

// ============================================================
// 3. Regression specs para cada VULN-ID activo del YAML
// ============================================================
const YAML_REL = '.claude/skills/goes-security-testing/references/pentest-history.yaml';
let yamlMissingRegression: string[] = [];
let yamlPresent = exists(YAML_REL);

if (yamlPresent) {
  const yamlContent = read(YAML_REL);
  const parsed = yaml.load(yamlContent) as { findings: Array<{ id: string; status: string }> };
  const activeOrTracked = (parsed.findings || []).filter((f) =>
    ['active', 'closed', 'accepted_risk'].includes(f.status),
  );
  yamlMissingRegression = activeOrTracked
    .filter((f) => !exists(`test/security/regression/${f.id}.regression.spec.ts`))
    .map((f) => f.id);
}

checks.push({
  id: 'PENTEST_REGRESSION',
  description: 'Cada VULN-ID del pentest-history tiene su regression spec',
  passed: yamlPresent && yamlMissingRegression.length === 0,
  details: yamlPresent ? 'pentest-history.yaml encontrado' : 'pentest-history.yaml AUSENTE',
  missing: yamlMissingRegression.map((id) => `test/security/regression/${id}.regression.spec.ts`),
});

// ============================================================
// 4. security.snapshot.json valido y aprobado
// ============================================================
let snapshotChecks: string[] = [];
const SNAPSHOT_PATH = 'test/security/security.snapshot.json';
if (exists(SNAPSHOT_PATH)) {
  try {
    const snap = JSON.parse(read(SNAPSHOT_PATH));
    if (!snap.approved_by) snapshotChecks.push('approved_by ausente');
    if (!snap.approved_at) snapshotChecks.push('approved_at ausente');
    if (!snap.headers || Object.keys(snap.headers).length < 10) {
      snapshotChecks.push('headers insuficientes (esperado >= 10 entradas)');
    }
    if (!snap.cors?.allowed_origins?.length) snapshotChecks.push('cors.allowed_origins vacio');
    if (!snap.session?.idle_timeout_minutes) snapshotChecks.push('session.idle_timeout_minutes ausente');
    if (!snap.error_response?.forbidden_keys?.length) snapshotChecks.push('error_response.forbidden_keys vacio');

    const projectName = snap.project || '';
    if (projectName.includes('REPLACE_WITH_')) {
      snapshotChecks.push('snapshot tiene placeholders REPLACE_WITH_* sin reemplazar');
    }
  } catch (e) {
    snapshotChecks.push(`JSON invalido: ${(e as Error).message}`);
  }
} else {
  snapshotChecks.push('archivo no existe');
}
checks.push({
  id: 'SNAPSHOT_VALID',
  description: 'security.snapshot.json existe, es valido y esta aprobado',
  passed: snapshotChecks.length === 0,
  missing: snapshotChecks,
});

// ============================================================
// 5. CI gate sin continue-on-error ni desactivaciones
// ============================================================
let gateProblems: string[] = [];
const GATE_PATH = '.github/workflows/security-gate.yml';
if (exists(GATE_PATH)) {
  const gateContent = read(GATE_PATH);
  // Buscar continue-on-error: true (con flexibilidad de espacios)
  if (/continue-on-error\s*:\s*true/i.test(gateContent)) {
    gateProblems.push('continue-on-error: true detectado — gate puede ser bypaseado');
  }
  if (/if\s*:\s*false/i.test(gateContent)) {
    gateProblems.push('if: false detectado — algun step esta deshabilitado');
  }
  // Jobs canonicos
  const requiredJobs = ['security-tests-local', 'checklist-coverage'];
  for (const job of requiredJobs) {
    if (!new RegExp(`^\\s*${job}\\s*:`, 'm').test(gateContent)) {
      gateProblems.push(`job canonico '${job}' ausente`);
    }
  }
  // Que el workflow corra en pull_request
  if (!/on:\s*[\s\S]*pull_request/.test(gateContent)) {
    gateProblems.push('workflow no corre en pull_request');
  }
} else {
  gateProblems.push('workflow no existe');
}
checks.push({
  id: 'CI_GATE_INTEGRITY',
  description: 'security-gate.yml integro, sin bypasses',
  passed: gateProblems.length === 0,
  missing: gateProblems,
});

// ============================================================
// 6. CODEOWNERS protege los archivos criticos
// ============================================================
let codeownersProblems: string[] = [];
const CODEOWNERS_PATH = '.github/CODEOWNERS';
if (exists(CODEOWNERS_PATH)) {
  const co = read(CODEOWNERS_PATH);
  const requiredOwned = [
    'test/security/security.snapshot.json',
    '.github/workflows/security-gate.yml',
  ];
  for (const target of requiredOwned) {
    if (!co.includes(target)) {
      codeownersProblems.push(`${target} no tiene owners declarados`);
    }
  }
  if (!/@[a-zA-Z0-9_-]/.test(co)) {
    codeownersProblems.push('CODEOWNERS sin handles @ — invalido');
  }
} else {
  codeownersProblems.push('CODEOWNERS no existe');
}
checks.push({
  id: 'CODEOWNERS',
  description: 'CODEOWNERS protege snapshot + workflow',
  passed: codeownersProblems.length === 0,
  missing: codeownersProblems,
});

// ============================================================
// 7. Scripts npm requeridos
// ============================================================
let scriptsProblems: string[] = [];
if (exists('package.json')) {
  const pkg = JSON.parse(read('package.json'));
  const required = ['test:security:html', 'security:doctor'];
  const recommended = ['test:security:release', 'test:security:snapshot:update'];
  for (const s of required) {
    if (!pkg.scripts?.[s]) scriptsProblems.push(`script '${s}' ausente (obligatorio)`);
  }
  for (const s of recommended) {
    if (!pkg.scripts?.[s]) scriptsProblems.push(`script '${s}' ausente (recomendado)`);
  }
} else {
  scriptsProblems.push('package.json no existe');
}
checks.push({
  id: 'NPM_SCRIPTS',
  description: 'Scripts npm test:security:* declarados',
  passed: scriptsProblems.filter((p) => p.includes('obligatorio')).length === 0,
  missing: scriptsProblems,
});

// ============================================================
// 8. Tests pasan (opcional — solo en modo --with-tests)
// ============================================================
// El doctor NO ejecuta los tests; eso lo hace el CI gate. El doctor
// verifica que la estructura este correcta antes de pasar a tests.

// ============================================================
// Reporte
// ============================================================
const passed = checks.filter((c) => c.passed).length;
const total = checks.length;
const allPassed = passed === total;

const report = {
  generated_at: new Date().toISOString(),
  project: path.basename(ROOT),
  passed,
  total,
  status: allPassed ? 'PASS' : 'FAIL',
  checks,
};

const outDir = path.join(ROOT, 'reports/security');
fs.mkdirSync(outDir, { recursive: true });
fs.writeFileSync(path.join(outDir, 'doctor-report.json'), JSON.stringify(report, null, 2));

// Print human-readable
console.log('');
console.log('===========================================');
console.log('  GOES Security Doctor — Audit Report');
console.log('===========================================');
console.log(`Proyecto: ${report.project}`);
console.log(`Resultado: ${allPassed ? 'PASS' : 'FAIL'} (${passed}/${total})`);
console.log('');

for (const c of checks) {
  const icon = c.passed ? 'OK  ' : 'FAIL';
  console.log(`[${icon}] ${c.id} — ${c.description}`);
  if (!c.passed) {
    if (c.details) console.log(`        detalle: ${c.details}`);
    if (c.missing?.length) {
      for (const m of c.missing) console.log(`        - ${m}`);
    }
  } else if (c.details) {
    console.log(`        ${c.details}`);
  }
}

console.log('');
console.log(`Reporte JSON: reports/security/doctor-report.json`);

if (!allPassed) {
  console.log('');
  console.log('REGLAS DE LA SKILL goes-security-testing:');
  console.log('- Si CHECKLIST_COVERAGE falla -> agregar tests para los R faltantes');
  console.log('- Si PENTEST_REGRESSION falla -> generar specs en test/security/regression/');
  console.log('- Si SNAPSHOT_VALID falla -> ejecutar npm run test:security:snapshot:update');
  console.log('- Si CI_GATE_INTEGRITY falla -> restaurar workflow desde la skill');
  console.log('- Si CODEOWNERS falla -> mergear contenido de CODEOWNERS.example al CODEOWNERS del proyecto');
  console.log('- Si NPM_SCRIPTS falla -> agregar los scripts al package.json');
  process.exit(1);
}

process.exit(0);
