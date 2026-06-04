# Pattern 27: User-Visible Log Exposure

> Migration note: usa `AllureCompat` y `await allure.flush()` al final de cada `it`.

**Covers:** R10 (Log Exposure Prevention)

> **Esta es una verificacion universal — NUNCA marcar N/A** (item universal segun SKILL.md):
>
> Todo backend produce logs. El control verifica que esos logs no se filtran al cliente:
>
> - El bundle de frontend (si lo hay) no contiene `console.log`, `console.debug`, `console.trace` ni `console.info` con datos del backend.
> - Las responses HTTP no incluyen stack traces ni objetos `req`/`res` serializados.
> - No hay log4j-style endpoints (`/logs`, `/debug`) accesibles sin auth.

```typescript
import * as fs from 'fs';
import * as path from 'path';
import * as glob from 'glob';
import { report } from '@security-reporter/metadata';

const stripComments = (src: string): string =>
  src
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/(^|[^:])\/\/.*$/gm, '$1');

it('R10 — production bundle MUST NOT contain console.log statements', async () => {
  const t = report();
  t.epic('Seguridad');
  t.feature('Log Exposure Prevention');
  t.story('console.log eliminado de codigo de produccion (no se filtra al cliente)');
  t.severity('critical');
  t.tag('Pentest', 'OWASP A09', 'GOES Checklist R10');

  t.remediation({
    summary: 'El sistema deja logs visibles al usuario (console.log en frontend bundle, stack traces en errores) que revelan internals.',
    howWeChecked: [
      'Inspeccionamos el codigo fuente de src/ por console.log/debug/info',
      'Verificamos endpoints /logs /debug /env publicamente accesibles',
      'Forzamos errores para revisar si exponen stack traces',
    ],
    whyItMatters: 'Los logs filtrados al cliente revelan la arquitectura interna, paths de archivos, valores de variables, y posibles credenciales hardcoded.',
  });

  // Buscar todos los .ts del src y verificar que no hay console.log sin comentar
  const srcRoot = path.resolve(__dirname, '../../src');
  const files = glob.sync('**/*.ts', { cwd: srcRoot, absolute: true });

  const findings: Array<{ file: string; line: number; statement: string }> = [];
  for (const file of files) {
    if (file.includes('.spec.ts') || file.includes('.test.ts')) continue;
    const src = stripComments(fs.readFileSync(file, 'utf-8'));
    const lines = src.split('\n');
    lines.forEach((line, i) => {
      if (/\bconsole\.(log|debug|info|trace)\s*\(/.test(line)) {
        findings.push({
          file: file.replace(srcRoot + '/', ''),
          line: i + 1,
          statement: line.trim().slice(0, 120),
        });
      }
    });
  }

  t.evidence('Source scan (input)', {
    filesScanned: files.length,
    findingsCount: findings.length,
  });
  t.evidence('Findings (output)', { findings: findings.slice(0, 20) });

  // 0 findings — si hay alguno es HALLAZGO
  expect(findings).toEqual([]);

  await t.flush();
});

it('R10 — error responses MUST NOT leak stack traces or internal paths', async () => {
  const t = report();
  t.epic('Seguridad');
  t.feature('Log Exposure Prevention');
  t.story('Las 5xx no exponen stack, queries, ni rutas absolutas del FS');
  t.severity('critical');
  t.tag('Pentest', 'OWASP A09', 'GOES Checklist R10');

  t.remediation({
    summary: 'El sistema deja logs visibles al usuario (console.log en frontend bundle, stack traces en errores) que revelan internals.',
    howWeChecked: [
      'Inspeccionamos el codigo fuente de src/ por console.log/debug/info',
      'Verificamos endpoints /logs /debug /env publicamente accesibles',
      'Forzamos errores para revisar si exponen stack traces',
    ],
    whyItMatters: 'Los logs filtrados al cliente revelan la arquitectura interna, paths de archivos, valores de variables, y posibles credenciales hardcoded.',
  });

  // Forzar un error en el service y verificar la response
  const payload = { malformed: true };
  t.evidence('Attacker payload (input)', payload);

  let caught: any;
  try {
    await service.process(payload as any);
  } catch (e) {
    caught = e;
  }

  // El exception filter global debe transformar a una response generica
  const responseBody = caught?.getResponse?.() || caught?.response || {};
  const bodyStr = typeof responseBody === 'string'
    ? responseBody
    : JSON.stringify(responseBody);

  // No debe contener stack trace
  expect(bodyStr).not.toMatch(/at\s+\w+\.\w+\s*\(/);
  expect(bodyStr).not.toContain('node_modules');
  expect(bodyStr).not.toMatch(/\/(home|Users|var)\/\w+/);
  // No debe contener SQL
  expect(bodyStr).not.toMatch(/SELECT\s+.*\s+FROM/i);
  expect(bodyStr).not.toMatch(/INSERT\s+INTO/i);
  // No debe contener nombres de variables internas comunes
  expect(bodyStr).not.toContain('prisma');
  expect(bodyStr).not.toContain('TypeORM');

  t.evidence('Defense response (output)', {
    bodyPreview: bodyStr.slice(0, 200),
    leaksStack: false,
    leaksSql: false,
    leaksFsPath: false,
  });

  await t.flush();
});

it('R10 — no public debug endpoints (/logs, /debug, /env, /metrics)', async () => {
  const t = report();
  t.epic('Seguridad');
  t.feature('Log Exposure Prevention');
  t.story('Endpoints de debug deshabilitados o protegidos por auth');
  t.severity('critical');
  t.tag('Pentest', 'OWASP A05', 'GOES Checklist R10');

  t.remediation({
    summary: 'El sistema deja logs visibles al usuario (console.log en frontend bundle, stack traces en errores) que revelan internals.',
    howWeChecked: [
      'Inspeccionamos el codigo fuente de src/ por console.log/debug/info',
      'Verificamos endpoints /logs /debug /env publicamente accesibles',
      'Forzamos errores para revisar si exponen stack traces',
    ],
    whyItMatters: 'Los logs filtrados al cliente revelan la arquitectura interna, paths de archivos, valores de variables, y posibles credenciales hardcoded.',
  });

  const moduleRef = await Test.createTestingModule({}).compile();
  const app = moduleRef.createNestApplication();
  await app.init();

  const dangerousPaths = ['/logs', '/debug', '/env', '/metrics', '/actuator', '/_status'];
  const results: Array<{ path: string; status: number }> = [];

  for (const p of dangerousPaths) {
    const res = await request(app.getHttpServer()).get(p);
    results.push({ path: p, status: res.status });
    // Aceptable: 401, 403, 404. Inaceptable: 200 sin auth.
    expect([401, 403, 404]).toContain(res.status);
  }

  t.evidence('Endpoints probed (input)', dangerousPaths);
  t.evidence('Responses (output)', results);

  await app.close();
  await t.flush();
});
```
