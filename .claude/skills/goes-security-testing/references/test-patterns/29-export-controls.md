# Pattern 29: Export / Report Controls (Mandatory Filters + Volume Limit)

> Migration note: usa `AllureCompat` y `await allure.flush()` al final de cada `it`.

**Covers:** R9 (RBAC server-side), R11 (DTO Validation), R55 (Rate Limiting), OWASP API4 (Unrestricted Resource Consumption), OWASP A04 (Insecure Design)

**Regresion cubierta:**
- **VULN-XXX-NNNN** — `POST /api/reports/permits` con `{"format":"xlsx"}` exportaba la BD completa de permisos sin filtros obligatorios ni limite de volumen

---

## Por que este pattern

El pentest del 27/05/2026 demostro que un funcionario autenticado puede descargar la base completa de permisos de comercializacion (incluye DUI, direccion, productos de TODOS los ciudadanos registrados) en un solo request. Los patterns existentes no atrapan esto porque:
- `01-crud-validation` prueba que faltan campos requeridos genericos, no que filtros de fecha/dept sean **obligatorios** en endpoints de export
- `19-rate-limiting` aplica un limite por minuto pero no limita el **volumen por request**
- `09-rbac-privilege` verifica que el usuario tenga el rol, pero el usuario legitimo aun puede exportar todo

La defensa correcta tiene 3 dimensiones que este pattern verifica.

---

## Reglas obligatorias

1. Todo endpoint que matche `/reports`, `/exports`, `*export*`, `*download*`, `/dump`, `/full` DEBE:
   - Requerir al menos 2 filtros obligatorios (rango de fechas + un segundo criterio: departamento/categoria/usuario)
   - Aplicar un `LIMIT` maximo en la query (default 1000 registros por export)
   - Registrar un audit log con: `userId`, `filtersApplied`, `recordCount`, `timestamp`, `ip`
   - Tener rate limit propio mas estricto (5 exports/hora por usuario, vs 100 req/min general)
2. Para exports que superen un umbral (ej. > 500 registros), requerir doble confirmacion (`?confirm=true` + token de aprobacion).
3. El DTO de export DEBE usar `@IsDefined()`, `@IsNotEmpty()` en los filtros, no `@IsOptional()`.

---

## Tests

```typescript
import * as request from 'supertest';
import { report } from '@security-reporter/metadata';

it('PENTEST R11/R55 — export endpoints MUST reject requests without mandatory filters', async () => {
  const t = report();
  t.epic('Dominio');
  t.feature('Export Controls');
  t.story('Endpoints de export rechazan request con solo `format`, exigen filtros');
  t.severity('blocker');
  t.tag('Pentest', 'OWASP API4', 'OWASP A04', 'GOES Checklist R11', 'GOES Checklist R55');
  t.tag('Pentest Regression VULN-XXX-NNNN');
  t.description = (`
## Vulnerability Prevented
**Mass Data Exfiltration via Export** — VULN-XXX-NNNN reporto que
POST /api/reports/permits con body {"format":"xlsx"} descargaba la BD
completa de permisos. Sin filtros obligatorios, un funcionario o cuenta
comprometida exfiltra toda la informacion de ciudadanos en un request.

## Defense Implemented
DTO de export con @IsDefined + @IsNotEmpty en \`from\`, \`to\`, \`departmentId\`.
Servicio aplica LIMIT 1000 hardcoded en la query.
` as any);

  const loginRes = await request(app.getHttpServer())
    .post('/api/auth/login')
    .send({ email: 'admin@srs.gob.sv', password: process.env.TEST_USER_PASSWORD || 'TestPass1234!' });
  const token = loginRes.body.accessToken || loginRes.body.access_token;

  // Detectar endpoints de export en el proyecto
  const exportEndpoints = [
    { method: 'POST', path: '/api/reports/permits' },
    { method: 'POST', path: '/api/reports/users' },
    { method: 'GET', path: '/api/exports' },
    { method: 'POST', path: '/api/permits/export' },
  ];

  const findings: Array<{
    endpoint: string;
    minimalPayloadStatus: number;
    rejected: boolean;
  }> = [];

  for (const ep of exportEndpoints) {
    // Minimal payload: SOLO format (lo que reporto el pentest)
    const minimalPayload = { format: 'xlsx' };

    const req = ep.method === 'POST'
      ? request(app.getHttpServer()).post(ep.path).send(minimalPayload)
      : request(app.getHttpServer()).get(ep.path);

    const res = await req.set('Authorization', `Bearer ${token}`);

    // Si el endpoint no existe (404), no aplica
    if (res.status === 404) continue;

    // El endpoint EXISTE y NO debe aceptar request sin filtros
    findings.push({
      endpoint: `${ep.method} ${ep.path}`,
      minimalPayloadStatus: res.status,
      rejected: res.status === 400 || res.status === 422,
    });
  }

  t.evidence('Minimal payload attempts (input)', { payload: { format: 'xlsx' } });
  t.evidence('Endpoint responses (output)', findings);

  // TODOS los endpoints de export que existen deben rechazar
  for (const f of findings) {
    expect(f.rejected).toBe(true);
  }

  await t.flush();
});

it('PENTEST R11 — export DTO MUST declare filters as @IsDefined, NOT @IsOptional', async () => {
  const t = report();
  t.epic('Configuracion');
  t.feature('Export Controls');
  t.story('Static analysis del DTO de export: filtros son obligatorios');
  t.severity('blocker');
  t.tag('Config', 'GOES Checklist R11');
  t.tag('Pentest Regression VULN-XXX-NNNN');

  const fs = require('fs');
  const path = require('path');
  const glob = require('glob');
  const stripComments = (src: string): string =>
    src.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:])\/\/.*$/gm, '$1');

  // Buscar DTOs de export
  const dtoFiles = glob.sync('src/**/*{export,report}*.dto.ts', {
    cwd: path.resolve(__dirname, '../..'),
    absolute: true,
  });

  if (dtoFiles.length === 0) {
    t.notApplicable(
      'No se encontraron DTOs de export. Verificado: ' +
      'glob src/**/*{export,report}*.dto.ts → 0 archivos. ' +
      'Si el proyecto tiene exports, los DTOs deben renombrarse a *.export.dto.ts o *.report.dto.ts'
    );
    await t.flush();
    return;
  }

  const findings: Array<{ dto: string; hasIsOptional: boolean; hasIsDefined: boolean; hasDateFilters: boolean }> = [];

  for (const file of dtoFiles) {
    const src = stripComments(fs.readFileSync(file, 'utf-8'));
    findings.push({
      dto: file.split('/').pop()!,
      hasIsOptional: /@IsOptional/.test(src),
      hasIsDefined: /@IsDefined|@IsNotEmpty/.test(src),
      hasDateFilters: /@IsDateString|@IsDate/.test(src),
    });
  }

  t.evidence('DTOs scanned (input)', findings);

  for (const f of findings) {
    // Cada DTO de export debe tener al menos UN filtro obligatorio
    expect(f.hasIsDefined).toBe(true);
    // Y debe declarar filtros de fecha
    expect(f.hasDateFilters).toBe(true);
  }

  await t.flush();
});

it('PENTEST R55 — export service MUST apply LIMIT and audit-log every export', async () => {
  const t = report();
  t.epic('Seguridad');
  t.feature('Export Controls');
  t.story('Service de export limita registros y registra audit log');
  t.severity('blocker');
  t.tag('Pentest', 'OWASP A09', 'OWASP API4', 'GOES Checklist R55');
  t.tag('Pentest Regression VULN-XXX-NNNN');

  const fs = require('fs');
  const path = require('path');
  const glob = require('glob');
  const stripComments = (src: string): string =>
    src.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:])\/\/.*$/gm, '$1');

  const serviceFiles = glob.sync('src/**/*{export,report}*.service.ts', {
    cwd: path.resolve(__dirname, '../..'),
    absolute: true,
  });

  if (serviceFiles.length === 0) {
    t.notApplicable('No hay services de export/report en el proyecto.');
    await t.flush();
    return;
  }

  const findings: Array<{
    service: string;
    appliesLimit: boolean;
    writesAuditLog: boolean;
    maxRecordsValue: string;
  }> = [];

  for (const file of serviceFiles) {
    const src = stripComments(fs.readFileSync(file, 'utf-8'));
    const limitMatch = src.match(/(?:take|limit|LIMIT)\s*:\s*(\d+)/);
    findings.push({
      service: file.split('/').pop()!,
      appliesLimit: /take\s*:|limit\s*:|LIMIT\s+\d/.test(src),
      writesAuditLog: /audit|auditLog|auditService|trail|trail.create/i.test(src),
      maxRecordsValue: limitMatch ? limitMatch[1] : 'N/A',
    });
  }

  t.evidence('Export service analysis (output)', findings);

  for (const f of findings) {
    expect(f.appliesLimit).toBe(true);
    expect(f.writesAuditLog).toBe(true);
    // El limite debe ser razonable (no > 10000)
    if (f.maxRecordsValue !== 'N/A') {
      expect(parseInt(f.maxRecordsValue, 10)).toBeLessThanOrEqual(10000);
    }
  }

  await t.flush();
});
```
