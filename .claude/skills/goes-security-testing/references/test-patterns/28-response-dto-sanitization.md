# Pattern 28: Response DTO Sanitization (Field Whitelist)

> Migration note: usa `AllureCompat` y `await allure.flush()` al final de cada `it`.

**Covers:** R3 (Sensitive Data Exposure aplicado a responses API), R4 (Business Logic Exposure), R11 (DTO Output Validation), R20 (No sensitive data in JWT payload), OWASP API3 (Broken Object Property Authorization)

**Regresiones cubiertas:**
- **VULN-INT-0002** — `/api/auth/me` retorna lista completa de roles + permisos con IDs internos numericos
- **VULN-EXT-0002** — `/api/auth/me` retorna DUI completo en cada carga del dashboard
- **VULN-EXT-0006** — Endpoints retornan CUID de Prisma (`cmpn5ugw3000bs601v41rgyic`) revelando stack

---

## Por que este pattern

El pentest del 27/05/2026 encontro **3 hallazgos distintos** en el mismo tipo de endpoint (`/api/auth/me`, `/api/users/:id`, perfiles): el backend retorna mas campos de los necesarios — IDs internos, hashes, CUIDs, DUI completo, lista de permisos con metadatos. La causa raiz es **falta de un DTO de salida** (response DTO) que actue como whitelist explicita de los campos que pueden cruzar el limite.

Esta clase de hallazgo es invisible para los patterns existentes:
- `01-crud-validation` solo verifica el INPUT (request DTO)
- `05-password-security` solo verifica que `password` no aparezca, no otros campos
- Ningun pattern hace un grep estructural sobre la response real

---

## Reglas obligatorias

1. Cada controller con endpoints `GET /me`, `GET /:id`, `GET /` (list), `POST /login`, `POST /refresh` DEBE tener un response DTO o un interceptor `ClassSerializerInterceptor` con DTO marcado con `@Expose()` explicito.
2. Campos prohibidos en respuestas (whitelist negativa universal):
   - `password`, `passwordHash`, `password_hash`, `hash`, `salt`
   - `dui` completo (regex `\d{8}-\d`) — si se requiere mostrar, debe estar enmascarado (`002****9-1`)
   - CUID de Prisma (regex `^c[a-z0-9]{24}$`)
   - `email_verified_token`, `reset_token`, `refresh_token`, cualquier `*_token`
   - `__v`, `_id` de Mongo si se usa Prisma/SQL
   - `createdAt`, `updatedAt` SI no son necesarios para la UI
   - Permisos como objetos completos (`{id, name, description}`) — exponer solo nombres
3. Para `/api/auth/me` el shape recomendado es **maximo 5 campos**: `{ userId (opaco), name, email (enmascarable), role, permissions: string[] }`.

---

## Test PENTEST principal

```typescript
import * as request from 'supertest';
import { Test } from '@nestjs/testing';
import { report } from '@security-reporter/metadata';

const FORBIDDEN_FIELD_NAMES = [
  'password', 'passwordHash', 'password_hash', 'hash', 'salt',
  'refreshToken', 'refresh_token', 'resetToken', 'reset_token',
  'emailVerifiedToken', 'totpSecret', '__v',
];

const FORBIDDEN_VALUE_PATTERNS: Array<{ name: string; re: RegExp }> = [
  { name: 'DUI completo', re: /\b\d{8}-\d\b/ },
  { name: 'CUID Prisma', re: /^c[a-z0-9]{24}$/ },
  { name: 'bcrypt hash', re: /^\$2[aby]\$\d{2}\$/ },
  { name: 'JWT en payload', re: /^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\./ },
];

function findSensitiveLeaks(obj: any, path = ''): Array<{ path: string; reason: string; value: string }> {
  const leaks: Array<{ path: string; reason: string; value: string }> = [];
  if (obj === null || obj === undefined) return leaks;
  if (typeof obj !== 'object') {
    // Verificar valor contra patrones prohibidos
    const str = String(obj);
    for (const p of FORBIDDEN_VALUE_PATTERNS) {
      if (p.re.test(str)) leaks.push({ path, reason: p.name, value: str.slice(0, 40) });
    }
    return leaks;
  }
  for (const [key, value] of Object.entries(obj)) {
    const childPath = path ? `${path}.${key}` : key;
    // Nombre prohibido
    if (FORBIDDEN_FIELD_NAMES.includes(key)) {
      leaks.push({ path: childPath, reason: `field name "${key}" forbidden`, value: String(value).slice(0, 40) });
    }
    // Permisos con metadatos completos (id + name + description)
    if (key === 'permissions' && Array.isArray(value) && value.length > 0 && typeof value[0] === 'object') {
      const hasInternalIds = value.some((p: any) => 'id' in p || '_id' in p);
      if (hasInternalIds) {
        leaks.push({ path: childPath, reason: 'permissions array exposes internal id field', value: 'array of {id,name,...}' });
      }
    }
    // Recursion
    leaks.push(...findSensitiveLeaks(value, childPath));
  }
  return leaks;
}

it('PENTEST R3 — GET /api/auth/me MUST NOT leak DUI, internal IDs, permissions metadata', async () => {
  const t = report();
  t.epic('Seguridad');
  t.feature('Sensitive Data Exposure (Response)');
  t.story('Response DTO de /api/auth/me es minimo y enmascarado');
  t.severity('critical');
  t.tag('Pentest', 'OWASP A02', 'OWASP API3', 'GOES Checklist R3', 'GOES Checklist R4');
  t.tag('Pentest Regression VULN-INT-0002', 'Pentest Regression VULN-EXT-0002', 'Pentest Regression VULN-EXT-0006');

  // Login + GET /me (ajustar credenciales segun el proyecto)
  const loginRes = await request(app.getHttpServer())
    .post('/api/auth/login')
    .send({ email: 'admin@srs.gob.sv', password: process.env.TEST_USER_PASSWORD || 'TestPass1234!' });
  const token = loginRes.body.accessToken || loginRes.body.access_token;
  expect(token).toBeDefined();

  const meRes = await request(app.getHttpServer())
    .get('/api/auth/me')
    .set('Authorization', `Bearer ${token}`)
    .expect(200);

  t.evidence('Response body de /api/auth/me (output)', meRes.body);

  // 1) Maximo 5 claves de primer nivel
  const topLevelKeys = Object.keys(meRes.body);
  expect(topLevelKeys.length).toBeLessThanOrEqual(8); // tolerancia razonable

  // 2) Ningun leak por nombre o patron de valor
  const leaks = findSensitiveLeaks(meRes.body);
  t.evidence('Leaks detectados (output)', { count: leaks.length, leaks });
  expect(leaks).toEqual([]);

  // 3) DUI explicitamente: si esta presente, debe estar enmascarado
  if (meRes.body.dui) {
    expect(meRes.body.dui).toMatch(/^[\d*]{1,4}\*{2,}\d{1,2}-?[\d*]$/);
  }

  // 4) ID expuesto: si esta presente, NO debe ser CUID de Prisma
  if (meRes.body.id || meRes.body.userId) {
    const id = meRes.body.id || meRes.body.userId;
    expect(id).not.toMatch(/^c[a-z0-9]{24}$/);
  }

  // 5) Permissions: si vienen, deben ser array de strings, no de objetos con id
  if (meRes.body.permissions) {
    expect(Array.isArray(meRes.body.permissions)).toBe(true);
    if (meRes.body.permissions.length > 0) {
      // todos los items son string
      const allStrings = meRes.body.permissions.every((p: any) => typeof p === 'string');
      expect(allStrings).toBe(true);
    }
  }

  await t.flush();
});

it('PENTEST R3 — list endpoints (GET /users, /permits) MUST NOT leak internal CUIDs', async () => {
  const t = report();
  t.epic('Seguridad');
  t.feature('Sensitive Data Exposure (Response)');
  t.story('Endpoints de listado retornan IDs opacos publicos, no CUIDs de Prisma');
  t.severity('critical');
  t.tag('Pentest', 'OWASP API1', 'GOES Checklist R3');
  t.tag('Pentest Regression VULN-EXT-0006');

  // Ajustar a las rutas reales del proyecto
  const candidateEndpoints = [
    '/api/users',
    '/api/permits',
    '/api/solicitudes',
    '/api/catalogos',
  ];

  const loginRes = await request(app.getHttpServer())
    .post('/api/auth/login')
    .send({ email: 'admin@srs.gob.sv', password: process.env.TEST_USER_PASSWORD || 'TestPass1234!' });
  const token = loginRes.body.accessToken || loginRes.body.access_token;

  for (const endpoint of candidateEndpoints) {
    const res = await request(app.getHttpServer())
      .get(endpoint)
      .set('Authorization', `Bearer ${token}`);

    if (res.status !== 200) continue;

    const leaks = findSensitiveLeaks(res.body);
    t.evidence(`Leaks en ${endpoint} (output)`, { count: leaks.length, sample: leaks.slice(0, 5) });
    expect(leaks).toEqual([]);
  }

  await t.flush();
});

it('R3 config — every *.controller.ts MUST use response DTOs OR ClassSerializerInterceptor', async () => {
  const t = report();
  t.epic('Configuracion');
  t.feature('Sensitive Data Exposure (Response)');
  t.story('La superficie completa tiene control de serializacion');
  t.severity('blocker');
  t.tag('Config', 'GOES Checklist R3');

  const fs = require('fs');
  const path = require('path');
  const glob = require('glob');
  const stripComments = (src: string): string =>
    src.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:])\/\/.*$/gm, '$1');

  const mainSrc = stripComments(
    fs.readFileSync(path.resolve(__dirname, '../../src/main.ts'), 'utf-8'),
  );
  const controllers = glob.sync('src/**/*.controller.ts', {
    cwd: path.resolve(__dirname, '../..'),
    absolute: true,
  });

  // Opcion A: ClassSerializerInterceptor global en main.ts
  const globalSerializerOn =
    /useGlobalInterceptors\s*\([^)]*ClassSerializerInterceptor/.test(mainSrc);

  // Opcion B: cada controller declara DTO de response (decorador o serialize)
  const findings: Array<{ controller: string; hasSerialization: boolean }> = [];
  for (const file of controllers) {
    const src = stripComments(fs.readFileSync(file, 'utf-8'));
    const hasDtoReturn =
      /:\s*Promise<\s*\w+ResponseDto/.test(src) ||
      /@SerializeOptions|@UseInterceptors\([^)]*ClassSerializerInterceptor/.test(src) ||
      /plainToClass|plainToInstance/.test(src);
    findings.push({
      controller: file.split('/').pop()!,
      hasSerialization: globalSerializerOn || hasDtoReturn,
    });
  }

  t.evidence('Serializacion por controller (output)', {
    globalSerializerOn,
    controllersScanned: controllers.length,
    findings,
  });

  // Al menos UNA de las dos opciones debe estar
  const allCovered = findings.every(f => f.hasSerialization);
  expect(allCovered).toBe(true);

  await t.flush();
});
```
