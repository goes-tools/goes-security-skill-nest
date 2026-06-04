# Pattern 03: Error Handling

> **Migration note (skill v2.0):** these patterns were originally written for
> `allure-js-commons`. They now run against the bundled custom HTML reporter
> via `AllureCompat`, which mirrors the same API. The `_setup.md` snippet
> shows the new top-level imports. Existing `await allure.epic(...)`,
> `await allure.step(...)` etc. work identically. Two extras:
>
> - Each `it(...)` block must end with `await allure.flush();` so the metadata
>   reaches the reporter.
> - `attach(name, data)` is now async — call it as `await attach(...)`.

**Covers:** R6 (Public Site Config), R8 (Generic Error Messages — incluye prohibicion de `path`/`timestamp`/`stack` en body, regresion VULN-XXX-NNNN), R22 (Unknown Route Handling)

```typescript
it('should return generic error messages without exposing internals', async () => {
  const allure = new AllureCompat();
  const attach = attachFor(allure);
  await allure.epic('Security');
  await allure.feature('Generic Error Messages');
  await allure.story('Error responses must not expose stack traces, queries, or paths');
  await allure.severity('critical');
  await allure.tag('Config');
  await allure.tag('OWASP A05');
  await allure.tag('GOES Checklist R8');

  allure.remediation({
    summary: 'Las respuestas de error exponen detalles tecnicos (rutas, stack traces, queries SQL) que dan reconocimiento al atacante.',
    howWeChecked: [
      'Forzamos un error en el endpoint con un payload invalido',
      'Esperabamos un body con solo {statusCode, message}',
      'El sistema devolvio path, timestamp, stack trace o query SQL',
    ],
    whyItMatters: 'Los detalles del error facilitan la enumeracion de la API y la identificacion del stack tecnologico.',
  });
  await allure.description(
    '## Objective\n' +
    'Verify that all error responses return generic messages.\n' +
    'Stack traces, SQL queries, file paths, and software versions\n' +
    'must never be exposed to the client.\n\n' +
    '## Reference\n' +
    'GOES Guide Section 9.1 — Secure Errors',
  );

  const errorScenarios = [
    { setup: () => prisma.user.findUnique.mockRejectedValue(new Error('ECONNREFUSED')), label: 'DB connection error' },
    { setup: () => prisma.user.findUnique.mockRejectedValue(new Error('relation "users" does not exist')), label: 'SQL error' },
    { setup: () => prisma.user.create.mockRejectedValue(new Error('Unique constraint failed')), label: 'Constraint error' },
  ];

  for (const scenario of errorScenarios) {
    await allure.step(`Test: ${scenario.label}`, async () => {
      scenario.setup();

      try {
        await service.findOne('1');
      } catch (error) {
        const message = error.message || error.response?.message;
        expect(message).not.toContain('ECONNREFUSED');
        expect(message).not.toContain('relation');
        expect(message).not.toContain('constraint');
        expect(message).not.toContain('/src/');
        expect(message).not.toContain('node_modules');
      }
    });
  }

  await attach('Error handling result (output)', {
    scenariosTested: errorScenarios.length,
    allGeneric: true,
  });
  await allure.flush();
});

it('should return 404 for undefined routes', async () => {
  const allure = new AllureCompat();
  const attach = attachFor(allure);
  await allure.epic('Configuration');
  await allure.feature('Unknown Route Handling');
  await allure.story('Return 404 for any route not defined in the application');
  await allure.severity('normal');
  await allure.tag('Config');
  await allure.tag('GOES Checklist R22');

  allure.remediation({
    summary: 'El sistema responde con 200, 500 o errores informativos en rutas inexistentes, permitiendo enumerar endpoints validos.',
    howWeChecked: [
      'Hicimos GET a rutas tipicas (/admin, /.env, /wp-admin)',
      'Esperabamos 404 plano sin info adicional',
      'El sistema respondio con codigo o body diferente que confirma cuales rutas existen',
    ],
    whyItMatters: 'La diferencia en respuestas permite enumerar la API completa y planificar ataques dirigidos.',
  });
  await allure.description(
    '## Objective\n' +
    'Verify that the application returns 404 for any undefined route,\n' +
    'not a default framework page or debug information.',
  );

  const undefinedRoutes = [
    '/api/nonexistent',
    '/admin/secret',
    '/.env',
    '/wp-admin',
    '/phpinfo.php',
  ];

  await allure.parameter('routes_tested', undefinedRoutes.length.toString());

  for (const route of undefinedRoutes) {
    await allure.step(`Test route: ${route}`, async () => {
      // Adapt to use supertest with the actual NestJS app
      const response = await request(app.getHttpServer()).get(route);
      expect(response.status).toBe(404);
      expect(response.body).not.toHaveProperty('stack');
    });
  }

  await attach('Routes tested (output)', { routes: undefinedRoutes, all404: true });
  await allure.flush();
});

it('PENTEST R8 — error body MUST NOT contain path, timestamp, or internal field names', async () => {
  const allure = new AllureCompat();
  const attach = attachFor(allure);
  await allure.epic('Seguridad');
  await allure.feature('Generic Error Messages');
  await allure.story('Las respuestas de error son exclusivamente {statusCode, message} genericos');
  await allure.severity('critical');
  await allure.tag('Pentest');
  await allure.tag('OWASP A05');
  await allure.tag('OWASP A09');
  await allure.tag('GOES Checklist R8');
  await allure.tag('Pentest Regression VULN-XXX-NNNN');

  t.remediation({
    summary:
      'El backend esta enviando informacion extra en los mensajes de error que un atacante ' +
      'puede usar para mapear la API y planear ataques mas dirigidos.',
    howWeChecked: [
      'Forzamos un error enviando un payload invalido a POST /api/auth/login',
      'Esperabamos que el body de la response fuera exclusivamente { statusCode, message }',
      'Encontramos tambien los campos `path` (la ruta interna) y `timestamp` con precision de milisegundos',
    ],
    whyItMatters:
      'El campo `path` deja ver rutas internas de la API que un atacante puede enumerar sin ' +
      'tener que adivinarlas. El `timestamp` con milisegundos habilita ataques de temporizacion ' +
      'para inferir si una cuenta existe o que tan lenta es una operacion sensible.',
    file: 'src/common/filters/http-exception.filter.ts (o equivalente)',
    symbol: 'catch(exception, host)',
    expected: 'response.json({ statusCode, message })',
    received: 'response.json({ statusCode, message, path: request.url, timestamp: new Date().toISOString() })',
    howToFix:
      '1. Abrir el archivo del exception filter global registrado en main.ts.\n' +
      '2. Quitar `path` y `timestamp` del objeto que se envia con response.json().\n' +
      '3. Mantener esos campos solo en el this.logger.log/error del servidor.\n' +
      '4. La response al cliente debe ser exclusivamente { statusCode, message } (y opcionalmente `error` con un slug generico).',
    exampleCode:
      'response.status(status).json({\n' +
      '  statusCode: status,\n' +
      '  message: exception instanceof HttpException\n' +
      '    ? exception.message\n' +
      '    : \'Ha ocurrido un error. Intente de nuevo mas tarde.\',\n' +
      '});',
    references: [
      { title: 'GOES Guide Seccion 9.1 — Secure Errors' },
      { title: 'OWASP A09 Security Logging Failures', url: 'https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/' },
      { title: 'NestJS Exception filters', url: 'https://docs.nestjs.com/exception-filters' },
    ],
  });

  await allure.description(
    '## Vulnerability Prevented\n' +
    '**Information Disclosure via Error Payload** — VULN-XXX-NNNN del pentest\n' +
    'del 27/05/2026 reporto que /api respondia con\n' +
    '`{"statusCode":400,"message":"...","timestamp":"2026-05-26T12:41:08.569Z",\n' +
    '"path":"/api/auth/login"}`. El campo `path` permite enumerar endpoints,\n' +
    'y el `timestamp` con ms permite ataques de temporizacion.\n\n' +
    '## Defense Implemented\n' +
    'El `HttpExceptionFilter` global retorna SOLO `{statusCode, message}`.\n' +
    'Path, timestamp, headers, req.url, stack quedan exclusivamente en logs.\n\n' +
    '## Reference\n' +
    'GOES Guide Seccion 9.1 — Secure Errors',
  );

  // ===== Capa 3: comportamiento E2E =====
  // Ajustar el setup para usar la app real con AppModule
  // Endpoints que tipicamente disparan distintos tipos de error
  const errorTriggers = [
    { path: '/api/auth/login', body: { malformed: true }, label: '400 desde DTO invalido' },
    { path: '/api/nonexistent-resource', body: {}, label: '404' },
    { path: '/api/users/999999999', body: null, label: '404 ID inexistente' },
    { path: '/api/auth/register', body: { email: 'not-an-email' }, label: '400 email invalido' },
  ];

  const forbiddenFields = ['path', 'timestamp', 'stack', 'cause', 'sql', 'query', 'url'];
  const forbiddenSubstrings = [
    /\.ts:\d+/,                           // stack frames "file.ts:42"
    /node_modules/,
    /\/(home|Users|var|opt|app)\//,        // rutas absolutas del FS
    /\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/, // ISO timestamps
    /prisma|typeorm|sequelize/i,
    /process\.env/,
    /Error:\s+/,                           // "Error: relation does not exist"
  ];

  for (const trigger of errorTriggers) {
    await allure.step(`Test: ${trigger.label} en ${trigger.path}`, async () => {
      const res = await request(app.getHttpServer())
        .post(trigger.path)
        .send(trigger.body ?? {});

      await attach(`Response body para ${trigger.path} (output)`, {
        status: res.status,
        body: res.body,
      });

      // El body debe ser un objeto plano con SOLO statusCode y message
      const keys = Object.keys(res.body || {});
      for (const forbidden of forbiddenFields) {
        expect(keys).not.toContain(forbidden);
      }
      // Verificar que ninguna substring prohibida esta en el JSON serializado
      const json = JSON.stringify(res.body || {});
      for (const re of forbiddenSubstrings) {
        expect(json).not.toMatch(re);
      }
      // Shape exacto recomendado
      expect(keys.sort()).toEqual(expect.arrayContaining(['message']));
      expect(keys.length).toBeLessThanOrEqual(3); // statusCode + message + (error?)
    });
  }

  await attach('Error response shape (output)', {
    requiredShape: '{ statusCode, message }',
    forbiddenFields,
    forbiddenSubstringCount: forbiddenSubstrings.length,
  });
  await allure.flush();
});

it('R8 config — HttpExceptionFilter MUST be registered globally and not leak req metadata', async () => {
  const allure = new AllureCompat();
  const attach = attachFor(allure);
  await allure.epic('Configuracion');
  await allure.feature('Generic Error Messages');
  await allure.story('Filtro global registrado y su catch() NO incluye request.url ni timestamp');
  await allure.severity('blocker');
  await allure.tag('Config');
  await allure.tag('GOES Checklist R8');
  await allure.tag('Pentest Regression VULN-XXX-NNNN');

  allure.remediation({
    summary: 'Las respuestas de error exponen detalles tecnicos (rutas, stack traces, queries SQL) que dan reconocimiento al atacante.',
    howWeChecked: [
      'Forzamos un error en el endpoint con un payload invalido',
      'Esperabamos un body con solo {statusCode, message}',
      'El sistema devolvio path, timestamp, stack trace o query SQL',
    ],
    whyItMatters: 'Los detalles del error facilitan la enumeracion de la API y la identificacion del stack tecnologico.',
  });

  const fs = require('fs');
  const path = require('path');
  const stripComments = (src: string): string =>
    src.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:])\/\/.*$/gm, '$1');

  // Capa 1: main.ts registra useGlobalFilters
  const mainSrc = stripComments(
    fs.readFileSync(path.resolve(__dirname, '../../src/main.ts'), 'utf-8'),
  );
  expect(mainSrc).toMatch(/useGlobalFilters\s*\(/);

  // Capa 2: el filter NO debe contener referencias a request.url ni new Date()
  // dentro del response. Busqueda en cualquier *.filter.ts.
  const glob = require('glob');
  const filterFiles = glob.sync('src/**/*.filter.ts', {
    cwd: path.resolve(__dirname, '../..'),
    absolute: true,
  });
  expect(filterFiles.length).toBeGreaterThan(0);

  for (const file of filterFiles) {
    const src = stripComments(fs.readFileSync(file, 'utf-8'));

    // El filter NO debe poner request.url ni similares en el body de respuesta
    // (acepta que los registre en logs, no en response.json)
    const responsesAssignedUrl = /response[^.]*\.\s*(json|send)\s*\([^)]*request\.url/;
    const responsesAssignedTimestamp = /response[^.]*\.\s*(json|send)\s*\([^)]*timestamp/i;
    const responsesAssignedPath = /response[^.]*\.\s*(json|send)\s*\([^)]*\bpath\b/;

    await attach(`Filter ${file.split('/').pop()} (input)`, {
      hasGetResponseCall: /\.getResponse\s*\(/.test(src),
      assignsUrlToResponseBody: responsesAssignedUrl.test(src),
      assignsTimestampToResponseBody: responsesAssignedTimestamp.test(src),
      assignsPathToResponseBody: responsesAssignedPath.test(src),
    });

    expect(src).not.toMatch(responsesAssignedUrl);
    expect(src).not.toMatch(responsesAssignedTimestamp);
    expect(src).not.toMatch(responsesAssignedPath);
  }

  await attach('Filter static analysis (output)', {
    globalFilterRegistered: true,
    leaksRequestUrl: false,
    leaksTimestamp: false,
    leaksPath: false,
  });
  await allure.flush();
});
```
