# Pattern 16: HTTP Security Headers

> **Migration note (skill v2.0):** these patterns were originally written for
> `allure-js-commons`. They now run against the bundled custom HTML reporter
> via `AllureCompat`, which mirrors the same API. The `_setup.md` snippet
> shows the new top-level imports. Existing `await allure.epic(...)`,
> `await allure.step(...)` etc. work identically. Two extras:
>
> - Each `it(...)` block must end with `await allure.flush();` so the metadata
>   reaches the reporter.
> - `attach(name, data)` is now async — call it as `await attach(...)`.

**Covers:** R44 (CSP — INCLUYE prohibicion estricta de `unsafe-inline`/`unsafe-eval`/wildcard, regresion VULN-XXX-NNNN), R45 (X-Content-Type-Options, X-Frame-Options, CORP/COOP — regresion VULN-XXX-NNNN), R46 (HSTS), R47 (X-XSS-Protection), R48 (Referrer-Policy), R49 (Permissions-Policy), R50 (Cache-Control)

```typescript
it('should configure all required HTTP security headers', async () => {
  const allure = new AllureCompat();
  const attach = attachFor(allure);
  await allure.epic('Configuration');
  await allure.feature('Security Headers');
  await allure.story('All HTTP security headers configured per GOES Guide Section 8');
  await allure.severity('critical');
  await allure.tag('Config');
  await allure.tag('OWASP A05');
  await allure.tag('GOES Checklist R44');
  await allure.tag('GOES Checklist R45');
  await allure.tag('GOES Checklist R46');
  await allure.tag('GOES Checklist R47');
  await allure.tag('GOES Checklist R48');
  await allure.tag('GOES Checklist R49');

  allure.remediation({
    summary: 'CSP permite estilos inline o eval.',
    howWeChecked: [
      'Inspeccionamos el header Content-Security-Policy',
      'Buscamos las palabras clave unsafe-inline, unsafe-eval, unsafe-hashes',
      'Las encontramos en script-src o style-src',
    ],
    whyItMatters: 'unsafe-inline desactiva la proteccion CSP contra XSS.',
  });
  await allure.description(
    '## Objective\n' +
    'Verify that all HTTP security headers are correctly configured\n' +
    'according to GOES Guide Section 8.\n\n' +
    '## Required Headers\n' +
    '- Content-Security-Policy: default-src \'self\'\n' +
    '- X-Content-Type-Options: nosniff\n' +
    '- X-Frame-Options: DENY\n' +
    '- Strict-Transport-Security: max-age=31536000\n' +
    '- X-XSS-Protection: 0 (deprecated, rely on CSP)\n' +
    '- Referrer-Policy: strict-origin-when-cross-origin\n' +
    '- Permissions-Policy: geolocation=(), camera=(), microphone=()',
  );

  // Adapt to use supertest or check helmet config directly
  const response = await request(app.getHttpServer()).get('/api/health');

  await allure.step('Verify: Content-Security-Policy — strict, NO unsafe-inline/eval', async () => {
    const csp = response.headers['content-security-policy'];
    expect(csp).toBeDefined();
    expect(csp).toContain("default-src 'self'");

    // Capa critica: el CSP NO debe contener directivas inseguras en NINGUNA seccion
    // (regresion VULN-XXX-NNNN — style-src 'self' 'unsafe-inline' fue marcado en pentest)
    expect(csp).not.toMatch(/unsafe-inline/);
    expect(csp).not.toMatch(/unsafe-eval/);
    expect(csp).not.toMatch(/unsafe-hashes/);

    // Ninguna directiva debe usar wildcard *
    const directivesWithWildcard = (csp.match(/[a-z-]+\s+\*/g) || []);
    expect(directivesWithWildcard).toEqual([]);

    // script-src y style-src deben estar presentes y restrictivos
    expect(csp).toMatch(/script-src[^;]+'self'/);
    expect(csp).toMatch(/style-src[^;]+'self'/);

    // frame-ancestors o equivalente
    expect(csp).toMatch(/frame-ancestors|frame-src/);
  });

  await allure.step('Verify: X-Content-Type-Options: nosniff', async () => {
    expect(response.headers['x-content-type-options']).toBe('nosniff');
  });

  await allure.step('Verify: X-Frame-Options: DENY or SAMEORIGIN', async () => {
    const xfo = response.headers['x-frame-options'];
    expect(xfo).toMatch(/^(DENY|SAMEORIGIN)$/i);
  });

  await allure.step('Verify: Strict-Transport-Security (HSTS)', async () => {
    const hsts = response.headers['strict-transport-security'];
    expect(hsts).toBeDefined();
    expect(hsts).toContain('max-age=');
    // min 1 year = 31536000
    const maxAge = parseInt(hsts.match(/max-age=(\d+)/)?.[1] || '0');
    expect(maxAge).toBeGreaterThanOrEqual(31536000);
  });

  await allure.step('Verify: X-XSS-Protection: 0 (deprecated)', async () => {
    const xxss = response.headers['x-xss-protection'];
    if (xxss) {
      expect(xxss).toBe('0');
    }
  });

  await allure.step('Verify: Referrer-Policy', async () => {
    const rp = response.headers['referrer-policy'];
    expect(rp).toBeDefined();
    expect(rp).toMatch(/strict-origin|no-referrer/);
  });

  await allure.step('Verify: Permissions-Policy', async () => {
    const pp = response.headers['permissions-policy'];
    expect(pp).toBeDefined();
    expect(pp).toContain('geolocation=()');
    expect(pp).toContain('camera=()');
  });

  await attach('Security headers (output)', {
    csp: !!response.headers['content-security-policy'],
    xContentType: response.headers['x-content-type-options'],
    xFrameOptions: response.headers['x-frame-options'],
    hsts: !!response.headers['strict-transport-security'],
    referrerPolicy: response.headers['referrer-policy'],
    permissionsPolicy: !!response.headers['permissions-policy'],
  });
  await allure.flush();
});

it('should set Cache-Control: no-store for sensitive responses', async () => {
  const allure = new AllureCompat();
  const attach = attachFor(allure);
  await allure.epic('Configuration');
  await allure.feature('Cache Control Header');
  await allure.story('Sensitive API responses must not be cached');
  await allure.severity('critical');
  await allure.tag('Config');
  await allure.tag('GOES Checklist R50');

  allure.remediation({
    summary: 'Endpoints sensibles permiten cache.',
    howWeChecked: [
      'GET a endpoints sensibles (/me, /admin, /auth/*)',
      'Esperabamos Cache-Control: no-store',
      'No esta o tiene max-age positivo',
    ],
    whyItMatters: 'Sin no-store, data sensible queda en el cache del browser/proxy.',
  });
  await allure.description(
    '## Objective\n' +
    'Verify that sensitive endpoints (user profile, auth, admin)\n' +
    'include Cache-Control: no-store to prevent caching of sensitive data.',
  );

  const sensitiveEndpoints = [
    '/api/auth/profile',
    '/api/users/me',
    '/api/admin/users',
  ];

  for (const endpoint of sensitiveEndpoints) {
    await allure.step(`Verify: ${endpoint} has no-store`, async () => {
      const response = await request(app.getHttpServer())
        .get(endpoint)
        .set('Authorization', `Bearer ${validToken}`);

      const cacheControl = response.headers['cache-control'];
      expect(cacheControl).toContain('no-store');
    });
  }

  await attach('Cache-Control results (output)', {
    endpoints: sensitiveEndpoints,
    allNoStore: true,
  });
  await allure.flush();
});

it('PENTEST R44 — CSP MUST NOT include unsafe-inline / unsafe-eval / unsafe-hashes', async () => {
  const allure = new AllureCompat();
  const attach = attachFor(allure);
  await allure.epic('Configuracion');
  await allure.feature('CSP Header');
  await allure.story('CSP rechaza todos los keywords "unsafe-*" y wildcards en cualquier directiva');
  await allure.severity('blocker');
  await allure.tag('Pentest');
  await allure.tag('OWASP A05');
  await allure.tag('OWASP A03');
  await allure.tag('GOES Checklist R44');
  await allure.tag('Pentest Regression VULN-XXX-NNNN');

  t.remediation({
    summary:
      'La configuracion de seguridad del navegador (CSP) esta abriendo una puerta: permite ' +
      'estilos inline, lo que habilita ataques de inyeccion de CSS y manipulacion visual.',
    howWeChecked: [
      'Hicimos GET a varios endpoints capturando el header Content-Security-Policy',
      'Buscamos que NO contenga las palabras clave "unsafe-inline", "unsafe-eval", "unsafe-hashes"',
      'Encontramos `style-src self unsafe-inline` — la directiva permite estilos inline sin restriccion',
    ],
    whyItMatters:
      'Aunque parezca cosmetico, un atacante con cualquier punto de inyeccion puede usar CSS ' +
      'malicioso para: capturar lo que el usuario escribe en formularios sensibles, superponer ' +
      'elementos invisibles que capturen clicks (clickjacking avanzado), o filtrar datos visibles ' +
      'en el DOM hacia un servidor externo. Es una capa de defensa que deberia ser dura.',
    file: 'src/main.ts (configuracion de helmet)',
    symbol: 'app.use(helmet({...}))',
    expected: 'helmet con CSP { styleSrc: ["\'self\'"], scriptSrc: ["\'self\'"] } sin unsafe-*',
    received: 'helmet con CSP { styleSrc: ["\'self\'", "\'unsafe-inline\'"] }',
    howToFix:
      '1. Abrir src/main.ts y localizar la llamada app.use(helmet({ contentSecurityPolicy: {...} })).\n' +
      '2. Quitar todas las apariciones de "\'unsafe-inline\'", "\'unsafe-eval\'" y "\'unsafe-hashes\'" de las directivas CSP.\n' +
      '3. Si hay estilos inline en el frontend que la app rendea, migrarlos a hojas externas servidas desde el mismo origen.\n' +
      '4. Si por necesidad tecnica deben existir estilos inline puntuales, usar nonces criptograficos por request en lugar de \'unsafe-inline\'.',
    exampleCode:
      'app.use(helmet({\n' +
      '  contentSecurityPolicy: {\n' +
      '    useDefaults: true,\n' +
      '    directives: {\n' +
      '      defaultSrc: ["\'self\'"],\n' +
      '      scriptSrc: ["\'self\'"],\n' +
      '      styleSrc: ["\'self\'"],         // SIN unsafe-inline\n' +
      '      frameAncestors: ["\'none\'"],\n' +
      '    },\n' +
      '  },\n' +
      '}));',
    references: [
      { title: 'GOES Guide Seccion 8 — HTTP Security Headers' },
      { title: 'helmet docs', url: 'https://helmetjs.github.io/' },
      { title: 'CSP — MDN', url: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP' },
    ],
  });

  await allure.description(
    '## Vulnerability Prevented\n' +
    '**CSS / Script Injection via permissive CSP** — VULN-XXX-NNNN del\n' +
    'pentest del 27/05/2026 reporto `style-src self unsafe-inline`,\n' +
    'lo cual habilita CSS injection, UI redressing y clickjacking avanzado.\n\n' +
    '## Defense Implemented\n' +
    'helmet().contentSecurityPolicy configurado SIN `unsafe-inline`,\n' +
    '`unsafe-eval`, `unsafe-hashes` ni `*` en ninguna directiva. Estilos\n' +
    'inline migrados a hojas externas o servidos con nonce criptografico.\n\n' +
    '## Reference\n' +
    'GOES Guide Seccion 8 — HTTP Security Headers\n' +
    'GOES Checklist v2 R44 — "Content-Security-Policy default-src self;\n' +
    'script-src self; style-src self iframe none" (sin unsafe-inline)',
  );

  // ===== Capa 2: static analysis de la config de helmet =====
  const fs = require('fs');
  const path = require('path');
  const stripComments = (src: string): string =>
    src.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:])\/\/.*$/gm, '$1');

  const mainSrc = stripComments(
    fs.readFileSync(path.resolve(__dirname, '../../src/main.ts'), 'utf-8'),
  );
  expect(mainSrc).toMatch(/helmet\s*\(/);

  // Si helmet recibe contentSecurityPolicy en su config, NO debe contener unsafe
  // (busqueda en main.ts y posibles archivos de config dedicados)
  const helmetConfigSearch = mainSrc;
  expect(helmetConfigSearch).not.toMatch(/'unsafe-inline'/);
  expect(helmetConfigSearch).not.toMatch(/'unsafe-eval'/);
  expect(helmetConfigSearch).not.toMatch(/'unsafe-hashes'/);

  // ===== Capa 3: comportamiento E2E — el header real =====
  const endpoints = ['/api/health', '/api/auth/login', '/'];
  const findings: Array<{ endpoint: string; csp: string; violations: string[] }> = [];

  for (const endpoint of endpoints) {
    const res = await request(app.getHttpServer()).get(endpoint);
    const csp = res.headers['content-security-policy'] || '';

    const violations: string[] = [];
    if (csp.includes("'unsafe-inline'")) violations.push('unsafe-inline');
    if (csp.includes("'unsafe-eval'")) violations.push('unsafe-eval');
    if (csp.includes("'unsafe-hashes'")) violations.push('unsafe-hashes');
    if (/[a-z-]+\s+\*/.test(csp)) violations.push('wildcard *');
    if (!csp.includes("default-src")) violations.push('missing default-src');

    findings.push({ endpoint, csp, violations });
  }

  await attach('CSP por endpoint (output)', findings);

  for (const f of findings) {
    expect(f.violations).toEqual([]);
  }

  await allure.flush();
});

it('PENTEST R45 — Cross-Origin-* hardening (CORP/COOP/COEP) for internal admin panels', async () => {
  const allure = new AllureCompat();
  const attach = attachFor(allure);
  await allure.epic('Configuracion');
  await allure.feature('Security Headers');
  await allure.story('Paneles admin internos usan CORP same-origin, no cross-origin');
  await allure.severity('normal');
  await allure.tag('Pentest');
  await allure.tag('OWASP A05');
  await allure.tag('GOES Checklist R45');
  await allure.tag('Pentest Regression VULN-XXX-NNNN');

  allure.remediation({
    summary: 'Faltan headers basicos contra mime-sniffing y clickjacking.',
    howWeChecked: [
      'GET a cualquier endpoint y revisar headers',
      'Esperabamos X-Content-Type-Options: nosniff y X-Frame-Options: DENY',
      'Faltan ambos o uno',
    ],
    whyItMatters: 'Sin nosniff, el browser puede interpretar archivos como JS aunque sean PDF. Sin X-Frame-Options, vulnerable a clickjacking.',
  });
  await allure.description(
    '## Vulnerability Prevented\n' +
    'VULN-XXX-NNNN reporto `Cross-Origin-Resource-Policy: cross-origin` en\n' +
    'el panel admin interno, ampliando la superficie de ataque ante Spectre\n' +
    'y cross-site leaks.\n\n' +
    '## Defense Implemented\n' +
    'Para paneles admin: `Cross-Origin-Resource-Policy: same-origin` y\n' +
    '`Cross-Origin-Opener-Policy: same-origin`.',
  );

  const isAdminPanel = process.env.APP_ROLE === 'admin' || process.env.APP_ROLE === 'internal';

  if (!isAdminPanel) {
    // Para portales publicos, same-site es aceptable
    const res = await request(app.getHttpServer()).get('/');
    const corp = res.headers['cross-origin-resource-policy'];
    expect(['same-origin', 'same-site']).toContain(corp);
    await attach('Public portal CORP (output)', { corp });
  } else {
    const res = await request(app.getHttpServer()).get('/');
    const corp = res.headers['cross-origin-resource-policy'];
    const coop = res.headers['cross-origin-opener-policy'];
    expect(corp).toBe('same-origin');
    expect(coop).toMatch(/same-origin/);
    await attach('Admin panel cross-origin headers (output)', { corp, coop });
  }

  await allure.flush();
});
```
