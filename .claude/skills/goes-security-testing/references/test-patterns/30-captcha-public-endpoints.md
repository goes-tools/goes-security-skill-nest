# Pattern 30: Captcha on Public Sensitive Endpoints

> Migration note: usa `AllureCompat` y `await allure.flush()` al final de cada `it`.

**Covers:** R5 (XSS / Input Sanitization), R14 (Auth failures: MFA, rate limit, session mgmt — incluye challenge humano), R27 (Brute Force Protection), R55 (Rate Limiting reforzado en endpoints publicos)

**Regresion cubierta:**
- **VULN-EXT-0003** — `/api/auth/verify-dui` (endpoint mas sensible del portal externo, expone PII del RNPN) NO implementa reCAPTCHA, mientras que `/api/auth/register` SI lo tiene. La proteccion esta en el paso menos critico del flujo.

---

## Por que este pattern

Cuando un endpoint publico devuelve datos sensibles (PII, lookup de identidad, recuperacion de cuenta), el rate limit por IP es insuficiente: un atacante con un pool de IPs evade el limite. El **challenge humano** (reCAPTCHA v3, Cloudflare Turnstile, hCaptcha) es la unica capa que escala. La regla canonica:

> **Si un endpoint es publico (sin auth) Y retorna datos sensibles, lookup de identidad, envia mensajes o consume recursos costosos, DEBE tener guard de captcha. Sin excepciones.**

Lista canonica de endpoints publicos sensibles (la skill debe enumerar y verificar cada uno):

| Endpoint | Razon |
|---|---|
| `POST /api/auth/register` | Crea cuenta, envia OTP por email/SMS |
| `POST /api/auth/login` | Brute force / credential stuffing |
| `POST /api/auth/forgot-password` | Envia email, enumeracion de cuentas |
| `POST /api/auth/recover-password` | Reset token validation |
| `POST /api/auth/verify-dui` (o equivalente lookup de identidad) | **VULN-EXT-0003 — expone PII del RNPN** |
| `POST /api/auth/verify-email` | Envia OTP |
| `POST /api/contact` | Envia email a admin, spam |
| `POST /api/newsletter/subscribe` | Spam, enumeracion de emails |

---

## Reglas obligatorias

1. Cada endpoint de la lista anterior DEBE tener `@UseGuards(RecaptchaGuard)` o middleware equivalente.
2. El token de captcha DEBE validarse server-side contra el servicio (Google/Cloudflare/hCaptcha), NO solo verificar presencia del campo.
3. El umbral minimo aceptable es **score >= 0.7** para reCAPTCHA v3.
4. La validacion DEBE rechazar requests sin token o con token invalido/expirado con HTTP 400 o 403, antes de procesar el cuerpo.
5. El captcha NO sustituye al rate limit; ambos deben estar.

---

## Tests

```typescript
import * as request from 'supertest';
import { report } from '@security-reporter/metadata';

// Lista de endpoints publicos sensibles que el proyecto debe proteger.
// Ajustar segun el proyecto bajo test.
const SENSITIVE_PUBLIC_ENDPOINTS = [
  { method: 'POST', path: '/api/auth/register',         reason: 'Crea cuenta, envia OTP' },
  { method: 'POST', path: '/api/auth/login',            reason: 'Brute force / credential stuffing' },
  { method: 'POST', path: '/api/auth/forgot-password',  reason: 'Envia email, enumeracion' },
  { method: 'POST', path: '/api/auth/recover-password', reason: 'Reset token validation' },
  { method: 'POST', path: '/api/auth/verify-dui',       reason: 'VULN-EXT-0003: lookup de PII RNPN' },
  { method: 'POST', path: '/api/auth/verify-email',     reason: 'Envia OTP' },
  { method: 'POST', path: '/api/contact',               reason: 'Envia email a admin, spam' },
];

it('PENTEST R14 — sensitive public endpoints MUST reject requests without captcha token', async () => {
  const t = report();
  t.epic('Seguridad');
  t.feature('Captcha on Public Sensitive Endpoints');
  t.story('Endpoints publicos sensibles requieren captcha valido o devuelven 400/403');
  t.severity('blocker');
  t.tag('Pentest', 'OWASP A07', 'OWASP API2', 'GOES Checklist R14', 'GOES Checklist R55');
  t.tag('Pentest Regression VULN-EXT-0003');

  const findings: Array<{
    endpoint: string;
    reason: string;
    statusWithoutCaptcha: number;
    rejected: boolean;
  }> = [];

  for (const ep of SENSITIVE_PUBLIC_ENDPOINTS) {
    // Body minimo valido SIN captcha token
    const body = ep.path.includes('verify-dui')
      ? { dui: '00000000-0', birthDate: '2000-01-01' }
      : ep.path.includes('login')
      ? { email: 'test@goes.gob.sv', password: 'TestPass1234!' }
      : ep.path.includes('register')
      ? { email: 'new@goes.gob.sv', password: 'TestPass1234!' }
      : ep.path.includes('forgot') || ep.path.includes('verify-email')
      ? { email: 'test@goes.gob.sv' }
      : ep.path.includes('recover')
      ? { token: 'fake', password: 'NewPass1234!' }
      : { name: 'Test', email: 'test@goes.gob.sv', message: 'Hola' };

    const res = await request(app.getHttpServer())
      .post(ep.path)
      .send(body);

    if (res.status === 404) continue; // Endpoint no existe en el proyecto

    findings.push({
      endpoint: `${ep.method} ${ep.path}`,
      reason: ep.reason,
      statusWithoutCaptcha: res.status,
      // Rechazar = 400, 403 o 422. Aceptar (200/201/204) sin captcha = HALLAZGO.
      rejected: [400, 403, 422].includes(res.status),
    });
  }

  t.evidence('Endpoints scanned (input)', SENSITIVE_PUBLIC_ENDPOINTS);
  t.evidence('Responses sin captcha (output)', findings);

  // TODOS los endpoints publicos sensibles que existen DEBEN rechazar
  for (const f of findings) {
    expect(f.rejected).toBe(true);
  }

  await t.flush();
});

it('R14 config — RecaptchaGuard o equivalente esta declarado en cada endpoint publico sensible', async () => {
  const t = report();
  t.epic('Configuracion');
  t.feature('Captcha on Public Sensitive Endpoints');
  t.story('Static analysis: decorador @UseGuards(RecaptchaGuard) presente en cada controller');
  t.severity('blocker');
  t.tag('Config', 'GOES Checklist R14');
  t.tag('Pentest Regression VULN-EXT-0003');

  const fs = require('fs');
  const path = require('path');
  const glob = require('glob');
  const stripComments = (src: string): string =>
    src.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:])\/\/.*$/gm, '$1');

  const authControllers = glob.sync('src/**/auth.controller.ts', {
    cwd: path.resolve(__dirname, '../..'),
    absolute: true,
  });

  if (authControllers.length === 0) {
    t.notApplicable('No hay auth.controller.ts en el proyecto. Verificado: glob src/**/auth.controller.ts');
    await t.flush();
    return;
  }

  const src = stripComments(fs.readFileSync(authControllers[0], 'utf-8'));

  // Buscar guards de captcha conocidos
  const captchaGuardPattern = /@UseGuards\([^)]*(?:Recaptcha|Captcha|Turnstile|HCaptcha)/;
  const hasCaptchaGuard = captchaGuardPattern.test(src);

  // Buscar metodos publicos sensibles (verify-dui, verify-email, forgot, recover)
  const sensitiveMethods = [
    'verify-dui', 'verifyDui',
    'verify-email', 'verifyEmail',
    'forgot-password', 'forgotPassword',
    'recover-password', 'recoverPassword',
  ];

  const findings: Array<{ method: string; foundInController: boolean; nearbyHasGuard: boolean }> = [];

  for (const method of sensitiveMethods) {
    // Buscar la posicion del metodo en el source
    const re = new RegExp(`@(Post|Get|Patch)\\s*\\(\\s*['"\\\`]([^'"\\\`]*${method}[^'"\\\`]*)['"\\\`]`, 'i');
    const match = src.match(re);
    if (!match) {
      findings.push({ method, foundInController: false, nearbyHasGuard: true });
      continue;
    }
    // Extraer las 10 lineas anteriores al match
    const idx = match.index ?? 0;
    const before = src.slice(Math.max(0, idx - 500), idx);
    const nearbyHasGuard = captchaGuardPattern.test(before);
    findings.push({ method, foundInController: true, nearbyHasGuard });
  }

  t.evidence('Static analysis (output)', { hasCaptchaGuard, findings });

  // Cada metodo que EXISTE en el controller debe tener guard captcha encima
  for (const f of findings) {
    if (f.foundInController) {
      expect(f.nearbyHasGuard).toBe(true);
    }
  }

  await t.flush();
});

it('PENTEST R14 — captcha guard MUST validate token server-side, not just presence', async () => {
  const t = report();
  t.epic('Seguridad');
  t.feature('Captcha on Public Sensitive Endpoints');
  t.story('Token de captcha invalido es rechazado por validacion server-side');
  t.severity('blocker');
  t.tag('Pentest', 'GOES Checklist R14');
  t.tag('Pentest Regression VULN-EXT-0003');

  // Enviar un token de captcha obviamente falso
  const fakeToken = 'AAAAAA-fake-token-not-a-real-recaptcha-response-AAAAAA';
  const body = {
    dui: '00000000-0',
    birthDate: '2000-01-01',
    recaptchaToken: fakeToken,
    captchaToken: fakeToken,
    'g-recaptcha-response': fakeToken,
  };

  const res = await request(app.getHttpServer())
    .post('/api/auth/verify-dui')
    .send(body);

  t.evidence('Request con token falso (input)', { tokenPrefix: fakeToken.slice(0, 20) });
  t.evidence('Response (output)', { status: res.status, body: res.body });

  // El server debe validar contra el servicio (Google/Cloudflare) y rechazar
  expect([400, 403]).toContain(res.status);

  await t.flush();
});
```
