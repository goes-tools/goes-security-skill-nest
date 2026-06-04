# Pattern 11: Session Management

> **Migration note (skill v2.0):** these patterns were originally written for
> `allure-js-commons`. They now run against the bundled custom HTML reporter
> via `AllureCompat`, which mirrors the same API. The `_setup.md` snippet
> shows the new top-level imports. Existing `await allure.epic(...)`,
> `await allure.step(...)` etc. work identically. Two extras:
>
> - Each `it(...)` block must end with `await allure.flush();` so the metadata
>   reaches the reporter.
> - `attach(name, data)` is now async — call it as `await attach(...)`.

**Covers:** R13 (Token Lifetime), R17 (Session ID Entropy), R18 (Session Fixation Prevention), R32 (Refresh Rotation), R35 (Session Inactivity Timeout — INCLUYE idle timeout independiente del exp del JWT, regresion VULN-XXX-NNNN)

```typescript
it('should generate session IDs with sufficient entropy', async () => {
  const allure = new AllureCompat();
  const attach = attachFor(allure);
  await allure.epic('Security');
  await allure.feature('Session ID Entropy');
  await allure.story('Session IDs must have at least 128 bits of entropy via CSPRNG');
  await allure.severity('critical');
  await allure.tag('Auth');
  await allure.tag('OWASP A07');
  await allure.tag('GOES Checklist R17');

  allure.remediation({
    summary: 'Los session IDs son predecibles o tienen entropia insuficiente. Un atacante puede adivinarlos por fuerza bruta.',
    howWeChecked: [
      'Generamos multiples session IDs',
      'Esperabamos al menos 128 bits de entropia (22+ caracteres base64)',
      'Los IDs eran cortos, secuenciales o derivados de informacion conocida',
    ],
    whyItMatters: 'Sin entropia suficiente, un atacante puede adivinar session IDs activos y secuestrar sesiones de otros usuarios.',
  });
  await allure.description(
    '## Objective\n' +
    'Verify that session IDs are generated with a cryptographically\n' +
    'secure random number generator (CSPRNG) and have at least\n' +
    '128 bits of entropy.\n\n' +
    '## Reference\n' +
    'GOES Guide Section 4.2 — Session Management',
  );

  await allure.step('Execute: generate multiple session IDs', async () => {
    const sessions = [];
    for (let i = 0; i < 10; i++) {
      const id = service.generateSessionId();
      sessions.push(id);
    }

    // Verify minimum length (128 bits = 16 bytes = 32 hex chars or ~22 base64 chars)
    for (const id of sessions) {
      expect(id.length).toBeGreaterThanOrEqual(22);
    }

    // Verify uniqueness (no collisions)
    const uniqueIds = new Set(sessions);
    expect(uniqueIds.size).toBe(sessions.length);
  });

  await attach('Session entropy result (output)', {
    minimumBits: 128,
    generatedWithCSPRNG: true,
  });
  await allure.flush();
});

it('PENTEST: should regenerate session after login (prevent session fixation)', async () => {
  const allure = new AllureCompat();
  const attach = attachFor(allure);
  await allure.epic('Security');
  await allure.feature('Session Fixation Prevention');
  await allure.story('Session ID must change after successful authentication');
  await allure.severity('critical');
  await allure.tag('Pentest');
  await allure.tag('OWASP A07');
  await allure.tag('GOES Checklist R18');

  allure.remediation({
    summary: 'El session ID no cambia tras login. Un atacante puede fijar un session ID en la victima antes del login y usar el mismo despues.',
    howWeChecked: [
      'Capturamos session ID antes del login',
      'Hicimos login y capturamos el session ID despues',
      'El session ID es el mismo — vulnerable a session fixation',
    ],
    whyItMatters: 'Session fixation permite al atacante secuestrar la sesion sin necesidad de robar el token.',
  });
  await allure.description(
    '## Vulnerability Prevented\n' +
    '**Session Fixation** — An attacker sets a known session ID\n' +
    'before the user logs in. After login, the attacker uses the\n' +
    'same session ID to hijack the authenticated session.\n\n' +
    '## Defense Implemented\n' +
    'The session ID is regenerated after every successful login.\n' +
    'The old session is invalidated.',
  );

  let preLoginToken: string;
  let postLoginToken: string;

  await allure.step('Prepare: capture pre-login session/token', async () => {
    preLoginToken = 'pre-login-session-id';
  });

  await allure.step('Execute: login with valid credentials', async () => {
    const result = await service.login(validCredentials, '1.2.3.4', 'ua');
    postLoginToken = result.accessToken;
  });

  await allure.step('Verify: session/token changed after login', async () => {
    expect(postLoginToken).not.toBe(preLoginToken);
    expect(postLoginToken).toBeDefined();
  });

  await attach('Session fixation prevention (output)', {
    preLoginSession: 'pre-login-session-id',
    postLoginSession: 'new-session-generated',
    sessionChanged: true,
  });
  await allure.flush();
});

it('should expire session after inactivity timeout', async () => {
  const allure = new AllureCompat();
  const attach = attachFor(allure);
  await allure.epic('Security');
  await allure.feature('Session Inactivity Timeout');
  await allure.story('Redirect to login after idle period');
  await allure.severity('critical');
  await allure.tag('Auth');
  await allure.tag('OWASP A07');
  await allure.tag('GOES Checklist R35');

  allure.remediation({
    summary: 'El sistema no controla el cierre de sesion luego de que el usuario pasa tiempo sin hacer peticiones. La sesion sigue activa aunque el JWT siga vigente.',
    howWeChecked: [
      'Hicimos login y capturamos el token (exp lejano)',
      'Simulamos 31 minutos sin actividad modificando lastActivityAt',
      'Esperabamos 401 al siguiente request — el sistema devolvio 200',
    ],
    whyItMatters: 'Sin idle timeout, un atacante con acceso fisico a una terminal abandonada puede retomar la sesion sin necesidad de la contrasena.',
  });
  await allure.description(
    '## Objective\n' +
    'Verify that sessions expire after a configurable inactivity period\n' +
    '(15-30 minutes recommended).\n\n' +
    '## Reference\n' +
    'GOES Guide Section 4.2 — Session Management',
  );

  await allure.parameter('inactivity_timeout', '30 minutes');

  await allure.step('Prepare: create token with short expiry', async () => {
    // Token was issued 31 minutes ago
    const expiredToken = jwtService.sign(
      { sub: 'user-1', role: 'USER' },
      { expiresIn: '-1m' }, // already expired
    );
    mockRequest.headers.authorization = `Bearer ${expiredToken}`;
  });

  await allure.step('Verify: expired token is rejected', async () => {
    await expect(guard.canActivate(mockContext)).rejects.toThrow();
  });

  await attach('Session timeout result (output)', {
    tokenExpired: true,
    accessDenied: true,
  });
  await allure.flush();
});

it('PENTEST R35 — refresh token with valid exp MUST be rejected after 30min idle', async () => {
  const allure = new AllureCompat();
  const attach = attachFor(allure);
  await allure.epic('Seguridad');
  await allure.feature('Session Inactivity Timeout');
  await allure.story('Idle timeout independiente de exp del token — sesion muere por inactividad');
  await allure.severity('blocker');
  await allure.tag('Pentest');
  await allure.tag('OWASP A07');
  await allure.tag('GOES Checklist R35');
  await allure.tag('Pentest Regression VULN-XXX-NNNN');

  t.remediation({
    summary:
      'La sesion del usuario no muere por inactividad. Aunque el JWT siga vigente, no se ' +
      'invalida el acceso si la persona dejo el equipo abandonado por horas o dias.',
    howWeChecked: [
      'Hicimos login y capturamos el refresh token (exp de 7 dias)',
      'Modificamos la columna lastActivityAt para simular que pasaron 31 minutos sin actividad',
      'Hicimos un GET protegido — esperabamos 401 porque la sesion esta inactiva',
      'El sistema devolvio 200 OK: nadie esta midiendo la inactividad, solo el exp del token',
    ],
    whyItMatters:
      'Un atacante que tenga acceso fisico o logico a la terminal de un usuario puede retomar ' +
      'una sesion abandonada por dias sin necesidad de la contrasena. En un sistema que maneja ' +
      'DUI y datos personales de ciudadanos, esto amplifica mucho el riesgo de cualquier descuido ' +
      'operativo (computadora abandonada, mouse compartido, robo).',
    file: 'src/auth/auth.service.ts (refresh) y src/auth/jwt-auth.guard.ts',
    symbol: 'refreshToken() / canActivate()',
    expected: 'El guard verifica `lastActivityAt` y rechaza si > 30 min',
    received: 'El guard valida solo `exp` del JWT, sin tracking de inactividad',
    howToFix:
      '1. Agregar columna `lastActivityAt` a la tabla de sesiones (Prisma schema o equivalente).\n' +
      '2. Cada vez que llega un request privado, actualizar `lastActivityAt = now()`.\n' +
      '3. En el guard, ANTES de validar firma del JWT, verificar:\n' +
      '   if ((now - session.lastActivityAt) > IDLE_TIMEOUT_MIN * 60_000) throw new UnauthorizedException(\'session idle\');\n' +
      '4. Configurar IDLE_TIMEOUT_MIN = 30 en `.env`.\n' +
      '5. En el endpoint /refresh, revocar la sesion si supero el idle.',
    exampleCode:
      'async canActivate(context: ExecutionContext): Promise<boolean> {\n' +
      '  const req = context.switchToHttp().getRequest();\n' +
      '  const session = await this.sessionRepo.findOne({ where: { token: req.headers.authorization } });\n' +
      '  if (!session) throw new UnauthorizedException();\n' +
      '  const idleMs = Date.now() - session.lastActivityAt.getTime();\n' +
      '  if (idleMs > parseInt(process.env.IDLE_TIMEOUT_MIN ?? \'30\') * 60_000) {\n' +
      '    await this.sessionRepo.update({ id: session.id }, { revokedAt: new Date() });\n' +
      '    throw new UnauthorizedException(\'session idle\');\n' +
      '  }\n' +
      '  await this.sessionRepo.update({ id: session.id }, { lastActivityAt: new Date() });\n' +
      '  return super.canActivate(context) as Promise<boolean>;\n' +
      '}',
    references: [
      { title: 'GOES Checklist v2 R35' },
      { title: 'OWASP Session Management Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html' },
      { title: 'NIST SP 800-63B 4.1.4 — Session timeouts', url: 'https://pages.nist.gov/800-63-3/sp800-63b.html' },
    ],
  });

  await allure.description(
    '## Vulnerability Prevented\n' +
    '**Stale Session Hijack** — VULN-XXX-NNNN de pentests previos:\n' +
    'el refresh token tiene exp de 7 dias, pero NO hay control de inactividad.\n' +
    'Un atacante con acceso fisico a la terminal puede retomar una sesion\n' +
    'abandonada por dias sin re-autenticacion.\n\n' +
    '## Defense Implemented\n' +
    'El servidor mantiene `lastActivityAt` por sesion. En cada request privado\n' +
    'verifica que `now() - lastActivityAt <= IDLE_TIMEOUT_MIN` (default 30 min).\n' +
    'Si excede, retorna 401 y revoca la sesion AUNQUE el JWT siga vigente.\n\n' +
    '## Reference\n' +
    'GOES Guide Seccion 4.2 — Session Management\n' +
    'GOES Checklist v2 R35 — "si no se detecta actividad por 30 min se saca de la sesion"',
  );

  // ===== Capa 1: config =====
  const idleTimeoutMin = parseInt(process.env.IDLE_TIMEOUT_MIN || '30', 10);
  expect(idleTimeoutMin).toBeGreaterThanOrEqual(15);
  expect(idleTimeoutMin).toBeLessThanOrEqual(30);
  await allure.parameter('idle_timeout_min', idleTimeoutMin.toString());

  // ===== Capa 2: aplicacion — el guard / strategy DEBE leer lastActivityAt =====
  const fs = require('fs');
  const path = require('path');
  const glob = require('glob');
  const stripComments = (src: string): string =>
    src.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:])\/\/.*$/gm, '$1');

  const guardFiles = glob.sync('src/**/*.{guard,strategy}.ts', {
    cwd: path.resolve(__dirname, '../..'),
    absolute: true,
  });
  const aggregated = guardFiles
    .map((f: string) => stripComments(fs.readFileSync(f, 'utf-8')))
    .join('\n');

  const tracksLastActivity =
    /lastActivityAt|last_activity|idleTimeout|lastSeen|inactivity/.test(aggregated);

  await attach('Guard static analysis (input)', {
    guardsScanned: guardFiles.length,
    tracksLastActivity,
  });
  expect(tracksLastActivity).toBe(true);

  // ===== Capa 3: comportamiento E2E con fake timers =====
  await allure.step('Preparar: login y obtener refresh token con exp lejana', async () => {
    const refreshToken = jwtService.sign(
      { sub: 'user-1', type: 'refresh' },
      { expiresIn: '7d' }, // exp valido por 7 dias
    );
    mockRequest.headers.authorization = `Bearer ${refreshToken}`;

    // Simular que la ultima actividad fue hace 31 min
    await sessionRepository.update(
      { userId: 'user-1' },
      { lastActivityAt: new Date(Date.now() - 31 * 60 * 1000) },
    );
  });

  await allure.step('Ejecutar: GET protegido tras 31 min de inactividad', async () => {
    // El guard debe rechazar a pesar de que exp del token sigue vigente
    await expect(guard.canActivate(mockContext)).rejects.toThrow(/inactiv|idle|session/i);
  });

  await allure.step('Verificar: sesion fue revocada del lado servidor', async () => {
    const session = await sessionRepository.findOne({ where: { userId: 'user-1' } });
    expect(session?.revokedAt).toBeDefined();
  });

  await attach('Idle timeout enforcement (output)', {
    tokenExpStillValid: true,
    idleMinutesElapsed: 31,
    requestRejected: true,
    sessionRevoked: true,
  });
  await allure.flush();
});

it('PENTEST R13/R35 — refresh token rotation MUST update lastActivityAt', async () => {
  const allure = new AllureCompat();
  const attach = attachFor(allure);
  await allure.epic('Seguridad');
  await allure.feature('Session Inactivity Timeout');
  await allure.story('Cada uso valido del refresh token actualiza lastActivityAt y rota el token');
  await allure.severity('critical');
  await allure.tag('Auth');
  await allure.tag('GOES Checklist R32');
  await allure.tag('GOES Checklist R35');
  await allure.tag('Pentest Regression VULN-XXX-NNNN');

  allure.remediation({
    summary: 'El refresh token no rota: se puede usar multiples veces antes de su exp.',
    howWeChecked: [
      'Usamos el refresh token una vez',
      'Volvimos a usar el mismo refresh token',
      'El sistema lo acepto en lugar de rechazarlo (debe ser invalidado tras 1 uso)',
    ],
    whyItMatters: 'Sin rotacion, un refresh token filtrado vale por toda su exp.',
  });

  let initialLastActivity: Date;
  let updatedLastActivity: Date;
  let firstRefreshToken: string;
  let secondRefreshToken: string;

  await allure.step('Preparar: capturar lastActivityAt inicial y refresh token', async () => {
    const session = await sessionRepository.findOne({ where: { userId: 'user-1' } });
    initialLastActivity = session!.lastActivityAt;
    firstRefreshToken = jwtService.sign({ sub: 'user-1' }, { expiresIn: '7d' });
  });

  await allure.step('Ejecutar: rotacion del refresh token', async () => {
    // Avanzar 5 minutos (dentro del idle window)
    jest.useFakeTimers().setSystemTime(Date.now() + 5 * 60 * 1000);
    const result = await service.refresh(firstRefreshToken);
    secondRefreshToken = result.refreshToken;
  });

  await allure.step('Verificar: lastActivityAt actualizado + token rotado', async () => {
    const session = await sessionRepository.findOne({ where: { userId: 'user-1' } });
    updatedLastActivity = session!.lastActivityAt;
    expect(updatedLastActivity.getTime()).toBeGreaterThan(initialLastActivity.getTime());
    expect(secondRefreshToken).not.toBe(firstRefreshToken);
  });

  jest.useRealTimers();

  await attach('Rotation + activity tracking (output)', {
    activityTracked: true,
    tokenRotated: true,
  });
  await allure.flush();
});
```
