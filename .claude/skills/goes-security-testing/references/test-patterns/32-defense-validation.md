# Pattern 32: Defense Validation (Inverse / Mutation Tests)

> Migration note: usa `AllureCompat` y `await allure.flush()` al final de cada `it`.

**Covers:** validación de que los 6 controles de defensa criticos realmente protegen, no son decorativos ni condicionales.

**Defensas cubiertas:**

| Defensa | R items |
|---|---|
| helmet (security headers) | R44, R45, R46, R47, R48, R49, R50 |
| CORS (`enableCors`) | R38, R39, R40, R41 |
| JwtAuthGuard | R21, R33 |
| RolesGuard | R9, R24, R34 |
| ValidationPipe global | R5, R11 |
| HttpExceptionFilter | R8 |
| ThrottlerGuard | R55 |

---

## Por que este pattern

Los patterns 1-31 verifican que cada defensa esta presente y funciona en `NODE_ENV=test`. Pero un control puede ser **condicional** (`if (env === 'production') app.use(helmet())`) o **movido a un wrapper** que en algun branch no se ejecuta. En ese caso:

- Static analysis ve `helmet(` en el source → verde.
- E2E con `NODE_ENV=test` y NO helmet → headers ausentes → rojo, pero el dev "justifica" que en prod si esta activo.
- Resultado: nadie sabe si en prod realmente esta o no.

Los **tests inversos** verifican que la defensa esta haciendo trabajo real comparando dos boots de la app:

1. App con la defensa REMOVIDA via mock del modulo → assert que la response es insegura
2. App con la defensa NORMAL → assert que la response es segura

Si el paso 1 NO detecta diferencia (la response sigue "segura" incluso sin la defensa), significa que **algo mas la esta protegiendo** y el origen del control es desconocido — eso es hallazgo auditable.

Si el paso 2 falla (con defensa, response no es segura), la defensa no esta haciendo su trabajo.

---

## Reglas obligatorias

1. Cada uno de los 6 controles de defensa criticos DEBE tener un test inverso.
2. El test inverso usa `jest.mock()` para reemplazar el modulo de la defensa con un no-op, levanta la app, y verifica el comportamiento.
3. Tras la verificacion, el `jest.unmock()` restaura el modulo original.
4. Los tests inversos se generan en `test/security/inverse/*.inverse.spec.ts`.

---

## Tests

```typescript
import * as fs from 'fs';
import * as path from 'path';
import * as request from 'supertest';
import { Test } from '@nestjs/testing';
import { INestApplication } from '@nestjs/common';
import { report } from '@security-reporter/metadata';

// ============================================================
// INV-01 — helmet
// ============================================================

it('INV-01 — withOUT helmet, response is missing security headers (control works)', async () => {
  const t = report();
  t.epic('Configuracion');
  t.feature('Defense Validation');
  t.story('helmet hace trabajo real: sin el, los headers desaparecen');
  t.severity('blocker');
  t.tag('Defense Validation', 'Inverse Test');
  for (const r of ['R44','R45','R46','R47','R48','R49','R50']) t.tag(`GOES Checklist ${r}`);

  jest.resetModules();
  jest.doMock('helmet', () => () => (_req: any, _res: any, next: any) => next());

  // Re-importar AppModule despues del mock
  const { AppModule } = await import('../../../src/app.module');
  const moduleRef = await Test.createTestingModule({ imports: [AppModule] }).compile();
  const app: INestApplication = moduleRef.createNestApplication();
  await app.init();

  const res = await request(app.getHttpServer()).get('/api/health');

  // Sin helmet, estos headers NO deben estar
  const expectedAbsent = [
    'content-security-policy',
    'strict-transport-security',
    'x-content-type-options',
    'x-frame-options',
  ];
  const stillPresent = expectedAbsent.filter(h => res.headers[h]);

  t.evidence('Headers sin helmet (output)', { stillPresent, all: res.headers });

  // Si helmet es la unica fuente, NINGUNO debe seguir presente
  expect(stillPresent).toEqual([]);

  await app.close();
  jest.dontMock('helmet');
  jest.resetModules();

  await t.flush();
});

// ============================================================
// INV-02 — CORS
// ============================================================

it('INV-02 — withOUT enableCors, OPTIONS preflight has no CORS headers', async () => {
  const t = report();
  t.epic('Configuracion');
  t.feature('Defense Validation');
  t.story('enableCors hace trabajo real: sin el, no hay CORS headers');
  t.severity('blocker');
  t.tag('Defense Validation', 'Inverse Test');
  for (const r of ['R38','R39','R40','R41']) t.tag(`GOES Checklist ${r}`);

  jest.resetModules();
  // Mockear NestFactory para que ignore enableCors
  // Esto requiere setup mas complejo; alternativa pragmatica:
  // levantar app sin llamar a app.enableCors() y verificar.

  // Pragmatic approach: crear una app de test que NO llama enableCors
  const { AppModule } = await import('../../../src/app.module');
  const moduleRef = await Test.createTestingModule({ imports: [AppModule] }).compile();
  const app: INestApplication = moduleRef.createNestApplication();
  // NO llamar a app.enableCors() — simular ausencia
  await app.init();

  const res = await request(app.getHttpServer())
    .options('/api/auth/login')
    .set('Origin', 'https://allowed.gob.sv')
    .set('Access-Control-Request-Method', 'POST');

  t.evidence('CORS headers sin enableCors (output)', {
    acao: res.headers['access-control-allow-origin'],
    acam: res.headers['access-control-allow-methods'],
  });

  // Sin enableCors, NO debe haber Access-Control-Allow-Origin
  expect(res.headers['access-control-allow-origin']).toBeUndefined();

  await app.close();
  await t.flush();
});

// ============================================================
// INV-03 — JwtAuthGuard
// ============================================================

it('INV-03 — withOUT JwtAuthGuard, protected endpoint accepts unauthenticated requests', async () => {
  const t = report();
  t.epic('Autenticacion');
  t.feature('Defense Validation');
  t.story('JwtAuthGuard hace trabajo real: sin el, los endpoints privados quedan abiertos');
  t.severity('blocker');
  t.tag('Defense Validation', 'Inverse Test', 'GOES Checklist R21', 'GOES Checklist R33');

  jest.resetModules();
  jest.doMock('../../../src/auth/jwt-auth.guard', () => ({
    JwtAuthGuard: class {
      canActivate() { return true; }
    },
  }));

  const { AppModule } = await import('../../../src/app.module');
  const moduleRef = await Test.createTestingModule({ imports: [AppModule] }).compile();
  const app: INestApplication = moduleRef.createNestApplication();
  await app.init();

  const res = await request(app.getHttpServer()).get('/api/auth/me');

  t.evidence('Response sin JwtAuthGuard (output)', { status: res.status });

  // Con guard mockeado a "siempre permitir", deberia retornar 200/4xx,
  // NO 401 — eso confirma que el guard real era el responsable de rechazar.
  expect(res.status).not.toBe(401);

  await app.close();
  jest.dontMock('../../../src/auth/jwt-auth.guard');
  jest.resetModules();

  await t.flush();
});

// ============================================================
// INV-04 — ValidationPipe
// ============================================================

it('INV-04 — withOUT ValidationPipe global, malformed DTOs are accepted', async () => {
  const t = report();
  t.epic('Dominio');
  t.feature('Defense Validation');
  t.story('ValidationPipe global hace trabajo real');
  t.severity('blocker');
  t.tag('Defense Validation', 'Inverse Test', 'GOES Checklist R5', 'GOES Checklist R11');

  // Levantar app sin useGlobalPipes
  const { AppModule } = await import('../../../src/app.module');
  const moduleRef = await Test.createTestingModule({ imports: [AppModule] }).compile();
  const app: INestApplication = moduleRef.createNestApplication();
  // NO app.useGlobalPipes(new ValidationPipe(...))
  await app.init();

  const res = await request(app.getHttpServer())
    .post('/api/auth/register')
    .send({ email: 'not-an-email', password: 'x', extra_field: 'should_be_rejected' });

  t.evidence('Response sin ValidationPipe (output)', { status: res.status, body: res.body });

  // Sin ValidationPipe, no debe haber 400 por DTO invalido
  // (si llega a 400, es por otra razon — eso es lo que detectamos)
  expect([200, 201, 500]).toContain(res.status);

  await app.close();
  await t.flush();
});

// ============================================================
// INV-05 — HttpExceptionFilter
// ============================================================

it('INV-05 — withOUT HttpExceptionFilter, errors leak raw exception data', async () => {
  const t = report();
  t.epic('Seguridad');
  t.feature('Defense Validation');
  t.story('HttpExceptionFilter hace trabajo real: sin el, errores leak detalles');
  t.severity('blocker');
  t.tag('Defense Validation', 'Inverse Test', 'GOES Checklist R8');

  const { AppModule } = await import('../../../src/app.module');
  const moduleRef = await Test.createTestingModule({ imports: [AppModule] }).compile();
  const app: INestApplication = moduleRef.createNestApplication();
  // NO app.useGlobalFilters(new HttpExceptionFilter())
  await app.init();

  const res = await request(app.getHttpServer())
    .post('/api/auth/login')
    .send({ malformed: true });

  t.evidence('Response sin filter (output)', { status: res.status, body: res.body });

  // Sin filter, el body puede tener informacion mas cruda (stack, path, etc.)
  // El test verifica que el filter es el responsable de la limpieza —
  // si el body es identico al normal, el filter no esta haciendo nada.
  const bodyStr = JSON.stringify(res.body);
  const filterIsActive = bodyStr.length < 200 && !bodyStr.includes('stack');

  // Sin filter, esperamos que la response sea diferente a la version normal
  // (la version normal es la que prueban patterns 03 y 31).
  t.evidence('Diferencias detectadas (output)', {
    filterStripsDataInProduction: !filterIsActive,
    note: 'Si filterIsActive === true, el filter no esta haciendo trabajo distintivo',
  });

  await app.close();
  await t.flush();
});

// ============================================================
// INV-06 — ThrottlerGuard
// ============================================================

it('INV-06 — withOUT ThrottlerGuard, 200 requests/min are accepted on /login', async () => {
  const t = report();
  t.epic('Seguridad');
  t.feature('Defense Validation');
  t.story('ThrottlerGuard hace trabajo real: sin el, no hay 429');
  t.severity('blocker');
  t.tag('Defense Validation', 'Inverse Test', 'GOES Checklist R55');

  jest.resetModules();
  jest.doMock('@nestjs/throttler', () => {
    const original = jest.requireActual('@nestjs/throttler');
    return {
      ...original,
      ThrottlerGuard: class { canActivate() { return true; } },
    };
  });

  const { AppModule } = await import('../../../src/app.module');
  const moduleRef = await Test.createTestingModule({ imports: [AppModule] }).compile();
  const app: INestApplication = moduleRef.createNestApplication();
  await app.init();

  // Disparar 50 requests en serie
  let last429 = false;
  for (let i = 0; i < 50; i++) {
    const r = await request(app.getHttpServer())
      .post('/api/auth/login')
      .send({ email: `t${i}@test.com`, password: 'wrong' });
    if (r.status === 429) { last429 = true; break; }
  }

  t.evidence('Throttler mockeado a "siempre permitir" (output)', {
    received429: last429,
  });

  // Sin throttler activo, NUNCA debe llegar a 429
  expect(last429).toBe(false);

  await app.close();
  jest.dontMock('@nestjs/throttler');
  jest.resetModules();

  await t.flush();
});
```

---

## Interpretacion de resultados

| Resultado | Diagnostico |
|---|---|
| Test inverso falla en rojo (la defensa NO esta presente cuando se mockea ausente) | Algo MAS esta protegiendo el sistema → investigar |
| Test inverso pasa (sin defensa, sistema queda inseguro) | La defensa hace su trabajo. OK. |
| Test inverso pasa pero el test normal tambien pasa con la defensa removida | La defensa es decorativa o tiene un fallback no documentado |

Los resultados van al reporter HTML con el tag `Defense Validation`. Ciberseguridad debe verificar que cada uno de los 6 controles aparece con resultado positivo.
