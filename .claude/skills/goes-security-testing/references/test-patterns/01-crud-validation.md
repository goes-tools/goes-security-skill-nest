# Pattern 01: CRUD + DTO Validation

> **Migration note (skill v2.0):** these patterns were originally written for
> `allure-js-commons`. They now run against the bundled custom HTML reporter
> via `AllureCompat`, which mirrors the same API. The `_setup.md` snippet
> shows the new top-level imports. Existing `await allure.epic(...)`,
> `await allure.step(...)` etc. work identically. Two extras:
>
> - Each `it(...)` block must end with `await allure.flush();` so the metadata
>   reaches the reporter.
> - `attach(name, data)` is now async — call it as `await attach(...)`.

**Covers:** R11 (DTO Validation / Input Constraints — incluye `forbidNonWhitelisted: true` para bloquear campos extras / mass assignment)

```typescript
it('should create a record successfully with valid data', async () => {
  const allure = new AllureCompat();
  const attach = attachFor(allure);
  await allure.epic('Domain');
  await allure.feature('Record Management');
  await allure.story('Create new record with valid DTO');
  await allure.severity('blocker');
  await allure.tag('CRUD');
  await allure.tag('Happy Path');
  await allure.tag('GOES Checklist R11');
  await allure.description(
    '## Objective\n' +
    'Verify that the service creates a record correctly when receiving valid data.\n\n' +
    '## Expected behavior\n' +
    '- Returns the created object with a generated ID\n' +
    '- Fields match the submitted DTO',
  );

  const dto = { name: 'Example', description: 'Test' };
  await allure.parameter('name', dto.name);

  await allure.step('Prepare: configure DB mock for insert', async () => {
    prisma.record.create.mockResolvedValue({ id: 1, ...dto });
  });

  await attach('DTO sent (input)', dto);

  const result = await allure.step('Execute: service.create(dto)', async () => {
    return service.create(dto);
  });

  await allure.step('Verify: returns object with ID', async () => {
    expect(result).toHaveProperty('id');
    expect(result.name).toBe(dto.name);
  });

  await attach('Created record (output)', result);
  await allure.flush();
});

it('should reject invalid DTO with missing required fields', async () => {
  const allure = new AllureCompat();
  const attach = attachFor(allure);
  await allure.epic('Domain');
  await allure.feature('Input Validation');
  await allure.story('Reject DTO missing required fields');
  await allure.severity('critical');
  await allure.tag('Validation');
  await allure.tag('GOES Checklist R11');
  await allure.description(
    '## Objective\n' +
    'Verify that the service rejects DTOs that are missing required fields,\n' +
    'have wrong data types, or exceed field length limits.\n\n' +
    '## Reference\n' +
    'GOES Guide Section 3 — Input Validation',
  );

  const invalidDtos = [
    { dto: {}, reason: 'empty object' },
    { dto: { name: '' }, reason: 'empty name' },
    { dto: { name: 'a'.repeat(256) }, reason: 'name exceeds max length' },
    { dto: { name: 123 }, reason: 'wrong data type' },
  ];

  for (const { dto, reason } of invalidDtos) {
    await allure.step(`Execute: attempt create with ${reason}`, async () => {
      await expect(service.create(dto as any)).rejects.toThrow();
    });
  }

  await attach('Invalid DTOs tested (output)', { total: invalidDtos.length, allRejected: true });
  await allure.flush();
});

it('PENTEST: should reject DTO with extra (non-whitelisted) fields', async () => {
  const allure = new AllureCompat();
  const attach = attachFor(allure);
  await allure.epic('Domain');
  await allure.feature('Input Validation');
  await allure.story('forbidNonWhitelisted blocks mass-assignment / parameter pollution');
  await allure.severity('blocker');
  await allure.tag('Pentest');
  await allure.tag('OWASP A03');
  await allure.tag('OWASP API3');
  await allure.tag('GOES Checklist R11');
  await allure.description(
    '## Vulnerability Prevented\n' +
    '**Mass Assignment / Property Pollution** — Attacker sends extra fields\n' +
    '(`isAdmin: true`, `role: "ADMIN"`, `password_hash`) on top of legitimate\n' +
    'DTO fields and the server persists them.\n\n' +
    '## Defense Implemented\n' +
    'Global `ValidationPipe` configured with `whitelist: true` AND\n' +
    '`forbidNonWhitelisted: true`. Any field not declared in the DTO\n' +
    'rejects the entire request with 400.\n\n' +
    '## Reference\n' +
    'GOES Checklist R11 + xlsx note: "si vienen campos extras bloquear la peticion"',
  );

  const maliciousDtos = [
    { dto: { name: 'ok', isAdmin: true }, extra: 'isAdmin' },
    { dto: { name: 'ok', role: 'ADMIN' }, extra: 'role' },
    { dto: { name: 'ok', password_hash: '$2b$12$abc' }, extra: 'password_hash' },
    { dto: { name: 'ok', __proto__: { polluted: true } }, extra: '__proto__' },
    { dto: { name: 'ok', createdAt: '1970-01-01' }, extra: 'createdAt (timestamp override)' },
  ];

  await attach('Attacker payloads (input)', maliciousDtos);

  for (const { dto, extra } of maliciousDtos) {
    await allure.step(`Test: reject DTO with extra field "${extra}"`, async () => {
      await expect(service.create(dto as any)).rejects.toThrow();
    });
  }

  await attach('Defense response (output)', {
    total: maliciousDtos.length,
    allRejected: true,
    pipeConfig: 'whitelist: true, forbidNonWhitelisted: true',
  });
  await allure.flush();
});

it('R11 config — ValidationPipe MUST have whitelist + forbidNonWhitelisted', async () => {
  const allure = new AllureCompat();
  const attach = attachFor(allure);
  await allure.epic('Configuracion');
  await allure.feature('Input Validation');
  await allure.story('main.ts registra ValidationPipe con flags estrictas');
  await allure.severity('blocker');
  await allure.tag('Config');
  await allure.tag('GOES Checklist R11');

  // Inspeccion estatica de main.ts (comentado = ausente)
  const fs = require('fs');
  const path = require('path');
  const stripComments = (src: string): string =>
    src.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:])\/\/.*$/gm, '$1');
  const mainSrc = stripComments(
    fs.readFileSync(path.resolve(__dirname, '../../src/main.ts'), 'utf-8'),
  );

  await attach('main.ts snippet (input)', {
    hasGlobalPipes: /useGlobalPipes\s*\(/.test(mainSrc),
    hasValidationPipe: /new\s+ValidationPipe\s*\(/.test(mainSrc),
  });

  expect(mainSrc).toMatch(/new\s+ValidationPipe\s*\(/);
  expect(mainSrc).toMatch(/whitelist\s*:\s*true/);
  expect(mainSrc).toMatch(/forbidNonWhitelisted\s*:\s*true/);
  expect(mainSrc).toMatch(/transform\s*:\s*true/);

  await attach('ValidationPipe config (output)', {
    whitelist: true,
    forbidNonWhitelisted: true,
    transform: true,
  });
  await allure.flush();
});
```
