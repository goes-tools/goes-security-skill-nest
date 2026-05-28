# Regression Spec Template — Como convertir cada entry de pentest-history.yaml en un test perpetuo

> **Proposito**: cada hallazgo del equipo de ciberseguridad listado en
> `pentest-history.yaml` se materializa como un test Jest en
> `test/security/regression/<VULN-ID>.regression.spec.ts`. El test corre
> en cada PR. Si el hallazgo vuelve a aparecer, el test se pone rojo y
> bloquea el merge.

## Convencion de nombres

```
test/security/regression/
├── VULN-INT-0002.regression.spec.ts
├── VULN-INT-0004.regression.spec.ts
├── VULN-INT-0009.regression.spec.ts
├── VULN-EXT-0002.regression.spec.ts
├── VULN-EXT-0003.regression.spec.ts
├── VULN-EXT-0005.regression.spec.ts
├── VULN-EXT-0006.regression.spec.ts
├── VULN-EXT-0011.regression.spec.ts
└── VULN-EXT-0013.regression.spec.ts
```

Un archivo = un VULN-ID. Un solo `it()` por archivo. Sin excepciones.

## Estructura obligatoria del spec

```typescript
// test/security/regression/VULN-<ID>.regression.spec.ts
//
// Trazabilidad: este test corresponde al hallazgo <ID> registrado en
// .claude/skills/goes-security-testing/references/pentest-history.yaml
// NO MODIFICAR sin actualizar el YAML primero.

import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication } from '@nestjs/common';
import * as request from 'supertest';
import { report } from '@security-reporter/metadata';
import { AppModule } from '../../../src/app.module';

describe('Regresion VULN-<ID> — <titulo del YAML>', () => {
  let app: INestApplication;

  beforeAll(async () => {
    const moduleRef: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();
    app = moduleRef.createNestApplication();
    await app.init();
  });

  afterAll(async () => {
    await app.close();
  });

  it('PENTEST <ID> — <story breve>', async () => {
    const t = report();
    t.epic(/* segun el R principal */);
    t.feature(/* feature del pattern original */);
    t.story(/* titulo del YAML */);
    t.severity(/* del YAML */);

    // Tags obligatorios
    t.tag('Pentest');
    t.tag('Pentest Regression');
    t.tag('<regression_tag exacto del YAML>');
    // Tags adicionales del YAML
    for (const r of /* covers_R */) t.tag(`GOES Checklist ${r}`);
    for (const o of /* covers_owasp */) t.tag(`OWASP ${o}`);

    t.description(
      `## Hallazgo original\n` +
      `<title del YAML>\n` +
      `Reportado el <found_date> en <pentest_report>.\n` +
      `CVSS <cvss> / CWE <cwe>.\n\n` +
      `## Por que este test existe\n` +
      `Este es un test de regresion perpetuo. Bloquea el merge si el\n` +
      `defensor identificado regresa al codebase. NO eliminar este test\n` +
      `aunque el equipo crea que el bug esta arreglado — es justamente\n` +
      `la prueba de que sigue arreglado.\n\n` +
      `## Referencia\n` +
      `Ver pentest-history.yaml entry "<ID>" + ${'\n'}` +
      `references/test-patterns/<pattern_ref del YAML>.`
    );

    // === Reproduccion del ataque ===
    // <serializar el `reproduce.request` del YAML>
    const res = await request(app.getHttpServer())
      .<method>('<path>')
      .send(<body>)
      .set(<headers>);

    t.evidence('Attack request (input)', {
      method: '<method>',
      path: '<path>',
      body: <body>,
    });
    t.evidence('Server response (output)', {
      status: res.status,
      headers: res.headers,
      body: res.body,
    });

    // === Assertions desde expected_defense del YAML ===
    // Traducir cada clave del expected_defense a un expect():
    //   status_in: [400, 401]        → expect(res.status).toBeOneOf([400, 401])
    //   header_equals: { x: y }      → expect(res.headers[x]).toBe(y)
    //   header_not_contains: {...}   → expect(res.headers[x]).not.toContain(y)
    //   body_not_contains_fields    → expect(keys).not.toContain(field)
    //   body_not_matches_regex      → expect(JSON.stringify(body)).not.toMatch(regex)
    //   body_message_should_mention → expect(body.message.toLowerCase()).toMatch(re)

    await t.flush();
  });
});
```

## Traduccion `expected_defense` → assertions

Esta es la tabla canonica. Toda entrada del YAML usa estas claves y se traduce mecanicamente.

| YAML key | Assertion Jest |
|---|---|
| `status_in: [400, 401]` | `expect([400, 401]).toContain(res.status)` |
| `header_equals: { name: value }` | `expect(res.headers['name']).toBe('value')` |
| `header_not_equals: { name: value }` | `expect(res.headers['name']).not.toBe('value')` |
| `header_not_contains: { name: [a, b] }` | `for (const s of [a,b]) expect(res.headers['name']).not.toContain(s)` |
| `header_must_match_regex: { name: [re] }` | `expect(res.headers['name']).toMatch(new RegExp(re))` |
| `body_keys_subset_of: [a, b, c]` | `for (const k of Object.keys(res.body)) expect([a,b,c]).toContain(k)` |
| `body_not_contains_fields: [a, b]` | `for (const f of [a,b]) expect(Object.keys(res.body)).not.toContain(f)` |
| `body_not_matches_regex: [{pattern, reason}]` | `expect(JSON.stringify(res.body)).not.toMatch(new RegExp(pattern))` |
| `body_message_should_mention: [w1, w2]` | `const m = (res.body.message \|\| '').toLowerCase(); expect([w1,w2].some(w => m.includes(w))).toBe(true)` |
| `body_dui_if_present_must_be_masked: true` + `body_dui_mask_pattern` | `if (res.body.dui) expect(res.body.dui).toMatch(new RegExp(pattern))` |
| `session_must_be_revoked_in_db: true` | requiere acceso al repositorio de sesiones — ver setup `e2e_request_with_clock_skew` |
| `body_not_contains_fields_in_path: ["a.b[*].c"]` | iterar el JSONPath con lodash + assert que cada match no existe |

## Variantes especiales

### `type: e2e_request_with_clock_skew` (ej. VULN-EXT-0005)

Necesita avanzar el reloj o manipular el `lastActivityAt` antes de la request:

```typescript
beforeEach(async () => {
  // Loguear normalmente y capturar el token
  const loginRes = await request(app.getHttpServer())
    .post('/api/auth/login')
    .send({ email: TEST_USER, password: TEST_PASSWORD });
  validToken = loginRes.body.accessToken;

  // Forzar lastActivityAt 31 min en el pasado
  const sessionRepo = app.get(SessionRepository); // adaptar al proyecto
  await sessionRepo.update(
    { token: validToken },
    { lastActivityAt: new Date(Date.now() - 31 * 60 * 1000) },
  );
});
```

### `type: static_analysis` (no usado actualmente)

Para hallazgos que se detectan por inspeccion del source en lugar de E2E
(ej. busqueda de hardcoded secrets). El test usa `fs.readFileSync` + regex.

### `type: mock_behavior`

Para hallazgos que se reproducen al nivel de service (no E2E completo).
Usar mocks de Prisma/TypeORM como en los specs unitarios.

## Cuando un hallazgo se cierra de verdad

1. El equipo arregla el codigo.
2. El test de regresion pasa en verde (porque el defensor funciona).
3. Actualizar el YAML: `status: closed` + agregar `closed_date: YYYY-MM-DD`
   y `closed_by_commit: <hash>`.
4. El spec NO se elimina — sigue corriendo para siempre como garantia.

## Cuando se acepta el riesgo

1. Documentar la decision en un ADR (Architecture Decision Record).
2. YAML: `status: accepted_risk` + `accepted_risk_reason: <texto>` +
   `accepted_risk_ticket: <link>`.
3. El spec se modifica a `t.notApplicable('Riesgo aceptado segun <ticket>')`.
4. El reporter HTML muestra el item como skipped con badge amarillo y
   referencia al ticket.

## Cuando aparece un hallazgo nuevo

1. Agregar la entrada al YAML siguiendo la plantilla al final del archivo.
2. Crear el archivo `test/security/regression/VULN-<ID>.regression.spec.ts`
   siguiendo la estructura de este documento.
3. Si la defensa requiere logica nueva no cubierta por ningun pattern
   existente, crear un nuevo pattern en `test-patterns/NN-...md` y
   referenciarlo en `pattern_ref` del YAML.
4. Correr `npm run test:security:html` localmente para verificar.
5. Commitear ambos archivos + el pattern (si aplica) en el mismo commit.

## Pre-commit gate (recomendado para .husky/pre-commit)

```bash
#!/usr/bin/env bash
# Verificar que toda entrada del YAML tiene su spec correspondiente.
set -e
YAML=".claude/skills/goes-security-testing/references/pentest-history.yaml"
REGRESSION_DIR="test/security/regression"

ids=$(grep -E "^  - id: VULN-" "$YAML" | sed 's/.*id: //')
missing=()
for id in $ids; do
  if [ ! -f "$REGRESSION_DIR/${id}.regression.spec.ts" ]; then
    missing+=("$id")
  fi
done

if [ ${#missing[@]} -gt 0 ]; then
  echo "Hallazgos sin spec de regresion:"
  for id in "${missing[@]}"; do echo "  - $id"; done
  exit 1
fi
```
