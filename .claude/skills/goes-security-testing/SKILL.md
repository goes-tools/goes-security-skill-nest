---
name: goes-security-testing
description: "Tests de seguridad para NestJS con reporte HTML autocontenido (sin Java ni Allure): Checklist de Ciberseguridad GOES (57 items), OWASP Top 10 y OWASP API Security Top 10, evidencia JSON y regresión de pentest. Runner-agnostic: detecta y usa el runner del proyecto (Jest o Vitest) sin imponer ninguno. Activar cuando el usuario pida: tests de seguridad, checklist GOES, pentest tests, security specs, reporte de seguridad HTML, security report, o variantes."
---

# GOES Security Testing — NestJS + (Jest|Vitest) + Custom HTML Reporter

Genera tests de seguridad profesionales para proyectos **NestJS**, con un
**Custom HTML Reporter** (puro Node.js, sin Java ni Allure) que cubre **57 items**
del Checklist GOES, **OWASP Top 10** y **OWASP API Security Top 10**.

El reporter es **runner-agnostic**: el mismo reporte HTML se genera desde Jest o
Vitest. La skill detecta el runner que el proyecto **ya tiene** y se adapta — no
impone uno nuevo ni crea conflictos. El reporte es un HTML autocontenido con
sidebar Epic→Feature→Story, modal de detalle, charts SVG, tema oscuro, búsqueda
y export PDF.

## Carga de contexto bajo demanda (importante para eficiencia)

Este SKILL.md es el índice del flujo. El detalle vive en `references/` y se lee
**solo cuando el paso lo requiere**:

| Necesitás… | Leé |
|------------|-----|
| Configurar runner / detección Jest vs Vitest | `references/runner-setup.md` |
| Decidir Hallazgo vs N/A vs Riesgo Aceptado, schema accepted_risks, 3 capas | `references/decision-rules.md` |
| Checklist completo R3-R63 + OWASP + Guía GOES | `references/goes-checklist.md` |
| CI gate, snapshot, branch protection, CODEOWNERS, SMTP | `references/ci-gate-setup.md` |
| Qué patrón usar para un item (item → archivo) | `references/test-patterns/INDEX.md` |
| Patrón concreto de un tipo de test | `references/test-patterns/NN-*.md` (ver INDEX primero) |
| Regresión de pentest | `references/regression-template.md` + `references/pentest-history.yaml` |

No copies estos archivos al proyecto salvo donde se indique (templates/examples).
El reporter se **referencia** desde `.claude/skills/.../reporter/`, no se duplica.

---

## Permisos: agilizar la ejecución sin decidir por el usuario

Para no pedir confirmación en cada comando, al INICIO ofrecer aplicar el allowlist
**acotado** de `references/examples/settings.skill.json` al `.claude/settings.json`
(equipo) o `.claude/settings.local.json` (personal) del proyecto. Con **una sola
aceptación**, la skill ejecuta sus instalaciones, edits en `test/security/`,
scripts `test:security:*`/`security:doctor` y greps sin prompts por comando. Si el
usuario lo rechaza, la skill funciona igual, solo que pidiendo permiso por comando.

**El allowlist cubre el "cómo" (ejecutar); NO el "qué" (criterio).** Estas
decisiones SIEMPRE se preguntan con `AskUserQuestion`, aunque exista el allowlist
— aceptar la skill NO equivale a decidirlas por el usuario:

- **Instalar Jest o Vitest** cuando el proyecto no tiene runner, o tiene otro
  (Mocha/Jasmine/AVA). Nunca elegir por él.
- **Runner ambiguo** (Jest y Vitest presentes y el script `test` no aclara).
- **Modo audit-only** vs aplicar fixes en `src/`, si el usuario no lo declaró.
- **Riesgos aceptados**: los decide el equipo + review de CODEOWNERS; la IA no
  los inventa para silenciar un rojo.

Regla: permiso de herramienta ≠ decisión de producto. El allowlist quita fricción;
las bifurcaciones de criterio siguen siendo del usuario.

---

## PASO 0 — Detectar el test runner (antes de instalar NADA)

Leer `references/runner-setup.md`. Resumen:

1. Inspeccionar `package.json` (deps, scripts, clave `jest`, `"type":"module"`,
   package manager), configs en raíz (`vitest.config.*`/`vite.config.*` con
   `test:` → Vitest; `jest.config.*`/`jest-e2e.json` → Jest; `.mocharc*` → Mocha;
   `jasmine.json`/`@types/jasmine` → Jasmine) y los imports de los specs existentes.
2. Decidir según lo detectado:
   - **Jest** → `security.config.ts`. No instalar otro runner.
   - **Vitest** → `security.config.ts`. No instalar otro runner.
   - **Ambos Jest y Vitest** → usar el del script `test`; si es ambiguo, **preguntar**.
   - **Otro runner (Mocha, Jasmine, AVA…)** → la suite de seguridad NO corre sobre
     ellos. **Avisar** al usuario: *"Detecté <runner>. La suite de seguridad GOES
     corre sobre Jest o Vitest; voy a crear un config **aislado** que no toca tu
     runner principal ni tus tests."* Luego **preguntar** Jest o Vitest (solo uno)
     e instalar ese runner únicamente para la suite de seguridad.
   - **Ninguno configurado** → **Avisar**: *"No detecté sistema de pruebas. Voy a
     instalar uno para la suite de seguridad."* Luego **preguntar** al usuario que
     elija **Jest o Vitest (solo uno de esos dos)** e instalarlo.
3. **Nunca** instalar Jest en un proyecto Vitest ni viceversa. Cuando haya que
   elegir (otro runner / ninguno), usar `AskUserQuestion` con exactamente dos
   opciones: **Jest** y **Vitest**. No ofrecer un tercero.
4. **Compatibilidad de versiones:** verificar la versión del runner contra la
   matriz soportada (`runner-setup.md`). Si está fuera de rango (ej. Vitest 4,
   Jest 27, Node 16): **notificar**, **proponer** una versión compatible acotada
   a la suite de seguridad, y **preguntar** al usuario (ajustar / entorno aparte /
   continuar igual). Nunca degradar o actualizar deps del proyecto sin su OK.

La suite de seguridad siempre vive en un config **aislado** bajo `test/security/`
(`security.config.ts`, `security.setup.ts`, `security-release.config.ts`) que no
toca el config del proyecto.

---

## PASO 1 — Analizar la superficie de seguridad (EXHAUSTIVO)

NO basta con `.service.ts`. Recorrer y leer lo relevante ANTES de escribir tests:

- **Manifiesto:** `package.json` (framework, ORM, auth: passport/@nestjs/jwt/
  bcrypt/argon2/otplib; hardening: helmet/cors/csurf/throttler/class-validator;
  archivos: multer/file-type/sharp; logging: winston/pino), `.env.example`,
  `tsconfig.json`.
- **Bootstrap global** (`main.ts`/`bootstrap.ts`): `helmet` (R44-R50), `enableCors`
  (R38-R41), `ValidationPipe` global (R5,R11), global guards (R9,R21,R33,R34),
  global filters (R8), `cookieParser` (R42,R51), prefix/versionado. `app.module.ts`:
  `ThrottlerModule`, `JwtModule`, `ConfigModule`.
- **Endpoints:** `src/**/*.controller.ts` (métodos HTTP, rutas, `@UseGuards`,
  `@Roles`, `@Public`, `@Throttle`), `*.dto.ts` (class-validator/transformer),
  `*.entity.ts`/`*.schema.ts` (campos sensibles, índices).
- **Componentes de defensa:** `*.guard.ts`, `*.strategy.ts`, `*.pipe.ts`,
  `*.interceptor.ts`, `*.filter.ts`, `*.middleware.ts`, `*.decorator.ts`.
- **Servicios/helpers:** `*.service.ts`, `*.repository.ts`, `common/`/`utils/`/
  `helpers/` (hashing, comparación timing-safe, sanitización), configs de jwt/cors/throttler.
- **Archivos (si aplica):** multer `diskStorage`/`memoryStorage`,
  `FileInterceptor`, file-type/sharp/clamav, carpetas de uploads, `Content-Disposition`.
- **Tests y config existentes:** `**/*.spec.ts` (NO sobreescribir), config del
  runner (PASO 0). Si hay otro reporter (jest-html-reporters, allure-jest), quitarlo.
- **CI/secretos (ligero):** workflows, `.env` no commiteado, `.gitignore` cubre
  node_modules/dist/coverage/reports/*.env.

**Salida (mental):** mapa de módulos → controllers/servicios/guards/DTOs; qué
items del checklist están implementados (→ testear), cuáles no (→ test rojo =
hallazgo + recomendación en `_recommendations.md`), cuáles no aplican (→
`t.notApplicable` con grep verificable). Ver `references/decision-rules.md`.

---

## PASO 2 — Instalar dependencias (solo lo que falte)

Según el runner detectado (PASO 0). Detalle y configs en
`references/runner-setup.md`. **NUNCA** instalar Allure, allure-commandline,
allure-jest, jest-html-reporters ni Java.

## PASO 3 — Configurar el reporter (sin copiarlo)

El reporter viene bundled en `.claude/skills/goes-security-testing/reporter/`:

- `reporter/html-reporter.js` — **reporter universal**: una sola clase que actúa
  como reporter de Jest (`onRunComplete`) y de Vitest (`onInit`/`onFinished`),
  con un core compartido `renderReport`. Jest y Vitest referencian el MISMO
  archivo; solo difiere cómo lo instancia cada config (ver `runner-setup.md`).
- `reporter/metadata.ts` — collector: `report()` y `AllureCompat`; cada test
  registra epic/feature/story/severity/tags/steps/evidencia, escrito a JSON temporal vía `flush()`.

**NO modificar el reporter.** Está listo. Referenciarlo desde el config; no copiar.
Estructura del proyecto:
```
test/security/
├── *.security-html.spec.ts            ← specs (idénticos en Jest y Vitest)
└── <jest|vitest>-security*.config.ts  ← config aislado (ver runner-setup.md)
```

## PASO 4 — Config del runner + scripts

Tomar el config (Jest o Vitest) y los scripts de `references/runner-setup.md`.
El alias `@security-reporter` permite `import { report } from '@security-reporter/metadata'`.
No sobrescribir scripts existentes (`test`, `test:e2e`); solo agregar
`test:security:html` y `test:all`. Ajustar a npm/pnpm/yarn detectado.

## PASO 5 — Archivos de soporte

`.gitignore`: agregar `/coverage` y `/reports` si faltan. `eslint.config.mjs`:
override para `**/*.spec.ts` y `test/**/*.ts` desactivando reglas `no-unsafe-*` y
`require-await` (ver `references/test-patterns/_setup.md`).

---

## PASO 6 — Generar tests

Por cada servicio/controller, crear un `.security-html.spec.ts`. Los specs son
**idénticos en Jest y Vitest** (usan `describe/it/expect` + `report()`). Para
mocks usar `jest.fn()`: en el camino Vitest, el setup `security.setup.ts`
aliasa `jest → vi` para que el mismo spec corra sin cambios (ver `runner-setup.md`).

### Estructura de cada test (patrón report())

```typescript
import { report } from '@security-reporter/metadata';

it('PENTEST: rechaza payload con SQL injection', async () => {
  const t = report();

  // 1. METADATA (obligatorio)
  t.epic('Seguridad');
  t.feature('Input Validation');
  t.story('Rechazar payload con SQL injection');
  t.severity('blocker');
  t.tag('Pentest', 'OWASP A03', 'GOES Checklist R5');

  // 2. PARAMETERS
  t.parameter('payload', "' OR 1=1 --");

  // 3. STEPS (Preparar/Ejecutar/Verificar) + EVIDENCE (input + output)
  t.step('Preparar: crear payload malicioso');
  const payload = { email: "' OR 1=1 --" };
  t.evidence('Attacker payload (input)', payload);

  t.step('Ejecutar: enviar al servicio');
  const result = await service.validate(payload);

  t.step('Verificar: debe rechazar la inyeccion');
  expect(result.valid).toBe(false);
  t.evidence('Defense response (output)', result);

  await t.flush();   // OBLIGATORIO: sin flush la metadata no llega al reporte
});
```

Migración desde Allure: `import { AllureCompat }` espeja la misma API
(`allure.epic/feature/severity/tag/parameter/step/attachment/notApplicable/flush`).
Ver `references/test-patterns/_allure-customization.md`.

### Reglas de metadata

| Campo | Regla |
|-------|-------|
| `epic` | Área: Seguridad, Autenticacion, Dominio, Configuracion, Auditoria, Infraestructura, Archivos |
| `feature` | Funcionalidad: Timing Attack Prevention, RBAC, Input Validation… |
| `story` | Escenario concreto probado |
| `severity` | blocker / critical / normal / minor (ver `_severity-guide.md`) |
| `tag` | SIEMPRE: tag de categoría (Pentest/CRUD/Auth/Config) + tag normativo (OWASP Axx, GOES Checklist Rxx) |
| `parameter` | Inputs clave: payloads, emails, tokens, configs |
| `step` | Preparar / Ejecutar / Verificar |
| `evidence` | Ver regla crítica abajo |

### Regla crítica: evidence (input + output)

Cada test DEBE registrar **al menos dos** evidencias, en orden: **input**
(payload/parámetros/estado previo) y **output** (respuesta/resultado/estado
final). Labels recomendados por tipo: Pentest `Attacker payload (input)` /
`Defense response (output)`; CRUD `Request body (input)` / `Service response
(output)`; Auth `Credentials (input)` / `Auth result (output)`; Config `Config
snapshot (input)` / `Effective behavior (output)`. Si no hay input real (config
estática), registrar uno descriptivo: `t.evidence('Initial state (input)', {...})`.

### Regla crítica: código comentado = AUSENTE

Todo test que inspeccione source por regex (helmet/CORS/ValidationPipe en
`main.ts`, imports en `*.module.ts`, ausencia de `$queryRawUnsafe`/`eval(`) DEBE
quitar comentarios primero. Helper `stripComments`/`readSrc` en
`references/test-patterns/_static-analysis.md`. Cuando haya metadata en runtime,
preferir `Reflect.getMetadata(...)` sobre la clase.

### Regla crítica: 3 capas + Hallazgo vs N/A vs Riesgo Aceptado

Los controles de defensa exigen 3 capas (config + aplicación + comportamiento) y
NUNCA van en un spec "config-only". Antes de marcar el estado de un item, aplicar
el árbol de decisión. Todo en `references/decision-rules.md` (leer antes de
marcar `notApplicable` o `acceptedRiskIfDeclared`).

---

## PASO 6.5 — Regresión de pentest (OBLIGATORIO)

Leer `references/pentest-history.yaml` (historia de hallazgos del proyecto; si no
existe, copiar el template vacío). Por cada entry con `status: active|closed|
accepted_risk`, generar `test/security/regression/<VULN-ID>.regression.spec.ts`
siguiendo `references/regression-template.md`: un solo `it()`, tag `Pentest
Regression <VULN-ID>`, reproduce el ataque de `reproduce.request`, assertions
desde `expected_defense`. Si la superficie no existe → `t.notApplicable('motivo
con grep')`. **Un archivo = un VULN-ID. Nunca borrar un spec de regresión** (solo
cambia el `status` del YAML). Cada proyecto mantiene su propio YAML; no hay
historia compartida entre proyectos.

## PASO 7 — Snapshot runtime + CI gate (OBLIGATORIO)

Congela los valores aprobados por ciberseguridad y bloquea merges con drift.
Flujo completo (snapshot, spec de validación, workflow, CODEOWNERS, branch
protection, SMTP, flujo rojo→violeta): `references/ci-gate-setup.md`.

## PASO 8 — Verificación estricta `security:doctor` (OBLIGATORIO)

Copiar `references/templates/security-doctor.ts` → `scripts/security-doctor.ts` y
el pre-commit `references/templates/pre-commit-pentest-history.sh` → `.husky/pre-commit`.
Agregar devDeps `js-yaml`, `@types/js-yaml`, `glob` y un ejecutor TS para los
scripts auxiliares (doctor + snapshot). Canónico: **`tsx`** (funciona en CJS y
ESM sin flags) — instalarlo si el proyecto no tiene ya `ts-node`. Script:
`"security:doctor": "tsx scripts/security-doctor.ts"` (si el proyecto ya usa
`ts-node`, reemplazar por `ts-node` / `ts-node --esm` en ESM). Ejecutar:

```bash
npm run test:security:html    # suite completa
npm run security:doctor       # auditoría estructural
```

Ambos deben salir con código 0. **NO emitir "skill aplicada con éxito" si el
doctor falla** — reportar FAILURE y listar las correcciones. NO marcar N/A para
hacer pasar el doctor. NO modificar el doctor para que pase. El doctor corre
también en CI.

---

## Checklist GOES, OWASP y Guía GOES

La fuente de verdad completa (tabla R3-R63 con epic/feature/severity, OWASP Top
10, OWASP API Top 10, y secciones 3-10 de la Guía de Desarrollo Seguro GOES) está
en **`references/goes-checklist.md`**. Cada item DEBE tener ≥1 test con tag
`GOES Checklist Rxx`; cada vuln OWASP ≥1 test con tag `OWASP Axx`/`OWASP APIx`.

Categorías: 1 Contenido Web (R3-R6) · 2 I/O servidor (R8-R11) · 3 Auth/registro
(R13-R35) · 4 Configuración (R37-R55) · 5 Archivos (R57-R63).

---

## NOTAS IMPORTANTES PARA LA IA

1. **Nunca tests vacíos/placeholder** — assertions reales contra el código del proyecto.
2. **Analizar el código real ANTES de escribir** (PASO 1, no solo `.service.ts`).
3. **Detectar y respetar el runner del proyecto** (PASO 0). No imponer Jest ni Vitest.
4. **Item no aplicable** → `t.notApplicable('motivo verificable con grep')`, nunca
   `it.skip` ni omitir. Si la superficie existe pero falta la defensa → HALLAZGO
   (rojo), no N/A. Ver `decision-rules.md`.
5. **Comentarios en código SIN tildes (ASCII)**; strings de metadata (epic,
   feature, story, steps, descriptions) en **español con tildes** (el reporter
   está en español).
6. **Respetar `tsconfig.json`** del proyecto (no cambiar `ignoreDeprecations`, etc.).
7. **Tests independientes** — sin depender de orden ni estado compartido.
8. **Mockear el ORM** (Prisma/TypeORM) — no BD real en unit tests (ver `_orm-mocks.md`).
9. **Cada test termina con `await t.flush()`**.
10. **El reporter es JS puro y universal** — no convertir `html-reporter.js` a TS.
    Una sola clase sirve a Jest y Vitest. Si necesitás tocar la ingesta de un
    runner, hacelo en su hook (`onRunComplete` Jest / `onFinished` Vitest); el
    core `renderReport` es compartido — no lo dupliques.
11. **Specs terminan en `.security-html.spec.ts`** (patrón que buscan ambos configs).
12. **≥1 par input+output en `t.evidence(...)`** por test.
13. **Regresión:** generar specs por cada VULN-ID activo de `pentest-history.yaml`.
14. **Modo audit-only (opt-in):** si el usuario pide *"no modifiques src/"*,
    *"solo generar tests"* o *"audit-only"*, no tocar `src/`/`main.ts`/controllers/
    services/DTOs/guards; dejar tests rojos como hallazgos; solo modificar
    `test/security/`, `package.json`, `eslint.config.mjs`, `.gitignore`, `.claude/`.
15. **Reportar solo el trabajo concreto, no la evolución de la skill.** NUNCA
    informar al usuario que la skill cambió de versión, que "antes se evaluaba
    distinto", que ahora soporta otro runner, ni comparar con corridas previas
    ni narrar migraciones internas. El reporte al usuario se limita a: qué specs
    se generaron, cobertura del checklist (N/57), hallazgos (rojos), N/A
    justificados, riesgos aceptados, y el resultado de `test:security:html` +
    `security:doctor`. Si la skill es más nueva que la última corrida del
    proyecto, adaptarse en silencio: aplicar el comportamiento actual sin avisos
    de cambio.
