# Runner setup — detect, don't impose

> Leer este archivo en PASO 0 y PASO 2. El objetivo es que la skill se adapte
> al test runner que el proyecto NestJS **ya tiene configurado** (Jest o Vitest)
> en lugar de imponer uno y crear conflictos.

El reporter HTML es un **único reporter universal** (`reporter/html-reporter.js`):
una sola clase que funciona como reporter de Jest (`onRunComplete`) y de Vitest
(`onInit`/`onFinished`), delegando en el mismo core `renderReport()`. Cada runner
referencia el MISMO archivo; solo cambia cómo lo instancia (Jest pasa
`(globalConfig, options)`, Vitest pasa `(options)` — el constructor lo detecta).
La suite de seguridad SIEMPRE usa un **config aislado y propio**
(`test/security/...`), nunca el config principal del proyecto, así que coexiste
sin tocar los tests del equipo.

---

## PASO 0 — Detectar el runner (antes de instalar NADA)

Recolectar señales en este orden y clasificar:

```
1. package.json
   - dependencies / devDependencies:
       vitest, @vitest/*  → señal VITEST
       jest, ts-jest, @nestjs/testing(+jest), babel-jest → señal JEST
   - scripts: ¿"test" invoca "vitest" o "jest"?
   - clave "jest": {...} en package.json → JEST
   - "type": "module" → proyecto ESM (afecta extensión del config; ver abajo)
   - packageManager / lockfile → npm | pnpm | yarn | bun (afecta scripts)

2. Archivos de config en la raíz (glob):
   - vitest.config.{ts,mts,js,mjs} | vite.config.* con bloque `test:` → VITEST
   - jest.config.{ts,js,mjs,cjs} | jest-e2e.json | test/jest-e2e.json → JEST
   - .mocharc.{js,cjs,json,yml} | "mocha" en deps → MOCHA
   - jasmine.json | @types/jasmine | "jasmine" en deps → JASMINE

3. Tests existentes:
   - imports `from 'vitest'` en **/*.spec.ts → VITEST
   - uso de globals jest (jest.fn, jest.mock) sin import → JEST
```

### Árbol de decisión

| Señales encontradas | Acción |
|---|---|
| Solo Vitest | **Vitest** (`security.config.ts`). No instalar otro runner. |
| Solo Jest | **Jest** (`security.config.ts`). No instalar otro runner. |
| Ambos Jest y Vitest | El del script `test` principal; si es ambiguo, **preguntar**. |
| Otro runner (Mocha, Jasmine, AVA…) | **Avisar** que la suite de seguridad NO corre sobre ellos y que se creará un config **aislado** que no toca su runner. **Preguntar** Jest o Vitest (solo uno) e instalar ese runner solo para la suite de seguridad. |
| Ninguno configurado | **Avisar** que no hay sistema de pruebas y que se instalará uno. **Preguntar** Jest o Vitest (solo uno de esos dos) e instalarlo. |

**Regla de oro:** no instalar Jest en un proyecto Vitest ni viceversa. Si el
runner ya está, no se instala otro. Cuando haya que elegir (otro runner /
ninguno), usar `AskUserQuestion` con **exactamente dos opciones: Jest y Vitest**
— nunca un tercero. La suite de seguridad siempre se añade como config aislado.

### Mensajes al usuario (plantillas)

- **Ninguno detectado:**
  > No detecté un sistema de pruebas en este proyecto. Para generar la suite de
  > seguridad GOES necesito instalar uno. ¿Cuál preferís: **Jest** o **Vitest**?
  > (Se instalará solo ese; ningún otro.)

- **Otro runner detectado (ej. Mocha/Jasmine):**
  > Detecté **<runner>** como runner del proyecto. La suite de seguridad GOES
  > corre sobre Jest o Vitest, así que voy a crear un config **aislado** en
  > `test/security/` que **no toca** tu runner ni tus tests actuales. ¿Sobre cuál
  > lo armo: **Jest** o **Vitest**?

---

## Compatibilidad de versiones (detectar antes de integrar)

La skill mantiene compatibilidad con un rango de versiones. Tras detectar el
runner, verificar su versión (major) contra esta matriz:

| Componente | Rango validado |
|------------|----------------|
| Node | ≥ 18 |
| Jest | 28 – 30 |
| Vitest | 1 – 3 |
| TypeScript | ≥ 4.7 |
| ts-jest | acorde a la versión de Jest |

**Dentro del rango:** continuar sin avisos (ver "reportar solo el trabajo
concreto" en SKILL.md).

**FUERA del rango** (ej. Vitest 4, Jest 27, Node 16):

1. **Notificar** concreto: qué componente, qué versión y por qué no está validada
   (ej. *"Vitest 4 removió `onFinished`; el reporter está validado hasta Vitest 3"*).
2. **Proponer** una versión compatible, que puede vivir **acotada a la suite de
   seguridad** (devDep pinneada en su config aislado o entorno aparte), sin tocar
   lo que el proyecto ya usa.
3. **La decisión final es del usuario.** Preguntar con `AskUserQuestion`:
   - *Ajustar a una versión compatible* (recomendado) — pinneada en la suite.
   - *Crear un entorno/proceso aparte* para la suite de seguridad.
   - *Continuar igual* (best-effort, puede fallar) — o no integrar por ahora.
4. **Nunca** forzar el cambio ni actualizar/degradar dependencias del proyecto
   sin aprobación explícita del usuario.

> No romper proyectos con versiones previas: si no hay compatibilidad, se avisa y
> se ofrece una salida acotada, pero manda el usuario.

---

## Camino A — Proyecto con Vitest

### A.1 Instalar (solo si falta)

Vitest ya está. Normalmente **no se instala nada**. Si el proyecto no compila TS
en tests, Vitest ya lo hace vía Vite/esbuild — no se necesita `ts-jest`.

### A.2 `test/security/security.config.ts`

```typescript
import { defineConfig } from 'vitest/config';
import * as path from 'path';
// @ts-expect-error — reporter universal en CJS, sin tipos. El MISMO archivo que
// usa Jest; aquí se instancia con (options) y Vitest llama onInit/onFinished.
import SecurityHtmlReporter from '../../.claude/skills/goes-security-testing/reporter/html-reporter.js';

const reporterDir = path.resolve(__dirname, '../../.claude/skills/goes-security-testing/reporter');

export default defineConfig({
  test: {
    globals: true,                 // REQUERIDO: metadata.ts usa expect.getState()
    environment: 'node',
    include: ['test/security/**/*.security-html.spec.ts'],
    setupFiles: ['test/security/security.setup.ts'], // alias jest → vi
    reporters: [
      'default',
      new SecurityHtmlReporter({
        outputPath: './reports/security/security-report.html',
        // projectName: 'Mi Proyecto GOES',   // opcional; cae al name de package.json
        // reportTitle: 'Reporte de Seguridad GOES',
      }),
    ],
  },
  resolve: {
    alias: {
      'src': path.resolve(__dirname, '../../src'),
      '@security-reporter': reporterDir,
    },
  },
});
```

Notas:
- **`globals: true` va SOLO en este config de seguridad**, no en el del proyecto.
  metadata.ts (compartido con Jest) lee el nombre/ruta del test vía
  `expect.getState()`, que en Vitest solo existe con globals activos.
- El alias `@security-reporter` permite `import { report } from '@security-reporter/metadata'`.
- Si el proyecto es ESM puro y el config debe ser `.mts`, usar `import` igual;
  el reporter CJS se carga vía interop de Vite sin cambios.

### A.2b `test/security/security.setup.ts` (specs idénticos en ambos runners)

Los patterns de la skill (`references/test-patterns/*`) escriben mocks con
`jest.fn()`. Vitest expone `vi`, no `jest`. Este setup aliasa `jest → vi` para
que **los mismos specs corran sin cambios** en Jest y Vitest:

```typescript
import { vi } from 'vitest';

// vi es API-compatible con jest para fn/spyOn/mock/clearAllMocks/useFakeTimers…
(globalThis as unknown as { jest: typeof vi }).jest = vi;
```

Así un `.security-html.spec.ts` con `jest.fn()` funciona bajo Vitest sin tocarlo.
(Alternativa: al generar specs nuevos para un proyecto Vitest, usar `vi.fn()`
directamente. El shim es lo que mantiene los specs **portables** entre proyectos.)

### A.3 Scripts (ajustar al package manager detectado)

```jsonc
{
  "test:security:html": "vitest run --config test/security/security.config.ts"
}
```

`test:all` (omitir e2e si no existe): `npm test && npm run test:security:html`
(pnpm/yarn: reemplazar `npm run` por `pnpm`/`yarn`).

---

## Camino B — Proyecto con Jest

### B.1 Instalar (solo lo que falte)

```bash
npm install --save-dev jest ts-jest @types/jest
```

Verificar en package.json primero. NO instalar Allure, allure-*, ni
jest-html-reporters. Si Nest ya trae Jest, instalar solo lo ausente.

### B.2 `test/security/security.config.ts`

```typescript
import type { Config } from 'jest';
import * as path from 'path';

const reporterPath = path.resolve(__dirname, '../../.claude/skills/goes-security-testing/reporter');

const config: Config = {
  moduleFileExtensions: ['js', 'json', 'ts'],
  rootDir: '../..',
  testMatch: ['<rootDir>/test/security/**/*.security-html.spec.ts'],
  transform: { '^.+\\.(t|j)s$': 'ts-jest' },
  testEnvironment: 'node',
  moduleNameMapper: {
    '^src/(.*)$': '<rootDir>/src/$1',
    '^@security-reporter/(.*)$': path.join(reporterPath, '$1'),
  },
  reporters: [
    'default',
    [
      path.join(reporterPath, 'html-reporter.js'),
      { outputPath: './reports/security/security-report.html' },
    ],
  ],
};

export default config;
```

### B.3 Scripts

```jsonc
{
  "test:security:html": "jest --config test/security/security.config.ts --verbose"
}
```

---

## Specs: idénticos en ambos runners

Los `.security-html.spec.ts` NO cambian entre Jest y Vitest. Usan
`describe/it/expect` (compatibles) y `import { report } from '@security-reporter/metadata'`.
Un mismo spec corre sin cambios bajo cualquiera de los dos runners.

Única diferencia interna (ya resuelta por el reporter): Vitest une los nombres
de test con `" > "` y Jest con espacio. `SecurityHtmlReporter.makeKey` normaliza
ambos, así que el cruce metadata↔resultados funciona igual en los dos.

---

## Errores comunes a evitar

- ❌ Instalar `jest` + `ts-jest` en un proyecto Vitest → dos runners, conflictos
  de tipos globales (`@types/jest` vs `vitest/globals`), CI más lento.
- ❌ Poner `globals: true` en el `vitest.config.ts` del proyecto → puede romper
  tests del equipo que no esperan globals. Va solo en el config de seguridad.
- ❌ Olvidar `globals: true` en el config de seguridad de Vitest → metadata vacía,
  el reporte sale sin epic/feature/evidencia.
- ❌ Asumir CommonJS en un proyecto `"type": "module"` para los scripts auxiliares
  (doctor, snapshot): usar `tsx`/`ts-node --esm` o `.mts` según corresponda.
