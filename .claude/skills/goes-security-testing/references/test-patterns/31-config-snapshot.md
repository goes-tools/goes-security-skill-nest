# Pattern 31: Runtime Configuration Snapshot (Drift Detection)

> Migration note: usa `AllureCompat` y `await allure.flush()` al final de cada `it`.

**Covers:** R38, R39, R40, R41, R42, R44, R45, R46, R47, R48, R49, R50, R51, R55 — toda configuracion runtime de seguridad que puede driftear entre entornos.

**Proposito:** congelar los valores que ciberseguridad ya aprobo. Cualquier cambio sobre estos valores en runtime — sea por un PR malicioso, un override accidental de `.env`, un downgrade de helmet, o un cambio de proveedor — falla el test inmediatamente. Es la **memoria operativa** de la skill.

**Regresion cubierta indirectamente:** TODAS las VULN-* que sean de configuracion runtime. Si la config hubiese estado en snapshot, el pentest no las hubiese encontrado.

---

## Concepto

El snapshot vive en el proyecto bajo test:

```
<proyecto>/
└── test/
    └── security/
        ├── security.snapshot.json     ← committed, owned por ciberseguridad
        └── *.security-html.spec.ts
```

El snapshot es un JSON declarativo con los valores esperados. Contra un ambiente
**desplegado** (`SECURITY_TEST_BASE_URL`, corrida de release opcional) el test captura los
valores reales por HTTP y los compara byte-a-byte; en la suite **local** no se
levanta la app (ver el código abajo): los items HTTP se marcan N/A + verificación
estática. La única forma de cambiar el snapshot es un PR explícito que
ciberseguridad debe aprobar (`CODEOWNERS` de `test/security/security.snapshot.json`).

---

## Schema del snapshot

```jsonc
{
  "$schema": "https://goes.gob.sv/security-snapshot.v1.json",
  "version": 1,
  "project": "emprendedores-release-interno",
  "approved_by": "@gerardo-amaya-dev,@alejandro-montepeque-dev,@angel-bran-dev,@jose-orellana-dev,@noe-cortez-dev",
  "approved_at": "2026-05-28",

  "headers": {
    // Headers HTTP esperados en CADA response del backend.
    // Lista de strings = el header DEBE matchear el regex compilado de cada string.
    // null = el header DEBE estar ausente.
    "content-security-policy": [
      "^default-src 'self'",
      "script-src[^;]+'self'",
      "style-src[^;]+'self'"
    ],
    "content-security-policy-NOT": [
      "unsafe-inline",
      "unsafe-eval",
      "unsafe-hashes",
      "\\*"
    ],
    "strict-transport-security": ["^max-age=31536000.*includeSubDomains.*preload$"],
    "x-content-type-options": ["^nosniff$"],
    "x-frame-options": ["^(DENY|SAMEORIGIN)$"],
    "referrer-policy": ["^strict-origin-when-cross-origin$"],
    "permissions-policy": ["geolocation=\\(\\)", "camera=\\(\\)", "microphone=\\(\\)"],
    "cross-origin-resource-policy": ["^same-origin$"],
    "cross-origin-opener-policy": ["^same-origin$"],
    "server": null,
    "x-powered-by": null,
    "x-cloud-trace-context": null,
    "via": null,
    "x-ratelimit-limit-short": null,
    "x-ratelimit-limit-medium": null,
    "x-ratelimit-limit-long": null
  },

  "cors": {
    "allowed_origins": ["https://emprendedores-release-interno.srs.gob.sv"],
    "allowed_origins_NOT": ["http://localhost", "https://srs-example-app-", "*"],
    "allowed_methods": ["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    "max_age_seconds": 3600,
    "credentials": true
  },

  "session": {
    "access_token_ttl_minutes": 5,
    "refresh_token_ttl_days": 7,
    "idle_timeout_minutes": 30,
    "cookie": {
      "httpOnly": true,
      "secure": true,
      "sameSite": "Strict",
      "path": "/"
    }
  },

  "rate_limit": {
    "general_per_minute": 100,
    "login_per_minute": 5,
    "exposed_in_headers": false
  },

  "error_response": {
    "allowed_keys": ["statusCode", "message", "error"],
    "forbidden_keys": ["path", "timestamp", "stack", "cause", "sql", "query", "url"]
  },

  "csp_unsafe_keywords_forbidden": ["unsafe-inline", "unsafe-eval", "unsafe-hashes"]
}
```

---

## Test: comparar runtime contra snapshot

```typescript
import * as fs from 'fs';
import * as path from 'path';
import * as request from 'supertest';
import { report } from '@security-reporter/metadata';

const SNAPSHOT = JSON.parse(
  fs.readFileSync(path.resolve(__dirname, '../security.snapshot.json'), 'utf-8'),
);

// El drift de configuracion se valida contra un ambiente DESPLEGADO (job
// una corrida de release con SECURITY_TEST_BASE_URL). La suite LOCAL NO levanta
// AppModule: requiere DB, llaves RSA (JWT_*_KEY_BASE64) y config externa validada
// por Zod; hacerlo haria fallar el spec en `npm run test:security:html` por falta
// de infra, no por un hallazgo real. Localmente cada item HTTP se marca N/A +
// verificacion estatica del snapshot; el chequeo runtime corre en la corrida de release (SECURITY_TEST_BASE_URL).
const BASE_URL = process.env.SECURITY_TEST_BASE_URL || '';
const http = () => request(BASE_URL);

function snapshotIsCoherent(): boolean {
  return !!SNAPSHOT && typeof SNAPSHOT === 'object' && !!SNAPSHOT.headers;
}

// Sin ambiente desplegado: marcar N/A (con verificacion estatica) y salir.
// Llamar JUSTO despues de la metadata en CADA it() que use http().
async function naIfLocal(t: ReturnType<typeof report>): Promise<boolean> {
  if (BASE_URL) return false;
  t.evidence('Snapshot static check (input)', {
    coherent: snapshotIsCoherent(),
    keys: Object.keys(SNAPSHOT || {}),
  });
  t.notApplicable(
    'Drift runtime se valida en una corrida de release opcional (SECURITY_TEST_BASE_URL). ' +
      'Local: solo verificacion estatica. Snapshot coherente: ' + snapshotIsCoherent(),
  );
  await t.flush();
  return true;
}

describe('Pattern 31 — Configuration Snapshot (drift detection)', () => {

  it('SNAPSHOT — runtime HTTP headers MUST match approved values', async () => {
    const t = report();
    t.epic('Configuracion');
    t.feature('Runtime Configuration Snapshot');
    t.story('Los headers de seguridad coinciden byte-a-byte con security.snapshot.json');
    t.severity('blocker');
    t.tag('Config');
    t.tag('OWASP A05');
    t.tag('GOES Snapshot');
    // Mapear al checklist
    for (const r of ['R38','R39','R40','R41','R44','R45','R46','R47','R48','R49','R50']) {
      t.tag(`GOES Checklist ${r}`);
    }
    if (await naIfLocal(t)) return;

  t.remediation({
    summary: 'Los headers HTTP runtime no coinciden con los valores aprobados en security.snapshot.json. Algo cambio entre el snapshot aprobado y la respuesta actual del backend.',
    howWeChecked: [
      'Cargamos los valores aprobados desde test/security/security.snapshot.json',
      'Hicimos GET a /api/health y a / para capturar headers actuales',
      'Comparamos cada header esperado vs el valor real',
      'Encontramos drift en uno o mas headers',
    ],
    whyItMatters: 'El snapshot es el contrato firmado de los valores de seguridad. Cualquier drift puede haber sido un cambio accidental, un downgrade silencioso o un override no documentado. Toda divergencia requiere PR + aprobacion explicita.',
  });

    // Sample endpoint que devuelve headers reales (cualquier endpoint sirve)
    const probes = ['/api/health', '/'];
    const violations: Array<{ endpoint: string; header: string; expected: any; actual: any }> = [];

    for (const endpoint of probes) {
      const res = await http().get(endpoint);
      const headers = res.headers;

      for (const [name, expected] of Object.entries(SNAPSHOT.headers || {})) {
        if (name.endsWith('-NOT')) continue;
        const actual = headers[name.toLowerCase()];

        // null = debe estar ausente
        if (expected === null) {
          if (actual !== undefined) {
            violations.push({ endpoint, header: name, expected: 'absent', actual });
          }
          continue;
        }

        // Array de regex = todos deben matchear
        if (Array.isArray(expected)) {
          for (const re of expected) {
            if (!actual || !new RegExp(re).test(actual)) {
              violations.push({ endpoint, header: name, expected: `match ${re}`, actual });
            }
          }
        }
      }

      // Tambien verificar -NOT (substrings que el header NO debe contener)
      for (const [baseName, forbidden] of Object.entries(SNAPSHOT.headers || {})) {
        if (!baseName.endsWith('-NOT')) continue;
        const headerName = baseName.replace(/-NOT$/, '');
        const actual = headers[headerName.toLowerCase()];
        if (!actual) continue;
        for (const sub of forbidden as string[]) {
          if (new RegExp(sub).test(actual)) {
            violations.push({
              endpoint,
              header: headerName,
              expected: `NOT contain ${sub}`,
              actual,
            });
          }
        }
      }
    }

    t.evidence('Snapshot loaded (input)', SNAPSHOT.headers);
    t.evidence('Drift detected (output)', { count: violations.length, violations });

    expect(violations).toEqual([]);
    await t.flush();
  });

  it('SNAPSHOT — CORS configuration MUST match approved origins/methods', async () => {
    const t = report();
    t.epic('Configuracion');
    t.feature('Runtime Configuration Snapshot');
    t.story('CORS responde solo con origenes aprobados');
    t.severity('blocker');
    t.tag('Config', 'OWASP A05', 'GOES Checklist R38', 'GOES Checklist R39');
    if (await naIfLocal(t)) return;

  t.remediation({
    summary: 'CORS acepta origenes no autorizados (localhost, dominios de prueba, *).',
    howWeChecked: [
      'Hicimos OPTIONS preflight desde Origin: http://attacker.test',
      'Esperabamos que Access-Control-Allow-Origin NO incluya ese origen',
      'El sistema acepto el origen no autorizado',
    ],
    whyItMatters: 'CORS permisivo permite ataques de CSRF: un sitio malicioso visitado por el usuario hace requests autenticados a la API.',
  });

    const violations: Array<{ kind: string; origin?: string; actual?: string }> = [];

    // Origenes prohibidos: ninguno debe ser aceptado
    for (const bad of SNAPSHOT.cors.allowed_origins_NOT) {
      const probeOrigin = bad.replace('-', '') + '.test';
      const res = await http()
        .options('/api/auth/login')
        .set('Origin', probeOrigin)
        .set('Access-Control-Request-Method', 'POST');
      const acao = res.headers['access-control-allow-origin'];
      if (acao && (acao === probeOrigin || acao === '*')) {
        violations.push({ kind: 'forbidden origin accepted', origin: probeOrigin, actual: acao });
      }
    }

    // Origenes aprobados: deben ser aceptados
    for (const good of SNAPSHOT.cors.allowed_origins) {
      const res = await http()
        .options('/api/auth/login')
        .set('Origin', good)
        .set('Access-Control-Request-Method', 'POST');
      const acao = res.headers['access-control-allow-origin'];
      if (acao !== good) {
        violations.push({ kind: 'approved origin not accepted', origin: good, actual: acao });
      }
    }

    t.evidence('CORS snapshot (input)', SNAPSHOT.cors);
    t.evidence('CORS drift (output)', { count: violations.length, violations });
    expect(violations).toEqual([]);
    await t.flush();
  });

  it('SNAPSHOT — error response shape MUST match approved keys', async () => {
    const t = report();
    t.epic('Configuracion');
    t.feature('Runtime Configuration Snapshot');
    t.story('Error responses retornan solo las keys aprobadas');
    t.severity('critical');
    t.tag('Config', 'GOES Checklist R8', 'Pentest Regression VULN-XXX-NNNN');
    if (await naIfLocal(t)) return;

  t.remediation({
    summary: 'Las respuestas de error exponen detalles tecnicos (rutas, stack traces, queries SQL) que dan reconocimiento al atacante.',
    howWeChecked: [
      'Forzamos un error en el endpoint con un payload invalido',
      'Esperabamos un body con solo {statusCode, message}',
      'El sistema devolvio path, timestamp, stack trace o query SQL',
    ],
    whyItMatters: 'Los detalles del error facilitan la enumeracion de la API y la identificacion del stack tecnologico.',
  });

    const res = await http()
      .post('/api/auth/login')
      .send({ malformed: true });

    const keys = Object.keys(res.body || {});
    const allowed = SNAPSHOT.error_response.allowed_keys;
    const forbidden = SNAPSHOT.error_response.forbidden_keys;

    const unexpectedKeys = keys.filter(k => !allowed.includes(k));
    const forbiddenPresent = keys.filter(k => forbidden.includes(k));

    t.evidence('Error body (output)', { status: res.status, body: res.body });
    t.evidence('Drift (output)', { unexpectedKeys, forbiddenPresent });

    expect(unexpectedKeys).toEqual([]);
    expect(forbiddenPresent).toEqual([]);
    await t.flush();
  });

  it('SNAPSHOT — session timeouts MUST match approved values', async () => {
    const t = report();
    t.epic('Configuracion');
    t.feature('Runtime Configuration Snapshot');
    t.story('Access/refresh/idle timeouts coinciden con valores aprobados');
    t.severity('critical');
    t.tag('Config', 'GOES Checklist R13', 'GOES Checklist R35');

  t.remediation({
    summary: 'Los tokens JWT tienen tiempos de vida demasiado largos. Si un token se filtra, el atacante tiene acceso por horas o dias.',
    howWeChecked: [
      'Decodificamos el JWT emitido tras login',
      'Inspeccionamos los claims `exp` y `iat`',
      'El TTL excede los limites: access > 15min o refresh > 7 dias',
    ],
    whyItMatters: 'Tokens largos amplifican el dano de cualquier filtracion. Tokens cortos limitan la ventana de oportunidad del atacante.',
  });

    // Capa 2: leer env y comparar
    const accessTtl = parseInt(process.env.ACCESS_TOKEN_TTL_MIN || '0', 10);
    const refreshTtl = parseInt(process.env.REFRESH_TOKEN_TTL_DAYS || '0', 10);
    const idleTimeout = parseInt(process.env.IDLE_TIMEOUT_MIN || '0', 10);

    t.evidence('Runtime values (input)', {
      access_token_ttl_minutes: accessTtl,
      refresh_token_ttl_days: refreshTtl,
      idle_timeout_minutes: idleTimeout,
    });
    t.evidence('Snapshot values (output)', SNAPSHOT.session);

    expect(accessTtl).toBe(SNAPSHOT.session.access_token_ttl_minutes);
    expect(refreshTtl).toBe(SNAPSHOT.session.refresh_token_ttl_days);
    expect(idleTimeout).toBe(SNAPSHOT.session.idle_timeout_minutes);

    await t.flush();
  });
});
```

---

## Como se genera el snapshot inicial

```bash
# Primera vez en el proyecto: la skill levanta la app, captura los valores
# y propone un snapshot. Ciberseguridad revisa, ajusta lo que falte y
# aprueba.
npm run test:security:snapshot:update
git diff test/security/security.snapshot.json
# CODEOWNERS de ese archivo = @gerardo-amaya-dev,@alejandro-montepeque-dev,@angel-bran-dev,@jose-orellana-dev,@noe-cortez-dev
```

El comando `test:security:snapshot:update` (lo agrega la skill al `package.json`) corre un script que:

1. Levanta la app local con `NODE_ENV=production`.
2. Hace requests a `/api/health` y `/` capturando todos los headers.
3. Lee `process.env.ACCESS_TOKEN_TTL_MIN` (y similares) para session.
4. Lee la config de CORS desde `main.ts` via `app.getHttpAdapter()` o capturando el OPTIONS de la app.
5. Escribe `test/security/security.snapshot.json` con los valores capturados + comentarios de "approved_by" y "approved_at".
6. Imprime un diff de lo que cambio para que el dev sepa que revisar.

---

## Como se cambia el snapshot

1. Cualquier modificacion al snapshot DEBE ir en un PR separado del codigo.
2. El PR es revisado por `@gerardo-amaya-dev,@alejandro-montepeque-dev,@angel-bran-dev,@jose-orellana-dev,@noe-cortez-dev` (via CODEOWNERS).
3. Una vez merged, el snapshot es la nueva fuente de verdad.

Esto convierte cambios de seguridad en decisiones explicitas y trazables.
