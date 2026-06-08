# Decision rules — Hallazgo vs N/A vs Riesgo Aceptado

> Leer antes de marcar el estado de cualquier item del checklist. Confundir
> estos 3 mecanismos produce falsos positivos en pentest y falsos negativos
> en la skill.

## Los 3 mecanismos

| Caso | Cuándo | Cómo marcarlo | En el reporte |
|------|--------|---------------|---------------|
| **HALLAZGO** | La superficie existe Y la defensa esperada NO existe (o está mal). Bug real. | El test FALLA con sus assertions. NUNCA `notApplicable` ni `acceptedRiskIfDeclared`. | ✗ rojo |
| **N/A — sin superficie** | El proyecto NO tiene la feature que el item evalúa (ej. R57-R63 file upload en backend sin uploads). | `t.notApplicable('motivo + comando grep verificable')` | ⊘ amarillo, badge "N/A" |
| **RIESGO ACEPTADO** | La feature EXISTE pero el contexto (interno/VPN/audiencia limitada) cambia el perfil y el equipo decide no implementar la defensa. | Declarar en `security.snapshot.json → accepted_risks[]`. El test llama `await t.acceptedRiskIfDeclared('R6')`; si está declarado retorna true → skipped violeta. | 🟪 violeta, badge "RIESGO ACEPTADO" + callout |

## Árbol de decisión (obligatorio antes de escribir cada test)

```
1. ¿El proyecto recibe/maneja este input o feature?
   (uploads, cookies, JWT, sesiones, MFA, SSRF egress, archivos…)
   │
   ├── NO existe la superficie → t.notApplicable(motivo verificable con grep)
   │
   └── SÍ existe la superficie
       │
       2. ¿El control de defensa específico está implementado y correcto?
          ├── SÍ, bien      → test pasa (verde ✓)
          ├── SÍ, pero mal  → test FALLA (rojo ✗) — HALLAZGO
          └── NO existe     → test FALLA (rojo ✗) — HALLAZGO
       │
       NUNCA marcar N/A si la superficie existe. Si el negocio acepta el
       riesgo, va a accepted_risks (violeta), no a N/A.
```

Ejemplo canónico (R57 Magic Bytes):

| Estado del proyecto | Resultado | Justificación |
|---|---|---|
| No usa multer ni FileInterceptor | ⊘ N/A | Superficie ausente |
| Usa multer, valida magic bytes con `file-type` | ✓ verde | Control implementado |
| Usa multer, NO valida magic bytes | ✗ ROJO | Hallazgo — defensa ausente |
| Usa multer, valida solo extensión (no magic) | ✗ ROJO | Hallazgo — defensa incompleta |

## Items que PUEDEN ser N/A (lista cerrada — verificar con grep en `src/`)

| Item | N/A solo si… | grep |
|------|--------------|------|
| R28 Account Recovery | Auth externa (SSO/OAuth), sin flujo propio | `grep -rE "forgot.?password\|reset.?password\|recovery" src/` → 0 |
| R29 Remember Me | No hay "recordarme" | `grep -rE "rememberMe\|remember.?me\|persistent.?login" src/` → 0 |
| R32 Token Rotation | Solo access tokens cortos, sin refresh | `grep -rE "refreshToken\|refresh.?token\|/refresh" src/` → 0 |
| R35 Session Inactivity | 100% stateless | `grep -rE "express-session\|sessionTimeout" src/` → 0 |
| R57-R63 File Upload | No acepta uploads | `grep -rE "multer\|FileInterceptor\|UploadedFile\|multipart/form-data" src/` → 0 |
| R6 Robots/Sitemap | No sirve contenido público | sin `@Public()` ni rutas a no-autenticados |

**Todos los demás items NUNCA son N/A.** Si un item universal (R3-R5, R8-R11,
R13-R55…) no está implementado → HALLAZGO (rojo), no N/A. Por defecto **ningún
item se marca N/A** sin verificación grep explícita.

Ejemplo correcto:
```typescript
t.notApplicable(
  'Backend no acepta file uploads. Verificado: ' +
  'grep -rE "multer|FileInterceptor|UploadedFile" src/ → 0 resultados; ' +
  'package.json sin multer.'
);
```
Ejemplo prohibido (esto es un HALLAZGO, no N/A):
```typescript
// ❌ Marca N/A porque "el código no implementa magic bytes" pero SÍ usa multer
t.notApplicable('Project does not validate magic bytes');
```

Reglas N/A:
- NO usar `it.skip(...)` — pierde toda la metadata, el item queda invisible.
- NO omitir el test — el checklist exige trazabilidad de los 57 items.
- La razón debe referenciar lo que SE BUSCÓ y NO se encontró.
- En `AllureCompat`: `allure.notApplicable('reason')`.

## Schema de `accepted_risks` en `security.snapshot.json`

```json
{
  "project_profile": {
    "type": "internal_admin",
    "exposure": "internal",
    "audience": "GOES staff (~50 usuarios)",
    "data_classification": "datos personales de ciudadanos"
  },
  "accepted_risks": [
    {
      "rid": "R6",
      "title": "robots.txt + sitemap.xml",
      "reason": "Panel admin no expuesto a Internet. Solo vía VPN. No indexable.",
      "approved_by": "@gerardo-amaya-dev",
      "approved_at": "2026-06-04",
      "review_at": "2026-12-04",
      "compensating_controls": ["VPN obligatorio", "Auth Keycloak con MFA", "IP allowlist a nivel LB"]
    }
  ]
}
```

Reglas:
1. Cada entrada requiere `rid`, `reason` (≥20 chars), `approved_by` (handle GitHub),
   `approved_at`, `review_at`. El doctor falla si falta alguno.
2. `review_at` debe ser fecha futura. Si vence, el doctor falla.
3. 30 días antes de vencer, el doctor emite warning.
4. Modificar `accepted_risks` requiere PR + review de CODEOWNERS (file protegido).
5. Al menos 1 `compensating_control` por entrada.

Uso en el test:
```typescript
it('R6 — robots.txt accesible o riesgo aceptado', async () => {
  const t = report();
  t.epic('Configuracion').feature('Public Site Config').story('robots.txt');
  t.tag('GOES Checklist R6');

  if (await t.acceptedRiskIfDeclared('R6')) { await t.flush(); return; }

  const res = await request(app.getHttpServer()).get('/robots.txt').expect(200);
  expect(res.text).toContain('User-agent');
  await t.flush();
});
```

## Cobertura de 3 capas para controles de defensa

Un test que verifica **solo** configuración (env vars, imports) NO es evidencia
de cumplimiento: si un dev comenta `@Throttle` o `@UseGuards(RolesGuard)`, el
test sigue verde y el control queda desactivado. Para items de defensa (rate
limiting, RBAC, auth guards, validation pipes, helmet, CORS, throttling, brute
force, IDOR) el spec DEBE incluir las 3 capas:

| Capa | Verifica | Cómo |
|------|----------|------|
| 1. Configuración | env vars, imports de módulo, defaults correctos | leer `envConfig()`, `app.module.ts` |
| 2. Aplicación | el decorator/guard está puesto en cada endpoint | `Reflect.getMetadata(...)` sobre el método del controller |
| 3. Comportamiento | cuando se dispara, rechaza efectivamente | mock que devuelve `false`/`429`; o E2E supertest |

Si solo cubrís la capa 1, el test es inválido y el item queda como falso
positivo. Documentar en el evidence si por contexto no podés cubrir capa 2/3.

Items afectados (lista canónica): R9/R24/R34 (RBAC), R21/R33 (forced browsing /
token per request), R27 (brute force), R5/R11 (DTO validation), R19 (JWT claims),
R37 (ORM), R38-R41 (CORS), R44-R50 (headers), R55 (rate limit), R57-R63 (file
upload), R3/R4/R11/R20 (response DTO sanitization, pattern 28), R11/R55 (export
controls, pattern 29), R14/R55 (captcha, pattern 30).
