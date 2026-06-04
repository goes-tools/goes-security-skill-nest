# CI gate + snapshot + branch protection (PASO 7 detallado)

> Esta capa congela los valores que ciberseguridad aprobó y bloquea el merge si
> driftean. Leer al ejecutar PASO 7.

## 7.1 Snapshot inicial

1. Copiar `references/examples/security.snapshot.example.json` →
   `test/security/security.snapshot.json`.
2. Reemplazar `REPLACE_WITH_PROJECT_NAME` y `REPLACE_WITH_PROD_DOMAIN`.
3. Ejecutar `scripts/security-snapshot-update.ts` (copia de
   `references/templates/snapshot-update.ts`): levanta la app y captura headers
   reales. Cualquier campo `MISSING` es un **hallazgo** a arreglar antes de
   commitear el snapshot.
4. Pedir review a ciberseguridad. Mergear solo con su aprobación.

> Nota ESM: si el proyecto es `"type": "module"`, correr los scripts auxiliares
> con `tsx` o `ts-node --esm` (no `ts-node` plano).

## 7.2 Spec que valida contra el snapshot

Copiar `references/test-patterns/31-config-snapshot.md` →
`test/security/snapshot.security-html.spec.ts`. Reporta drift contra el snapshot
aprobado en cada PR.

## 7.3 Configurar el gate

1. `references/templates/security-gate.yml` → `.github/workflows/security-gate.yml`.
2. `references/templates/jest-security-release.config.ts` →
   `test/security/jest-security-release.config.ts` (camino Vitest: análogo con
   `vitest-security-release.config.ts` apuntando al reporter Vitest).
3. Scripts:
   ```jsonc
   {
     "test:security:html": "<runner> ...",   // ver references/runner-setup.md
     "test:security:release": "<runner> --config test/security/...-release.config.ts",
     "test:security:snapshot:update": "tsx scripts/security-snapshot-update.ts"
   }
   ```
4. Mergear `references/examples/CODEOWNERS.example` en `.github/CODEOWNERS`.

### Variables y secrets (una vez por repo)

**Variables:** `RELEASE_BASE_URL` (URL del ambiente release/uat/main).

**Secrets:** `SECURITY_TEST_USER`, `SECURITY_TEST_PASSWORD` (usuario de prueba con
rol mínimo).

**SMTP (envío de PDF al líder tras merge a rama protegida):** `SMTP_HOST`,
`SMTP_USER`, `SMTP_PASSWORD`, opcionales `SMTP_PORT` (587), `SMTP_SECURE` (false),
`SMTP_FROM`. Si faltan, el step de email falla silenciosamente y el PDF queda
como artifact `security-report-pdf`. Destinatario por defecto
`ludwing.serapio@goes.gob.sv`, editable en el workflow (`to:`, separar por coma).
El correo se envía solo en `push` a `dev/qa/uat/main`, no en cada update de PR.

### CODEOWNERS catch-all

```
*   @gerardo-amaya-dev @alejandro-montepeque-dev @angel-bran-dev @jose-orellana-dev @noe-cortez-dev
```

### Branch protection (una regla por rama: dev, qa, uat, main)

Settings → Branches → Add rule:
- [x] Require a pull request before merging
  - [x] Required approving reviews: 1
  - [x] Require review from Code Owners
  - [x] Dismiss stale approvals on new commits
- [x] Require status checks to pass before merging
  - [x] Require branches to be up to date
  - Checks: `Verify gate integrity`, `Security tests (local build)`,
    `Checklist GOES coverage gate`, `Security doctor (skill compliance)`;
    en uat/main además `Security tests (release env)`
- [x] Require conversation resolution before merging
- [x] **Do not allow bypassing the above settings** (nadie, ni admins, mergea con rojos)
- Allow specified actors to bypass PRs: **VACÍO**
- [x] Restrict who can push: solo CODEOWNERS + bots de Actions

Resultado: dev y CODEOWNER necesitan 1 approval de CODEOWNER; con checks rojos el
botón de merge queda gris para todos.

## Flujo rojo → violeta (en vez de bypass)

Cuando un test sale rojo porque el item NO aplica a este proyecto (ej. R6 en
panel admin interno), en el MISMO PR el dev:

1. Agrega la entrada a `accepted_risks[]` del snapshot (ver
   `decision-rules.md` para el schema completo).
2. Añade al inicio del test:
   ```typescript
   if (await t.acceptedRiskIfDeclared('R6')) { await t.flush(); return; }
   ```
3. Push → el workflow re-corre → R6 sale violeta "RIESGO ACEPTADO".
4. GitHub pide review de CODEOWNERS automáticamente (tocó `snapshot.json`,
   protegido). Evalúan razón, compensating_controls y `review_at`.
5. Con approval, todos los checks pasan (verde/violeta/N/A = OK para el gate).
6. A partir del merge, R6 sale violeta en todas las corridas hasta que vence
   `review_at`; entonces se renueva o quita con otro PR (mismo review).

Por qué es mejor que el bypass: la decisión queda persistente en el JSON (no en
la conversación del PR), con git blame, aplica a todas las corridas futuras,
tiene `review_at` obligatorio + warning a 30 días, y el cambio al snapshot exige
CODEOWNERS review. **El "rojo mergeado" no existe en el historial.**

## 7.5 Nuevo hallazgo en pentest (cierre del ciclo)

1. Ciberseguridad reporta `VULN-XXX-NNNN`.
2. Equipo agrega entry a `references/pentest-history.yaml`.
3. Crea `test/security/regression/VULN-XXX-NNNN.regression.spec.ts` (ver
   `references/regression-template.md`).
4. Si es de runtime, actualiza el snapshot (review CODEOWNERS).
5. `npm run security:doctor` debe pasar. PR + merge.

Detalle del flujo de ingest: `references/templates/pentest-ingest.md`.
