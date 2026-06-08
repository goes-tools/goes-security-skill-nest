# Índice de patrones de test → items del checklist

> Leer ESTO antes de abrir patrones. Permite leer **solo** el `NN-*.md` que
> corresponde al item que estás cubriendo, en vez de abrir varios. Cada patrón
> trae el código de ejemplo y las assertions para ese control.

| Patrón | Cubre (checklist / OWASP) | Tipo |
|--------|---------------------------|------|
| `01-crud-validation.md` | R11 | CRUD / DTO |
| `02-xss-input-sanitization.md` | R5 · A03 | Pentest |
| `03-error-handling.md` | R8 | Config / errores |
| `04-jwt-security.md` | R16, R19, R20 · A02 | Auth |
| `05-password-security.md` | R11(password), R15, R30, R31 · A02, A07 | Auth |
| `06-brute-force.md` | R27 · A07 | Auth |
| `07-timing-attack.md` | A07 | Pentest |
| `08-replay-attack.md` | R32, R33 · A07 | Auth |
| `09-rbac-privilege.md` | R9, R24, R34 · A01, API5 | Authz |
| `10-idor.md` | R23 · A01, API1 | Authz |
| `11-session-management.md` | R17, R18, R35 | Auth |
| `12-forced-browsing.md` | R21 · A01 | Authz |
| `13-registration-security.md` | R25, R26 | Auth |
| `14-cors-configuration.md` | R38, R39, R40, R41 · A05, API8 | Config |
| `15-cookie-security.md` | R42, R51 | Config |
| `16-security-headers.md` | R44, R45, R46, R47, R48, R49, R50 · A05 | Config |
| `17-debug-http-methods.md` | R43, R52, R53, R54 · A05 | Config |
| `18-sql-injection-orm.md` | R37 · A03 | Pentest |
| `19-rate-limiting.md` | R55 · A04, API4 | Config / Pentest |
| `20-file-upload-security.md` | R57, R58, R59, R60 | Archivos |
| `21-audit-log.md` | A09 (auditoría) | Logging |
| `22-logout-flow.md` | R35 (logout/invalidación) | Auth |
| `23-secrets-detection.md` | R3 | Pentest / estático |
| `24-public-files-exposure.md` | R3, R4 | Estático |
| `25-file-storage-and-serving.md` | R61, R62, R63 | Archivos |
| `26-robots-sitemap.md` | R6 | Config |
| `27-log-exposure.md` | R10 | Logging |
| `28-response-dto-sanitization.md` | R3, R4, R11, R20 · API3 | DTO / respuesta |
| `29-export-controls.md` | R11, R55 · API4 | Config / Pentest |
| `30-captcha-public-endpoints.md` | R14 · A07 | Auth |
| `31-config-snapshot.md` | snapshot runtime (PASO 7) | Config |
| `32-defense-validation.md` | helper de cobertura en 3 capas | Transversal |

Archivos auxiliares (no mapean a un item; son guía/soporte):
`_setup.md`, `_e2e-setup.md`, `_support-files.md`, `_orm-mocks.md`,
`_static-analysis.md`, `_severity-guide.md`, `_recommendations.md`,
`_html-reporter-customization.md`, `_allure-customization.md`.

Cobertura inversa rápida (item → patrón principal): R3→23/24/28, R4→24/28,
R5→02, R6→26, R8→03, R9→09, R10→27, R11→01/28/29, R13→04, R14→30, R15→05,
R16→04, R17→11, R18→11, R19→04, R20→04/28, R21→12, R23→10, R24→09, R25→13,
R26→13, R27→06, R28→13, R30→05, R31→05, R32→08, R33→08, R34→09, R35→11/22,
R37→18, R38-R41→14, R42→15, R43→17, R44-R50→16, R51→15, R52-R54→17, R55→19/29,
R57-R60→20, R61-R63→25.
