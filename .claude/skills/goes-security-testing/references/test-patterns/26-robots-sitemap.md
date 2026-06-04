# Pattern 26: robots.txt + sitemap.xml (Public Site Config)

> Migration note: usa `AllureCompat` y `await allure.flush()` al final de cada `it`.

**Covers:** R6 (Public Site Config — robots.txt + sitemap.xml)

> **3 estados:**
>
> 1. El backend NO sirve un sitio publico (solo APIs internas / auth) → `t.notApplicable('No hay rutas publicas servidas — verificar con grep -r "useStaticAssets|sendFile|res.render" src/')`.
> 2. Sirve frontend publico + tiene `robots.txt` y `sitemap.xml` correctos → verde.
> 3. Sirve frontend publico pero NO los tiene, o `robots.txt` permite indexar rutas privadas → HALLAZGO rojo.

```typescript
import * as request from 'supertest';
import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication } from '@nestjs/common';
import { report } from '@security-reporter/metadata';

it('R6 — public site MUST expose robots.txt with sane defaults', async () => {
  const t = report();
  t.epic('Configuracion');
  t.feature('Public Site Config');
  t.story('robots.txt accesible y NO permite indexar rutas privadas');
  t.severity('minor');
  t.tag('Config', 'GOES Checklist R6');

  t.remediation({
    summary: 'El sitio publico no tiene robots.txt/sitemap.xml configurados, o estos exponen rutas privadas.',
    howWeChecked: [
      'GET /robots.txt y /sitemap.xml',
      'Esperabamos archivos validos sin exponer rutas internas',
      'No estan presentes o tienen `Disallow: /admin` que confirma la existencia del admin',
    ],
    whyItMatters: 'robots.txt mal configurado revela rutas privadas a buscadores. Si el sitio es interno, no deberia existir o no deberia listar /admin.',
  });

  const moduleRef: TestingModule = await Test.createTestingModule({
    // imports: [AppModule],
  }).compile();
  const app: INestApplication = moduleRef.createNestApplication();
  await app.init();

  // Capa 1: existe el archivo
  const res = await request(app.getHttpServer()).get('/robots.txt').expect(200);
  const body = (res.text || '').toLowerCase();

  t.evidence('robots.txt response (output)', {
    status: res.status,
    contentType: res.headers['content-type'],
    bodyPreview: body.slice(0, 200),
  });

  // Capa 2: no expone rutas privadas
  expect(body).toContain('user-agent');
  expect(body).not.toMatch(/disallow:\s*\/admin/);   // NO mencionar /admin (revela su existencia)
  expect(body).not.toMatch(/allow:\s*\/api\/private/);

  await app.close();
  await t.flush();
});

it('R6 — public site MUST expose sitemap.xml with valid XML', async () => {
  const t = report();
  t.epic('Configuracion');
  t.feature('Public Site Config');
  t.story('sitemap.xml es XML valido y solo lista URLs publicas');
  t.severity('minor');
  t.tag('Config', 'GOES Checklist R6');

  t.remediation({
    summary: 'El sitio publico no tiene robots.txt/sitemap.xml configurados, o estos exponen rutas privadas.',
    howWeChecked: [
      'GET /robots.txt y /sitemap.xml',
      'Esperabamos archivos validos sin exponer rutas internas',
      'No estan presentes o tienen `Disallow: /admin` que confirma la existencia del admin',
    ],
    whyItMatters: 'robots.txt mal configurado revela rutas privadas a buscadores. Si el sitio es interno, no deberia existir o no deberia listar /admin.',
  });

  const moduleRef: TestingModule = await Test.createTestingModule({}).compile();
  const app: INestApplication = moduleRef.createNestApplication();
  await app.init();

  const res = await request(app.getHttpServer()).get('/sitemap.xml').expect(200);
  const body = res.text || '';

  t.evidence('sitemap.xml response (output)', {
    status: res.status,
    contentType: res.headers['content-type'],
    isXml: body.startsWith('<?xml'),
    sizeBytes: body.length,
  });

  expect(body).toMatch(/^<\?xml\b/);
  expect(body).toMatch(/<urlset\b/);

  // No exponer rutas internas
  expect(body).not.toContain('/admin');
  expect(body).not.toContain('/api/internal');

  await app.close();
  await t.flush();
});
```
