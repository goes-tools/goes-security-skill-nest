// scripts/security-snapshot-update.ts
//
// Genera o actualiza test/security/security.snapshot.json capturando los
// valores reales que el backend retorna. CAMBIOS A ESTE ARCHIVO REQUIEREN
// APROBACION DE @gerardo-amaya-dev,@alejandro-montepeque-dev,@angel-bran-dev,@jose-orellana-dev,@noe-corte-dev segun CODEOWNERS.

import * as fs from 'fs';
import * as path from 'path';
import { Test } from '@nestjs/testing';
import { INestApplication } from '@nestjs/common';
import * as request from 'supertest';
import { AppModule } from '../src/app.module';

async function main() {
  const moduleRef = await Test.createTestingModule({ imports: [AppModule] }).compile();
  const app: INestApplication = moduleRef.createNestApplication();
  await app.init();

  const res = await request(app.getHttpServer()).get('/api/health');
  const headers = res.headers;

  const snapshot = {
    $schema: 'https://goes.gob.sv/security-snapshot.v1.json',
    version: 1,
    project: require('../package.json').name,
    approved_by: '@gerardo-amaya-dev,@alejandro-montepeque-dev,@angel-bran-dev,@jose-orellana-dev,@noe-corte-dev',
    approved_at: new Date().toISOString().slice(0, 10),
    headers: {
      'content-security-policy': [headers['content-security-policy'] ? `^${escapeRegex(headers['content-security-policy'])}$` : 'MISSING'],
      'strict-transport-security': [headers['strict-transport-security'] ? `^${escapeRegex(headers['strict-transport-security'])}$` : 'MISSING'],
      'x-content-type-options': [`^${headers['x-content-type-options'] || 'MISSING'}$`],
      'x-frame-options': [`^${headers['x-frame-options'] || 'MISSING'}$`],
      'referrer-policy': [`^${headers['referrer-policy'] || 'MISSING'}$`],
      'permissions-policy': [headers['permissions-policy'] ? escapeRegex(headers['permissions-policy']) : 'MISSING'],
      'server': null,
      'x-powered-by': null,
    },
    session: {
      access_token_ttl_minutes: parseInt(process.env.ACCESS_TOKEN_TTL_MIN || '5', 10),
      refresh_token_ttl_days: parseInt(process.env.REFRESH_TOKEN_TTL_DAYS || '7', 10),
      idle_timeout_minutes: parseInt(process.env.IDLE_TIMEOUT_MIN || '30', 10),
    },
    rate_limit: {
      general_per_minute: parseInt(process.env.RATE_LIMIT_GENERAL || '100', 10),
      login_per_minute: parseInt(process.env.RATE_LIMIT_LOGIN || '5', 10),
      exposed_in_headers: !!headers['x-ratelimit-limit'],
    },
    error_response: {
      allowed_keys: ['statusCode', 'message', 'error'],
      forbidden_keys: ['path', 'timestamp', 'stack', 'cause', 'sql', 'query', 'url'],
    },
  };

  const outPath = path.resolve(__dirname, '../test/security/security.snapshot.json');
  fs.mkdirSync(path.dirname(outPath), { recursive: true });
  fs.writeFileSync(outPath, JSON.stringify(snapshot, null, 2) + '\n', 'utf-8');

  console.log(`Snapshot escrito en: ${outPath}`);
  console.log('REVISAR el contenido. Cualquier valor "MISSING" indica que el');
  console.log('header no se esta enviando — eso es un HALLAZGO que hay que arreglar');
  console.log('antes de commitear el snapshot.');

  await app.close();
}

function escapeRegex(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});
