// test/security/jest-security-release.config.ts
//
// Config alterna de Jest que corre la misma suite de seguridad pero
// contra un ambiente desplegado (staging, release, prod). Usar:
//   SECURITY_TEST_BASE_URL=https://...release... npm run test:security:release
//
// La suite de tests detecta automaticamente esta variable y dispara
// supertest contra la URL en vez de createNestApplication() local.

import type { Config } from 'jest';
import * as path from 'path';

const reporterPath = path.resolve(
  __dirname,
  '../../.claude/skills/goes-security-testing/reporter',
);

const config: Config = {
  moduleFileExtensions: ['js', 'json', 'ts'],
  rootDir: '../..',
  testMatch: [
    '<rootDir>/test/security/**/*.security-html.spec.ts',
    '<rootDir>/test/security/regression/**/*.regression.spec.ts',
  ],
  transform: {
    '^.+\\.(t|j)s$': 'ts-jest',
  },
  testEnvironment: 'node',
  testTimeout: 30000,
  moduleNameMapper: {
    '^src/(.*)$': '<rootDir>/src/$1',
    '^@security-reporter/(.*)$': path.join(reporterPath, '$1'),
  },
  reporters: [
    'default',
    [
      path.join(reporterPath, 'html-reporter.js'),
      {
        outputPath: './reports/security/security-report.html',
        reportTitle: `GOES Security Report — ${process.env.SECURITY_TEST_BASE_URL || 'local'}`,
      },
    ],
  ],
};

export default config;
