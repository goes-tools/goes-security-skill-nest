# goes-security-skill

A Claude Code skill that **generates, runs, and reports automated security tests** for **NestJS** projects — **runner-agnostic** (auto-detects and uses Jest *or* Vitest, without imposing one) — aligned with the **GOES Cybersecurity Checklist** (57 items), **OWASP Top 10 (2021)**, and **OWASP API Security Top 10 (2023)**.

The output is a single self-contained HTML report — no server, no external assets — designed for compliance audits in government environments.

---

## How it works

1. The user copies the `.claude/` folder from this repo into a NestJS project.
2. In Claude Code, the user types a short trigger like *"Generate security tests for this project with the goes-security-testing skill"*.
3. Claude reads `SKILL.md`, exhaustively maps the project's security surface (controllers, DTOs, guards, pipes, interceptors, filters, middleware, custom decorators, helpers, `main.ts`, entities/schemas — not just `*.service.ts`), and generates one `.security-html.spec.ts` per relevant module with full metadata (epic, feature, story, severity, GOES + OWASP tags, input/output evidence).
4. Claude configures the project's test runner (Jest or Vitest, detected — never imposed) with the bundled universal HTML reporter and runs the suite.
5. The output is `reports/security/security-report.html` — a single auditable file.

The bundled reporter is pure Node.js JavaScript.

---

## Installation

```bash
# 1. Clone this repo
git clone https://github.com/goes-tools/goes-security-skill.git

# 2. Copy .claude/ into your NestJS project
cp -r goes-security-skill/.claude /path/to/your-nestjs-project/.claude

# 3. Open Claude Code in that project
cd /path/to/your-nestjs-project
claude
```

Then in Claude Code:

```
Generate security tests for this project with the goes-security-testing skill.
```

That's it. The skill auto-activates on phrases like *"security tests"*, *"GOES checklist"*, *"pentest tests"*, *"security report"*, etc.

---

## Usage

The skill is invoked with a short prompt in Claude Code. There are **two modes** — pick the one that fits your context:

### Mode 1 — Audit-only (recommended for compliance, institutional pilots)

Claude **only generates and runs tests**. If a test fails, it stays red as a finding. Claude does **not** touch your application code (`src/`). The team decides whether to fix the source or accept the risk.

```
Generá tests de seguridad para este proyecto con el skill
goes-security-testing. Aplicá las reglas críticas del SKILL.md
(3 capas, notApplicable solo con grep, input+output, stripComments).

NO modifiques código fuente del proyecto (src/) para hacer pasar
tests. Si un test falla, dejalo rojo y reportalo como hallazgo —
el equipo decide si arreglar el código o aceptar el riesgo.
Solo podés tocar test/security/, package.json (scripts/devDeps)
y el reporter dentro de .claude/.

Reporter:
- projectName: "GOES — [Sistema]"
- reportTitle: "Security Test Report — GOES [Sistema]"

Al final, npm run test:security:html y resumen con cobertura,
hallazgos rojos e ítems N/A con su grep.
```

**Use when**: you want a clean compliance report, a third-party audit, or a baseline before the team starts remediation. Findings stay visible in the HTML.

### Mode 2 — Standard (lets Claude suggest and apply fixes)

Claude generates the tests **and may also propose or apply fixes** to the source code if it identifies straightforward gaps (missing helmet, missing decorator, etc.). Useful during active development.

```
Generate security tests for this project with the goes-security-testing skill.

Reporter:
- projectName: "GOES — [System Name]"
- reportTitle: "Security Test Report — GOES [System Name]"
```

**Use when**: you are actively developing the project and want Claude to help close gaps as it finds them. Note that fixes applied this way should still be reviewed in PR before merging.

### Minimal trigger

```
Generate security tests for this project with the goes-security-testing skill.
```

**Prompt recomendado (español, un solo paso):**

```
Aplica la skill goes-security-testing a este proyecto NestJS: genera los tests de seguridad y el reporte HTML del checklist GOES. Corre el doctor al final.
```

The skill reads `SKILL.md`, detects the project's test runner (Jest or Vitest) without imposing one, scans the project, generates tests, configures the security suite, runs it, produces the HTML report, and finishes with `npm run security:doctor`. `projectName` defaults to the value in `package.json#name`. By default this falls under Mode 2 (standard).

### Replace `[Sistema]` / `[System Name]`

In every prompt above, replace the placeholder with the real project name (e.g. `"GOES — Sistema de Trámites"`, `"GOES — Portal de Transparencia"`).

### Targeted regeneration

```
Regenerate tests for AuthService with the goes-security-testing skill.
```

### Run the report

After Claude configures the skill, `package.json` has these scripts:

```bash
npm run test:security:html    # security suite + HTML report
npm run test:all              # unit + e2e + security
npm test                      # only the regular unit tests
```

The HTML lands at `reports/security/security-report.html` — open it in any browser, no server needed. Self-contained (CSS, JS, data inline) so you can email it, attach it to a Jira ticket, or zip it as a compliance annex.

---

## What the HTML report includes

### Header

- Project name and report title (configurable).
- **Generation timestamp** in `es-SV` locale (e.g. `28/04/2026, 14:35:00`) for audit traceability.
- Reporter version.

### Interactive charts

Two SVG charts (not images) with native tooltips and click-to-filter:

- **Test Status** — donut chart (passed / failed / skipped). Click a slice to filter the table to those tests.
- **Severity Distribution** — bar chart by `blocker / critical / high / normal / minor / trivial / skipped`. Click a bar to filter.

A filter pill appears next to "Test Results" when a chart filter is active, with a clear button.

### Sidebar navigation

Tree of `Epic → Feature → Story` derived from test metadata. **Collapsed by default** (▶ to expand). Each entry shows the test count and a pass/fail indicator. Sidebar search filters the tree (does not affect the test table).

### Test results table

- Sortable by severity by default.
- Per-row badges: severity (or **N/A**) + GOES / OWASP tags.
- Status icon (✓ pass · ✗ fail · ⊘ skipped).
- A second search box (**"Filter test results..."**) above the table filters only the rows below.
- Fade-in animation when filtering.

### Test detail modal

Click any row to open. Contents:

- Severity + tags badges, with `OWASP A03` and similar styled distinctively.
- **Not Applicable callout** if the test was marked with `t.notApplicable(reason)` — yellow stripe with the verifiable reason.
- **Classification** (Epic / Feature / Story / Owner).
- **Description** (HTML allowed).
- **Steps** (numbered, in `Prepare / Execute / Verify` style).
- **Evidence** — JSON evidence with syntax highlighting. Tests follow an `input + output` convention: at minimum one entry capturing the payload/request and one capturing the result/response.
- **References** — automatic links to OWASP documentation derived from tags. `OWASP A03` → `owasp.org/Top10/A03_2021-Injection/`. Custom links via `t.link()` are appended.
- **Errors** — full failure messages with stack traces (when status is failed).
- **Reproducibility** — file path (relative), test name, and exact `npm` command to re-run, each with a copy-to-clipboard button.
- Status footer (Status / Duration).

### Search, filtering, export

- **Sidebar search** — filters the category tree.
- **Tests search** — filters the result table.
- **Chart click** — filters by status or severity.
- **Filter pill** — clears any chart filter.
- **PDF export** — `Cmd/Ctrl+P` produces a print layout with header, charts, stats, and per-test detail visible. Suitable as an audit annex.

### Visual

- Dark theme.
- Smooth animations (chart hover, row fade-in).
- Native page scroll — sidebar is sticky, the rest scrolls.
- Responsive grid for stat cards.

---

## Coverage

### GOES Cybersecurity Checklist

57 actionable items grouped in 5 categories:

| Category | Range | What it covers |
|---|---|---|
| Web Content | R3-R6 | Sensitive data exposure, XSS, sanitization |
| Server I/O | R8-R11 | Generic errors, RBAC, DTO validation |
| Auth & Sessions | R13-R35 | JWT (RS256, payload, claims), bcrypt, brute force, IDOR, token rotation, RBAC, session inactivity |
| Configuration | R37-R55 | ORM enforcement, CORS, security headers, cookies, debug mode, HTTP methods, rate limiting |
| File Handling | R57-R60 | Magic byte validation, extension whitelist, size limit, UUID rename |

### OWASP Top 10 (2021)

A01 (Broken Access Control), A02 (Cryptographic Failures), A03 (Injection), A04 (Insecure Design), A05 (Security Misconfiguration), A07 (Auth Failures), A09 (Logging Failures).

A06 (Vulnerable Components), A08 (Data Integrity), and A10 (SSRF) are partially covered or on the roadmap.

### OWASP API Security Top 10 (2023)

API1 (Object Level Auth), API2 (Broken Auth), API3 (Object Property Auth — partial), API4 (Resource Consumption), API5 (Function Level Auth), API8 (Security Misconfiguration).

API6, API9, API10 are on the roadmap.

### Test patterns (32)

The skill ships with 32 reusable patterns under [references/test-patterns/](.claude/skills/goes-security-testing/references/test-patterns/). Use [`INDEX.md`](.claude/skills/goes-security-testing/references/test-patterns/INDEX.md) (checklist item → pattern file) to open only the one you need:

CRUD/DTO validation · XSS sanitization · Error handling · JWT security · Password security · Brute force · Timing attacks · Replay attacks · RBAC · IDOR · Session management · Forced browsing · Registration security · CORS · Cookie security · HTTP security headers · Debug & HTTP methods · SQL injection / ORM · Rate limiting · File upload · Audit log · Logout flow.

---

## Marking items as Not Applicable

When a checklist item does not apply to the project (e.g. R57-R60 file upload rules on a backend that never accepts uploads), do **not** use `it.skip()` (which loses metadata) or omit the item (which breaks GOES traceability). Use the `notApplicable()` API:

```typescript
it('R57-R60 — File upload rules', async () => {
  const t = report();
  t.epic('Archivos').feature('File Upload Security');
  t.story('Backend does not handle file uploads');
  t.severity('blocker');
  t.tag('GOES Checklist R57', 'GOES Checklist R58', 'GOES Checklist R59', 'GOES Checklist R60');

  t.notApplicable('Backend does not accept uploads: no multer dependency, no @UseInterceptors(FileInterceptor) anywhere, no multipart/form-data endpoints');

  await t.flush();
});
```

Such tests render as **skipped** (⊘) with a **Skipped** badge and a yellow callout in the modal explaining why. They are counted in the `Skipped` stat card, preserving full traceability.

---

## Reporter customization

Pass options to the bundled reporter in `test/security/security.config.ts`:

```typescript
[
  path.join(reporterPath, 'html-reporter.js'),
  {
    outputPath: './reports/security/security-report.html',
    projectName: 'GOES — Sistema de Trámites',  // optional, falls back to package.json#name
    reportTitle: 'Security Test Report — GOES',  // optional
  },
],
```

Two environment variables help in CI / parallel runs:

| Variable | Purpose |
|---|---|
| `SECURITY_REPORTER_RUN_ID` | Subdir per run under `$TMPDIR/security-html-reporter/<runId>` — required when the runner executes in parallel (Jest `--maxWorkers > 1`, Vitest threads/forks) or when several CI jobs share a runner. |
| `SECURITY_REPORTER_TEMP_DIR` | Full override of the metadata tempdir (use it when you need the metadata under your CI workspace). |

See [`_html-reporter-customization.md`](.claude/skills/goes-security-testing/references/test-patterns/_html-reporter-customization.md) for branding, badge classification, GitHub Actions / GitLab CI snippets, and troubleshooting.

---

## Architecture

```
.claude/skills/goes-security-testing/
├── SKILL.md                          ← instructions for Claude
├── reporter/
│   ├── html-reporter.js              ← universal Jest/Vitest reporter (~3900 lines, JS)
│   ├── metadata.ts                   ← metadata collector + AllureCompat
│   └── smoke.js                      ← Node-only smoke test (Jest + Vitest paths)
└── references/
    ├── goes-checklist.md             ← GOES checklist (57 items) + OWASP + guide
    ├── runner-setup.md               ← runner detection, configs, version matrix
    ├── decision-rules.md             ← Hallazgo vs N/A vs Riesgo Aceptado
    ├── ci-gate-setup.md              ← CI gate, snapshot, branch protection
    └── test-patterns/                ← 32 patterns + INDEX + support files
        ├── INDEX.md                  ← item → pattern map
        ├── _setup.md
        ├── 01-crud-validation.md
        ├── ...
        └── 32-defense-validation.md
```

The reporter consists of:

- **`reporter/html-reporter.js`** — universal reporter (pure JavaScript). A single class works as a Jest reporter (`onRunComplete`) and a Vitest reporter (`onInit` + `onTestRunEnd` for Vitest 4 / `onFinished` for ≤3), sharing one `renderReport` core. Reads metadata JSON files written by tests, merges with the runner's results, generates a self-contained HTML.
- **`reporter/metadata.ts`** — metadata collector. Exposes `report()` and `AllureCompat`. Each test registers epic, feature, story, severity, tags, parameters, steps, evidence, and optionally `notApplicable(reason)`.

---

## Demo

A full presentation guide is at [`docs/DEMO.md`](docs/DEMO.md), including a 12-minute script, pre-flight checklist, recovery plan, and Q&A talking points for institutional audiences.

---

## Requirements

- **NestJS** project with **Jest or Vitest** (auto-detected; if neither is present the skill asks which one to install — only that one)
- **Node.js 18+**
- **Claude Code** (or Claude Cowork) for skill activation

No Java required.

---

## Changelog

### v2.0 (2026-06)

**Runner-agnostic**
- **Universal reporter** — one `html-reporter.js` works as both a Jest reporter (`onRunComplete`) and a Vitest reporter (`onInit` + `onTestRunEnd` for **Vitest 4** / `onFinished` for ≤3), sharing one render core. Test-name matching normalizes Jest's space vs Vitest's `>` separators.
- **PASO 0 runner detection** — detects and uses the project's runner (Jest/Vitest) without imposing one; if none or another runner (Mocha/Jasmine) is present, asks the user which to install (Jest or Vitest, only one). Supported-version matrix with notify-and-ask when out of range; never degrades project deps.
- **Single config name** — `security.config.ts` / `security.setup.ts` / `security-release.config.ts` (no `jest-`/`vitest-` prefix).

**Robustness & anti-regression**
- Specs that **fail to load** (Jest `testExecError` / Vitest collection error) now surface as a **red** test instead of vanishing from the report.
- Reporter emits `window.__GOES_STATS__` for the CI coverage gate; warns when 0 tests cross metadata (e.g. missing Vitest `globals:true` or `flush()`).
- **`reporter/smoke.js`** — Node-only dual-runner smoke test guarding the reporter across future changes.
- **Stricter doctor** — new `SPEC_AUTHORING` (flush + evidence) and `RUNNER_WIRING` checks; CI-gate check now strips comments/echo before scanning (no false-FAIL on self-reference).
- Pattern 31 (config snapshot) no longer boots `AppModule` locally — N/A + static check locally, runtime drift in the release job.

**Token efficiency**
- `SKILL.md` slimmed ~80% (router + on-demand `references/`); pattern `INDEX.md` (item → file); tightened `description`.

### v1.2 (2026-04)

**Interactivity**
- **Charts are interactive SVG** (not images) — hover tooltips with counts and percentages, click-to-filter the test table by status / severity.
- **Filter pill** with clear button when a chart filter is active.
- **Dual search**: sidebar search filters the category tree only; new "Filter test results" search above the table filters rows.
- **Sidebar collapsed by default** — top-level epics start collapsed (▶); user expands as needed.
- **Fade-in animation** on test rows when filtering.

**Modal enhancements**
- **References section** with automatic OWASP links — tags like `OWASP A03` and `OWASP API1` resolve to official URLs (`owasp.org/Top10/...` and `owasp.org/API-Security/editions/2023/...`).
- **Reproducibility section** — every test shows its file path (relative to project root), test name, and exact `npm` command to re-run, each with copy-to-clipboard buttons.
- **Not Applicable support** — new `t.notApplicable(reason)` API on `report()` and `AllureCompat`. Renders as skipped (⊘) with **Skipped** badge in the row, and a yellow callout in the modal explaining why.
- **Input + output evidence convention** — SKILL.md now requires every test to register at least one `input` evidence and one `output` evidence, with recommended labels per test type (Pentest, CRUD, Auth, Config, Headers).

**Skill rules (SKILL.md)**
- **3-layer coverage rule** — defense controls require Layer 1 (config), Layer 2 (decorator/structural), and Layer 3 (behavior).
- **Universal `notApplicable` rule** — only 6 items can ever be N/A (R6, R28, R29, R32, R35, R57-R60), each with a `grep` verifier; surface present + defense missing is a **finding**, not N/A.
- **`stripComments` static helper** ([_static-analysis.md](.claude/skills/goes-security-testing/references/test-patterns/_static-analysis.md)) — required when verifying presence of code in `main.ts` / `*.module.ts`; commented code counts as absent.
- **Audit-only mode (opt-in via prompt)** — when the prompt asks Claude not to modify `src/`, failing tests stay red as findings; the team decides whether to remediate.

**Reporter polish**
- **Generation timestamp** in the header in `es-SV` locale for audit traceability.
- **Print/PDF preview fixed** — header, charts, stats, and test details are now visible when exporting to PDF (previously hidden).
- **Natural page scroll** — sidebar is sticky, content scrolls naturally instead of being trapped in nested overflow containers.
- **Stat cards layout** is now `auto-fit` (responsive on any screen width).
- **Absolute file paths no longer leaked** in the embedded report data — only relative paths are embedded.
- **CommonJS reporter is intentional** — Jest loads reporters via `require()`, and the SKILL.md explicitly forbids converting it to TypeScript or ES modules.

### v1.1 (2026-04)

- Reporter project name and report title parametrizable.
- `SECURITY_REPORTER_RUN_ID` env var scopes metadata per process for parallel Jest workers.
- `createStatusChart()` renders a "No tests" placeholder when zero tests run, instead of `NaN` paths.
- Patterns migrated from `allure-js-commons` to bundled `AllureCompat`.
- New `attachFor(allure)` helper for legacy `attach('name', data)` calls.
- Path typo fixed: `.claude/skills/goes-security-test/` → `.claude/skills/goes-security-testing/`.

### v1.0

- Initial release with HTML reporter, 21 patterns, 60 GOES checklist items.

---

## Roadmap

Items currently out of scope or partially covered, planned for future versions:

- **A10 SSRF** test pattern.
- **R12 payload size limit** test pattern.
- **API3 mass assignment** explicit pattern.
- **API6 unrestricted access to sensitive business flows** pattern.
- **API9 / API10** patterns.
- **Framework adapters** beyond NestJS (Express, Fastify).
- **Baseline / diff** between runs to highlight regressions.
- **SARIF export** for GitHub Code Scanning / GitLab Security Dashboard ingestion.
- **Severity gates** in CI (e.g. `failOn: 'blocker'`).
- **ISO 27001 / NIST 800-53** mapping in the GOES checklist.

See [`_recommendations.md`](.claude/skills/goes-security-testing/references/test-patterns/_recommendations.md) for the per-project recommendation file Claude generates when items in the checklist are not yet implemented.

---

## Contributing

Pull requests are welcome for:

- New test patterns in [`references/test-patterns/`](.claude/skills/goes-security-testing/references/test-patterns/) — especially the roadmap gaps above.
- Updates to the checklist in [`references/goes-checklist.md`](.claude/skills/goes-security-testing/references/goes-checklist.md).
- Improvements to skill instructions in [`SKILL.md`](.claude/skills/goes-security-testing/SKILL.md).
- Support for other frameworks (Express, Fastify, etc.).

### How to contribute

1. Fork the repo.
2. Create a branch: `git checkout -b feature/new-pattern`.
3. Make changes.
4. Open a PR with a description of what was added or changed.

---

## License

Internal use — Government of El Salvador (GOES).
