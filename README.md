# JS Info Flow

An exploratory static information-flow (taint) analyzer for JavaScript, with an interactive web demo.

It parses JavaScript with [Acorn](https://github.com/acornjs/acorn) and follows data from configured **sources** (such as `readPassword()`) through variables, function parameters and return values to configured **sinks** (such as `console.log`). Submitted code is parsed, never executed.

This is a learning and research-preparation prototype. It is not a production security tool and does not cover the full JavaScript language.

- **Live demo:** _not deployed yet_
- **Source:** _add the repository URL here_

## Features

- Static source-to-sink tracking through declarations, intermediate variables, selected function calls, parameters and returns
- Express API (`POST /api/analyze`) that runs the analyzer in an isolated worker thread with time, memory, size and rate limits
- Terminal-style website with commands (`help`, `demo`, `analyze`, `tests`, `limitations`, `github`, `clear`, ...)
- Playground with example programs, line-level markers for findings and parse errors, and explanations built only from what the API returns
- "Not modeled" notes that flag constructs the analyzer ignores, so an empty result is not presented as a clean one
- Documented test cases that run live on the server, plus an automated test suite

## Quick start

Requires Node.js 20 or newer.

```bash
npm install
npm start
```

Open <http://localhost:3000>. In local development the server serves both the website and the API from the same origin.

Analyze a file from the command line:

```bash
node analyzer/analyzer.js path/to/file.js
```

Run the tests:

```bash
npm test               # everything
npm run test:analyzer  # analyzer only
npm run test:api       # HTTP API only
```

## How the analyzer works

1. **Parse.** Acorn builds an AST (`ecmaVersion: "latest"`, module mode).
2. **Register.** Top-level `function` declarations are collected.
3. **Track.** Top-level statements are walked in order. A variable is tainted when its declaration contains a source call or an already tainted value.
4. **Follow calls.** For calls to known functions, tainted arguments mark parameters, local declarations propagate taint, and the first top-level `return` decides whether the call's result is tainted. A call stack prevents infinite recursion.
5. **Report.** A call to a configured sink with a tainted argument is recorded as a finding (sink, line, column), once per sink and line.

The original analysis logic is unchanged. For the web demo it is wrapped in `analyze(code, options)` with per-call state, a step budget (results are marked `truncated` when it is reached) and structured parse errors. See the header of `analyzer/analyzer.js`.

## API

All responses are JSON.

### `POST /api/analyze`

Request:

```json
{ "code": "const secret = readPassword();\nconsole.log(secret);" }
```

Response `200`:

```json
{
  "ok": true,
  "findingCount": 1,
  "findings": [{ "destination": "console.log", "line": 2, "column": 0 }],
  "taintedVariables": ["secret"],
  "truncated": false,
  "stats": { "steps": 24, "maxSteps": 100000, "truncated": false },
  "coverageNotes": [],
  "config": { "sources": ["getSensitiveData", "readPassword", "getUserToken"], "sinks": ["console.log", "sendToServer"] },
  "durationMs": 58
}
```

`column` is 0-based (Acorn). `taintedVariables` lists top-level variables only. `coverageNotes` comes from a separate scan and never changes `findings`.

| Status | `error.type` | When |
|---|---|---|
| 400 | `BadRequest` | Invalid JSON, missing/non-string/empty `code` |
| 413 | `PayloadTooLarge` | Body over 32 KB or code over 10,000 characters |
| 415 | `UnsupportedMediaType` | Content-Type is not `application/json` |
| 422 | `SyntaxError` | Code is not valid JavaScript (includes `line`, `column`) |
| 429 | `RateLimited` | Over the per-IP rate limit |
| 503 | `Busy` | Too many analyses running at once |
| 504 | `AnalysisTimeout` | Analysis exceeded the time limit |
| 500 | `AnalysisFailed` / `InternalError` | Unexpected failure |

### `GET /api/health`

Status, version, configured sources/sinks and limits.

### `GET /api/tests`

Runs the cases from `tests/test-cases.md` through the analyzer at request time and reports observed results.

## Evaluation

| # | Case | Expected | Automated result |
|---|---|---|---|
| 1 | Direct source to sink | Finding | Passes |
| 2 | Intermediate variable | Finding | Passes |
| 3 | Helper function | Findings for both sinks | Passes |
| 4 | Function returns a constant | No finding | Passes |
| 5 | Unknown function | Not modeled | Documented limitation |

`npm test` runs 36 tests: the documented cases, input handling, pinned limitations, coverage notes, and the HTTP API. See `tests/test-cases.md` for how the automated tests differ from the manual evaluation. These are small, hand-built examples, not a benchmark.

## Limitations

- Only top-level function declarations are analyzed. Arrow functions, function expressions, methods and nested functions are treated as unknown.
- Reassignment (`x = ...`) is ignored: it neither adds nor removes taint.
- Only the first top-level `return` in a function body is used.
- Unknown functions are not followed, and their return values are treated as clean.
- A known function called as a plain statement inside another function is not analyzed.
- No control-flow, path, async, class, closure, DOM or browser API modeling.
- Objects are tainted as a whole; destructuring is skipped.
- Sources and sinks are a fixed list matched by name, and findings do not record which source they came from.
- Input is parsed in module (strict) mode.

A finding is a potential flow under these rules, not a confirmed vulnerability. No findings does not mean the code is safe.

## Security notes

- Submitted code is only parsed. Nothing uses `eval`, `Function`, `node:vm` or a shell.
- Each analysis runs in a short-lived worker thread with a wall-clock timeout (3 s), memory limits, a step budget and a concurrency cap.
- Request body limit 32 KB, code limit 10,000 characters, rate limit 30 requests per minute per IP.
- CORS allows only origins listed in `ALLOWED_ORIGINS`. Security headers come from Helmet.
- The website renders all output with `textContent`; untrusted input is never inserted as HTML.
- Submitted code is not stored or logged.

These controls are reasonable for a public demo. They have not been independently reviewed, and the service should not be treated as hardened. The in-memory rate limiter resets on restart and is per instance.

## Deployment

The website is static and goes on GitHub Pages. GitHub Pages cannot run Node.js, so the API must be hosted separately. The steps below use Render; any Node host works.

### 1. Backend (Render)

1. Create a Render account and connect your GitHub account.
2. **New > Blueprint**, select this repository. `render.yaml` defines the service.
3. Set `ALLOWED_ORIGINS` to your Pages origin, for example `https://USERNAME.github.io` (origin only, no path, no trailing slash).
4. Deploy, then check: `curl https://YOUR-SERVICE.onrender.com/api/health`

Render's free plan sleeps when idle; the first request after a pause can take up to about a minute. The website shows a waiting message in that case. Check Render's current plans and limits before relying on it.

### 2. Frontend (GitHub Pages)

1. In `website/config.js` set:
   ```js
   API_BASE_URL: "https://YOUR-SERVICE.onrender.com",
   GITHUB_URL: "https://github.com/USERNAME/REPO"
   ```
2. Commit and push to `main`.
3. In the repository: **Settings > Pages > Source: GitHub Actions**. The workflow in `.github/workflows/pages.yml` publishes `website/`.
4. Open `https://USERNAME.github.io/REPO/` and run `health` in the terminal.

### Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `PORT` | `3000` | HTTP port (set automatically by most hosts) |
| `ALLOWED_ORIGINS` | `http://localhost:PORT` | Comma-separated origins allowed by CORS |
| `TRUST_PROXY` | `0` | Set to `1` behind a proxy so rate limiting sees client IPs |
| `SERVE_WEBSITE` | on | Set to `0` to serve only the API |
| `MAX_CODE_CHARS` | `10000` | Maximum code length |
| `MAX_STEPS` | `100000` | Analyzer step budget |
| `ANALYSIS_TIMEOUT_MS` | `3000` | Worker time limit |
| `MAX_CONCURRENT_ANALYSES` | `4` | Concurrent workers |
| `RATE_LIMIT_MAX` / `RATE_LIMIT_WINDOW_MS` | `30` / `60000` | Rate limit for `/api/analyze` |

### Troubleshooting

| Symptom | Likely cause |
|---|---|
| Terminal shows `api: not set` | `API_BASE_URL` is empty in `website/config.js` on GitHub Pages |
| `api: offline`, browser console shows a CORS error | `ALLOWED_ORIGINS` does not exactly match the Pages origin (scheme, no path, no trailing slash) |
| First request hangs for ~1 minute | Free backend waking from sleep |
| Everyone gets 429 at once | `TRUST_PROXY` not set, so all requests appear to come from the proxy's IP |
| Pages shows a 404 | Pages source not set to GitHub Actions, or the workflow has not run |
| Mixed content error | `API_BASE_URL` uses `http://`; it must be `https://` |

## Project structure

```text
analyzer/
  analyzer.js          the analyzer (original logic, wrapped as analyze())
  documented-cases.js  test-cases.md cases in executable form
  coverage-notes.js    separate scan for constructs the analyzer ignores
server/
  app.js               Express app and routes
  server.js            entry point
  config.js            environment configuration
  run-analysis.js      worker-thread runner (timeout, limits, concurrency)
  analysis-worker.js   worker entry point
website/
  index.html, style.css, script.js, config.js
tests/
  test-cases.md        manual evaluation
  analyzer.test.js     analyzer tests
  api.test.js          API tests
```

## Technologies

Node.js, Acorn, Express, Helmet, cors, express-rate-limit, `node:test`, plain HTML/CSS/JavaScript.
