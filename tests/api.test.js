// API tests: start the Express app on a random port and call it over HTTP.
// Run: npm run test:api
import { test, describe, before, after } from "node:test";
import assert from "node:assert/strict";

import { createApp } from "../server/app.js";
import { loadConfig } from "../server/config.js";

let server;
let base;

before(async () => {
    const config = loadConfig({
        allowedOrigins: ["https://example.github.io"],
        serveWebsite: false,
        rateLimitMax: 1000
    });
    server = createApp(config).listen(0);
    await new Promise(resolve => server.once("listening", resolve));
    base = `http://127.0.0.1:${server.address().port}`;
});

after(() => new Promise(resolve => server.close(resolve)));

const post = (body, headers = { "Content-Type": "application/json" }) =>
    fetch(`${base}/api/analyze`, {
        method: "POST",
        headers,
        body: typeof body === "string" ? body : JSON.stringify(body)
    });

describe("GET /api/health", () => {
    test("reports status and configured sources/sinks", async () => {
        const res = await fetch(`${base}/api/health`);
        assert.equal(res.status, 200);
        const body = await res.json();
        assert.equal(body.status, "ok");
        assert.ok(body.analyzer.sources.includes("readPassword"));
        assert.ok(body.analyzer.sinks.includes("console.log"));
    });
});

describe("POST /api/analyze", () => {
    test("direct flow returns one finding", async () => {
        const res = await post({ code: "const secret = readPassword();\nconsole.log(secret);" });
        assert.equal(res.status, 200);
        const body = await res.json();
        assert.equal(body.ok, true);
        assert.equal(body.findingCount, 1);
        assert.deepEqual(body.findings[0], { destination: "console.log", line: 2, column: 0 });
        assert.equal(body.truncated, false);
    });

    test("constant return returns zero findings", async () => {
        const code = 'function f(v) { return "x"; }\nconst s = readPassword();\nconst m = f(s);\nconsole.log(m);';
        const body = await (await post({ code })).json();
        assert.equal(body.ok, true);
        assert.equal(body.findingCount, 0);
    });

    test("unknown function returns zero findings plus a coverage note", async () => {
        const body = await (await post({ code: "const s = readPassword();\nunknownFunction(s);" })).json();
        assert.equal(body.findingCount, 0);
        assert.equal(body.coverageNotes[0].kind, "unknown-call");
    });

    test("invalid JavaScript returns 422 with location", async () => {
        const res = await post({ code: "const = ;" });
        assert.equal(res.status, 422);
        const body = await res.json();
        assert.equal(body.ok, false);
        assert.equal(body.error.type, "SyntaxError");
        assert.equal(body.error.line, 1);
    });

    test("malformed JSON returns 400", async () => {
        const res = await post("{not json");
        assert.equal(res.status, 400);
        assert.equal((await res.json()).error.type, "BadRequest");
    });

    test("missing, non-string and empty code return 400", async () => {
        for (const body of [{}, { code: 42 }, { code: "   " }, ["code"]]) {
            const res = await post(body);
            assert.equal(res.status, 400, JSON.stringify(body));
        }
    });

    test("wrong content type returns 415", async () => {
        const res = await post("const a = 1;", { "Content-Type": "text/plain" });
        assert.equal(res.status, 415);
    });

    test("oversized body returns 413", async () => {
        const res = await post({ code: "a".repeat(40_000) });
        assert.equal(res.status, 413);
        assert.equal((await res.json()).error.type, "PayloadTooLarge");
    });

    test("code over the character limit returns 413", async () => {
        const res = await post({ code: "a;".repeat(5_001) });
        assert.equal(res.status, 413);
    });

    test("pathological input is truncated, not hung", async () => {
        let code = "";
        for (let i = 0; i < 22; i++) code += `function f${i}(v){ const a = f${i + 1}(v); const b = f${i + 1}(v); return a; }\n`;
        code += "function f22(v){ return v; }\nconst s = readPassword();\nconsole.log(f0(s));";
        const res = await post({ code });
        assert.equal(res.status, 200);
        assert.equal((await res.json()).truncated, true);
    });

    test("submitted code is not executed", async () => {
        globalThis.__jsifExecuted = false;
        const res = await post({ code: "globalThis.__jsifExecuted = true;\nprocess.exit(1);" });
        assert.equal(res.status, 200);
        assert.equal(globalThis.__jsifExecuted, false);
    });
});

describe("GET /api/tests", () => {
    test("runs the documented cases", async () => {
        const body = await (await fetch(`${base}/api/tests`)).json();
        assert.deepEqual(body.summary, { passed: 4, failed: 0, limitations: 1 });
    });
});

describe("CORS", () => {
    test("allowed origin gets Access-Control-Allow-Origin", async () => {
        const res = await fetch(`${base}/api/health`, { headers: { Origin: "https://example.github.io" } });
        assert.equal(res.headers.get("access-control-allow-origin"), "https://example.github.io");
    });

    test("other origins get no CORS header", async () => {
        const res = await fetch(`${base}/api/health`, { headers: { Origin: "https://evil.example" } });
        assert.equal(res.headers.get("access-control-allow-origin"), null);
    });
});

describe("unknown routes", () => {
    test("unknown API route returns JSON 404", async () => {
        const res = await fetch(`${base}/api/nope`);
        assert.equal(res.status, 404);
        assert.equal((await res.json()).error.type, "NotFound");
    });
});
