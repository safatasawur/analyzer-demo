// Analyzer tests: call analyze() directly, no HTTP involved.
// Run: npm run test:analyzer
import { test, describe } from "node:test";
import assert from "node:assert/strict";

import { analyze } from "../analyzer/analyzer.js";
import { DOCUMENTED_CASES, runDocumentedCases } from "../analyzer/documented-cases.js";
import { coverageNotes } from "../analyzer/coverage-notes.js";

const sinks = result => result.findings.map(f => f.destination).sort();

describe("documented cases (tests/test-cases.md)", () => {
    test("1. direct source-to-sink flow", () => {
        const r = analyze(DOCUMENTED_CASES[0].code);
        assert.equal(r.ok, true);
        assert.deepEqual(r.findings, [{ destination: "console.log", line: 2, column: 0 }]);
        assert.deepEqual(r.taintedVariables, ["secret"]);
    });

    test("2. propagation through an intermediate variable", () => {
        const r = analyze(DOCUMENTED_CASES[1].code);
        assert.deepEqual(r.findings, [{ destination: "console.log", line: 3, column: 0 }]);
        assert.deepEqual(r.taintedVariables, ["secret", "copy"]);
    });

    test("3. helper function: both sinks reported", () => {
        const r = analyze(DOCUMENTED_CASES[2].code);
        assert.deepEqual(sinks(r), ["console.log", "sendToServer"]);
        const byName = Object.fromEntries(r.findings.map(f => [f.destination, f.line]));
        assert.equal(byName["console.log"], 3, "sink inside the helper body");
        assert.equal(byName.sendToServer, 7, "call site");
    });

    test("4. function returning a constant: no finding", () => {
        const r = analyze(DOCUMENTED_CASES[3].code);
        assert.equal(r.ok, true);
        assert.deepEqual(r.findings, []);
        assert.deepEqual(r.taintedVariables, ["secret"], "message is not tainted");
    });

    test("5. unknown function: no finding (documented limitation)", () => {
        const r = analyze(DOCUMENTED_CASES[4].code);
        assert.equal(r.ok, true);
        assert.deepEqual(r.findings, []);
    });

    test("runDocumentedCases reports 4 passed and 1 limitation", () => {
        const statuses = runDocumentedCases(analyze).map(r => r.status);
        assert.deepEqual(statuses, ["passed", "passed", "passed", "passed", "limitation"]);
    });
});

describe("input handling", () => {
    test("invalid JavaScript returns a structured SyntaxError", () => {
        const r = analyze("const = ;");
        assert.equal(r.ok, false);
        assert.equal(r.error.type, "SyntaxError");
        assert.equal(r.error.line, 1);
        assert.equal(r.error.column, 6);
    });

    test("non-string input throws TypeError", () => {
        assert.throws(() => analyze(null), TypeError);
        assert.throws(() => analyze({ code: "x" }), TypeError);
    });

    test("state does not leak between calls", () => {
        analyze("const secret = readPassword();");
        const r = analyze("console.log(secret);");
        assert.deepEqual(r.findings, []);
        assert.deepEqual(r.taintedVariables, []);
    });

    test("exponential call fan-out stops at the step budget and is marked truncated", () => {
        const n = 22;
        let src = "";
        for (let i = 0; i < n; i++) {
            src += `function f${i}(v){ const a = f${i + 1}(v); const b = f${i + 1}(v); return a; }\n`;
        }
        src += `function f${n}(v){ return v; }\nconst s = readPassword();\nconsole.log(f0(s));`;
        const started = Date.now();
        const r = analyze(src, { maxSteps: 50_000 });
        assert.equal(r.ok, true);
        assert.equal(r.stats.truncated, true);
        assert.ok(Date.now() - started < 2_000, "budget stops the analysis quickly");
    });

    test("custom sources and sinks", () => {
        const r = analyze("const k = loadKey();\nfetchLog(k);", { sources: ["loadKey"], sinks: ["fetchLog"] });
        assert.deepEqual(r.findings, [{ destination: "fetchLog", line: 2, column: 0 }]);
    });
});

// These pin the prototype's CURRENT behavior for cases it does not model.
// They are not claims of correctness. If the analyzer is improved, these
// tests are expected to change.
describe("known limitations (current behavior pinned)", () => {
    test("reassignment is not tracked (missed flow)", () => {
        const r = analyze("let s = 'x';\ns = readPassword();\nconsole.log(s);");
        assert.deepEqual(r.findings, []);
    });

    test("reassignment does not clear taint (reported anyway)", () => {
        const r = analyze("let s = readPassword();\ns = 'x';\nconsole.log(s);");
        assert.deepEqual(sinks(r), ["console.log"]);
    });

    test("return inside a block is ignored (missed flow)", () => {
        const r = analyze("function f(v){ if (v) { return v; } return 1; }\nconst s = readPassword();\nconsole.log(f(s));");
        assert.deepEqual(r.findings, []);
    });

    test("arrow functions are treated as unknown (missed flow)", () => {
        const r = analyze("const f = (v) => v;\nconst s = readPassword();\nconsole.log(f(s));");
        assert.deepEqual(r.findings, []);
    });

    test("known function called as a statement inside another function (missed flow)", () => {
        const r = analyze("function a(v){ b(v); }\nfunction b(w){ console.log(w); }\nconst s = readPassword();\na(s);");
        assert.deepEqual(r.findings, []);
    });

    test("non-strict syntax is rejected because input is parsed as a module", () => {
        const r = analyze("with (o) { x(); }");
        assert.equal(r.ok, false);
    });
});

describe("coverage notes (separate from the analyzer)", () => {
    const cfg = { sources: ["readPassword"], sinks: ["console.log", "sendToServer"] };

    test("flags an unknown function call", () => {
        const notes = coverageNotes(DOCUMENTED_CASES[4].code, cfg);
        assert.equal(notes.length, 1);
        assert.equal(notes[0].kind, "unknown-call");
        assert.equal(notes[0].line, 2);
    });

    test("flags reassignment and nested returns", () => {
        assert.equal(coverageNotes("let s = 1;\ns = readPassword();", cfg)[0].kind, "reassignment");
        assert.equal(coverageNotes("function f(v){ if (v) return v; return 1; }", cfg)[0].kind, "nested-return");
    });

    test("stays quiet on fully modeled code", () => {
        for (const c of DOCUMENTED_CASES.slice(0, 4)) {
            assert.deepEqual(coverageNotes(c.code, cfg), [], `case ${c.id}`);
        }
    });
});
