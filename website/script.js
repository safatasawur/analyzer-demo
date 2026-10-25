"use strict";

(() => {
    // ------------------------------------------------------------------
    // Configuration
    // ------------------------------------------------------------------
    const CFG = window.JSIF_CONFIG || {};
    const API_BASE = (CFG.API_BASE_URL || "").replace(/\/+$/, "");
    const GITHUB_URL = CFG.GITHUB_URL || "";
    const ON_STATIC_HOST = /\.github\.io$/i.test(location.hostname) || location.protocol === "file:";
    const API_CONFIGURED = Boolean(API_BASE) || !ON_STATIC_HOST;
    const REQUEST_TIMEOUT_MS = 70_000; // free hosts can take ~60 s to wake up
    const SLOW_HINT_MS = 4_000;

    // ------------------------------------------------------------------
    // Content
    // ------------------------------------------------------------------
    const EXAMPLES = [
        {
            id: "a",
            label: "A. Sensitive data reaches a sink",
            expectation: "Expected (test-cases.md #1): a finding for console.log.",
            code: `const secret = readPassword();
console.log(secret);
`
        },
        {
            id: "b",
            label: "B. Intermediate variable",
            expectation: "Expected (test-cases.md #2): a finding for console.log through copy.",
            code: `const secret = readPassword();
const copy = secret;
console.log(copy);
`
        },
        {
            id: "c",
            label: "C. Constant return",
            expectation: "Expected (test-cases.md #4): no finding, because formatMessage returns a constant.",
            code: `function formatMessage(value) {
    return "Hello, world!";
}

const secret = readPassword();
const message = formatMessage(secret);
console.log(message);
`
        },
        {
            id: "d",
            label: "D. Helper function with sinks",
            expectation: "Expected (test-cases.md #3): findings for sendToServer and console.log.",
            code: `function sendToServer(value) {
    const copy = value;
    console.log(copy);
}

const secret = readPassword();
sendToServer(secret);
`
        },
        {
            id: "e",
            label: "E. Unknown function (limitation)",
            expectation: "Documented limitation (test-cases.md #5): unknown functions are not modeled.",
            code: `const secret = readPassword();
unknownFunction(secret);
`
        },
        {
            id: "f",
            label: "F. Reassignment (known gap)",
            expectation: "Known gap: reassignment is not tracked, so this real flow is missed.",
            code: `let token = "placeholder";
token = getUserToken();
sendToServer(token);
`
        }
    ];

    const LIMITATIONS = [
        { text: "Only top-level function declarations are analyzed. Arrow functions, function expressions, methods and nested functions are treated as unknown.", example: `const forward = (value) => value;\nconst secret = readPassword();\nconsole.log(forward(secret));\n` },
        { text: "Reassignment (x = ...) is ignored. Taint is set only by declarations, so later assignments neither add nor remove it.", example: "f" },
        { text: "Only the first top-level return in a function body counts. Returns inside if, loops or try blocks are not used.", example: `function pick(value, flag) {\n    if (flag) {\n        return value;\n    }\n    return "safe";\n}\n\nconst secret = readPassword();\nconsole.log(pick(secret, true));\n` },
        { text: "Calls to unknown functions are not followed, and their return values are treated as clean.", example: "e" },
        { text: "A known function called as a plain statement inside another function is not analyzed, so sinks inside it can be missed.", example: `function outer(value) {\n    inner(value);\n}\n\nfunction inner(value) {\n    console.log(value);\n}\n\nconst secret = readPassword();\nouter(secret);\n` },
        { text: "Control flow is not modeled: branches and loops are read as straight-line code, with no path sensitivity." },
        { text: "Objects are tracked as a whole: one tainted property taints the entire object. Destructuring is skipped." },
        { text: "No modeling of async code, Promises, callbacks, classes, closures, the DOM or other browser APIs." },
        { text: "Sources and sinks are a fixed list matched by name. A finding records the sink and line, not which source it came from." },
        { text: "Analysis stops after a fixed step budget. Results are then marked incomplete instead of being reported as clean." }
    ];

    // ------------------------------------------------------------------
    // DOM helpers (all text goes through textContent; no innerHTML)
    // ------------------------------------------------------------------
    const $ = sel => document.querySelector(sel);

    function el(tag, attrs = {}, ...children) {
        const node = document.createElement(tag);
        for (const [key, value] of Object.entries(attrs)) {
            if (value === undefined || value === null || value === false) continue;
            if (key === "class") node.className = value;
            else if (key === "text") node.textContent = value;
            else if (key.startsWith("on") && typeof value === "function") node.addEventListener(key.slice(2), value);
            else node.setAttribute(key, value === true ? "" : String(value));
        }
        for (const child of children.flat()) {
            if (child === null || child === undefined || child === false) continue;
            node.append(child instanceof Node ? child : document.createTextNode(String(child)));
        }
        return node;
    }

    const code = s => el("code", { text: s });

    // ------------------------------------------------------------------
    // API client
    // ------------------------------------------------------------------
    class ApiError extends Error {
        constructor(kind, message, extra = {}) {
            super(message);
            this.kind = kind;
            Object.assign(this, extra);
        }
    }

    async function api(path, options = {}, onSlow) {
        if (!API_CONFIGURED) {
            throw new ApiError("not-configured",
                "No backend is configured for this site. Set API_BASE_URL in website/config.js.");
        }
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
        const slowTimer = onSlow ? setTimeout(onSlow, SLOW_HINT_MS) : null;

        let res;
        try {
            res = await fetch(API_BASE + path, { ...options, signal: controller.signal });
        } catch (err) {
            if (err.name === "AbortError") {
                throw new ApiError("network", `The backend did not respond within ${REQUEST_TIMEOUT_MS / 1000} s.`);
            }
            throw new ApiError("network", "Could not reach the backend. It may be offline, or blocked by CORS.");
        } finally {
            clearTimeout(timer);
            if (slowTimer) clearTimeout(slowTimer);
        }

        let body = null;
        try { body = await res.json(); } catch { /* non-JSON response */ }

        if (!body || typeof body !== "object") {
            throw new ApiError("http", `The backend returned HTTP ${res.status} without a JSON body.`, { status: res.status });
        }
        return { status: res.status, body };
    }

    const analyzeRequest = (source, onSlow) => api("/api/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ code: source })
    }, onSlow);

    // ------------------------------------------------------------------
    // Editor
    // ------------------------------------------------------------------
    const textarea = $("#code");
    const gutter = $("#gutter");
    const select = $("#example-select");
    const expectationEl = $("#expectation");
    const charCount = $("#char-count");
    let marks = new Map(); // line -> class
    let currentExample = EXAMPLES[0];
    let lastAnalyzedCode = null;
    let maxChars = 10_000;

    function renderGutter() {
        const count = Math.max(1, textarea.value.split("\n").length);
        const frag = document.createDocumentFragment();
        for (let i = 1; i <= count; i++) {
            const div = el("div", { class: marks.get(i) || null, text: String(i) });
            frag.append(div);
        }
        gutter.replaceChildren(frag);
        gutter.scrollTop = textarea.scrollTop;
        const n = textarea.value.length;
        charCount.textContent = ` ${n.toLocaleString()} / ${maxChars.toLocaleString()} characters.`;
        charCount.className = n > maxChars ? "t-err" : "";
    }

    function setMarks(next) {
        marks = next;
        renderGutter();
    }

    function loadExample(id) {
        const example = EXAMPLES.find(e => e.id === id) || EXAMPLES[0];
        currentExample = example;
        select.value = example.id;
        textarea.value = example.code;
        expectationEl.replaceChildren(el("b", { text: "Expected, not a result. " }), example.expectation);
        setMarks(new Map());
        return example;
    }

    function loadCustom(source, note) {
        select.value = "custom";
        textarea.value = source;
        expectationEl.textContent = note || "";
        setMarks(new Map());
    }

    function jumpToLine(line) {
        const lines = textarea.value.split("\n");
        let offset = 0;
        for (let i = 0; i < line - 1 && i < lines.length; i++) offset += lines[i].length + 1;
        textarea.focus();
        textarea.setSelectionRange(offset, offset + (lines[line - 1] || "").length);
        const lineHeight = parseFloat(getComputedStyle(textarea).lineHeight) || 22;
        textarea.scrollTop = Math.max(0, (line - 3) * lineHeight);
    }

    for (const example of EXAMPLES) {
        select.append(el("option", { value: example.id, text: example.label }));
    }
    select.append(el("option", { value: "custom", text: "Custom code" }));

    select.addEventListener("change", () => {
        if (select.value !== "custom") loadExample(select.value);
    });
    textarea.addEventListener("input", () => {
        if (marks.size) marks = new Map();
        if (select.value !== "custom" && textarea.value !== currentExample.code) {
            select.value = "custom";
            expectationEl.textContent = "Edited code. Results reflect only what the analyzer returns.";
        }
        renderGutter();
        markStale();
    });
    textarea.addEventListener("scroll", () => { gutter.scrollTop = textarea.scrollTop; });

    let escaped = false;
    textarea.addEventListener("keydown", e => {
        if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
            e.preventDefault();
            runAnalysis("editor");
            return;
        }
        if (e.key === "Escape") { escaped = true; return; }
        if (e.key === "Tab" && !escaped && !e.shiftKey) {
            e.preventDefault();
            const { selectionStart: s, selectionEnd: end } = textarea;
            textarea.setRangeText("    ", s, end, "end");
            textarea.dispatchEvent(new Event("input"));
            return;
        }
        escaped = false;
    });

    $("#reset-btn").addEventListener("click", () => {
        const id = select.value === "custom" ? currentExample.id : select.value;
        loadExample(id);
        resetResults();
    });
    $("#analyze-btn").addEventListener("click", () => runAnalysis("button"));

    // ------------------------------------------------------------------
    // Results panel
    // ------------------------------------------------------------------
    const resultsEl = $("#results");
    const analyzeBtn = $("#analyze-btn");

    function resetResults() {
        lastAnalyzedCode = null;
        resultsEl.replaceChildren(el("div", { class: "results-empty" },
            el("p", { class: "r-title", text: "Results will appear here" }),
            el("p", { text: "Press Analyze to check the code on the left." })));
    }

    function markStale() {
        if (lastAnalyzedCode === null || textarea.value === lastAnalyzedCode) {
            $("#stale-note")?.remove();
            return;
        }
        if (!$("#stale-note")) {
            resultsEl.prepend(el("div", { id: "stale-note", class: "r-warn",
                text: "The code has changed since this analysis. Analyze again to update the results." }));
        }
    }

    function showLoading(message = "Analyzing on the server") {
        resultsEl.setAttribute("aria-busy", "true");
        resultsEl.replaceChildren(el("div", { class: "loading" },
            el("p", { class: "r-title" }, el("span", { class: "spinner", "aria-hidden": "true" }), " ", message),
            el("p", { class: "muted", id: "slow-hint" })));
    }

    function slowHint() {
        const hint = $("#slow-hint");
        if (hint) hint.textContent = "Still waiting. If the backend is on a free host it may be waking up, which can take up to a minute.";
    }

    function renderSuccess(body) {
        const { findings, findingCount, truncated, taintedVariables, stats, coverageNotes = [], durationMs } = body;
        const nodes = [];

        let badge;
        let title;
        if (truncated) {
            badge = el("span", { class: "r-badge partial", text: "incomplete" });
            title = findingCount
                ? `${findingCount} potential flow${findingCount === 1 ? "" : "s"} before the analysis stopped`
                : "Analysis stopped before finishing";
        } else if (findingCount > 0) {
            badge = el("span", { class: "r-badge found", text: `${findingCount} finding${findingCount === 1 ? "" : "s"}` });
            title = `${findingCount} potential flow${findingCount === 1 ? "" : "s"} to a sink`;
        } else {
            badge = el("span", { class: "r-badge none", text: "0 findings" });
            title = "No flows found under the analyzer's rules";
        }

        nodes.push(el("div", { class: "r-status" }, badge, el("span", { class: "fine", text: "parsed successfully" })));
        nodes.push(el("p", { class: "r-title", text: title }));
        nodes.push(el("p", { class: "r-sub", text: `${stats.steps.toLocaleString()} analysis steps, ${durationMs} ms round trip on the server` }));

        if (truncated) {
            nodes.push(el("div", { class: "r-warn" },
                `The analyzer reached its budget of ${stats.maxSteps.toLocaleString()} steps and stopped. `,
                "Any findings shown are partial, and a missing finding here means nothing about the code."));
        }

        if (findingCount > 0) {
            const list = el("ul", { class: "findings" });
            findings.forEach(f => {
                list.append(el("li", { class: "finding" },
                    el("div", { class: "finding-head" },
                        el("span", { class: "finding-sink", text: f.destination }),
                        el("span", { class: "finding-loc" },
                            el("button", { type: "button", text: `line ${f.line}, col ${f.column + 1}`, onclick: () => jumpToLine(f.line) }))),
                    el("p", {}, "A value the analyzer tracks as sensitive is passed to ", code(f.destination), ", a configured sink."),
                    el("p", { class: "src", text: "Source: not reported. The analyzer records where the data ends up, not which source call it came from." })));
            });
            nodes.push(list);
        } else if (!truncated) {
            nodes.push(el("p", {},
                "No configured source reached a configured sink in the cases this prototype models. ",
                el("strong", { text: "That is not evidence the code is safe." })));
        }

        if (coverageNotes.length) {
            const notes = el("ul", { class: "notes" });
            coverageNotes.forEach(n => notes.append(el("li", {},
                el("span", { class: "ln", text: n.line ? `L${n.line}` : "" }),
                el("span", { text: n.message }))));
            nodes.push(el("div", { class: "r-block" },
                el("h3", { text: "Not modeled in this code" }),
                el("p", { class: "fine", text: "A separate scan for constructs the analyzer ignores. It does not change the findings above; it shows where they may be incomplete." }),
                notes));
        }

        nodes.push(el("div", { class: "r-block" },
            el("dl", { class: "kv" },
                el("dt", { text: "tainted (top level)" }),
                el("dd", { text: taintedVariables.length ? taintedVariables.join(", ") : "none" }),
                el("dt", { text: "sources" }), el("dd", { text: body.config.sources.join(", ") }),
                el("dt", { text: "sinks" }), el("dd", { text: body.config.sinks.join(", ") }))));

        nodes.push(el("p", { class: "disclaimer", text: "Findings are potential information flows under the prototype's rules, not confirmed vulnerabilities." }));

        resultsEl.replaceChildren(...nodes);

        const nextMarks = new Map();
        coverageNotes.forEach(n => n.line && nextMarks.set(n.line, "note"));
        findings.forEach(f => nextMarks.set(f.line, "hit"));
        setMarks(nextMarks);
    }

    function renderSyntaxError(error) {
        const where = error.line ? `line ${error.line}, col ${(error.column ?? 0) + 1}` : "unknown position";
        resultsEl.replaceChildren(
            el("div", { class: "r-status" }, el("span", { class: "r-badge bad", text: "parse error" })),
            el("p", { class: "r-title", text: "This is not valid JavaScript" }),
            el("p", { class: "r-sub", text: `Acorn could not parse it at ${where}. Nothing was analyzed.` }),
            // Acorn appends a 0-based "(line:col)"; the position is shown 1-based above.
            el("div", { class: "r-error", text: error.message.replace(/\s*\(\d+:\d+\)\s*$/, "") }),
            el("p", { class: "fine" }, "The parser expects modern JavaScript in module (strict) mode, so constructs like ", code("with"), " are rejected."));
        if (error.line) {
            setMarks(new Map([[error.line, "bad"]]));
            jumpToLine(error.line);
        }
    }

    function renderFailure(title, message, hint) {
        resultsEl.replaceChildren(
            el("div", { class: "r-status" }, el("span", { class: "r-badge bad", text: "no result" })),
            el("p", { class: "r-title", text: title }),
            el("div", { class: "r-error", text: message }),
            hint ? el("p", { class: "fine", text: hint }) : null);
        setMarks(new Map());
    }

    const FAILURE_COPY = {
        BadRequest: ["The request was rejected", null],
        PayloadTooLarge: ["The code is too long", "Shorten the program and try again."],
        UnsupportedMediaType: ["The request was rejected", null],
        RateLimited: ["Too many requests", "The backend allows a limited number of analyses per minute."],
        Busy: ["The analyzer is busy", "Try again in a moment."],
        AnalysisTimeout: ["The analysis took too long", "Very large or deeply nested programs can exceed the time limit."],
        AnalysisFailed: ["The analyzer could not process this input", null],
        InternalError: ["Backend error", null]
    };

    let inFlight = false;

    async function runAnalysis(origin) {
        if (inFlight) return null;
        const source = textarea.value;

        if (!source.trim()) {
            renderFailure("Nothing to analyze", "The editor is empty.", "Pick an example or paste some JavaScript.");
            return { kind: "empty" };
        }

        inFlight = true;
        analyzeBtn.disabled = true;
        showLoading();
        if (origin !== "terminal") termEcho("analyze --run", true);

        let outcome;
        try {
            const { status, body } = await analyzeRequest(source, slowHint);
            lastAnalyzedCode = source;
            if (status === 200 && body.ok) {
                renderSuccess(body);
                outcome = { kind: "ok", body };
            } else if (status === 422 && body.error?.type === "SyntaxError") {
                renderSyntaxError(body.error);
                outcome = { kind: "syntax", error: body.error };
            } else {
                const type = body.error?.type || "InternalError";
                const [title, hint] = FAILURE_COPY[type] || [`Backend error (HTTP ${status})`, null];
                renderFailure(title, body.error?.message || `HTTP ${status}`, hint);
                outcome = { kind: "http", status, error: body.error };
            }
        } catch (err) {
            const notConfigured = err.kind === "not-configured";
            renderFailure(notConfigured ? "Backend not configured" : "Could not reach the backend", err.message,
                notConfigured ? null : "Check the API status in the terminal header, or try again shortly.");
            outcome = { kind: "network", message: err.message };
        } finally {
            inFlight = false;
            analyzeBtn.disabled = false;
            resultsEl.setAttribute("aria-busy", "false");
        }

        if (origin !== "terminal") summarizeInTerminal(outcome);
        return outcome;
    }

    // ------------------------------------------------------------------
    // Terminal
    // ------------------------------------------------------------------
    const log = $("#terminal-log");
    const termBody = $("#terminal-body");
    const input = $("#prompt-input");
    const history = [];
    let historyIndex = 0;

    function print(...lines) {
        for (const line of lines) {
            if (line instanceof Node) log.append(line);
            else log.append(el("div", { class: "entry t-out", text: line }));
        }
        termBody.scrollTop = termBody.scrollHeight;
    }
    const out = (text, cls = "t-out") => el("div", { class: `entry ${cls}`, text });
    const row = (k, v, cls = "") => el("div", { class: `t-row ${cls}` }, el("span", { class: "t-accent", text: k }), el("span", { text: v }));
    const block = (...kids) => el("div", { class: "entry" }, ...kids);

    function termEcho(command, external = false) {
        print(el("div", { class: "entry t-cmd" },
            el("span", { class: "p-user", text: "visitor" }), el("span", { class: "p-at", text: "@" }),
            el("span", { class: "p-host", text: "js-info-flow" }), el("span", { class: "p-path", text: ":~$ " }),
            el("span", { text: command }),
            external ? el("span", { class: "t-dim", text: "   (from playground)" }) : null));
    }

    function summarizeInTerminal(outcome) {
        if (!outcome) return;
        switch (outcome.kind) {
            case "ok": {
                const b = outcome.body;
                if (b.truncated) {
                    print(out(`! analysis incomplete: stopped at the ${b.stats.maxSteps.toLocaleString()}-step budget (${b.findingCount} partial findings)`, "t-warn"));
                } else if (b.findingCount === 0) {
                    print(out("0 findings. No modeled flow from a source to a sink. Not proof of safety.", "t-ok"));
                } else {
                    print(out(`${b.findingCount} potential flow${b.findingCount === 1 ? "" : "s"}:`, "t-warn"));
                    print(block(...b.findings.map(f => row(`  ${f.destination}`, `line ${f.line}, col ${f.column + 1}`))));
                }
                if (b.coverageNotes?.length) {
                    print(out(`${b.coverageNotes.length} construct${b.coverageNotes.length === 1 ? "" : "s"} not modeled. See the playground for details.`, "t-dim"));
                }
                break;
            }
            case "syntax":
                print(out(`parse error at line ${outcome.error.line}, col ${(outcome.error.column ?? 0) + 1}: ${outcome.error.message.replace(/\s*\(\d+:\d+\)\s*$/, "")}`, "t-err"));
                break;
            case "http":
                print(out(`error ${outcome.status}: ${outcome.error?.message || "request failed"}`, "t-err"));
                break;
            case "network":
                print(out(`error: ${outcome.message}`, "t-err"));
                break;
            case "empty":
                print(out("error: the editor is empty", "t-err"));
                break;
        }
    }

    function scrollToSection(id) {
        document.getElementById(id)?.scrollIntoView({ block: "start" });
    }

    const COMMANDS = {
        help: {
            desc: "list commands",
            run() {
                print(block(...Object.entries(COMMANDS)
                    .filter(([, c]) => !c.hidden)
                    .map(([name, c]) => row(c.usage || name, c.desc))));
                print(out("Up/Down browse history, Tab completes, Ctrl+L clears.", "t-dim"));
            }
        },
        about: {
            desc: "what this project is",
            run() {
                print(
                    out("JS Info Flow is an exploratory static information-flow analyzer for JavaScript."),
                    out("It parses code with Acorn and follows data from configured sources (e.g. readPassword()) through variables, parameters and returns to configured sinks (console.log, sendToServer)."),
                    out("It is a learning and research-preparation prototype, not a production security tool.", "t-dim"),
                    out("This terminal is part of the website. It is not a shell and cannot run system commands.", "t-dim"));
            }
        },
        demo: {
            usage: "demo [a-f]",
            desc: "load an example and analyze it on the server",
            async run(args) {
                const id = (args[0] || "a").toLowerCase();
                if (!EXAMPLES.some(e => e.id === id)) {
                    print(out(`unknown example "${id}". Available: ${EXAMPLES.map(e => e.id).join(", ")}. Try "examples".`, "t-err"));
                    return;
                }
                const example = loadExample(id);
                print(out(`loaded ${example.label}`, "t-dim"));
                print(out(example.expectation, "t-dim"));
                print(out("sending to POST /api/analyze ...", "t-dim"));
                const outcome = await runAnalysis("terminal");
                summarizeInTerminal(outcome);
            }
        },
        examples: {
            desc: "list example programs",
            run() {
                print(block(...EXAMPLES.map(e => row(`  ${e.id}`, e.label.replace(/^[A-F]\.\s*/, "")))));
                print(out('Run one with "demo b", for example.', "t-dim"));
            }
        },
        analyze: {
            usage: "analyze [--run]",
            desc: "focus the playground (--run analyzes its current code)",
            async run(args) {
                scrollToSection("playground");
                if (args.includes("--run")) {
                    print(out("sending playground code to POST /api/analyze ...", "t-dim"));
                    summarizeInTerminal(await runAnalysis("terminal"));
                } else {
                    textarea.focus({ preventScroll: true });
                    print(out("Playground focused. Edit the code and press Ctrl+Enter, or run \"analyze --run\".", "t-dim"));
                }
            }
        },
        tests: {
            desc: "run the documented test cases on the server",
            async run() {
                print(out("GET /api/tests ...", "t-dim"));
                const data = await loadTests();
                if (!data) return;
                print(block(...data.results.map(r => row(`  #${r.id} ${r.status}`, r.title,
                    r.status === "passed" ? "t-ok" : r.status === "failed" ? "t-err" : "t-warn"))));
                print(out(`${data.summary.passed} passed, ${data.summary.failed} failed, ${data.summary.limitations} documented limitation. Executed just now on the server.`, "t-dim"));
            }
        },
        limitations: {
            desc: "known limitations of the prototype",
            run() {
                LIMITATIONS.forEach(l => print(out(`- ${l.text}`)));
                print(out("Details and runnable examples are in the Limitations section.", "t-dim"));
            }
        },
        health: {
            desc: "check the backend",
            async run() {
                print(out(`GET ${API_BASE || location.origin}/api/health ...`, "t-dim"));
                const data = await checkHealth();
                if (data) {
                    print(row("  status", data.status, "t-ok"), row("  version", data.version),
                        row("  max code", `${data.limits.maxCodeChars.toLocaleString()} chars`),
                        row("  step budget", data.limits.maxSteps.toLocaleString()),
                        row("  timeout", `${data.limits.timeoutMs} ms`));
                }
            }
        },
        github: {
            desc: "open the source repository",
            run() {
                if (!GITHUB_URL) {
                    print(out("The repository link has not been configured yet (GITHUB_URL in website/config.js).", "t-warn"));
                    return;
                }
                print(out(`opening ${GITHUB_URL}`, "t-dim"));
                window.open(GITHUB_URL, "_blank", "noopener");
            }
        },
        clear: {
            desc: "clear the terminal (does not reset anything else)",
            run() { log.replaceChildren(); }
        }
    };

    const NOT_A_SHELL = new Set(["ls", "cd", "cat", "rm", "sudo", "pwd", "whoami", "bash", "sh", "node", "npm", "curl", "exit", "vim", "nano"]);

    function closest(name) {
        const names = Object.keys(COMMANDS);
        return names.find(n => n.startsWith(name.slice(0, 2))) || null;
    }

    async function execute(line) {
        const trimmed = line.trim();
        termEcho(trimmed);
        if (!trimmed) return;

        history.push(trimmed);
        historyIndex = history.length;

        const [name, ...args] = trimmed.split(/\s+/);
        const command = COMMANDS[name.toLowerCase()];

        if (command) {
            input.disabled = true;
            try {
                await command.run(args);
            } catch (err) {
                print(out(`error: ${err.message}`, "t-err"));
            } finally {
                input.disabled = false;
                input.focus({ preventScroll: true });
            }
            return;
        }

        if (NOT_A_SHELL.has(name.toLowerCase())) {
            print(out(`${name}: this is a website terminal, not a shell. There is no filesystem or OS here. Type "help".`, "t-warn"));
            return;
        }
        const guess = closest(name.toLowerCase());
        print(out(`command not found: ${name}.${guess ? ` Did you mean "${guess}"?` : ""} Type "help" for the list.`, "t-err"));
    }

    $("#prompt-form").addEventListener("submit", e => {
        e.preventDefault();
        const value = input.value;
        input.value = "";
        execute(value);
    });

    input.addEventListener("keydown", e => {
        if (e.key === "ArrowUp") {
            if (!history.length) return;
            e.preventDefault();
            historyIndex = Math.max(0, historyIndex - 1);
            input.value = history[historyIndex];
        } else if (e.key === "ArrowDown") {
            if (!history.length) return;
            e.preventDefault();
            historyIndex = Math.min(history.length, historyIndex + 1);
            input.value = history[historyIndex] ?? "";
        } else if (e.key === "Tab" && input.value.trim() && !input.value.includes(" ")) {
            const matches = Object.keys(COMMANDS).filter(n => n.startsWith(input.value.trim().toLowerCase()));
            if (matches.length === 1) {
                e.preventDefault();
                input.value = matches[0] + " ";
            } else if (matches.length > 1) {
                e.preventDefault();
                print(out(matches.join("   "), "t-dim"));
            }
        } else if (e.key === "l" && e.ctrlKey) {
            e.preventDefault();
            log.replaceChildren();
        }
    });

    document.querySelectorAll(".quick-btn").forEach(btn => {
        btn.addEventListener("click", () => {
            if (input.disabled) return;
            execute(btn.dataset.cmd);
        });
    });

    termBody.addEventListener("click", () => {
        if (!window.getSelection()?.toString()) input.focus({ preventScroll: true });
    });

    // ------------------------------------------------------------------
    // Tests section
    // ------------------------------------------------------------------
    const testsBody = $("#tests-body");
    const testsMeta = $("#tests-meta");
    const runTestsBtn = $("#run-tests-btn");

    function describeObserved(r) {
        if (r.observed.error) return `parse error: ${r.observed.error.message}`;
        if (!r.observed.findings.length) return "no findings";
        return r.observed.findings.map(f => `${f.destination} @ line ${f.line}`).join(", ");
    }

    async function loadTests() {
        runTestsBtn.disabled = true;
        testsMeta.textContent = "Running on the server...";
        try {
            const { status, body } = await api("/api/tests");
            if (status !== 200 || !body.ok) throw new ApiError("http", body.error?.message || `HTTP ${status}`);
            testsBody.replaceChildren(...body.results.map(r => el("tr", {},
                el("td", { class: "num", text: String(r.id) }),
                el("td", {}, el("button", {
                    type: "button", class: "link", text: r.title,
                    title: "Load this case into the playground",
                    onclick: () => { loadCustom(r.code + "\n", `Documented case #${r.id}. Expected: ${r.expected}.`); scrollToSection("playground"); }
                })),
                el("td", { text: r.expected }),
                el("td", {}, el("span", { class: "obs", text: describeObserved(r) })),
                el("td", {}, el("span", { class: `status ${r.status}`, text: r.status === "limitation" ? "limitation documented" : r.status })))));
            const when = new Date(body.ranAt).toLocaleTimeString();
            testsMeta.textContent = `${body.summary.passed} passed, ${body.summary.failed} failed, ${body.summary.limitations} limitation. Executed on the server at ${when}.`;
            return body;
        } catch (err) {
            testsMeta.textContent = "";
            testsBody.replaceChildren(el("tr", {}, el("td", { colspan: "5", class: "t-err", text: `Could not run the cases: ${err.message}` })));
            print(out(`error: ${err.message}`, "t-err"));
            return null;
        } finally {
            runTestsBtn.disabled = false;
        }
    }
    runTestsBtn.addEventListener("click", loadTests);

    // ------------------------------------------------------------------
    // Limitations section
    // ------------------------------------------------------------------
    const limList = $("#lim-list");
    LIMITATIONS.forEach(l => {
        const item = el("li", {}, l.text);
        if (l.example) {
            item.append(el("button", {
                type: "button", class: "link", text: "try it",
                onclick: () => {
                    if (EXAMPLES.some(e => e.id === l.example)) loadExample(l.example);
                    else loadCustom(l.example, "Limitation example. Compare the analyzer's output with what the code actually does.");
                    scrollToSection("playground");
                    textarea.focus({ preventScroll: true });
                }
            }));
        }
        limList.append(item);
    });

    // ------------------------------------------------------------------
    // Health / config
    // ------------------------------------------------------------------
    const pill = $("#api-pill");

    async function checkHealth() {
        try {
            const { status, body } = await api("/api/health");
            if (status !== 200 || body.status !== "ok") throw new ApiError("http", `HTTP ${status}`);
            pill.dataset.state = "up";
            pill.textContent = "api: online";
            maxChars = body.limits.maxCodeChars;
            renderGutter();
            $("#sources-list").replaceChildren(...body.analyzer.sources.map(s => el("li", { text: `${s}()` })));
            $("#sinks-list").replaceChildren(...body.analyzer.sinks.map(s => el("li", { text: `${s}()` })));
            $("#footer-api").textContent = `Backend ${API_BASE || location.origin} is online (v${body.version}).`;
            return body;
        } catch (err) {
            pill.dataset.state = "down";
            pill.textContent = err.kind === "not-configured" ? "api: not set" : "api: offline";
            $("#footer-api").textContent = err.message;
            for (const id of ["#sources-list", "#sinks-list"]) {
                $(id).replaceChildren(el("li", { class: "muted", text: "unavailable" }));
            }
            print(out(`backend: ${err.message}`, "t-err"));
            return null;
        }
    }

    // ------------------------------------------------------------------
    // Boot
    // ------------------------------------------------------------------
    const navGithub = $("#nav-github");
    if (GITHUB_URL) {
        navGithub.href = GITHUB_URL;
        navGithub.target = "_blank";
    } else {
        navGithub.addEventListener("click", e => {
            e.preventDefault();
            scrollToSection("top");
            execute("github");
        });
    }

    loadExample("a");
    print(
        out("Welcome to JS Info Flow, a JavaScript data-leak analyzer.", "t-accent"),
        out("This terminal controls the website. It is not a real system shell."),
        block(
            row("  help", "see every command"),
            row("  demo", "analyze an example program"),
            row("  analyze", "jump to the playground to test your own code")),
        out("Type a command below and press Enter, or click a button under the terminal.", "t-dim"));
    checkHealth();
    input.focus({ preventScroll: true });
})();
