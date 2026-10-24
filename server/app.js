import express from "express";
import cors from "cors";
import helmet from "helmet";
import { rateLimit } from "express-rate-limit";
import { fileURLToPath } from "node:url";
import { performance } from "node:perf_hooks";

import { analyze, DEFAULT_SOURCES, DEFAULT_SINKS } from "../analyzer/analyzer.js";
import { runDocumentedCases } from "../analyzer/documented-cases.js";
import {
    createAnalysisRunner,
    AnalysisBusy,
    AnalysisTimeout,
    AnalysisFailed
} from "./run-analysis.js";

const WEBSITE_DIR = fileURLToPath(new URL("../website/", import.meta.url));
const VERSION = "1.0.0";

function apiError(res, status, type, message, extra = {}) {
    return res.status(status).json({ ok: false, error: { type, message, ...extra } });
}

export function createApp(config) {
    const app = express();
    const runner = createAnalysisRunner(config);

    app.disable("x-powered-by");
    if (config.trustProxy) app.set("trust proxy", config.trustProxy);

    app.use(helmet({
        contentSecurityPolicy: {
            useDefaults: true,
            directives: {
                "script-src": ["'self'"],
                "style-src": ["'self'", "https://fonts.googleapis.com"],
                "font-src": ["'self'", "https://fonts.gstatic.com"],
                "connect-src": ["'self'"],
                "img-src": ["'self'", "data:"]
            }
        },
        crossOriginResourcePolicy: { policy: "same-site" }
    }));

    // CORS: only configured origins (e.g. the GitHub Pages site) may call the API
    // from a browser. Requests without an Origin header (curl, same-origin) pass.
    const allowed = new Set(config.allowedOrigins);
    app.use("/api", cors({
        origin(origin, callback) {
            callback(null, !origin || allowed.has(origin));
        },
        methods: ["GET", "POST"],
        allowedHeaders: ["Content-Type"],
        maxAge: 600
    }));

    // Submitted code is never logged or stored, so there is no request logger here.

    app.get("/api/health", (req, res) => {
        res.json({
            status: "ok",
            version: VERSION,
            analyzer: { sources: DEFAULT_SOURCES, sinks: DEFAULT_SINKS },
            limits: {
                maxCodeChars: config.maxCodeChars,
                maxSteps: config.maxSteps,
                timeoutMs: config.timeoutMs
            }
        });
    });

    // Runs the documented cases through the analyzer at request time,
    // so the results shown on the website are observed, not hardcoded.
    app.get("/api/tests", (req, res) => {
        const results = runDocumentedCases(code => analyze(code, { maxSteps: config.maxSteps }));
        res.json({
            ok: true,
            ranAt: new Date().toISOString(),
            summary: {
                passed: results.filter(r => r.status === "passed").length,
                failed: results.filter(r => r.status === "failed").length,
                limitations: results.filter(r => r.status === "limitation").length
            },
            results
        });
    });

    const analyzeLimiter = rateLimit({
        windowMs: config.rateLimitWindowMs,
        limit: config.rateLimitMax,
        standardHeaders: "draft-8",
        legacyHeaders: false,
        handler: (req, res) => apiError(res, 429, "RateLimited",
            "Too many analysis requests. Wait a minute and try again.")
    });

    app.post(
        "/api/analyze",
        analyzeLimiter,
        (req, res, next) => {
            if (!req.is("application/json")) {
                return apiError(res, 415, "UnsupportedMediaType",
                    "Send the request body as JSON with Content-Type: application/json.");
            }
            next();
        },
        express.json({ limit: config.bodyLimit, strict: true }),
        async (req, res, next) => {
            const body = req.body;

            if (!body || typeof body !== "object" || Array.isArray(body)) {
                return apiError(res, 400, "BadRequest", 'Body must be a JSON object like {"code": "..."}.');
            }
            if (!("code" in body)) {
                return apiError(res, 400, "BadRequest", 'Missing required field "code".');
            }
            if (typeof body.code !== "string") {
                return apiError(res, 400, "BadRequest", 'Field "code" must be a string.');
            }
            if (body.code.trim() === "") {
                return apiError(res, 400, "BadRequest", 'Field "code" is empty. Paste some JavaScript to analyze.');
            }
            if (body.code.length > config.maxCodeChars) {
                return apiError(res, 413, "PayloadTooLarge",
                    `Code is ${body.code.length} characters; the limit is ${config.maxCodeChars}.`,
                    { limit: config.maxCodeChars });
            }

            const started = performance.now();
            try {
                const result = await runner.run(body.code);
                const durationMs = Math.round(performance.now() - started);

                if (!result.ok) {
                    return res.status(422).json({ ok: false, error: result.error, durationMs });
                }

                return res.json({
                    ok: true,
                    findingCount: result.findings.length,
                    findings: result.findings,
                    taintedVariables: result.taintedVariables,
                    truncated: result.stats.truncated,
                    stats: result.stats,
                    coverageNotes: result.coverageNotes ?? [],
                    config: { sources: DEFAULT_SOURCES, sinks: DEFAULT_SINKS },
                    durationMs
                });
            } catch (err) {
                if (err instanceof AnalysisBusy) {
                    res.set("Retry-After", "2");
                    return apiError(res, 503, "Busy", "The analyzer is busy. Try again in a moment.");
                }
                if (err instanceof AnalysisTimeout) {
                    return apiError(res, 504, "AnalysisTimeout",
                        `Analysis took longer than ${config.timeoutMs} ms and was stopped.`);
                }
                if (err instanceof AnalysisFailed) {
                    return apiError(res, 500, "AnalysisFailed", err.message);
                }
                return next(err);
            }
        }
    );

    app.use("/api", (req, res) => apiError(res, 404, "NotFound", `No API route for ${req.method} ${req.path}.`));

    // Local development convenience: serve the website from the same origin.
    if (config.serveWebsite) {
         app.use(express.static(WEBSITE_DIR, { index: "index.html", extensions: ["html"] }));
       } else {
           app.get("/", (req, res) => {
               res.json({ name: "JS Info Flow API", status: "ok", health: "/api/health" });
           });
       }

    // Error handler (body-parser errors and anything unexpected).
    // eslint-disable-next-line no-unused-vars
    app.use((err, req, res, next) => {
        if (err.type === "entity.too.large") {
            return apiError(res, 413, "PayloadTooLarge",
                `Request body exceeds the ${config.bodyLimit} limit.`);
        }
        if (err.type === "entity.parse.failed") {
            return apiError(res, 400, "BadRequest", "Request body is not valid JSON.");
        }
        if (err.type === "encoding.unsupported" || err.type === "charset.unsupported") {
            return apiError(res, 415, "UnsupportedMediaType", "Unsupported request encoding.");
        }
        console.error("Unhandled error:", err.name, err.message);
        return apiError(res, 500, "InternalError", "Unexpected server error.");
    });

    return app;
}
