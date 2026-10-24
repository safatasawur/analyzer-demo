// Runtime configuration, read once from environment variables.
// See .env.example and README.md for descriptions.

function int(name, fallback) {
    const raw = process.env[name];
    if (raw === undefined || raw === "") return fallback;
    const value = Number.parseInt(raw, 10);
    if (!Number.isFinite(value)) {
        throw new Error(`Environment variable ${name} must be an integer`);
    }
    return value;
}

function list(name, fallback) {
    const raw = process.env[name];
    if (!raw) return fallback;
    return raw.split(",").map(s => s.trim()).filter(Boolean);
}

export function loadConfig(overrides = {}) {
    const port = int("PORT", 3000);
    return {
        port,
        allowedOrigins: list("ALLOWED_ORIGINS", [`http://localhost:${port}`, `http://127.0.0.1:${port}`]),
        trustProxy: int("TRUST_PROXY", 0),
        serveWebsite: process.env.SERVE_WEBSITE !== "0",

        // Request limits
        bodyLimit: process.env.BODY_LIMIT || "32kb",
        maxCodeChars: int("MAX_CODE_CHARS", 10_000),

        // Analysis limits
        maxSteps: int("MAX_STEPS", 100_000),
        timeoutMs: int("ANALYSIS_TIMEOUT_MS", 3_000),
        maxConcurrent: int("MAX_CONCURRENT_ANALYSES", 4),

        // Rate limiting for POST /api/analyze
        rateLimitWindowMs: int("RATE_LIMIT_WINDOW_MS", 60_000),
        rateLimitMax: int("RATE_LIMIT_MAX", 30),

        ...overrides
    };
}
