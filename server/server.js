import { createApp } from "./app.js";
import { loadConfig } from "./config.js";

const config = loadConfig();
const app = createApp(config);

const server = app.listen(config.port, () => {
    console.log(`JS Info Flow API listening on http://localhost:${config.port}`);
    console.log(`Allowed origins: ${config.allowedOrigins.join(", ")}`);
    if (config.serveWebsite) {
        console.log(`Website: http://localhost:${config.port}/`);
    }
});

// Bound slow clients.
server.requestTimeout = 15_000;
server.headersTimeout = 10_000;

for (const signal of ["SIGINT", "SIGTERM"]) {
    process.on(signal, () => server.close(() => process.exit(0)));
}
