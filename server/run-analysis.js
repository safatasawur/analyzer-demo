import { Worker } from "node:worker_threads";

const WORKER_URL = new URL("./analysis-worker.js", import.meta.url);

export class AnalysisTimeout extends Error {}
export class AnalysisBusy extends Error {}
export class AnalysisFailed extends Error {}

/**
 * Creates a runner that executes analyses in short-lived worker threads
 * with a wall-clock timeout, memory limits and a concurrency cap.
 */
export function createAnalysisRunner({ timeoutMs, maxSteps, maxConcurrent }) {
    let active = 0;

    function run(code) {
        if (active >= maxConcurrent) {
            return Promise.reject(new AnalysisBusy("Too many analyses in progress"));
        }
        active += 1;

        return new Promise((resolve, reject) => {
            let settled = false;
            const worker = new Worker(WORKER_URL, {
                workerData: { code, maxSteps },
                resourceLimits: {
                    maxOldGenerationSizeMb: 64,
                    maxYoungGenerationSizeMb: 16,
                    stackSizeMb: 4
                },
                stdout: true,
                stderr: true
            });

            const finish = (fn, value) => {
                if (settled) return;
                settled = true;
                clearTimeout(timer);
                active -= 1;
                worker.terminate().catch(() => {});
                fn(value);
            };

            const timer = setTimeout(() => {
                finish(reject, new AnalysisTimeout(`Analysis exceeded ${timeoutMs} ms`));
            }, timeoutMs);

            worker.once("message", msg => {
                if (msg.kind === "result") finish(resolve, { ...msg.result, coverageNotes: msg.notes });
                else finish(reject, new AnalysisFailed(msg.message));
            });
            worker.once("error", err => {
                const message = err?.code === "ERR_WORKER_OUT_OF_MEMORY"
                    ? "The analyzer ran out of memory on this input."
                    : "The analyzer failed unexpectedly on this input.";
                finish(reject, new AnalysisFailed(message));
            });
            worker.once("exit", code => {
                finish(reject, new AnalysisFailed(`Analyzer worker exited (code ${code})`));
            });
        });
    }

    return { run, get active() { return active; } };
}
