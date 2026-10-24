// Runs one analysis inside a worker thread so the main server thread is
// never blocked and a runaway analysis can be terminated.
// The submitted code is only parsed by acorn. It is never executed.
import { parentPort, workerData } from "node:worker_threads";
import { analyze, DEFAULT_SOURCES, DEFAULT_SINKS } from "../analyzer/analyzer.js";
import { coverageNotes } from "../analyzer/coverage-notes.js";

const { code, maxSteps } = workerData;

try {
    const result = analyze(code, { maxSteps });
    const notes = result.ok
        ? coverageNotes(code, { sources: DEFAULT_SOURCES, sinks: DEFAULT_SINKS })
        : [];
    parentPort.postMessage({ kind: "result", result, notes });
} catch (err) {
    // e.g. RangeError (stack overflow) on extremely deeply nested input
    parentPort.postMessage({
        kind: "error",
        name: err?.name ?? "Error",
        message: err instanceof RangeError
            ? "Input is nested too deeply for the analyzer to process."
            : "The analyzer failed unexpectedly on this input."
    });
}
