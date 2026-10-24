// JS Info Flow analyzer.
//
// The analysis logic below (getCalleeName, getChildNodes, walk,
// containsTaintedData, analyzeFunctionCall and the two top-level passes)
// is the original prototype, unchanged. It has only been wrapped so it
// can be called repeatedly from a server:
//   - analyze(code) replaces the hardcoded input string
//   - state is created per call instead of at module level
//   - a step budget stops pathological inputs (results marked truncated)
//   - parse errors are returned as data instead of thrown
// Known analysis limitations are intentionally left as they are.
import * as acorn from "acorn";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

// 1. Default sources and sinks.
export const DEFAULT_SOURCES = Object.freeze([
    "getSensitiveData",
    "readPassword",
    "getUserToken"
]);

export const DEFAULT_SINKS = Object.freeze([
    "console.log",
    "sendToServer"
]);

// Upper bound on analysis work per call. The analyzer re-analyzes a
// function body at every call site, so cost can grow exponentially
// with call depth. When the budget runs out, analysis stops and the
// result is marked as truncated (incomplete), not as "no findings".
export const DEFAULT_MAX_STEPS = 100_000;

class BudgetExceeded extends Error {}

/**
 * Statically analyze JavaScript source code for flows from configured
 * sources to configured sinks. The code is parsed, never executed.
 *
 * Returns either:
 *   { ok: true, findings: [{ destination, line, column }],
 *     taintedVariables: [...], stats: { steps, maxSteps, truncated } }
 * or:
 *   { ok: false, error: { type, message, line, column } }
 */
export function analyze(code, options = {}) {
    if (typeof code !== "string") {
        throw new TypeError("analyze(code): code must be a string");
    }

    const SOURCES = new Set(options.sources ?? DEFAULT_SOURCES);
    const SINKS = new Set(options.sinks ?? DEFAULT_SINKS);
    const maxSteps = options.maxSteps ?? DEFAULT_MAX_STEPS;

    // 2. Parse the program into an AST.
    let ast;
    try {
        ast = acorn.parse(code, {
            ecmaVersion: "latest",
            sourceType: "module",
            locations: true
        });
    } catch (err) {
        if (err instanceof SyntaxError) {
            return {
                ok: false,
                error: {
                    type: "SyntaxError",
                    message: err.message,
                    line: err.loc?.line ?? null,
                    column: err.loc?.column ?? null
                }
            };
        }
        throw err;
    }

    // Per-call analysis state (previously module-level globals).
    const taintedVariables = new Set();
    const findings = [];
    const functions = new Map();
    const reportedFindings = new Set();
    let steps = 0;

    function tick() {
        steps += 1;
        if (steps > maxSteps) {
            throw new BudgetExceeded();
        }
    }

    // Get names such as "sendToServer" and "console.log".
    function getCalleeName(node) {
        if (!node) return null;

        if (node.type === "Identifier") {
            return node.name;
        }

        if (
            node.type === "MemberExpression" &&
            !node.computed
        ) {
            const objectName = getCalleeName(node.object);

            return objectName
                ? `${objectName}.${node.property.name}`
                : null;
        }

        return null;
    }

    // Get the direct AST child nodes.
    function getChildNodes(node) {
        const children = [];

        for (const value of Object.values(node)) {
            if (Array.isArray(value)) {
                for (const item of value) {
                    if (item && typeof item.type === "string") {
                        children.push(item);
                    }
                }
            } else if (
                value &&
                typeof value.type === "string"
            ) {
                children.push(value);
            }
        }

        return children;
    }

    // Visit nodes in an AST subtree.
    function walk(node, callback) {
        if (!node || typeof node.type !== "string") return;

        tick();
        callback(node);

        for (const child of getChildNodes(node)) {
            walk(child, callback);
        }
    }

    // Record each destination and line only once.
    function reportFinding(destination, loc) {
        const key = `${destination}:${loc.line}`;

        if (reportedFindings.has(key)) return;

        reportedFindings.add(key);
        findings.push({
            destination,
            line: loc.line,
            column: loc.column
        });
    }

    // 3. Determine whether an expression carries sensitive data.
    function containsTaintedData(
        node,
        localTainted = new Set(),
        callStack = new Set()
    ) {
        if (!node) return false;

        tick();

        if (node.type === "Identifier") {
            return (
                localTainted.has(node.name) ||
                taintedVariables.has(node.name)
            );
        }

        if (node.type === "CallExpression") {
            const name = getCalleeName(node.callee);

            if (SOURCES.has(name)) {
                return true;
            }

            if (functions.has(name) && !callStack.has(name)) {
                return analyzeFunctionCall(
                    node,
                    callStack,
                    localTainted
                );
            }

            // Unknown function return values are not assumed
            // to contain sensitive data.
            return false;
        }

        // Handle expressions such as value + "text".
        return getChildNodes(node).some(child =>
            containsTaintedData(
                child,
                localTainted,
                callStack
            )
        );
    }

    // 4. Analyze a function call using its actual arguments.
    function analyzeFunctionCall(
        call,
        callStack = new Set(),
        callerLocalTainted = new Set()
    ) {
        tick();

        const name = getCalleeName(call.callee);
        const fn = functions.get(name);

        if (!fn || callStack.has(name)) {
            return false;
        }

        const localTainted = new Set();

        // Transfer sensitive arguments to parameters.
        for (let i = 0; i < fn.params.length; i++) {
            const parameter = fn.params[i];
            const argument = call.arguments[i];

            if (
                parameter.type === "Identifier" &&
                containsTaintedData(
                    argument,
                    callerLocalTainted,
                    callStack
                )
            ) {
                localTainted.add(parameter.name);
            }
        }

        const nextCallStack = new Set(callStack);
        nextCallStack.add(name);

        // Process statements in order, updating local taint
        // before inspecting sinks in each statement.
        for (const statement of fn.body.body) {

            // Handle declarations such as: const copy = value;
            if (statement.type === "VariableDeclaration") {
                for (const declaration of statement.declarations) {
                    if (declaration.id.type !== "Identifier") {
                        continue;
                    }

                    const variableName = declaration.id.name;

                    if (
                        containsTaintedData(
                            declaration.init,
                            localTainted,
                            nextCallStack
                        )
                    ) {
                        localTainted.add(variableName);
                    } else {
                        localTainted.delete(variableName);
                    }
                }
            }

            // Inspect calls in this statement using the
            // current local taint state.
            walk(statement, innerNode => {
                if (innerNode.type !== "CallExpression") {
                    return;
                }

                const destination = getCalleeName(
                    innerNode.callee
                );

                if (!SINKS.has(destination)) return;

                for (const argument of innerNode.arguments) {
                    if (
                        containsTaintedData(
                            argument,
                            localTainted,
                            nextCallStack
                        )
                    ) {
                        reportFinding(
                            destination,
                            innerNode.loc.start
                        );
                        break;
                    }
                }
            });

            // Propagate sensitive return values to callers.
            if (statement.type === "ReturnStatement") {
                return containsTaintedData(
                    statement.argument,
                    localTainted,
                    nextCallStack
                );
            }
        }

        return false;
    }

    let truncated = false;

    try {
        // 5. Register function declarations before analysis.
        for (const statement of ast.body) {
            if (
                statement.type === "FunctionDeclaration" &&
                statement.id
            ) {
                functions.set(statement.id.name, statement);
            }
        }

        // 6. Analyze top-level statements in order.
        for (const statement of ast.body) {

            // Track top-level variables.
            if (statement.type === "VariableDeclaration") {
                for (const declaration of statement.declarations) {
                    if (declaration.id.type !== "Identifier") {
                        continue;
                    }

                    const variableName = declaration.id.name;

                    if (containsTaintedData(declaration.init)) {
                        taintedVariables.add(variableName);
                    } else {
                        taintedVariables.delete(variableName);
                    }
                }
            }

            // Find configured sinks at the top level.
            // Skip function declarations here: their bodies
            // are analyzed using call-site parameter values.
            if (statement.type !== "FunctionDeclaration") {
                walk(statement, node => {
                    if (node.type !== "CallExpression") return;

                    const destination = getCalleeName(node.callee);

                    if (!SINKS.has(destination)) return;

                    for (const argument of node.arguments) {
                        if (containsTaintedData(argument)) {
                            reportFinding(
                                destination,
                                node.loc.start
                            );
                            break;
                        }
                    }
                });
            }

            // Analyze known function calls to inspect their bodies.
            walk(statement, node => {
                if (node.type !== "CallExpression") return;

                const name = getCalleeName(node.callee);

                if (functions.has(name)) {
                    analyzeFunctionCall(node, new Set());
                }
            });
        }
    } catch (err) {
        if (!(err instanceof BudgetExceeded)) throw err;
        truncated = true;
    }

    return {
        ok: true,
        findings,
        taintedVariables: [...taintedVariables],
        stats: { steps: Math.min(steps, maxSteps), maxSteps, truncated }
    };
}

// 7. Command-line usage:
//    node analyzer.js            analyze the built-in example
//    node analyzer.js file.js    analyze a file
const DEMO_CODE = `
function formatMessage(value) {
    return "Hello, world!";
}
const secret = readPassword();
const message = formatMessage(secret);
console.log(message);
`;

const isMain =
    process.argv[1] &&
    path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);

if (isMain) {
    const file = process.argv[2];
    const code = file ? fs.readFileSync(file, "utf8") : DEMO_CODE;
    const result = analyze(code);

    if (!result.ok) {
        const { message } = result.error;
        console.error(`SyntaxError: ${message}`);
        process.exitCode = 1;
    } else {
        console.log("Sensitive variables:", result.taintedVariables);
        console.log(
            "Findings:",
            result.findings.map(({ destination, line }) => ({ destination, line }))
        );
        if (result.stats.truncated) {
            console.warn(
                `Warning: analysis stopped after ${result.stats.maxSteps} steps; results are incomplete.`
            );
        }
    }
}
