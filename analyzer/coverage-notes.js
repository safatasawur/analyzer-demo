// Coverage notes: a separate, read-only scan of the AST that flags
// constructs the analyzer does not model. It does NOT change findings.
// Its purpose is to stop the website from presenting "no findings" as a
// clean result when the input relies on behavior the analyzer ignores.
import * as acorn from "acorn";

const MAX_NOTES = 10;

function calleeName(node) {
    if (!node) return null;
    if (node.type === "Identifier") return node.name;
    if (node.type === "MemberExpression" && !node.computed) {
        const obj = calleeName(node.object);
        return obj ? `${obj}.${node.property.name}` : null;
    }
    return null;
}

function children(node) {
    const out = [];
    for (const value of Object.values(node)) {
        if (Array.isArray(value)) {
            for (const item of value) if (item && typeof item.type === "string") out.push(item);
        } else if (value && typeof value.type === "string") {
            out.push(value);
        }
    }
    return out;
}

/**
 * @returns {{ kind: string, line: number, message: string }[]}
 */
export function coverageNotes(code, { sources, sinks }) {
    let ast;
    try {
        ast = acorn.parse(code, { ecmaVersion: "latest", sourceType: "module", locations: true });
    } catch {
        return [];
    }

    const sourceSet = new Set(sources);
    const sinkSet = new Set(sinks);
    const topLevelFunctions = new Set(
        ast.body
            .filter(s => s.type === "FunctionDeclaration" && s.id)
            .map(s => s.id.name)
    );

    const notes = [];
    const seen = new Set();
    const add = (kind, key, line, message) => {
        const id = `${kind}:${key}`;
        if (seen.has(id) || notes.length >= MAX_NOTES) return;
        seen.add(id);
        notes.push({ kind, line, message });
    };

    // Iterative walk with parent tracking (avoids deep recursion).
    const stack = [{ node: ast, parent: null, fnDepth: 0 }];
    while (stack.length) {
        const { node, parent, fnDepth } = stack.pop();
        const line = node.loc?.start.line ?? null;

        switch (node.type) {
            case "AssignmentExpression":
                if (node.left.type === "Identifier") {
                    add("reassignment", node.left.name, line,
                        `Reassignment of "${node.left.name}" is not tracked. Only declarations (const/let/var) update taint.`);
                } else {
                    add("member-assignment", line, line,
                        "Assignments to object properties are not tracked.");
                }
                break;
            case "ArrowFunctionExpression":
            case "FunctionExpression":
                add("function-expression", "x", line,
                    "Arrow functions and function expressions are not registered, so calls to them are treated as unknown.");
                break;
            case "FunctionDeclaration":
                if (fnDepth > 0) {
                    add("nested-function", node.id?.name ?? line, line,
                        `Nested function "${node.id?.name}" is not registered; only top-level function declarations are analyzed.`);
                }
                if (node.async || node.generator) {
                    add("async", "fn", line, "Async functions and generators are not modeled.");
                }
                break;
            case "ReturnStatement":
                if (!parent?._isFunctionBody) {
                    add("nested-return", line, line,
                        "A return inside a block (if, loop, try) is not used for taint propagation; only top-level returns in a function body are.");
                }
                break;
            case "AwaitExpression":
                add("async", "await", line, "await and Promises are not modeled.");
                break;
            case "ClassDeclaration":
            case "ClassExpression":
                add("class", "class", line, "Classes and methods are not modeled.");
                break;
            case "VariableDeclarator":
                if (node.id.type !== "Identifier") {
                    add("destructuring", line, line, "Destructuring declarations are skipped by the analyzer.");
                }
                break;
            case "CallExpression": {
                const name = calleeName(node.callee);
                if (name === null) {
                    add("dynamic-call", line, line, "Calls through computed or dynamic callees are not modeled.");
                } else if (!sourceSet.has(name) && !sinkSet.has(name) && !topLevelFunctions.has(name)) {
                    add("unknown-call", name, line,
                        `"${name}" is not a configured source, sink or top-level function, so data passed to it is not followed.`);
                }
                break;
            }
        }

        const isFn = node.type === "FunctionDeclaration" ||
            node.type === "FunctionExpression" ||
            node.type === "ArrowFunctionExpression";
        if (isFn && node.body?.type === "BlockStatement") {
            node.body._isFunctionBody = true;
        }

        const kids = children(node);
        for (let i = kids.length - 1; i >= 0; i--) {
            stack.push({ node: kids[i], parent: node, fnDepth: fnDepth + (isFn ? 1 : 0) });
        }
    }

    return notes.sort((a, b) => (a.line ?? 0) - (b.line ?? 0));
}
