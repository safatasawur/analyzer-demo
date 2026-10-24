// The manually documented cases from tests/test-cases.md, in a form that
// can be executed. Shared by GET /api/tests and the automated test suite.
//
// "expectedSinks" encodes what test-cases.md says should be reported.
// test-cases.md does not specify line numbers, so only sinks are compared.
// Case 5 is documented as a limitation, not a pass/fail test.

export const DOCUMENTED_CASES = [
    {
        id: 1,
        title: "Direct sensitive data passed to a sink",
        code: `const secret = readPassword();
console.log(secret);`,
        kind: "test",
        expected: "Finding reported for console.log",
        expectedSinks: ["console.log"]
    },
    {
        id: 2,
        title: "Sensitive data copied to another variable",
        code: `const secret = readPassword();
const copy = secret;
console.log(copy);`,
        kind: "test",
        expected: "Finding reported for console.log",
        expectedSinks: ["console.log"]
    },
    {
        id: 3,
        title: "Sensitive data passed through a helper function",
        code: `function sendToServer(value) {
    const copy = value;
    console.log(copy);
}

const secret = readPassword();
sendToServer(secret);`,
        kind: "test",
        expected: "Findings reported for sendToServer and console.log",
        expectedSinks: ["console.log", "sendToServer"]
    },
    {
        id: 4,
        title: "Function returns a constant instead of its argument",
        code: `function formatMessage(value) {
    return "Hello, world!";
}

const secret = readPassword();
const message = formatMessage(secret);
console.log(message);`,
        kind: "test",
        expected: "No finding for the returned constant",
        expectedSinks: []
    },
    {
        id: 5,
        title: "Sensitive data passed to an unknown function",
        code: `const secret = readPassword();
unknownFunction(secret);`,
        kind: "limitation",
        expected: "Not modeled: unknown functions are not analyzed",
        expectedSinks: null
    }
];

/** Runs every documented case through analyzeFn and reports observed results. */
export function runDocumentedCases(analyzeFn) {
    return DOCUMENTED_CASES.map(testCase => {
        const result = analyzeFn(testCase.code);
        const observedSinks = result.ok
            ? [...new Set(result.findings.map(f => f.destination))].sort()
            : null;

        let status;
        if (testCase.kind === "limitation") {
            status = "limitation";
        } else if (!result.ok || result.stats.truncated) {
            status = "failed";
        } else {
            const expected = [...testCase.expectedSinks].sort();
            status = JSON.stringify(expected) === JSON.stringify(observedSinks)
                ? "passed"
                : "failed";
        }

        return {
            id: testCase.id,
            title: testCase.title,
            code: testCase.code,
            kind: testCase.kind,
            expected: testCase.expected,
            observed: result.ok
                ? { findings: result.findings, taintedVariables: result.taintedVariables }
                : { error: result.error },
            status
        };
    });
}
