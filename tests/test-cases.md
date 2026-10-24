# Test Cases and Evaluation

## Overview

This document describes the manually constructed test cases used to evaluate the JavaScript information-flow analyzer. The tests examine whether the prototype can track potentially sensitive data through simple assignments and selected function calls, and whether it avoids reporting a flow when a function returns a constant instead of its sensitive argument.

## Summary

| # | Test case                                           | Expected result                     |Outcome    |
|---|------------------------------------------------------------------------------------------ |-----------|
| 1 | Direct sensitive data passed to a sink              | Finding reported                     | Passed   |
| 2 | Sensitive data copied to another variable           | Finding reported                     | Passed   |
| 3 | Sensitive data passed through a helper function     | Finding reported                     | Passed   |
| 4 | Function returns a constant instead of its argument | No finding for the returned constant | Passed   |
| 5 | Sensitive data passed to an unknown function        | Behavior may be incomplete           | documented|

**Evaluation summary:** The prototype was tested on selected positive and negative examples. The results demonstrate basic source-to-sink tracking, but do not establish comprehensive coverage of JavaScript information flows.

---

## Test 1: Direct Sensitive Data Passed to a Sink

**Objective**

Verify that the analyzer detects sensitive data flowing from a configured source to a configured sink.

**Input**

```javascript
const secret = readPassword();
console.log(secret);
```

**Expected result**

The analyzer identifies `secret` as sensitive and reports a finding for `console.log`.

**Observed result**

The analyzer detected the sensitive variable and reported the flow to the configured sink in the tested example.

**Status:** Passed

**What this demonstrates**

The prototype can detect a basic source-to-sink flow through a variable assignment.

---

## Test 2: Sensitive Data Copied to Another Variable

**Objective**

Verify that sensitive-data tracking propagates through an intermediate variable.

**Input**

```javascript
const secret = readPassword();
const copy = secret;
console.log(copy);
```

**Expected result**

The analyzer tracks the sensitive value from `secret` to `copy` and reports a finding for `console.log`.

**Observed result**

The analyzer detected the sensitive flow through the intermediate variable in the tested example.

**Status:** Passed

**What this demonstrates**

The prototype supports basic taint propagation through variable assignments.

---

## Test 3: Sensitive Data Passed Through a Helper Function

**Objective**

Evaluate whether the analyzer can track sensitive data through a function parameter and a local variable.

**Input**

```javascript
function sendToServer(value) {
    const copy = value;
    console.log(copy);
}

const secret = readPassword();
sendToServer(secret);
```

**Expected result**

The analyzer reports potential flows to the configured `sendToServer` and `console.log` sinks.

**Observed result**

The analyzer reported findings for both configured sinks in the tested example.

**Status:** Passed

**What this demonstrates**

The prototype can track selected function-call flows and intermediate variables within a simple function body.

---

## Test 4: Function Returns a Constant Instead of Its Argument

**Objective**

Check whether the analyzer distinguishes a constant return value from a sensitive argument in a simple function.

**Input**

```javascript
function formatMessage(value) {
    return "Hello, world!";
}

const secret = readPassword();
const message = formatMessage(secret);
console.log(message);
```

**Expected result**

The analyzer should not report a sensitive-data flow to `console.log` through `message`, because the function returns a constant string rather than its argument.

**Observed result**

The analyzer reported no findings for this example.

**Status:** Passed

**What this demonstrates**

For this tested case, the analyzer does not automatically treat the function's return value as sensitive merely because its argument is sensitive.

---

## Test 5: Sensitive Data Passed to an Unknown Function

**Objective**

Document the limitations of tracking sensitive data through functions whose behavior is not modeled by the analyzer.

**Scenario**

```javascript
const secret = readPassword();
unknownFunction(secret);
```

**Expected behavior**

A complete analysis would need to determine whether `unknownFunction` forwards, stores, transforms, or discards the sensitive value. The current prototype does not reliably model arbitrary unknown functions.

**Observed result**

This scenario is documented as a limitation rather than a verified experimental test result.

**Status:** Limitation documented

**What this demonstrates**

The analyzer's coverage depends on its function models and supported analysis rules. Unmodeled functions can lead to missed information flows.

---

## Limitations of the Evaluation

These tests are small, manually constructed examples designed to check specific behaviors. They are not an exhaustive benchmark.

The prototype does not fully model JavaScript scoping, complex control flow, asynchronous execution, browser DOM interactions, or arbitrary function behavior. Its findings depend on the configured sources and sinks.

A missing finding does not prove that a program is secure, and a reported finding indicates a potential flow under the prototype's rules rather than a confirmed security vulnerability.

## Conclusion

The evaluation demonstrates basic information-flow tracking through variable assignments and selected function calls, alongside a simple negative case involving a constant return value. The results provide a starting point for understanding the capabilities and limitations of a small JavaScript static-analysis prototype.

---

## Automated Tests and How They Relate to This Document

The cases above were evaluated by hand. They now also run automatically:

- `tests/analyzer.test.js` calls the analyzer directly. It covers cases 1 to 5 above, invalid input, isolation between runs, the step budget, and a set of **pinned limitations** (reassignment, returns inside blocks, arrow functions, nested statement calls, strict-mode parsing).
- `tests/api.test.js` starts the HTTP server and covers the API: findings, parse errors (422), malformed JSON (400), wrong content type (415), oversized input (413), CORS, and a check that submitted code is not executed.
- `GET /api/tests` (the "Run documented cases" button and the `tests` terminal command) runs cases 1 to 5 through the live analyzer at request time.

Differences from the manual evaluation:

- This document does not give line numbers. The automated tests assert exact sinks and lines (for example, in case 3 `console.log` is reported at line 3 inside the helper and `sendToServer` at line 7, the call site). `GET /api/tests` compares sinks only, matching what this document specifies.
- Case 5 stays a documented limitation. The automated test only pins the current output (no findings); it does not claim the behavior is correct.
- The pinned-limitation tests record current behavior, including a false positive (taint is not cleared by reassignment). They are expected to change if the analyzer is improved.

Run everything with `npm test`.
