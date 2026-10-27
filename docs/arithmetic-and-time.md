# Arithmetic and the clock

Two builtins in `src/builtins.mjs`: `math.evaluate`, which computes, and `time.now`, which reads
the host clock. They are documented together because the interesting part of both is the same
question — how does a harness that promises byte-identical replay offer them at all.

The answers differ, and the difference is the whole design. Arithmetic is a function of its input,
so it is `pure`. A clock is not, so it is `read`.

## `math.evaluate` — pure

```json
{"id": "sum", "tool": "math.evaluate", "input": {"expression": "(17*23)+sqrt(81)"}}
```

returns `{"value": 400, "expression": "(17*23)+sqrt(81)", "limitations": [...]}`.

Supported: `+ - * / %`, `^` with an integer exponent, parentheses, unary sign, the functions
`sqrt abs floor ceil round trunc sign min max`, and the constants `pi` and `e`. Exponentiation
binds tighter than unary minus and associates rightwards, so `-2^2` is `-4` and `2^3^2` is `512`.

### It is a parser, not an evaluator

There is no `eval` and no `new Function` here. Model output is untrusted by contract, and those
two would execute it inside the kernel. What is implemented instead is a recursive-descent parser
over a fixed grammar with no variables, no assignment and no property access: `constructor`,
`process` and `globalThis` are unknown names, not values.

### The operator set is chosen for reproducibility, not completeness

A `pure` tool makes the strictest promise in this codebase — the same input gives the same bytes
on any machine, under any future Node, forever. IEEE-754 specifies `+ - * / %` and `sqrt` as
*exactly rounded*, so they keep that promise. It does not specify `sin`, `cos`, `tan`, `log`,
`exp`, or a fractional power: implementations may differ in the last bit, and V8 has changed its
own more than once.

Offering them would mean recording a run here that replays differently somewhere else — a worse
failure than not having the function. They are therefore refused **by name**, with
`MATH_UNSUPPORTED` and a reason, so a model is told the operation is excluded rather than meeting
a bare "unknown function". `^` is implemented by squaring from multiplications alone, for the same
reason `Math.pow` is not used.

### Non-finite results are errors, not values

Canonical JSON rejects non-finite numbers, so a tool returning `Infinity` or `NaN` would produce
output the kernel cannot journal, and the failure would surface later and less usefully. Division
by zero, remainder by zero, `sqrt` of a negative and overflow are each refused where they happen.

### What it is not

Double precision: roughly 15 significant digits, and `0.1 + 0.2` is not exactly `0.3`. This is not
decimal arithmetic and should not be used to settle money to the cent.

| Code | Meaning |
| --- | --- |
| `MATH_SYNTAX` | The expression could not be parsed |
| `MATH_UNKNOWN` | An unknown name or function |
| `MATH_UNSUPPORTED` | Excluded because its result would not replay identically |
| `MATH_UNDEFINED` | Division by zero, remainder by zero, `sqrt` of a negative |
| `MATH_RANGE` | Overflow, or an exponent outside ±1024 |
| `MATH_ARITY` | Wrong number of arguments to a function |
| `MATH_DEPTH` | Nested deeper than 32 |

## `time.now` — read

```json
{"id": "clock", "tool": "time.now", "input": {}}
```

returns `{"iso": "2026-10-27T23:23:59.903Z", "epochMs": 1793143439903, "limitations": [...]}`.
UTC only, millisecond precision, no timezone or calendar conversion.

### Why `read` and not `pure`

`pure` would be a lie. A pure tool promises the same output for the same input forever, and a
clock cannot. AGENTS.md admits ambient state in exactly one way — through an explicit effect — and
`read` is that way. The instant is recorded when the tool runs, and **replay never invokes a
tool**, so a replay returns the instant the original run observed rather than the time of the
replay. The recorded run stays byte-identical.

What does change is that two *live* runs of the same plan differ, and their run identities differ
with them. That is not new: it is already true of every tool that reads a file. A plan that reads
the clock is a plan whose identity depends on when it ran, and that is the honest description.

`read` is not a gated effect, because reading a clock does not act on the world. No approval is
required.

### It does not make anything fire

A clock is not a scheduler. Nothing in Concord runs on its own, and `time.now` does not change
that — there is still no daemon, and being due is still a statement about a supplied time rather
than an event.

### Composing with `schedule.due`

`schedule.due` was written to require `now` from its caller, so that it stays reproducible. That
is unchanged. What changed is that the caller now has somewhere true to get the answer, instead of
the model inventing a timestamp:

```json
{"version": 1, "tasks": [
  {"id": "clock", "tool": "time.now", "input": {}},
  {"id": "due", "tool": "schedule.due",
   "input": {"now": {"$task": "clock", "path": "/iso"}}, "dependsOn": ["clock"]}
]}
```

The `iso` form is what `schedule.due` parses, so that is the field to reference.

| Code | Meaning |
| --- | --- |
| `CLOCK_UNAVAILABLE` | The host clock did not return a usable instant |

The instant is whatever the host clock said. That is not evidence the host clock is correct.

## Tests

`test/arithmetic.test.mjs` and `test/clock.test.mjs`. The two that carry the design claims are
*a replay returns the instant that was recorded, not the time of the replay* and *two live runs of
the same plan are different runs* — together they show the clock genuinely varies and that replay
reproduces it anyway.
