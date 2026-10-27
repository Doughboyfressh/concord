import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { canonical } from '../src/value.mjs';
import { runPlan, replayPlan } from '../src/engine.mjs';
import { makeBuiltinTools } from '../src/builtins.mjs';

const registry = new Map(makeBuiltinTools().map(t => [t.name, t]));
const math = registry.get('math.evaluate');
const policy = {
  version: 1, allowedTools: [...registry.keys()], allowedEffects: ['pure', 'read'],
  maxOutputBytes: 10000, maxJournalBytes: 100000,
};
const base = (plan) => ({ plan, policy, registry, sourceLock: { version: 1 }, workspaceRoot: path.resolve('/explicit/workspace') });
const value = (expression) => math.execute({ expression }).value;
const code = (expression) => {
  try { math.execute({ expression }); } catch (error) { return error.code; }
  return 'NO_ERROR';
};

test('arithmetic follows the precedence a calculator is expected to have', () => {
  assert.equal(value('2+3*4'), 14);
  assert.equal(value('(2+3)*4'), 20);
  assert.equal(value('10-2-3'), 5, 'subtraction associates leftwards');
  assert.equal(value('100/8'), 12.5);
  assert.equal(value('10%3'), 1);
  // Exponentiation binds tighter than unary minus, and associates rightwards. Both are the
  // conventions every calculator uses, and both are easy to get backwards in a parser.
  assert.equal(value('-2^2'), -4);
  assert.equal(value('2^3^2'), 512);
  assert.equal(value('2^-1'), 0.5);
  assert.equal(value('2^10'), 1024);
  assert.equal(value('2^0'), 1);
});

test('the function and constant set computes what it claims', () => {
  assert.equal(value('sqrt(16)'), 4);
  assert.equal(value('abs(-7)+floor(3.9)+ceil(0.1)'), 11);
  assert.equal(value('trunc(-3.7)'), -3);
  assert.equal(value('sign(-5)'), -1);
  assert.equal(value('round(2.5)'), 3);
  assert.equal(value('min(3,1,2)'), 1);
  assert.equal(value('max(1,2)'), 2);
  assert.equal(value('pi'), Math.PI);
  assert.equal(value('e'), Math.E);
});

test('operations that could not replay identically are refused by name, not silently approximated', () => {
  // The point of each refusal is that the result is not specified to the last bit, so a recorded
  // run holding one could replay differently on another machine. Refusing is the honest outcome.
  for (const expression of ['sin(1)', 'cos(1)', 'tan(1)', 'log(2)', 'exp(1)', 'pow(2,3)', 'random()']) {
    assert.equal(code(expression), 'MATH_UNSUPPORTED', expression);
  }
  assert.equal(code('2^0.5'), 'MATH_UNSUPPORTED', 'a fractional exponent has no exactly-rounded construction');
});

test('a result canonical JSON could not carry is an error, never an emitted Infinity or NaN', () => {
  // Tied to the real reason rather than asserted on its own: the kernel cannot journal these, so
  // a tool returning one would fail later and less informatively.
  for (const unjournalable of [Infinity, -Infinity, NaN]) {
    assert.throws(() => canonical({ value: unjournalable }), (error) => error.code === 'INVALID_JSON');
  }
  assert.equal(code('1/0'), 'MATH_UNDEFINED');
  assert.equal(code('0/0'), 'MATH_UNDEFINED');
  assert.equal(code('5%0'), 'MATH_UNDEFINED');
  assert.equal(code('sqrt(-1)'), 'MATH_UNDEFINED');
  assert.equal(code('1e308*10'), 'MATH_RANGE', 'overflow is caught where it happens');
  assert.equal(code('2^99999'), 'MATH_RANGE');
});

test('an expression is parsed, never executed, so no name reaches anything outside it', () => {
  // There is no eval and no new Function in this tool. Each of these would be reachable if there
  // were, and each must come back as an unknown name rather than as a value.
  for (const expression of ['constructor', 'process', 'globalThis', 'require("fs")', 'x+1']) {
    assert.match(code(expression), /^MATH_(UNKNOWN|SYNTAX)$/, expression);
  }
  assert.equal(code('__proto__'), 'MATH_SYNTAX', 'underscores are not even tokens');
});

test('malformed input is rejected with a reason rather than a partial answer', () => {
  for (const expression of ['2+', '(1+2', '1 2', '*3', ',']) {
    assert.match(code(expression), /^MATH_/, expression);
  }
  assert.equal(code('min()'), 'MATH_SYNTAX');
  assert.equal(code('sqrt(1,2)'), 'MATH_ARITY');
});

test('it is a pure tool, so the same plan replays to the same bytes', async () => {
  const plan = { version: 1, tasks: [{ id: 'sum', tool: 'math.evaluate', input: { expression: '(17*23)+sqrt(81)' } }] };
  const first = await runPlan(base(plan));
  const second = await runPlan(base(plan));
  assert.equal(first.results.sum.value, 400);
  // Pure means two live runs are indistinguishable, down to the run identity.
  assert.deepEqual(first, second);
  assert.equal(replayPlan({ ...base(plan), journal: first, expectedRoot: first.root }).replayed, true);
});
