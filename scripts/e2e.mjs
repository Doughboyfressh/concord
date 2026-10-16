import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import assert from 'node:assert/strict';

const temp = mkdtempSync(path.join(tmpdir(), 'concord-e2e-'));
function cli(args, expected = 0) {
  const r = spawnSync(process.execPath, ['src/cli.mjs', ...args], { encoding: 'utf8', timeout: 30000 });
  assert.equal(r.status, expected, r.stderr + r.stdout);
  return r.stdout;
}
try {
  const run = path.join(temp, 'run.json');
  const policy = 'examples/offline.policy.json', plan = 'examples/offline.plan.json';
  cli(['run', plan, '--policy', policy, '--out', run, '--workspace', temp, '--journal', path.join(temp, 'events.jsonl')]);
  const captured = JSON.parse(readFileSync(run, 'utf8'));
  cli(['replay', run, '--plan', plan, '--policy', policy, '--workspace', temp, '--root', captured.root]);
  assert.equal(captured.results['30-verify'].passed, true);
  assert.equal(captured.results['40-learn'].status, 'proposed');
  const blocked = path.join(temp, 'blocked.json');
  cli(['run', 'examples/write.plan.json', '--policy', 'examples/write.policy.json', '--out', blocked, '--workspace', temp], 3);
  const hash = JSON.parse(readFileSync(blocked, 'utf8')).outcome.requestHash;
  const grants = path.join(temp, 'grants.json');
  writeFileSync(grants, JSON.stringify([hash]));
  const written = path.join(temp, 'written.json');
  cli(['run', 'examples/write.plan.json', '--policy', 'examples/write.policy.json', '--out', written, '--workspace', temp, '--approvals', grants]);
  const before = readFileSync(path.join(temp, 'approved-memory.json'), 'utf8');
  cli(['replay', written, '--plan', 'examples/write.plan.json', '--policy', 'examples/write.policy.json', '--workspace', temp]);
  assert.equal(readFileSync(path.join(temp, 'approved-memory.json'), 'utf8'), before);
  const tampered = JSON.parse(readFileSync(written, 'utf8'));
  tampered.events[1].data.inputHash = '0'.repeat(64);
  const bad = path.join(temp, 'tampered.json'); writeFileSync(bad, JSON.stringify(tampered));
  cli(['replay', bad, '--plan', 'examples/write.plan.json', '--policy', 'examples/write.policy.json', '--workspace', temp], 2);
  console.log(JSON.stringify({ offlineRun: 'pass', anchoredReplay: 'pass', exactApproval: 'pass', noWriteOnReplay: 'pass', tamperRejection: 'pass', tasks: captured.events.filter(e => e.type === 'completed').length }, null, 2));
} finally { rmSync(temp, { recursive: true, force: true }); }
