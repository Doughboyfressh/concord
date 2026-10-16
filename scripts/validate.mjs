import { spawnSync } from 'node:child_process';
import { mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';

// Native Windows equivalent of no-mistakes' mechanical pipeline. No remote exists.
const evidence = path.resolve('.agents/evidence', 'validation-' + new Date().toISOString().replaceAll(/[:.]/g, '-'));
mkdirSync(evidence, { recursive: true });
const steps = ['check', 'test', 'e2e'];
const results = [];
for (const step of steps) {
  const run = spawnSync(process.execPath, ['scripts/' + step + '.mjs'], { encoding: 'utf8', timeout: 120000, maxBuffer: 8 * 1048576 });
  const output = (run.stdout ?? '') + (run.stderr ?? '');
  writeFileSync(path.join(evidence, step + '.log'), output);
  results.push({ step, passed: run.status === 0, exitCode: run.status, signal: run.signal });
  console.log(step + ': ' + (run.status === 0 ? 'PASS' : 'FAIL'));
}
const summary = { runtime: process.version, platform: process.platform, rebase: 'not applicable: local repository on main, no remote', results, evidence };
writeFileSync(path.join(evidence, 'summary.json'), JSON.stringify(summary, null, 2) + '\n');
console.log('Evidence: ' + evidence);
process.exitCode = results.every(r => r.passed) ? 0 : 1;
