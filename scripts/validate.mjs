import { spawnSync } from 'node:child_process';
import { mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';

// Native Windows validation pipeline; preserve existing working changes and Git history.
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
  // The full log goes to the evidence directory; a CI reader still needs to see what failed
  // without downloading it.
  if (run.status !== 0) {
    const failed = output.split(/\r?\n/).filter(line => /^\s*not ok \d+/.test(line));
    for (const line of failed.slice(0, 40)) console.log('  ' + line.trim());
    if (!failed.length) console.log(output.slice(-2000));
  }
}
const gitText = args => {
  const run = spawnSync('git', args, { encoding: 'utf8' });
  return run.status === 0 ? run.stdout.trim() : null;
};
const summary = { runtime: process.version, platform: process.platform,
  git: { head: gitText(['rev-parse', 'HEAD']), branch: gitText(['branch', '--show-current']), remotes: (gitText(['remote']) ?? '').split('\n').filter(Boolean) },
  rebase: 'not performed: validation preserves working changes and Git history', results, evidence };
writeFileSync(path.join(evidence, 'summary.json'), JSON.stringify(summary, null, 2) + '\n');
console.log('Evidence: ' + evidence);
process.exitCode = results.every(r => r.passed) ? 0 : 1;
