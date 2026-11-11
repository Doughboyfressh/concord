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
    const lines = output.split(/\r?\n/);
    let shown = 0;
    for (let i = 0; i < lines.length && shown < 40; i += 1) {
      if (!/^\s*not ok \d+/.test(lines[i])) continue;
      shown += 1;
      console.log('  ' + lines[i].trim());
      // The YAML block under a failure carries its reason; show that much and no more.
      for (let j = i + 1; j < lines.length && j < i + 40 && !/^\s*\.\.\.\s*$/.test(lines[j]); j += 1) {
        if (/^\s*(duration_ms|type):/.test(lines[j])) continue;
        console.log('    ' + lines[j].trimEnd().slice(0, 400));
      }
    }
    if (!shown) console.log(output.slice(-2000));
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
