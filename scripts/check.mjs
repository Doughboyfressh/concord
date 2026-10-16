import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
for (const folder of ['src', 'scripts', 'test']) {
  for (const file of fs.readdirSync(folder).filter(n => n.endsWith('.mjs'))) {
    const r = spawnSync(process.execPath, ['--check', folder + '/' + file], { stdio: 'inherit' });
    if (r.status !== 0) process.exit(r.status ?? 1);
  }
}
console.log('All JavaScript source files parsed successfully.');
