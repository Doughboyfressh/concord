import { spawnSync } from 'node:child_process';
import { readdirSync } from 'node:fs';
// Never let Node discover or execute tests inside inert upstream source snapshots.
const tests = readdirSync('test').filter(n => /^[a-zA-Z0-9._-]+\.test\.mjs$/.test(n)).sort().map(n => 'test/' + n);
if (!tests.length) throw new Error('No Concord tests found');
const result = spawnSync(process.execPath, ['--test', ...tests], { stdio: 'inherit' });
process.exitCode = result.status ?? 1;
