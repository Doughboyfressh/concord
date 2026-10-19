#!/usr/bin/env node
import { HarnessError } from '../src/value.mjs';
import { parseFlags, startChatServer } from '../src/app.mjs';

/**
 * The terminal launcher: start the application and print where it is listening.
 *
 * The assembly itself lives in `src/app.mjs`, shared with the windowed launcher in
 * `scripts/desktop.mjs`, so the two cannot register different tools or default a different policy.
 */
async function start() {
  const flags = parseFlags(process.argv.slice(2));
  const { url, store, status, mode, server } = await startChatServer({ flags, entry: 'scripts/chat.mjs' });
  console.log(`Concord chat: ${url}\nMode: ${mode}\nSources: ${status.sourceCount}; indexed references: ${status.capabilities}; skill files: ${status.skillFiles}\nLocal evidence: ${store}`);
  const stop = () => server.close(() => process.exit(0));
  process.on('SIGINT', stop); process.on('SIGTERM', stop);
}

start().catch(error => {
  console.error(error instanceof HarnessError ? `${error.code}: ${error.message}` : 'CHAT_START_FAILED: Check local configuration and paths.');
  process.exitCode = 1;
});
