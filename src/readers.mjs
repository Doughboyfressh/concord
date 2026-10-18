import { makeDexTools } from './dex.mjs';
import { makeManagedTools } from './managed.mjs';

/**
 * One registration point for the static format readers that realize REA's `internalizable` tools.
 *
 * Each format family lives in its own module; this barrel exists so adding a family is a new file
 * plus one line here, rather than a fourth edit to every registry construction site
 * (src/cli.mjs, src/mcp.mjs, scripts/chat.mjs). Readers are `read` or `pure` effects over bytes
 * already inside the workspace: nothing here spawns a process or reaches the network.
 */
export function makeReaderTools() {
  return [...makeDexTools(), ...makeManagedTools()];
}
