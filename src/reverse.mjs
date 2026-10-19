import { HarnessError, clone, deepFreeze, digest, validateSchema } from './value.mjs';
import { limits, processEnv, resolveExecutable, spawnBounded } from './integrations.mjs';
import { workspaceFile } from './workspace-fs.mjs';

/**
 * The REA capability compiler.
 *
 * `reverse-tools.json` is the contract table, generated from the pinned REA clone so the tool list
 * has one source of truth. Each entry is realized one of two ways, and in both the contract, input
 * schema, bounds, effect, approval gate and journaled receipt belong to Concord:
 *
 *   static    an internal reader (see src/artifacts.mjs). Reported here, registered there, so a
 *             capability is never registered twice under two names.
 *   provider  a bounded single call to an operator-reviewed executable, under the `process` effect.
 *
 * Replay does not forbid the provider path. `replayPlan` never calls `execute`: for an effectful
 * tool it takes the recorded value and asserts legality properties, exactly as it already does for
 * `process.run` and `browser.snapshot`. What a provider tool cannot do is invent its own argv.
 *
 * The invariant carried over from `processRun`: argv SHAPE comes from reviewed configuration, never
 * from a plan. A reviewed template may contain `{placeholder}` slots, and only those slots are
 * filled from task input, each against a fixed pattern, never through a shell. The set of slots the
 * operator wrote is what determines the tool's input schema, so a plan cannot reach a slot the
 * operator did not open.
 */

const MAX_TEMPLATE_ARGS = 64;
const MAX_VALUE_CHARS = 192;

// Every slot a reviewed template may open, with the exact pattern its value must match. `path` is
// absent here because it is not pattern-checked: it is resolved inside the workspace instead.
const SLOT_PATTERNS = {
  serial: /^[A-Za-z0-9._:-]{1,64}$/,
  package: /^[A-Za-z0-9._]{1,128}$/,
  component: /^[A-Za-z0-9._/]{1,192}$/,
  pid: /^[0-9]{1,10}$/,
  name: /^[A-Za-z0-9._-]{1,128}$/,
  symbol: /^[A-Za-z0-9._$:<>-]{1,128}$/,
  address: /^(0x)?[0-9a-fA-F]{1,16}$/,
  index: /^[0-9]{1,6}$/,
  setting: /^[A-Za-z0-9._-]{1,64}$/,
};
const SLOT_NAMES = [...Object.keys(SLOT_PATTERNS), 'path'];
const SLOT_RE = /^\{([a-z]+)\}$/;

const fail = (code, message, details) => { throw new HarnessError(code, message, details); };
const isObject = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);

function checkTable(table) {
  if (!isObject(table) || table.schemaVersion !== 1 || !Array.isArray(table.tools) || !table.tools.length) {
    fail('REVERSE_TABLE_INVALID', 'The reverse tool table requires schemaVersion 1 and a nonempty tools array');
  }
  if (typeof table.revision !== 'string' || !/^[0-9a-f]{40}$/.test(table.revision)) {
    fail('REVERSE_TABLE_INVALID', 'The reverse tool table requires the full source revision it was generated from');
  }
  const seen = new Set();
  for (const entry of table.tools) {
    if (!isObject(entry) || typeof entry.name !== 'string' || !/^[a-z][a-z0-9_]{2,80}$/.test(entry.name) || seen.has(entry.name)) {
      fail('REVERSE_TABLE_INVALID', 'Reverse tool names must be unique lower-case identifiers');
    }
    seen.add(entry.name);
  }
  return deepFreeze(clone(table));
}

/** One reviewed provider: an exact executable plus the argv templates it is permitted to run. */
function checkProvider(value) {
  if (!isObject(value)) fail('REVERSE_CONFIG', 'A reverse provider entry must be an object');
  const allowed = ['name', 'executable', 'executableSha256', 'cwd', 'env', 'allowedEnv', 'timeoutMs', 'maxOutputBytes', 'commands'];
  for (const key of Object.keys(value)) if (!allowed.includes(key)) fail('REVERSE_CONFIG', 'Unsupported reverse provider field', { field: key });
  const name = value.name;
  if (typeof name !== 'string' || !/^[a-z][a-z0-9-]{1,31}$/.test(name)) fail('REVERSE_CONFIG', 'A reverse provider needs a portable name');
  if (!isObject(value.commands) || !Object.keys(value.commands).length) {
    fail('REVERSE_CONFIG', 'A reverse provider must declare at least one reviewed command template', { provider: name });
  }
  const commands = new Map();
  for (const [tool, template] of Object.entries(value.commands)) {
    if (!Array.isArray(template) || !template.length || template.length > MAX_TEMPLATE_ARGS) {
      fail('REVERSE_CONFIG', 'A reviewed command template must be a bounded nonempty argv array', { provider: name, tool });
    }
    const slots = [];
    for (const arg of template) {
      if (typeof arg !== 'string' || arg.includes('\0')) fail('REVERSE_CONFIG', 'Template argv entries must be strings', { provider: name, tool });
      const slot = SLOT_RE.exec(arg);
      if (!slot) continue;
      if (!SLOT_NAMES.includes(slot[1])) fail('REVERSE_CONFIG', 'Unknown template slot', { provider: name, tool, slot: slot[1] });
      if (slots.includes(slot[1])) continue;
      slots.push(slot[1]);
    }
    commands.set(tool, { template: [...template], slots });
  }
  return {
    name, executable: value.executable, executableSha256: value.executableSha256,
    cwd: value.cwd ?? '.', env: value.env ?? {}, allowedEnv: value.allowedEnv ?? [],
    timeoutMs: value.timeoutMs ?? 30_000, maxOutputBytes: value.maxOutputBytes ?? 1_048_576,
    commands,
  };
}

/** Input schema derived from the slots the operator actually opened. */
function schemaForSlots(slots) {
  const properties = {};
  for (const slot of slots) {
    properties[slot] = slot === 'path'
      ? { type: 'string', minLength: 1, maxLength: 1024 }
      : { type: 'string', minLength: 1, maxLength: MAX_VALUE_CHARS };
  }
  return { type: 'object', additionalProperties: false, required: [...slots].sort(), properties };
}

/**
 * Fill a reviewed template. A value that is not exactly what its slot permits stops the call
 * before any process starts, and a value beginning with `-` is refused whatever its pattern says:
 * an argument that looks like an option would change the meaning of the operator's command rather
 * than supply data to it.
 */
function renderArgv(entry, input, workspaceRoot) {
  return entry.template.map((arg) => {
    const slot = SLOT_RE.exec(arg);
    if (!slot) return arg;
    const key = slot[1];
    const value = input[key];
    if (typeof value !== 'string' || !value.length) fail('REVERSE_INPUT', 'A template slot was not supplied', { slot: key });
    if (value.startsWith('-')) fail('REVERSE_INPUT', 'A slot value may not begin with a dash', { slot: key });
    if (key === 'path') {
      // Resolved, not pattern-matched: containment is the property that matters for a path.
      workspaceFile(workspaceRoot, value);
      return value;
    }
    if (!SLOT_PATTERNS[key].test(value)) fail('REVERSE_INPUT', 'A slot value does not match its permitted pattern', { slot: key });
    return value;
  });
}

/**
 * Compile the REA contract table plus reviewed providers into Concord tools.
 *
 * Only what can actually run is registered. A provider that is not provisioned, or a reviewed
 * provider with no template for a tool, yields no tool rather than one that reports failure after
 * being approved. `rea.catalog` is how the whole surface stays discoverable regardless.
 */
export function makeReverseTools(table, config = {}) {
  const checked = checkTable(table);
  if (!isObject(config)) fail('REVERSE_CONFIG', 'Reverse configuration must be an object');
  for (const key of Object.keys(config)) if (key !== 'providers') fail('REVERSE_CONFIG', 'Unsupported reverse configuration field', { field: key });
  const providers = new Map();
  for (const value of config.providers ?? []) {
    const provider = checkProvider(value);
    if (providers.has(provider.name)) fail('REVERSE_CONFIG', 'Reverse provider names must be unique', { provider: provider.name });
    providers.set(provider.name, provider);
  }

  const byName = new Map(checked.tools.map((entry) => [entry.name, entry]));
  for (const provider of providers.values()) {
    for (const tool of provider.commands.keys()) {
      const entry = byName.get(tool);
      if (!entry) fail('REVERSE_CONFIG', 'A reviewed command names no known REA tool', { provider: provider.name, tool });
      if (entry.provider !== provider.name) {
        fail('REVERSE_CONFIG', 'A reviewed command belongs to a different provider', { provider: provider.name, tool, expected: entry.provider });
      }
    }
  }

  const availability = checked.tools.map((entry) => {
    const provider = entry.provider ? providers.get(entry.provider) : undefined;
    const reviewed = provider ? provider.commands.has(entry.name) : false;
    return {
      name: entry.name, effect: entry.effect, provider: entry.provider,
      internalizable: entry.internalizable, implementedBy: entry.implementedBy,
      realization: entry.implementedBy ? 'static' : entry.provider ? 'provider' : 'unrealized',
      available: Boolean(entry.implementedBy) || reviewed,
      slots: reviewed ? provider.commands.get(entry.name).slots : [],
    };
  });
  const catalogData = deepFreeze({
    schemaVersion: 1, sourceId: checked.sourceId, revision: checked.revision,
    total: availability.length,
    availableNow: availability.filter((a) => a.available).length,
    tools: availability,
  });

  const catalogSchema = {
    type: 'object', additionalProperties: false,
    properties: {
      provider: { type: 'string', minLength: 1, maxLength: 32 },
      availableOnly: { type: 'boolean' },
      query: { type: 'string', minLength: 1, maxLength: 256 },
    },
  };

  const tools = [{
    name: 'rea.catalog', version: '1.0.0', effect: 'pure',
    outputKeys: ['schemaVersion', 'revision', 'total', 'availableNow', 'tools', 'matched', 'grantsCapabilities'],
    inputSchema: catalogSchema, config: { tableDigest: digest(catalogData), total: availability.length },
    execute(input = {}) {
      validateSchema(input, catalogSchema);
      const terms = input.query ? [...new Set(input.query.toLowerCase().match(/[a-z0-9]+/g) ?? [])] : null;
      const rows = catalogData.tools.filter((row) => (!input.provider || row.provider === input.provider)
        && (!input.availableOnly || row.available)
        && (!terms || terms.every((term) => row.name.includes(term))));
      // Inert data describing another program. Listing a name never grants it.
      return { ...catalogData, tools: clone(rows), matched: rows.length, grantsCapabilities: false };
    },
  }];

  for (const provider of providers.values()) {
    for (const [tool, entry] of provider.commands) {
      const inputSchema = schemaForSlots(entry.slots);
      const processShape = {
        name: 'rea.' + tool, version: '1.0.0', executable: provider.executable,
        executableSha256: provider.executableSha256, cwd: provider.cwd,
        env: provider.env, allowedEnv: provider.allowedEnv,
        timeoutMs: provider.timeoutMs, maxOutputBytes: provider.maxOutputBytes,
      };
      tools.push({
        name: 'rea.' + tool, version: '1.0.0', effect: 'process',
        outputKeys: ['tool', 'provider', 'exitCode', 'stdout', 'stderr', 'untrusted'],
        inputSchema,
        // The digest binds the reviewed template into the approval, so changing the operator's
        // command invalidates an approval granted for the previous one.
        config: { provider: provider.name, reaTool: tool, slots: entry.slots, templateDigest: digest(entry.template) },
        async execute(input, context) {
          validateSchema(input, inputSchema);
          const bound = limits(processShape, context, 'rea.' + tool, 'process');
          const args = renderArgv(entry, input, context.workspaceRoot);
          const { executable, cwd } = await resolveExecutable(processShape, context.workspaceRoot);
          // Narrower than it looks: limits() above already refuses an aborted signal as
          // INTEGRATION_ABORTED, so this only fires when cancellation lands in the window while
          // renderArgv and resolveExecutable are running. Measured — an already-aborted signal
          // raises INTEGRATION_ABORTED and never reaches here. Kept because that window is real
          // and resolveExecutable awaits, so the check is not redundant, only hard to reach.
          if (context?.signal?.aborted) fail('REVERSE_ABORTED', 'Provider call was cancelled');
          const { env, secrets } = processEnv(processShape);
          const result = await spawnBounded({
            executable, args, cwd, env, secrets,
            timeoutMs: bound.timeoutMs, maxOutputBytes: bound.maxOutputBytes, signal: context?.signal,
          });
          // Provider output is untrusted text from a program reading a hostile artifact.
          return { tool, provider: provider.name, ...result, untrusted: true };
        },
      });
    }
  }
  return tools;
}
