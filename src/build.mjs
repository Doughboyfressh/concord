import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { lstatSync, readdirSync, readFileSync, realpathSync } from 'node:fs';
import path from 'node:path';
import { digest, parseJson, validateSchema, HarnessError } from './value.mjs';
import { readWorkspaceFile, workspaceFile } from './workspace-fs.mjs';
import { resolveExecutable, processEnv } from './integrations.mjs';

/**
 * Building, as an attestation rather than a transcript.
 *
 * Three tools, and the reason they are not one wrapper around "run the build command":
 *
 * `build.detect` (read) says what build systems the workspace *contains*, with the marker file
 * and its digest as the evidence, and lists the script or target names it actually read out of
 * that file rather than ones it assumes exist. It reports separately which of those systems this
 * harness could actually run — a detected system with no reviewed target configured is detected
 * and not runnable, and the two are different facts. Same posture as sources.catalog: listing
 * something is never a claim to be able to use it.
 *
 * `build.run` (process) runs one reviewed target and returns a receipt: the digest of every
 * declared input file, the digest of every declared output file, the exact argv, the compiler's
 * exit code, and structured diagnostics in which every file:line is bound to the SHA-256 of that
 * file *as the build saw it*. So a reported error is attributable to exact bytes, and a
 * diagnostic that outlived its file can be shown to be stale. A non-zero exit is the result, not
 * an exception — which is why this does not reuse integrations' spawnBounded, whose contract is
 * to reject on any non-zero exit and so would discard the diagnostics of every failing build,
 * the case that matters most.
 *
 * `build.compare` (pure) reads two receipts and separates the two questions a single pass/fail
 * cannot: did the inputs change, and did the output bytes change. Same inputs with different
 * artifacts is a non-reproducible build; different inputs with identical artifacts is an edit
 * that never reached the output. Both are invisible to a harness that only knows whether the
 * build succeeded. Like experiment.compare, it deliberately emits no aggregate score: the exit
 * code transition is reported on its own axis rather than folded into a verdict.
 */

const object = (properties, required = Object.keys(properties)) => ({ type: 'object', properties, required, additionalProperties: false });
const toolName = /^[A-Za-z][A-Za-z0-9_.-]{0,127}$/;
const DEFAULT_TIMEOUT = 120_000;
const DEFAULT_OUTPUT = 1_048_576;
const MAX_TARGETS = 32;
const MAX_PATHS = 64;
const MAX_INPUT_FILES = 4_000;
const MAX_FILE_BYTES = 8 * 1_048_576;
const MAX_DIAGNOSTICS = 200;
const MAX_TAIL = 8_000;
const MAX_ENTRIES = 100;
const MARKER_BYTES = 262_144;

function fail(code, message, details) { throw new HarnessError(code, message, details); }
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');

function text(value, label) {
  if (typeof value !== 'string' || value.length === 0 || value.includes('\0')) fail('BUILD_CONFIG', `${label} must be a nonempty string`);
  return value;
}
function positive(value, fallback, label) {
  const result = value ?? fallback;
  if (!Number.isSafeInteger(result) || result < 1 || result > 2_147_483_647) fail('BUILD_CONFIG', `${label} must be a positive bounded integer`);
  return result;
}
function keys(value, allowed, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail('BUILD_CONFIG', `${label} configuration must be an object`);
  const extra = Object.keys(value).filter((key) => !allowed.includes(key));
  if (extra.length) fail('BUILD_CONFIG', `Unsupported ${label} configuration field`, { field: extra[0] });
}

/** A relative, forward-slashed workspace path, with the same refusals workspaceFile applies. */
function relativePath(value, label) {
  if (typeof value !== 'string' || !value || value.includes('\\') || value.includes(':') || value.includes('\0') || path.isAbsolute(value) ||
      value.split('/').some((part) => !part || part === '.' || part === '..')) {
    fail('BUILD_CONFIG', `${label} must be an unambiguous relative workspace path`);
  }
  return value;
}

/**
 * Build-system markers, as a reviewed table rather than as inference.
 *
 * A marker is a file whose presence identifies a build system, and `entries` names the function
 * that reads the available script or target names out of it. Where nothing can be read honestly,
 * there is no reader and the system reports no entries rather than a guess — a `Cargo.toml` does
 * not list its own build targets, and pretending otherwise would be the most convincing kind of
 * wrong answer.
 */
const DETECTORS = [
  { system: 'npm', marker: 'package.json', entries: (bytes) => Object.keys(parseJson(bytes.toString('utf8')).scripts ?? {}).sort() },
  { system: 'make', marker: 'Makefile', entries: (bytes) => [...new Set([...bytes.toString('utf8').matchAll(/^([A-Za-z0-9_][A-Za-z0-9_.-]*)\s*:(?!=)/gm)].map((match) => match[1]))].sort() },
  { system: 'cmake', marker: 'CMakeLists.txt', entries: null },
  { system: 'cargo', marker: 'Cargo.toml', entries: null },
  { system: 'go', marker: 'go.mod', entries: null },
  { system: 'gradle', marker: 'build.gradle', entries: null },
  { system: 'gradle-kts', marker: 'build.gradle.kts', entries: null },
  { system: 'maven', marker: 'pom.xml', entries: null },
  { system: 'python', marker: 'pyproject.toml', entries: null },
  { system: 'typescript', marker: 'tsconfig.json', entries: null },
  { system: 'dotnet', marker: 'global.json', entries: null },
  { system: 'zig', marker: 'build.zig', entries: null },
];

/**
 * Diagnostic matchers, each named in the output and each written against real measured output.
 *
 * `node-uncaught-v1` exists because node's own first line lies about location: an uncaught
 * assertion prints `node:internal/modules/run_main:107` as its header, and the file the operator
 * edited appears only in the first non-internal stack frame. A matcher that took the header would
 * report a location inside node for every failing test — measured, not assumed, and the reason
 * this matcher looks for the frame before the header, and reports no location at all rather than
 * one inside node when every frame is internal.
 *
 * Two things these were wrong about on first contact with real output, both found by running a
 * compiler rather than by reading its documentation. A path is matched lazily against an anchored
 * `:line:column` tail instead of by a character class, because `file:///C:/…` contains a colon
 * and a class excluding `:` silently matched nothing — a null location on every Windows frame.
 * And every matcher is fed LF-normalised text (see `normaliseOutput`), because with CRLF the
 * trailing `\r` lands inside the captured message and a multi-line pattern like rustc's never
 * matches at all.
 */
const normaliseOutput = (value) => value.replace(/\r\n?/g, '\n');
/**
 * A stack frame's own file:line:column, matched lazily against the anchored numeric tail.
 *
 * The optional `functionName (` prefix excludes newlines, and that is load-bearing rather than
 * tidiness. With a class that merely excluded parentheses, the prefix matched *across* the line
 * break and consumed the next frame's opening paren, so a stack whose first frame was the
 * operator's file and whose second was inside node matched only the node frame — the one case
 * this matcher exists to avoid reporting. Measured against real node output, not reasoned about.
 */
const FRAME = /^\s+at (?:[^()\n]*\()?(?<file>[^\s()]+?):(?<line>\d+):(?<column>\d+)\)?$/gm;
/** The header line node prints above a stack, which names a file and a line but no column. */
const HEADER = /^(?<file>[^\s()]+?):(?<line>\d+)$/m;
const MATCHERS = {
  none: { name: 'none', parse: () => [] },
  'gcc-v1': {
    name: 'gcc-v1',
    parse: (output) => [...output.matchAll(/^(?<file>[^\s:][^:\n]*):(?<line>\d+):(?<column>\d+): (?<severity>error|warning|note): (?<message>[^\n]*)$/gm)]
      .map((match) => ({ ...match.groups, line: Number(match.groups.line), column: Number(match.groups.column), code: null })),
  },
  'tsc-v1': {
    name: 'tsc-v1',
    parse: (output) => [...output.matchAll(/^(?<file>[^(\n]+)\((?<line>\d+),(?<column>\d+)\): (?<severity>error|warning) (?<code>TS\d+): (?<message>[^\n]*)$/gm)]
      .map((match) => ({ ...match.groups, line: Number(match.groups.line), column: Number(match.groups.column) })),
  },
  'msvc-v1': {
    name: 'msvc-v1',
    parse: (output) => [...output.matchAll(/^(?<file>[^(\n]+)\((?<line>\d+)\): (?<severity>error|warning) (?<code>[A-Z]+\d+): (?<message>[^\n]*)$/gm)]
      .map((match) => ({ ...match.groups, line: Number(match.groups.line), column: null })),
  },
  'rustc-v1': {
    name: 'rustc-v1',
    parse: (output) => [...output.matchAll(/^(?<severity>error|warning)(?:\[(?<code>E\d+)\])?: (?<message>[^\n]*)\n(?:[^\n]*\n)??\s*--> (?<file>[^:\n]+):(?<line>\d+):(?<column>\d+)$/gm)]
      .map((match) => ({ ...match.groups, code: match.groups.code ?? null, line: Number(match.groups.line), column: Number(match.groups.column) })),
  },
  'node-uncaught-v1': {
    name: 'node-uncaught-v1',
    parse: (output) => {
      // The prefix before Error/Exception is optional, because a bare `Error: …` — the commonest
      // form node prints — needs no prefix at all, and requiring one silently matched nothing.
      const thrown = output.match(/^(?<kind>(?:[A-Za-z_$][\w$]*)?(?:Error|Exception))(?: \[(?<code>[A-Z_0-9]+)\])?: (?<message>[^\n]*)$/m);
      if (!thrown) return [];
      // The first stack frame that is not inside node itself is the only location in this output
      // that refers to code an operator wrote. The header line above the stack usually does not,
      // so it is used only as a fallback and only when it is not itself a node-internal path.
      const frame = [...output.matchAll(FRAME)].find((match) => !match.groups.file.startsWith('node:'));
      const header = output.match(HEADER);
      const fallback = header?.groups && !header.groups.file.startsWith('node:') ? { ...header.groups, column: null } : null;
      const where = frame?.groups ?? fallback;
      return [{
        file: where?.file ?? null,
        line: where ? Number(where.line) : null,
        column: where?.column == null ? null : Number(where.column),
        severity: 'error', code: thrown.groups.code ?? thrown.groups.kind, message: thrown.groups.message,
      }];
    },
  },
};

function targetSettings(value, index) {
  keys(value, ['name', 'system', 'executable', 'executableSha256', 'args', 'cwd', 'env', 'allowedEnv', 'diagnostics', 'inputs', 'artifacts', 'timeoutMs', 'maxOutputBytes'], 'build target');
  const target = {
    name: text(value.name, `target[${index}] name`),
    system: text(value.system ?? 'custom', `target[${index}] system`),
    executable: text(value.executable, `target[${index}] executable`),
    executableSha256: value.executableSha256,
    args: value.args ?? [],
    cwd: value.cwd ?? '.',
    env: value.env ?? {},
    allowedEnv: value.allowedEnv ?? [],
    diagnostics: value.diagnostics ?? 'none',
    inputs: value.inputs ?? [],
    artifacts: value.artifacts ?? [],
    timeoutMs: positive(value.timeoutMs, DEFAULT_TIMEOUT, `target[${index}] timeoutMs`),
    maxOutputBytes: positive(value.maxOutputBytes, DEFAULT_OUTPUT, `target[${index}] maxOutputBytes`),
  };
  if (!toolName.test(target.name)) fail('BUILD_CONFIG', 'Invalid build target name');
  if (!path.isAbsolute(target.executable)) fail('BUILD_CONFIG', 'Build target executable must be an absolute path');
  if (!/^[a-f0-9]{64}$/.test(target.executableSha256 ?? '')) fail('BUILD_CONFIG', 'A reviewed build target requires an exact executable digest');
  if (!Array.isArray(target.args) || target.args.length > 64 || target.args.some((arg) => typeof arg !== 'string' || arg.includes('\0'))) {
    fail('BUILD_CONFIG', 'Build target args must be at most 64 fixed strings');
  }
  if (typeof target.cwd !== 'string' || path.isAbsolute(target.cwd)) fail('BUILD_CONFIG', 'Build target cwd must be relative to the workspace');
  if (target.cwd !== '.') relativePath(target.cwd, `target[${index}] cwd`);
  if (!Object.hasOwn(MATCHERS, target.diagnostics)) fail('BUILD_CONFIG', 'Unknown diagnostics matcher', { known: Object.keys(MATCHERS).sort().join(',') });
  for (const field of ['inputs', 'artifacts']) {
    if (!Array.isArray(target[field]) || target[field].length > MAX_PATHS) fail('BUILD_CONFIG', `Build target ${field} must be at most ${MAX_PATHS} paths`);
    target[field] = target[field].map((entry) => relativePath(entry, `target[${index}] ${field}`));
  }
  return target;
}

function buildSettings(value) {
  keys(value, ['detectName', 'runName', 'compareName', 'targets', 'timeoutMs', 'maxOutputBytes'], 'build');
  const config = {
    detectName: value.detectName ?? 'build.detect',
    runName: value.runName ?? 'build.run',
    compareName: value.compareName ?? 'build.compare',
    timeoutMs: positive(value.timeoutMs, DEFAULT_TIMEOUT, 'timeoutMs'),
    maxOutputBytes: positive(value.maxOutputBytes, DEFAULT_OUTPUT, 'maxOutputBytes'),
    targets: [],
  };
  for (const field of ['detectName', 'runName', 'compareName']) {
    if (!toolName.test(config[field])) fail('BUILD_CONFIG', 'Invalid build tool name');
  }
  if (new Set([config.detectName, config.runName, config.compareName]).size !== 3) fail('BUILD_CONFIG', 'Build tool names must be distinct');
  if (value.targets !== undefined) {
    if (!Array.isArray(value.targets) || value.targets.length === 0) fail('BUILD_CONFIG', 'targets must be a nonempty array when present');
    if (value.targets.length > MAX_TARGETS) fail('BUILD_CONFIG', `At most ${MAX_TARGETS} build targets may be configured`);
    config.targets = value.targets.map(targetSettings);
    const names = config.targets.map((target) => target.name);
    if (new Set(names).size !== names.length) fail('BUILD_CONFIG', 'Build target names must be distinct');
  }
  return config;
}

/**
 * Same shape as browser.limits and web.limits, with this module's own codes, and the same rule:
 * narrow against policy, never widen.
 */
function limits(config, context, name, effect) {
  const policy = context?.policy ?? {};
  if (Array.isArray(policy.allowedTools) && !policy.allowedTools.includes(name)) fail('BUILD_POLICY', 'Build tool is not allowlisted');
  if (Array.isArray(policy.allowedEffects) && !policy.allowedEffects.includes(effect)) fail('BUILD_POLICY', `Build ${effect} effect is not allowlisted`);
  if (context?.signal?.aborted) fail('BUILD_ABORTED', 'Build was cancelled');
  return {
    timeoutMs: Math.min(config.timeoutMs, positive(policy.timeoutMs, config.timeoutMs, 'policy timeoutMs')),
    maxOutputBytes: Math.min(config.maxOutputBytes, positive(policy.maxOutputBytes, config.maxOutputBytes, 'policy maxOutputBytes')),
  };
}

/**
 * Digest every file under a declared path, or refuse.
 *
 * Bounded by file count and by per-file size, and the bound is a refusal rather than a
 * truncation: an input set that silently stopped at four thousand files would make inputsSha256
 * describe a prefix of the build's inputs while claiming to describe all of them, which is worse
 * than having no digest at all. Links are skipped and counted, because the digest should describe
 * what this walk read and nothing else.
 */
function digestPaths(root, entries) {
  const files = [];
  let skipped = 0;
  const visit = (relative) => {
    if (files.length > MAX_INPUT_FILES) fail('BUILD_INPUT_LIMIT', `A declared path set exceeds ${MAX_INPUT_FILES} files`);
    const absolute = path.resolve(root, relative);
    let stat;
    try { stat = lstatSync(absolute); } catch { return; }
    if (stat.isSymbolicLink()) { skipped += 1; return; }
    if (stat.isDirectory()) {
      for (const child of readdirSync(absolute, { withFileTypes: true }).map((entry) => entry.name).sort()) visit(`${relative}/${child}`);
      return;
    }
    if (!stat.isFile()) { skipped += 1; return; }
    if (stat.size > MAX_FILE_BYTES) { skipped += 1; return; }
    // Routed through workspaceFile so a declared path cannot reach outside the workspace, and so
    // a link anywhere along it is refused by the same check every other reader here uses.
    let bytes;
    try { bytes = readFileSync(workspaceFile(root, relative)); } catch { skipped += 1; return; }
    files.push({ path: relative, sha256: sha256(bytes), bytes: bytes.length });
  };
  for (const entry of entries) visit(entry);
  files.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  // The declared path list is inside the digest, not only the files found under it. Without it, a
  // target declaring no artifacts and a target whose declared artifact was never produced both
  // hash the empty list and compare as identical — so a build that produced nothing would look
  // reproducible against one that was never asked to produce anything.
  return { files, skipped, sha256: digest({ declared: [...entries].sort(), files }) };
}

/** One bounded child whose non-zero exit is data. Only transport, timeout and abort are refusals. */
function runBounded({ executable, args, cwd, env, timeoutMs, maxOutputBytes, signal }) {
  return new Promise((resolveRun, reject) => {
    const child = spawn(executable, args, { cwd, env, shell: false, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
    let outcome;
    let total = 0;
    let truncated = false;
    const stdout = [];
    const stderr = [];
    let timer;
    const cancelled = () => stop('BUILD_ABORTED', 'Build was cancelled');
    const stop = (code, message) => {
      outcome ??= new HarnessError(code, message);
      child.kill('SIGKILL');
      child.stdout.destroy();
      child.stderr.destroy();
    };
    // Output past the budget is dropped and flagged rather than failing the build: a compiler that
    // emits ten thousand warnings has still told us its exit code, and losing that to a byte limit
    // would discard the one fact the caller most needs. The flag is what keeps it honest.
    const collect = (chunk, chunks) => {
      total += chunk.length;
      if (total > maxOutputBytes) truncated = true;
      else chunks.push(chunk);
    };
    child.stdout.on('data', (chunk) => collect(chunk, stdout));
    child.stderr.on('data', (chunk) => collect(chunk, stderr));
    child.stdout.on('error', () => stop('BUILD_IO', 'Build output failed'));
    child.stderr.on('error', () => stop('BUILD_IO', 'Build diagnostics failed'));
    child.on('error', () => { outcome ??= new HarnessError('BUILD_PROCESS', 'Build could not start'); });
    child.on('close', (code, sig) => {
      clearTimeout(timer);
      signal?.removeEventListener('abort', cancelled);
      if (outcome) { reject(outcome); return; }
      const decode = (chunks) => Buffer.concat(chunks).toString('utf8');
      resolveRun({ exitCode: code, signal: sig ?? null, stdout: decode(stdout), stderr: decode(stderr), truncated });
    });
    timer = setTimeout(() => stop('BUILD_TIMEOUT', 'Build timed out'), timeoutMs);
    signal?.addEventListener('abort', cancelled, { once: true });
    if (signal?.aborted) cancelled();
  });
}

/**
 * Bind every diagnostic to the bytes of the file it names.
 *
 * A diagnostic is a claim about a file at a moment. Recording the file's digest is what makes the
 * claim checkable later: if the digest no longer matches, the diagnostic describes bytes that no
 * longer exist, and a caller can tell that without rebuilding. A path outside the workspace, or
 * one that cannot be read, gets a null digest rather than a fabricated one.
 */
function resolved(file) {
  try { return realpathSync.native(file); } catch { return file; }
}

function bindDiagnostics(raw, root) {
  const cache = new Map();
  const digestOf = (file) => {
    if (typeof file !== 'string' || !file) return null;
    let relative = file;
    if (relative.startsWith('file:///')) {
      try { relative = new URL(relative).pathname.replace(/^\/([A-Za-z]:)/, '$1'); } catch { return null; }
    }
    // A toolchain reports the path the operating system resolved, which need not be spelled the
    // way the workspace root was given (a Windows 8.3 short name, a macOS /var symlink). Compare
    // the resolved forms, or a file inside the workspace is mistaken for one outside it.
    const absolute = resolved(path.isAbsolute(relative) ? relative : path.resolve(root, relative));
    const rooted = path.relative(resolved(root), absolute);
    if (!rooted || rooted.startsWith('..') || path.isAbsolute(rooted)) return null;
    const key = rooted.split(path.sep).join('/');
    if (!cache.has(key)) {
      try { cache.set(key, { path: key, sha256: sha256(readWorkspaceFile(root, key, MAX_FILE_BYTES)) }); }
      catch { cache.set(key, { path: key, sha256: null }); }
    }
    return cache.get(key);
  };
  return raw.slice(0, MAX_DIAGNOSTICS).map((entry) => {
    const bound = digestOf(entry.file);
    return {
      file: entry.file ?? null, workspacePath: bound?.path ?? null, fileSha256: bound?.sha256 ?? null,
      line: entry.line ?? null, column: entry.column ?? null,
      severity: entry.severity ?? 'error', code: entry.code ?? null,
      message: typeof entry.message === 'string' ? entry.message.slice(0, 2048) : '',
    };
  });
}

const detectInputSchema = object({ directory: { type: 'string', minLength: 1, maxLength: 1024 } }, []);
const runInputSchema = object({
  target: { type: 'string', minLength: 1, maxLength: 128 },
  expectArtifactsSha256: { type: 'string', minLength: 64, maxLength: 64 },
}, ['target']);
/**
 * Deliberately open: a whole build.run result is a valid receipt.
 *
 * Closing this to four properties would mean a plan could not write
 * `{left: {$task: 'before'}, right: {$task: 'after'}}` — it would have to project the fields by
 * hand, and the tool that consumes build.run's output would be the one tool unable to accept it.
 * The four fields it reads are required and typed; everything else travels along unread.
 */
const receiptSchema = {
  type: 'object', required: ['inputsSha256', 'artifactsSha256', 'exitCode'],
  properties: {
    inputsSha256: { type: 'string', minLength: 64, maxLength: 64 },
    artifactsSha256: { type: 'string', minLength: 64, maxLength: 64 },
    exitCode: { type: 'integer', minimum: -1, maximum: 255 },
    receipt: { type: 'string', minLength: 64, maxLength: 64 },
  },
};
const compareInputSchema = object({ left: receiptSchema, right: receiptSchema });

/**
 * `build.detect` and `build.compare` always, `build.run` only where a reviewed target exists.
 *
 * An absent configuration registers nothing. A configuration with no targets registers the two
 * tools that need no executable, because detecting a build system and comparing two receipts are
 * both useful on a machine that is not permitted to build anything — and a `build.run` that could
 * only ever refuse would be a capability in name only.
 */
export function makeBuildTools(config) {
  if (config === undefined) return [];
  const settings = buildSettings(config);
  const byName = new Map(settings.targets.map((target) => [target.name, target]));
  const names = [...byName.keys()].sort();

  const detectTool = {
    name: settings.detectName, version: '1', effect: 'read', inputSchema: detectInputSchema, config: settings,
    outputKeys: ['directory', 'detector', 'markersChecked', 'systems', 'count', 'multiple', 'runnable', 'untrusted'],
    execute(input, context) {
      validateSchema(input, detectInputSchema);
      limits(settings, context, settings.detectName, 'read');
      const directory = input.directory === undefined ? null : relativePath(input.directory, 'directory');
      const root = context.workspaceRoot;
      const systems = [];
      for (const detector of DETECTORS) {
        const relative = directory ? `${directory}/${detector.marker}` : detector.marker;
        let bytes;
        try { bytes = readWorkspaceFile(root, relative, MARKER_BYTES); } catch { continue; }
        let entries = [];
        let entriesRead = false;
        if (detector.entries) {
          // A marker this harness cannot parse is still a marker. The system is reported with
          // entriesRead:false rather than dropped, because "there is a package.json here and I
          // could not read its scripts" is a different fact from "there is no package.json".
          try { entries = detector.entries(bytes).slice(0, MAX_ENTRIES); entriesRead = true; } catch { entries = []; }
        }
        systems.push({
          system: detector.system, marker: relative, markerSha256: sha256(bytes), bytes: bytes.length,
          entries, entriesRead,
          targets: settings.targets.filter((target) => target.system === detector.system).map((target) => target.name).sort(),
        });
      }
      const runnable = systems.filter((entry) => entry.targets.length > 0).map((entry) => entry.system).sort();
      return {
        directory, detector: 'markers-v1', markersChecked: DETECTORS.length,
        systems, count: systems.length,
        // The normal real-world case, and the usual source of a confident wrong guess about which
        // build system a repository "is". Reported rather than resolved: choosing for the caller
        // would hide the ambiguity that is the actual finding.
        multiple: systems.length > 1,
        runnable, untrusted: true,
      };
    },
  };

  const compareTool = {
    name: settings.compareName, version: '1', effect: 'pure', inputSchema: compareInputSchema, config: settings,
    outputKeys: ['inputsChanged', 'artifactsChanged', 'exitCodeChanged', 'verdict', 'transition', 'sameReceipt', 'interpretation'],
    execute(input) {
      validateSchema(input, compareInputSchema);
      const { left, right } = input;
      const inputsChanged = left.inputsSha256 !== right.inputsSha256;
      const artifactsChanged = left.artifactsSha256 !== right.artifactsSha256;
      const verdict = inputsChanged
        ? (artifactsChanged ? 'changed' : 'inputs-changed-output-did-not')
        : (artifactsChanged ? 'nondeterministic-build' : 'identical');
      const interpretation = {
        identical: 'The same declared inputs produced the same declared output bytes.',
        changed: 'The declared inputs changed and so did the output bytes.',
        'inputs-changed-output-did-not': 'The declared inputs changed but the output bytes did not, so the change did not reach what was built.',
        'nondeterministic-build': 'The declared inputs are identical but the output bytes differ, so this build is not reproducible from its declared inputs.',
      }[verdict];
      const ok = (value) => value.exitCode === 0;
      return {
        inputsChanged, artifactsChanged, exitCodeChanged: left.exitCode !== right.exitCode,
        verdict,
        // Reported on its own axis rather than folded into the verdict, because "the build now
        // fails" and "the build is not reproducible" are independent findings and a single score
        // would hide whichever one it did not name.
        transition: ok(left) && ok(right) ? 'still-succeeding' : (!ok(left) && !ok(right) ? 'still-failing' : (ok(left) ? 'broken' : 'fixed')),
        sameReceipt: left.receipt !== undefined && right.receipt !== undefined ? left.receipt === right.receipt : null,
        interpretation,
      };
    },
  };

  const runTool = names.length === 0 ? null : {
    name: settings.runName, version: '1', effect: 'process',
    inputSchema: {
      type: 'object', required: ['target'], additionalProperties: false,
      properties: { target: { enum: names }, expectArtifactsSha256: { type: 'string', minLength: 64, maxLength: 64 } },
    },
    config: settings,
    outputKeys: ['target', 'system', 'matcher', 'argv', 'exitCode', 'signal', 'ok', 'truncated',
      'stdoutBytes', 'stdoutSha256', 'stdoutTail', 'stderrBytes', 'stderrSha256', 'stderrTail',
      'diagnostics', 'diagnosticCounts', 'inputs', 'inputsSkipped', 'inputsSha256',
      'artifacts', 'artifactsProduced', 'artifactsSha256', 'receipt', 'reproduced', 'untrusted'],
    async execute(input, context) {
      validateSchema(input, runTool.inputSchema);
      const target = byName.get(input.target);
      if (!target) fail('BUILD_UNKNOWN_TARGET', 'No such reviewed build target', { known: names.join(',') });
      if (input.expectArtifactsSha256 !== undefined && !/^[a-f0-9]{64}$/.test(input.expectArtifactsSha256)) {
        fail('BUILD_INPUT', 'expectArtifactsSha256 must be a lowercase hex SHA-256');
      }
      const bound = limits(
        { timeoutMs: Math.min(settings.timeoutMs, target.timeoutMs), maxOutputBytes: Math.min(settings.maxOutputBytes, target.maxOutputBytes) },
        context, settings.runName, 'process',
      );
      // The same guard integrations' reviewed process entries use, reused rather than reimplemented:
      // realpath, regular-file, workspace-contained cwd, and a mandatory digest match. It reports
      // INTEGRATION_EXECUTABLE/CWD/PATH, and keeping those codes is the point — one guard, one set
      // of codes, no second copy to drift.
      const { executable, cwd } = await resolveExecutable(target, context.workspaceRoot);
      const { env } = processEnv(target);
      const root = context.workspaceRoot;
      // Inputs are digested before the build so the receipt describes what was compiled, not
      // whatever the tree looks like afterwards; artifacts are digested after, for the same reason.
      const inputs = digestPaths(root, target.inputs);
      // The declared artifacts are digested before the run as well as after, so the receipt can
      // say which of them this run actually wrote. Without the before-snapshot a file left by an
      // earlier build is reported exactly like one this build produced, and the receipt attests
      // to an output it had nothing to do with. Found by a training round whose failing target
      // declared the same artifact path as a successful one that had already run.
      const before = digestPaths(root, target.artifacts);
      const run = await runBounded({
        executable, args: target.args, cwd, env,
        timeoutMs: bound.timeoutMs, maxOutputBytes: bound.maxOutputBytes, signal: context?.signal,
      });
      const artifacts = digestPaths(root, target.artifacts);
      const previous = new Map(before.files.map((entry) => [entry.path, entry.sha256]));
      const produced = artifacts.files.filter((entry) => previous.get(entry.path) !== entry.sha256).map((entry) => entry.path);
      const matcher = MATCHERS[target.diagnostics];
      const diagnostics = bindDiagnostics(matcher.parse(normaliseOutput(`${run.stdout}\n${run.stderr}`)), root);
      const counts = {};
      for (const entry of diagnostics) counts[entry.severity] = (counts[entry.severity] ?? 0) + 1;
      const argv = [path.basename(executable), ...target.args];
      const receipt = digest({
        target: target.name, argv, executableSha256: target.executableSha256,
        inputsSha256: inputs.sha256, artifactsSha256: artifacts.sha256, exitCode: run.exitCode ?? -1,
      });
      const tail = (value) => (value.length > MAX_TAIL ? value.slice(value.length - MAX_TAIL) : value);
      return {
        target: target.name, system: target.system, matcher: matcher.name,
        // The executable's own path is never echoed; its basename plus the reviewed args is what a
        // reader needs, and the full path belongs to the configuration rather than to the result.
        // A child killed by a signal reports no exit code at all. Recorded as -1 rather than null
        // so a receipt stays comparable through build.compare, with `signal` carrying the detail.
        argv, exitCode: run.exitCode ?? -1, signal: run.signal, ok: run.exitCode === 0, truncated: run.truncated,
        stdoutBytes: Buffer.byteLength(run.stdout), stdoutSha256: sha256(run.stdout), stdoutTail: tail(run.stdout),
        stderrBytes: Buffer.byteLength(run.stderr), stderrSha256: sha256(run.stderr), stderrTail: tail(run.stderr),
        diagnostics, diagnosticCounts: counts,
        inputs: inputs.files, inputsSkipped: inputs.skipped, inputsSha256: inputs.sha256,
        artifacts: artifacts.files,
        // Which declared artifacts this run changed or created, as distinct from which exist.
        // Deliberately outside artifactsSha256 and outside the receipt: the digest has to stay a
        // statement about bytes, so that two runs over identical inputs keep an identical receipt
        // whether the second one needed to rewrite the file or found it already correct.
        artifactsProduced: produced,
        artifactsSha256: artifacts.sha256,
        receipt,
        // A rebuild that was asked to match and did not is the finding, so it is a value rather
        // than a refusal: the diagnostics and both digests travel with the answer.
        reproduced: input.expectArtifactsSha256 === undefined ? null : artifacts.sha256 === input.expectArtifactsSha256,
        untrusted: true,
      };
    },
  };

  const tools = runTool ? [detectTool, runTool, compareTool] : [detectTool, compareTool];
  for (const tool of tools) {
    Object.freeze(tool.config);
    Object.freeze(tool.inputSchema);
    Object.freeze(tool.outputKeys);
    Object.freeze(tool);
  }
  return tools;
}

/** Exported for direct unit testing of the parts that need no child process. */
export const internals = { DETECTORS, MATCHERS, buildSettings, digestPaths, bindDiagnostics, limits };
