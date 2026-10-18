import { createHash } from 'node:crypto';
import { readWorkspaceFile } from './workspace-fs.mjs';
import { parseJson } from './value.mjs';

/**
 * JavaScript, source maps, bundles, HTML scripts and HTTP archives.
 *
 * REA reaches these through a browser and its JavaScript provider. The parts that are specified
 * formats — source map VLQ mappings, HAR JSON — are decoded here exactly. The parts that need a
 * JavaScript parser are deliberately *lexical*, and say so: a full ECMAScript parser is not
 * reimplemented, so what these tools report is what the token stream states, never what the
 * program would do at runtime.
 *
 * The one thing a lexical scan must get right is not being fooled by its own input. `stripNonCode`
 * blanks comments, strings, template literals and regular expressions while preserving every byte
 * offset and newline, so a later match cannot fire on the word `import` inside a comment or a
 * string, and reported line numbers still refer to the real file.
 */

const object = (properties, required = Object.keys(properties)) => ({ type: 'object', properties, required, additionalProperties: false });
const string = { type: 'string', maxLength: 65536 };
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');

const MAX_LISTED = 2000;
const MAX_MAPPINGS = 200000;
const MAX_TEXT_BYTES = 8 * 1024 * 1024;
const MAX_SOURCE_CHARS = 262144;
const MAX_GRAPH_FILES = 512;

const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const B64_INDEX = new Map([...B64].map((c, i) => [c, i]));

const readText = (context, relative, divisor = 4) => {
  const bytes = readWorkspaceFile(context.workspaceRoot, relative, Math.min(MAX_TEXT_BYTES, Math.floor(context.policy.maxOutputBytes / divisor)));
  let text = null;
  try { text = new TextDecoder('utf-8', { fatal: true }).decode(bytes); }
  catch { text = null; }
  return { bytes, text };
};

/**
 * Blank everything that is not code, keeping length and newlines.
 *
 * Whether `/` begins a regular expression or is a division operator depends on what preceded it,
 * which is decided here from the last significant character. That rule is correct for ordinary
 * code and imperfect after a closing brace, where a block and an object literal are
 * indistinguishable without parsing; the tools that use this report it as a limitation rather than
 * implying the scan is a parse.
 */
export function stripNonCode(text) {
  const out = Array.from(text);
  const blank = (from, to) => {
    for (let i = from; i < to && i < out.length; i++) if (out[i] !== '\n') out[i] = ' ';
  };
  let lastSignificant = '';
  let i = 0;
  const templates = [];
  while (i < text.length) {
    const ch = text[i];
    const next = text[i + 1];
    if (ch === '/' && next === '/') {
      let end = text.indexOf('\n', i);
      if (end < 0) end = text.length;
      blank(i, end);
      i = end;
      continue;
    }
    if (ch === '/' && next === '*') {
      const end = text.indexOf('*/', i + 2);
      const stop = end < 0 ? text.length : end + 2;
      blank(i, stop);
      i = stop;
      continue;
    }
    if (ch === '"' || ch === "'") {
      let j = i + 1;
      while (j < text.length) {
        if (text[j] === '\\') { j += 2; continue; }
        if (text[j] === ch || text[j] === '\n') break;
        j += 1;
      }
      blank(i + 1, j);
      lastSignificant = ch;
      i = Math.min(j + 1, text.length);
      continue;
    }
    if (ch === '`') {
      templates.push(i);
      let j = i + 1;
      while (j < text.length) {
        if (text[j] === '\\') { j += 2; continue; }
        if (text[j] === '`') break;
        // A ${...} hole is code, so it is left intact and only the literal parts are blanked.
        if (text[j] === '$' && text[j + 1] === '{') {
          blank(i + 1, j);
          let depth = 1;
          let k = j + 2;
          while (k < text.length && depth > 0) {
            if (text[k] === '{') depth += 1;
            else if (text[k] === '}') depth -= 1;
            k += 1;
          }
          i = k - 1;
          j = k - 1;
          break;
        }
        j += 1;
      }
      if (j < text.length && text[j] === '`') { blank(i + 1, j); i = j + 1; lastSignificant = '`'; continue; }
      i += 1;
      continue;
    }
    if (ch === '/') {
      const regexAllowed = lastSignificant === '' || !/[\w$)\]'"`]/.test(lastSignificant);
      if (regexAllowed) {
        let j = i + 1;
        let inClass = false;
        let closed = false;
        while (j < text.length) {
          if (text[j] === '\\') { j += 2; continue; }
          if (text[j] === '\n') break;
          if (text[j] === '[') inClass = true;
          else if (text[j] === ']') inClass = false;
          else if (text[j] === '/' && !inClass) { closed = true; break; }
          j += 1;
        }
        if (closed) {
          while (j + 1 < text.length && /[a-z]/.test(text[j + 1])) j += 1;
          blank(i, j + 1);
          lastSignificant = ')';
          i = j + 1;
          continue;
        }
      }
    }
    if (!/\s/.test(ch)) lastSignificant = ch;
    i += 1;
  }
  return out.join('');
}

const lineOf = (text, index) => {
  let line = 1;
  for (let i = 0; i < index && i < text.length; i++) if (text[i] === '\n') line += 1;
  return line;
};

/** Signed VLQ base64, as source map mappings use. */
function decodeVlq(segment, at) {
  let result = 0;
  let shift = 0;
  let index = at;
  for (;;) {
    if (index >= segment.length) return null;
    const digit = B64_INDEX.get(segment[index]);
    if (digit === undefined) return null;
    index += 1;
    result += (digit & 31) * 2 ** shift;
    shift += 5;
    if ((digit & 32) === 0) break;
    if (shift > 50) return null;
  }
  const negative = (result & 1) === 1;
  const value = Math.floor(result / 2);
  return { value: negative ? -value : value, offset: index };
}

/**
 * Decode a source map's `mappings` field.
 *
 * Every field is a delta against a running state, and only `generatedColumn` resets per line, so
 * a decoder that reset the others would silently produce plausible-looking wrong origins.
 */
export function decodeMappings(mappings, limitations) {
  const entries = [];
  let generatedLine = 0;
  let sourceIndex = 0;
  let originalLine = 0;
  let originalColumn = 0;
  let nameIndex = 0;
  for (const lineText of mappings.split(';')) {
    let generatedColumn = 0;
    if (lineText.length) {
      for (const segment of lineText.split(',')) {
        if (!segment.length) continue;
        if (entries.length >= MAX_MAPPINGS) { limitations.push('The mapping bound was reached'); return entries; }
        let at = 0;
        const column = decodeVlq(segment, at);
        if (!column) { limitations.push('A mapping segment is malformed'); return entries; }
        generatedColumn += column.value;
        at = column.offset;
        const entry = { generatedLine, generatedColumn, originalSource: null, originalLine: null, originalColumn: null, name: null };
        if (at < segment.length) {
          const source = decodeVlq(segment, at);
          if (!source) { limitations.push('A mapping source field is malformed'); return entries; }
          sourceIndex += source.value;
          at = source.offset;
          const line = decodeVlq(segment, at);
          if (!line) { limitations.push('A mapping line field is malformed'); return entries; }
          originalLine += line.value;
          at = line.offset;
          const col = decodeVlq(segment, at);
          if (!col) { limitations.push('A mapping column field is malformed'); return entries; }
          originalColumn += col.value;
          at = col.offset;
          entry.sourceIndex = sourceIndex;
          entry.originalLine = originalLine;
          entry.originalColumn = originalColumn;
          if (at < segment.length) {
            const named = decodeVlq(segment, at);
            if (!named) { limitations.push('A mapping name field is malformed'); return entries; }
            nameIndex += named.value;
            entry.nameIndex = nameIndex;
          }
        }
        entries.push(entry);
      }
    }
    generatedLine += 1;
  }
  return entries;
}

/** A source map document, with its mappings decoded. */
export function parseSourceMap(text) {
  const limitations = [];
  let document;
  try { document = parseJson(text); }
  catch { return { supported: false, reason: 'not_json', detail: 'The file is not strict JSON', limitations }; }
  if (!document || typeof document !== 'object' || Array.isArray(document)) {
    return { supported: false, reason: 'not_a_source_map', detail: 'The document is not a JSON object', limitations };
  }
  if (document.sections) {
    return { supported: false, reason: 'index_map_unsupported',
      detail: 'This is an index map, whose sections are not combined by this reader', limitations };
  }
  if (document.version !== 3) {
    return { supported: false, reason: 'version_unsupported', detail: 'Only source map version 3 is decoded', limitations };
  }
  const sources = Array.isArray(document.sources) ? document.sources : [];
  const names = Array.isArray(document.names) ? document.names : [];
  const contents = Array.isArray(document.sourcesContent) ? document.sourcesContent : [];
  if (typeof document.mappings !== 'string') {
    return { supported: false, reason: 'mappings_absent', detail: 'The map declares no mappings string', limitations };
  }
  const entries = decodeMappings(document.mappings, limitations);
  const resolved = entries.map((entry) => ({
    generatedLine: entry.generatedLine, generatedColumn: entry.generatedColumn,
    originalSource: entry.sourceIndex === undefined ? null : sources[entry.sourceIndex] ?? null,
    originalLine: entry.originalLine, originalColumn: entry.originalColumn,
    name: entry.nameIndex === undefined ? null : names[entry.nameIndex] ?? null,
  }));
  if (resolved.some((entry) => entry.originalSource === null && entry.originalLine !== null)) {
    limitations.push('A mapping names a source index the sources array does not contain');
  }
  return { supported: true, reason: null, version: 3, file: document.file ?? null,
    sourceRoot: document.sourceRoot ?? null, sources, names, contents, entries: resolved, limitations };
}

const IMPORT_PATTERNS = [
  // Static import with any clause form, and the bare side-effect form.
  [/\bimport\s+(?:[\w$*{][^;'"]*?\s+from\s+)?(['"])/g, 'import'],
  // Re-exports, including export * and export * as ns.
  [/\bexport\s+(?:\*(?:\s+as\s+[\w$]+)?|\{[^}]*\})\s+from\s+(['"])/g, 'reexport'],
  // Dynamic import and CommonJS require.
  [/\bimport\s*\(\s*(['"])/g, 'dynamic-import'],
  [/\brequire\s*\(\s*(['"])/g, 'require'],
];

/** Specifier strings are taken from the original text at offsets found in the stripped text. */
function findImports(text, stripped, limitations) {
  const found = [];
  for (const [pattern, kind] of IMPORT_PATTERNS) {
    pattern.lastIndex = 0;
    let match;
    while ((match = pattern.exec(stripped)) !== null) {
      const quote = match[1];
      const start = match.index + match[0].length;
      const end = text.indexOf(quote, start);
      if (end < 0) { limitations.push('An unterminated specifier was skipped'); continue; }
      const specifier = text.slice(start, end);
      if (specifier.includes('\n') || specifier.length > 2048) continue;
      found.push({ kind, specifier, line: lineOf(text, match.index),
        relative: specifier.startsWith('.') || specifier.startsWith('/') });
      if (found.length >= MAX_LISTED) { limitations.push('The import bound was reached'); return found; }
    }
  }
  return found.sort((a, b) => a.line - b.line || (a.specifier < b.specifier ? -1 : 1));
}

const EXPORT_PATTERNS = [
  [/\bexport\s+default\b/g, () => [{ name: 'default', kind: 'default' }]],
  [/\bexport\s+(?:async\s+)?function\s*\*?\s*([\w$]+)/g, (m) => [{ name: m[1], kind: 'function' }]],
  [/\bexport\s+class\s+([\w$]+)/g, (m) => [{ name: m[1], kind: 'class' }]],
  [/\bexport\s+(?:const|let|var)\s+([\w$]+)/g, (m) => [{ name: m[1], kind: 'variable' }]],
  [/\bexport\s*\{([^}]*)\}/g, (m) => m[1].split(',').map((part) => {
    const pieces = part.trim().split(/\s+as\s+/);
    const name = (pieces[1] ?? pieces[0] ?? '').trim();
    return name && /^[\w$"']+$/.test(name) ? { name: name.replace(/['"]/g, ''), kind: 'named' } : null;
  }).filter((entry) => entry !== null)],
  [/\bexports\.([\w$]+)\s*=/g, (m) => [{ name: m[1], kind: 'commonjs' }]],
  [/\bmodule\.exports\s*=/g, () => [{ name: 'module.exports', kind: 'commonjs-whole' }]],
];

function findExports(stripped, limitations) {
  const found = [];
  const seen = new Set();
  for (const [pattern, extract] of EXPORT_PATTERNS) {
    pattern.lastIndex = 0;
    let match;
    while ((match = pattern.exec(stripped)) !== null) {
      for (const entry of extract(match)) {
        const key = entry.kind + ':' + entry.name;
        if (seen.has(key)) continue;
        seen.add(key);
        found.push({ ...entry, line: lineOf(stripped, match.index) });
        if (found.length >= MAX_LISTED) { limitations.push('The export bound was reached'); return found; }
      }
    }
  }
  // A re-export forwards names this file never declares, so it is reported as its own kind.
  const star = /\bexport\s+\*(?:\s+as\s+([\w$]+))?\s+from\b/g;
  let match;
  while ((match = star.exec(stripped)) !== null) {
    found.push({ name: match[1] ?? '*', kind: match[1] ? 'star-as' : 'star', line: lineOf(stripped, match.index) });
  }
  return found.sort((a, b) => a.line - b.line || (a.name < b.name ? -1 : 1));
}

// Constructs worth reporting about a script, each decidable from the token stream alone.
const SEMANTIC_PATTERNS = [
  ['eval', /\beval\s*\(/g, 'evaluates a string as code'],
  ['function-constructor', /\bnew\s+Function\s*\(/g, 'builds a function from a string'],
  ['dynamic-import', /\bimport\s*\(/g, 'loads a module chosen at runtime'],
  ['with', /\bwith\s*\(/g, 'introduces a dynamic scope'],
  ['debugger', /\bdebugger\b/g, 'breaks into a debugger'],
  ['document-write', /\bdocument\s*\.\s*write(?:ln)?\s*\(/g, 'writes markup into the document'],
  ['inner-html', /\.\s*(?:inner|outer)HTML\s*=/g, 'assigns markup as a string'],
  ['insert-adjacent-html', /\.\s*insertAdjacentHTML\s*\(/g, 'inserts markup as a string'],
  ['post-message', /\.\s*postMessage\s*\(/g, 'sends a cross-context message'],
  ['xhr', /\bnew\s+XMLHttpRequest\s*\(/g, 'opens a request through XMLHttpRequest'],
  ['fetch', /\bfetch\s*\(/g, 'opens a request through fetch'],
  ['websocket', /\bnew\s+WebSocket\s*\(/g, 'opens a WebSocket'],
  ['worker', /\bnew\s+(?:Shared)?Worker\s*\(/g, 'starts a worker'],
  ['local-storage', /\b(?:local|session)Storage\b/g, 'reads or writes web storage'],
  ['cookie', /\bdocument\s*\.\s*cookie\b/g, 'reads or writes cookies'],
  ['timer-string', /\bset(?:Timeout|Interval)\s*\(\s*['"]/g, 'passes a string to a timer, which evaluates it'],
];

const BUNDLER_MARKERS = [
  ['webpack', [/\b__webpack_require__\b/, /\bwebpackChunk\w*\b/, /\b__webpack_modules__\b/]],
  ['rollup', [/\bdefine\(\['exports'/, /\/\/#\s*sourceMappingURL=.*\.map\s*$/]],
  ['esbuild', [/\b__toCommonJS\b/, /\b__esmMin\b/, /\b__commonJS\b/]],
  ['parcel', [/\bparcelRequire\b/]],
  ['vite', [/\b__vite__mapDeps\b/, /\bvite\/preload-helper\b/]],
  ['browserify', [/\bbrowserify\b/, /\brequire=function\s*\(/]],
  ['systemjs', [/\bSystem\.register\s*\(/]],
];

const listed = (items, limitations, label) => {
  if (items.length <= MAX_LISTED) return items;
  limitations.push(`Only the first ${MAX_LISTED} ${label} are listed`);
  return items.slice(0, MAX_LISTED);
};

const LEXICAL_NOTE = 'This is a lexical scan rather than a parse, so a construct built at runtime is not visible and a declaration inside an unusual syntactic position may be missed';

/** Parse a HAR document into bounded per-entry facts. */
function parseHar(text) {
  const limitations = [];
  let document;
  try { document = parseJson(text); }
  catch { return { supported: false, reason: 'not_json', detail: 'The file is not strict JSON', entries: [], limitations }; }
  const log = document && typeof document === 'object' ? document.log : null;
  if (!log || typeof log !== 'object' || !Array.isArray(log.entries)) {
    return { supported: false, reason: 'not_a_har', detail: 'The document declares no log.entries array', entries: [], limitations };
  }
  const entries = [];
  for (const entry of log.entries) {
    if (entries.length >= MAX_LISTED) { limitations.push('The entry bound was reached'); break; }
    if (!entry || typeof entry !== 'object') continue;
    const request = entry.request ?? {};
    const response = entry.response ?? {};
    const content = response.content ?? {};
    let origin = null;
    let pathname = null;
    try { const url = new URL(request.url); origin = url.origin; pathname = url.pathname; }
    catch { origin = null; }
    entries.push({
      method: typeof request.method === 'string' ? request.method : null,
      url: typeof request.url === 'string' ? request.url.slice(0, 2048) : null,
      origin, pathname,
      status: typeof response.status === 'number' ? response.status : null,
      mimeType: typeof content.mimeType === 'string' ? content.mimeType.split(';')[0] : null,
      bodySize: typeof content.size === 'number' ? content.size : null,
      transferSize: typeof response.bodySize === 'number' ? response.bodySize : null,
      timeMs: typeof entry.time === 'number' ? entry.time : null,
      startedDateTime: typeof entry.startedDateTime === 'string' ? entry.startedDateTime : null,
      // Header and cookie values are not copied: a capture routinely carries credentials.
      requestHeaderCount: Array.isArray(request.headers) ? request.headers.length : null,
      responseHeaderCount: Array.isArray(response.headers) ? response.headers.length : null,
      hasRequestCookies: Array.isArray(request.cookies) ? request.cookies.length > 0 : null,
    });
  }
  limitations.push('Header, cookie and body values are not reported, because a capture routinely carries credentials');
  return { supported: true, reason: null, creator: log.creator ?? null, version: log.version ?? null, entries, limitations };
}

const requestKey = (entry) => (entry.method ?? '?') + ' ' + (entry.origin ?? '') + (entry.pathname ?? entry.url ?? '');

/** JavaScript, source map, bundle, HTML and HAR readers. */
export function makeWebTools() {
  const pathOnly = object({ path: string });
  const base = (relative, bytes) => ({ path: relative, sha256: sha256(bytes), untrusted: true });
  const notText = (relative, bytes, extra) => ({ ...base(relative, bytes), supported: false, reason: 'not_utf8_text',
    detail: 'The file is not valid UTF-8 text', limitations: [], ...extra });
  const exportShape = {
    type: 'object', additionalProperties: true, required: ['exports'],
    properties: { exports: { type: 'array', maxItems: MAX_LISTED * 2, items: {
      type: 'object', additionalProperties: true, required: ['name', 'kind'],
      properties: { name: { type: 'string', maxLength: 1024 }, kind: { type: 'string', maxLength: 64 } } } } },
  };
  const harShape = {
    type: 'object', additionalProperties: true, required: ['entries'],
    properties: { entries: { type: 'array', maxItems: MAX_LISTED, items: { type: 'object', additionalProperties: true } } },
  };

  return [
    { name: 'artifact.sourceMap', version: '1.0.0', outputKeys: ['path', 'sha256', 'supported', 'sources', 'mappingCount', 'limitations', 'untrusted'], effect: 'read', inputSchema: pathOnly,
      execute({ path: relative }, context) {
        const { bytes, text } = readText(context, relative);
        if (text === null) return notText(relative, bytes, { sources: [], mappingCount: 0 });
        const map = parseSourceMap(text);
        if (!map.supported) return { ...base(relative, bytes), supported: false, reason: map.reason, detail: map.detail, sources: [], mappingCount: 0, limitations: map.limitations };
        const limitations = [...map.limitations];
        const perSource = map.sources.map((source, index) => ({
          source, mappings: map.entries.filter((entry) => entry.originalSource === source).length,
          hasContent: typeof map.contents[index] === 'string',
          contentChars: typeof map.contents[index] === 'string' ? map.contents[index].length : null,
        }));
        return { ...base(relative, bytes), supported: true, reason: null, version: 3,
          file: map.file, sourceRoot: map.sourceRoot, sources: map.sources, names: map.names,
          mappingCount: map.entries.length,
          generatedLines: map.entries.length ? map.entries[map.entries.length - 1].generatedLine + 1 : 0,
          embeddedSources: perSource.filter((entry) => entry.hasContent).length,
          perSource: listed(perSource, limitations, 'sources'), limitations };
      } },
    { name: 'artifact.sourceLocation', version: '1.0.0', outputKeys: ['path', 'sha256', 'supported', 'entry', 'limitations', 'untrusted'], effect: 'read',
      inputSchema: object({ path: string, line: { type: 'integer', minimum: 0 }, column: { type: 'integer', minimum: 0 } }, ['path', 'line', 'column']),
      execute({ path: relative, line, column }, context) {
        const { bytes, text } = readText(context, relative);
        if (text === null) return notText(relative, bytes, { entry: null });
        const map = parseSourceMap(text);
        if (!map.supported) return { ...base(relative, bytes), supported: false, reason: map.reason, detail: map.detail, entry: null, limitations: map.limitations };
        // The nearest mapping at or before the position, which is how a generated position is
        // attributed: an exact hit is not guaranteed because mappings are sparse.
        let best = null;
        for (const entry of map.entries) {
          if (entry.generatedLine > line) break;
          if (entry.generatedLine === line && entry.generatedColumn > column) break;
          best = entry;
        }
        const limitations = [...map.limitations];
        if (best && !(best.generatedLine === line && best.generatedColumn === column)) {
          limitations.push('No mapping starts exactly at the requested position, so the nearest preceding mapping is reported');
        }
        return { ...base(relative, bytes), supported: true, reason: best ? null : 'no_mapping',
          requested: { line, column }, entry: best, limitations };
      } },
    { name: 'artifact.recoverSources', version: '1.0.0', outputKeys: ['path', 'sha256', 'supported', 'sources', 'content', 'limitations', 'untrusted'], effect: 'read',
      inputSchema: object({ path: string, source: string }, ['path']),
      execute({ path: relative, source }, context) {
        const { bytes, text } = readText(context, relative, 2);
        if (text === null) return notText(relative, bytes, { sources: [], content: null });
        const map = parseSourceMap(text);
        if (!map.supported) return { ...base(relative, bytes), supported: false, reason: map.reason, detail: map.detail, sources: [], content: null, limitations: map.limitations };
        const limitations = [...map.limitations];
        const index = map.sources.map((name, i) => ({
          source: name, hasContent: typeof map.contents[i] === 'string',
          chars: typeof map.contents[i] === 'string' ? map.contents[i].length : null,
          sha256: typeof map.contents[i] === 'string' ? sha256(Buffer.from(map.contents[i], 'utf8')) : null,
        }));
        let content = null;
        let reason = null;
        if (source !== undefined) {
          const at = map.sources.indexOf(source);
          if (at < 0) reason = 'source_absent';
          else if (typeof map.contents[at] !== 'string') reason = 'content_absent';
          else {
            content = map.contents[at].slice(0, MAX_SOURCE_CHARS);
            if (map.contents[at].length > MAX_SOURCE_CHARS) limitations.push('The recovered source was truncated to the read bound');
          }
        }
        // Recovered text is the original author's source as the bundler embedded it; it is
        // reported, never written back, because writing would be a different effect entirely.
        if (!index.some((entry) => entry.hasContent)) limitations.push('The map embeds no sourcesContent, so no original source is recoverable from it alone');
        return { ...base(relative, bytes), supported: true, reason, requested: source ?? null,
          sources: listed(index, limitations, 'sources'), content, limitations };
      } },
    { name: 'artifact.moduleImports', version: '1.0.0', outputKeys: ['path', 'sha256', 'supported', 'imports', 'counts', 'limitations', 'untrusted'], effect: 'read', inputSchema: pathOnly,
      execute({ path: relative }, context) {
        const { bytes, text } = readText(context, relative, 2);
        if (text === null) return notText(relative, bytes, { imports: [], counts: null });
        const limitations = [LEXICAL_NOTE];
        const stripped = stripNonCode(text);
        const imports = findImports(text, stripped, limitations);
        const counts = imports.reduce((totals, entry) => { totals[entry.kind] = (totals[entry.kind] ?? 0) + 1; return totals; }, {});
        return { ...base(relative, bytes), supported: true, reason: null,
          imports: listed(imports, limitations, 'imports'), counts,
          specifiers: [...new Set(imports.map((entry) => entry.specifier))].sort(),
          bareSpecifiers: [...new Set(imports.filter((entry) => !entry.relative).map((entry) => entry.specifier))].sort(),
          limitations };
      } },
    { name: 'artifact.jsExports', version: '1.0.0', outputKeys: ['path', 'sha256', 'supported', 'exports', 'limitations', 'untrusted'], effect: 'read', inputSchema: pathOnly,
      execute({ path: relative }, context) {
        const { bytes, text } = readText(context, relative, 2);
        if (text === null) return notText(relative, bytes, { exports: [] });
        const limitations = [LEXICAL_NOTE];
        const stripped = stripNonCode(text);
        const found = findExports(stripped, limitations);
        if (found.some((entry) => entry.kind === 'star' || entry.kind === 'star-as')) {
          limitations.push('A star re-export forwards names declared elsewhere, so this shape is incomplete without the target module');
        }
        return { ...base(relative, bytes), supported: true, reason: null,
          exports: listed(found, limitations, 'exports'),
          moduleKind: found.some((entry) => entry.kind.startsWith('commonjs')) ? (found.some((entry) => entry.kind !== 'commonjs' && entry.kind !== 'commonjs-whole') ? 'mixed' : 'commonjs') : 'module',
          limitations };
      } },
    { name: 'artifact.compareJsExports', version: '1.0.0', outputKeys: ['changes', 'summary', 'limitations'], effect: 'pure',
      inputSchema: object({ left: exportShape, right: exportShape }, ['left', 'right']),
      execute({ left, right }) {
        const index = (side) => new Map(side.exports.map((entry) => [entry.kind + ':' + entry.name, entry]));
        const a = index(left);
        const b = index(right);
        const changes = [];
        for (const key of [...new Set([...a.keys(), ...b.keys()])].sort()) {
          const mine = a.get(key);
          const theirs = b.get(key);
          if (!theirs) { changes.push({ export: key, state: 'removed' }); continue; }
          if (!mine) { changes.push({ export: key, state: 'added' }); continue; }
          changes.push({ export: key, state: 'unchanged' });
        }
        // A name exported as a different kind is reported as both removed and added rather than
        // renamed, because a lexical scan establishes no identity across kinds.
        const tally = (state) => changes.filter((change) => change.state === state).length;
        return { changes, summary: { added: tally('added'), removed: tally('removed'), unchanged: tally('unchanged') },
          limitations: ['Comparison is by exported name and kind; a changed value or signature behind the same name is not visible'] };
      } },
    { name: 'artifact.compareSourceToBundle', version: '1.0.0', outputKeys: ['findings', 'summary', 'limitations'], effect: 'pure',
      inputSchema: object({ source: exportShape, bundle: exportShape }, ['source', 'bundle']),
      execute({ source, bundle }) {
        const bundled = new Set(bundle.exports.map((entry) => entry.name));
        const findings = source.exports.map((entry) => ({
          name: entry.name, kind: entry.kind,
          state: bundled.has(entry.name) ? 'present' : 'absent',
          reason: bundled.has(entry.name) ? null
            : 'An export declared in source does not appear in the bundle, which a minifier renaming it would also produce',
        }));
        const extra = bundle.exports.filter((entry) => !source.exports.some((other) => other.name === entry.name))
          .map((entry) => ({ name: entry.name, kind: entry.kind, state: 'bundle-only', reason: 'The bundle exports a name the source does not declare' }));
        const all = [...findings, ...extra];
        const tally = (state) => all.filter((entry) => entry.state === state).length;
        return { findings: all,
          summary: { present: tally('present'), absent: tally('absent'), bundleOnly: tally('bundle-only') },
          limitations: ['An absent export is equally consistent with minification renaming it, so absence is not evidence of removal'] };
      } },
    { name: 'artifact.jsSemantics', version: '1.0.0', outputKeys: ['path', 'sha256', 'supported', 'findings', 'counts', 'limitations', 'untrusted'], effect: 'read', inputSchema: pathOnly,
      execute({ path: relative }, context) {
        const { bytes, text } = readText(context, relative, 2);
        if (text === null) return notText(relative, bytes, { findings: [], counts: null });
        const limitations = [LEXICAL_NOTE,
          'A construct listed here is present in the token stream; whether it is reachable is a separate question this scan does not answer'];
        const stripped = stripNonCode(text);
        const findings = [];
        for (const [name, pattern, meaning] of SEMANTIC_PATTERNS) {
          pattern.lastIndex = 0;
          let match;
          while ((match = pattern.exec(stripped)) !== null) {
            findings.push({ construct: name, meaning, line: lineOf(stripped, match.index) });
            if (findings.length >= MAX_LISTED) { limitations.push('The finding bound was reached'); break; }
          }
        }
        findings.sort((a, b) => a.line - b.line || (a.construct < b.construct ? -1 : 1));
        const counts = findings.reduce((totals, entry) => { totals[entry.construct] = (totals[entry.construct] ?? 0) + 1; return totals; }, {});
        return { ...base(relative, bytes), supported: true, reason: null, findings, counts,
          codeChars: stripped.replace(/\s/g, '').length, limitations };
      } },
    { name: 'artifact.webBundle', version: '1.0.0', outputKeys: ['path', 'sha256', 'supported', 'bundlers', 'sourceMappingUrl', 'limitations', 'untrusted'], effect: 'read', inputSchema: pathOnly,
      execute({ path: relative }, context) {
        const { bytes, text } = readText(context, relative, 2);
        if (text === null) return notText(relative, bytes, { bundlers: [], sourceMappingUrl: null });
        const limitations = [LEXICAL_NOTE];
        const stripped = stripNonCode(text);
        const bundlers = BUNDLER_MARKERS.filter(([, patterns]) => patterns.some((pattern) => pattern.test(stripped))).map(([name]) => name);
        // The sourceMappingURL comment is in the part stripNonCode blanks, so it is matched in
        // the original text.
        const mapComment = /[#@]\s*sourceMappingURL\s*=\s*(\S+)/.exec(text);
        const url = mapComment ? mapComment[1] : null;
        const imports = findImports(text, stripped, limitations);
        const lines = text.split('\n');
        const longest = lines.reduce((most, line) => Math.max(most, line.length), 0);
        if (!bundlers.length) limitations.push('No bundler marker was recognised, which means this reader does not identify it rather than that the file is unbundled');
        return { ...base(relative, bytes), supported: true, reason: null,
          bundlers, sourceMappingUrl: url,
          inlineSourceMap: url !== null && url.startsWith('data:'),
          lineCount: lines.length, longestLineChars: longest,
          // A single very long line is the usual signature of minified output.
          likelyMinified: longest > 2000 && lines.length < Math.max(50, text.length / 2000),
          bareSpecifiers: [...new Set(imports.filter((entry) => !entry.relative).map((entry) => entry.specifier))].sort().slice(0, MAX_LISTED),
          limitations };
      } },
    { name: 'artifact.htmlScripts', version: '1.0.0', outputKeys: ['path', 'sha256', 'supported', 'scripts', 'counts', 'limitations', 'untrusted'], effect: 'read', inputSchema: pathOnly,
      execute({ path: relative }, context) {
        const { bytes, text } = readText(context, relative, 2);
        if (text === null) return notText(relative, bytes, { scripts: [], counts: null });
        const limitations = ['Script elements are located lexically; markup built at runtime is not visible, and a script inside a comment or template is reported as present'];
        const scripts = [];
        const pattern = /<script\b([^>]*)>([\s\S]*?)<\/script\s*>/gi;
        let match;
        while ((match = pattern.exec(text)) !== null) {
          if (scripts.length >= MAX_LISTED) { limitations.push('The script bound was reached'); break; }
          const attributeText = match[1];
          const body = match[2];
          const attribute = (name) => {
            const found = new RegExp(name + '\\s*=\\s*(?:"([^"]*)"|\'([^\']*)\'|([^\\s>]+))', 'i').exec(attributeText);
            return found ? found[1] ?? found[2] ?? found[3] ?? '' : null;
          };
          const src = attribute('src');
          scripts.push({
            inline: src === null, src, type: attribute('type'),
            integrity: attribute('integrity'), crossorigin: attribute('crossorigin'),
            // Presence only: a nonce value is a secret that defeats CSP if copied out.
            hasNonce: /\bnonce\s*=/i.test(attributeText),
            defer: /\bdefer\b/i.test(attributeText), async: /\basync\b/i.test(attributeText),
            module: (attribute('type') ?? '').toLowerCase() === 'module',
            line: lineOf(text, match.index),
            bodyChars: src === null ? body.length : 0,
            bodySha256: src === null && body.length ? sha256(Buffer.from(body, 'utf8')) : null,
          });
        }
        const external = scripts.filter((entry) => !entry.inline);
        return { ...base(relative, bytes), supported: true, reason: null,
          scripts, counts: { total: scripts.length, inline: scripts.length - external.length, external: external.length,
            modules: scripts.filter((entry) => entry.module).length,
            withIntegrity: external.filter((entry) => entry.integrity !== null).length },
          limitations };
      } },
    { name: 'artifact.harCapture', version: '1.0.0', outputKeys: ['path', 'sha256', 'supported', 'entries', 'summary', 'limitations', 'untrusted'], effect: 'read', inputSchema: pathOnly,
      execute({ path: relative }, context) {
        const { bytes, text } = readText(context, relative, 2);
        if (text === null) return notText(relative, bytes, { entries: [], summary: null });
        const har = parseHar(text);
        if (!har.supported) return { ...base(relative, bytes), supported: false, reason: har.reason, detail: har.detail, entries: [], summary: null, limitations: har.limitations };
        const limitations = [...har.limitations];
        const byStatus = {};
        const byType = {};
        const origins = new Set();
        let totalBytes = 0;
        for (const entry of har.entries) {
          const bucket = entry.status === null ? 'unknown' : String(Math.floor(entry.status / 100)) + 'xx';
          byStatus[bucket] = (byStatus[bucket] ?? 0) + 1;
          if (entry.mimeType) byType[entry.mimeType] = (byType[entry.mimeType] ?? 0) + 1;
          if (entry.origin) origins.add(entry.origin);
          if (typeof entry.bodySize === 'number' && entry.bodySize > 0) totalBytes += entry.bodySize;
        }
        return { ...base(relative, bytes), supported: true, reason: null, creator: har.creator, version: har.version,
          entries: listed(har.entries, limitations, 'entries'),
          summary: { entryCount: har.entries.length, origins: [...origins].sort(), byStatus, byType, totalBodyBytes: totalBytes },
          limitations };
      } },
    { name: 'artifact.compareHar', version: '1.0.0', outputKeys: ['changes', 'summary', 'limitations'], effect: 'pure',
      inputSchema: object({ left: harShape, right: harShape }, ['left', 'right']),
      execute({ left, right }) {
        const index = (side) => {
          const map = new Map();
          for (const entry of side.entries) {
            const key = requestKey(entry);
            if (!map.has(key)) map.set(key, []);
            map.get(key).push(entry);
          }
          return map;
        };
        const a = index(left);
        const b = index(right);
        const changes = [];
        for (const key of [...new Set([...a.keys(), ...b.keys()])].sort()) {
          const mine = a.get(key) ?? [];
          const theirs = b.get(key) ?? [];
          if (!theirs.length) { changes.push({ request: key, state: 'removed', count: mine.length }); continue; }
          if (!mine.length) { changes.push({ request: key, state: 'added', count: theirs.length }); continue; }
          // A capture routinely repeats a request, so a differing count is its own observation
          // rather than evidence that the request changed.
          if (mine.length !== theirs.length) {
            changes.push({ request: key, state: 'count-differs', left: mine.length, right: theirs.length });
            continue;
          }
          const statusChanged = mine[0].status !== theirs[0].status;
          const typeChanged = mine[0].mimeType !== theirs[0].mimeType;
          changes.push({ request: key, state: statusChanged || typeChanged ? 'changed' : 'unchanged',
            left: { status: mine[0].status, mimeType: mine[0].mimeType },
            right: { status: theirs[0].status, mimeType: theirs[0].mimeType } });
        }
        const tally = (state) => changes.filter((change) => change.state === state).length;
        return { changes,
          summary: { added: tally('added'), removed: tally('removed'), changed: tally('changed'),
            unchanged: tally('unchanged'), countDiffers: tally('count-differs') },
          limitations: ['Requests are keyed by method, origin and path; query strings, timing and body content are not part of the key'] };
      } },
    { name: 'artifact.jsApplication', version: '1.0.0', outputKeys: ['entry', 'supported', 'modules', 'edges', 'limitations'], effect: 'read',
      inputSchema: object({ entry: string, maxFiles: { type: 'integer', minimum: 1, maximum: MAX_GRAPH_FILES } }, ['entry']),
      execute({ entry, maxFiles = 128 }, context) {
        // Follow relative specifiers from an entry file, resolving them inside the workspace.
        // A bare specifier is a package rather than a file, so it is recorded and not followed.
        const limitations = [LEXICAL_NOTE];
        const visited = new Map();
        const edges = [];
        const external = new Set();
        const unresolved = [];
        const queue = [entry];
        const extensions = ['', '.js', '.mjs', '.cjs', '.jsx', '/index.js', '/index.mjs'];
        const dirOf = (file) => { const at = file.lastIndexOf('/'); return at < 0 ? '' : file.slice(0, at + 1); };
        const normalise = (value) => {
          const parts = [];
          for (const piece of value.split('/')) {
            if (piece === '' || piece === '.') continue;
            if (piece === '..') { parts.pop(); continue; }
            parts.push(piece);
          }
          return parts.join('/');
        };
        // Resolution happens by actually reading the candidate, because readWorkspaceFile is the
        // only audited way in and it refuses a file larger than the limit it is given: a cheap
        // one-byte existence probe would report every real file as absent. The text is kept so
        // the file is not read a second time when it is dequeued.
        const texts = new Map();
        const tryRead = (candidate, divisor) => {
          try { return readText(context, candidate, divisor); }
          catch { return null; }
        };
        const seeded = tryRead(entry, 8);
        if (seeded) texts.set(entry, seeded);
        while (queue.length && visited.size < maxFiles) {
          const current = queue.shift();
          if (visited.has(current)) continue;
          const loaded = texts.get(current) ?? tryRead(current, 8);
          if (!loaded || loaded.text === null) { visited.set(current, { readable: false }); continue; }
          const { bytes, text } = loaded;
          const stripped = stripNonCode(text);
          const imports = findImports(text, stripped, limitations);
          visited.set(current, { readable: true, sha256: sha256(bytes), importCount: imports.length,
            exports: findExports(stripped, limitations).length });
          for (const found of imports) {
            if (!found.relative) { external.add(found.specifier); continue; }
            const candidate = normalise(dirOf(current) + found.specifier);
            let resolved = null;
            for (const extension of extensions) {
              const attempt = candidate + extension;
              if (visited.has(attempt) || texts.has(attempt)) { resolved = attempt; break; }
              const got = tryRead(attempt, 8);
              if (got) { texts.set(attempt, got); resolved = attempt; break; }
            }
            if (resolved === null) { unresolved.push({ from: current, specifier: found.specifier }); continue; }
            edges.push({ from: current, to: resolved, kind: found.kind });
            if (!visited.has(resolved)) queue.push(resolved);
          }
        }
        if (queue.length) limitations.push('The file bound was reached, so the graph is partial');
        if (unresolved.length) limitations.push('Some relative specifiers resolved to no file under the tried extensions');
        return { entry, supported: visited.get(entry) ? visited.get(entry).readable : false,
          reason: visited.get(entry) && visited.get(entry).readable ? null : 'entry_unreadable',
          modules: [...visited].map(([file, info]) => ({ file, ...info })),
          edges: listed(edges, limitations, 'edges'),
          externalPackages: [...external].sort(), unresolved, limitations };
      } },
  ];
}
