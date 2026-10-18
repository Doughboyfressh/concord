import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import mod from 'node:module';
import { makeWebTools, parseSourceMap, stripNonCode } from '../src/webjs.mjs';

const tools = new Map(makeWebTools().map((t) => [t.name, t]));
const policy = { maxOutputBytes: 4 * 1024 * 1024 };

function workspace(t) {
  const dir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'concord-webjs-')));
  t.after(() => { fs.rmSync(dir, { recursive: true, force: true }); });
  return { dir, context: { workspaceRoot: dir, policy } };
}
const write = (dir, name, text) => {
  fs.mkdirSync(path.dirname(path.join(dir, name)), { recursive: true });
  fs.writeFileSync(path.join(dir, name), text);
  return name;
};

const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const encodeVlq = (value) => {
  let v = value < 0 ? ((-value) << 1) | 1 : value << 1;
  let out = '';
  do { let digit = v & 31; v >>>= 5; if (v > 0) digit |= 32; out += B64[digit]; } while (v > 0);
  return out;
};

/** Count the VLQ fields in a segment, so a claim about its field count is checked not assumed. */
function fieldCount(segment) {
  let fields = 0;
  let i = 0;
  while (i < segment.length) {
    let more = true;
    while (more && i < segment.length) { more = (B64.indexOf(segment[i]) & 32) !== 0; i += 1; }
    fields += 1;
  }
  return fields;
}

/** Mappings built from absolute positions, converted here to the deltas the format stores. */
function buildMappings(rows) {
  let sourceIndex = 0, originalLine = 0, originalColumn = 0, nameIndex = 0;
  return rows.map((segments) => {
    let generatedColumn = 0;
    return segments.map((seg) => {
      let out = encodeVlq(seg.generatedColumn - generatedColumn);
      generatedColumn = seg.generatedColumn;
      if (seg.sourceIndex !== undefined) {
        out += encodeVlq(seg.sourceIndex - sourceIndex); sourceIndex = seg.sourceIndex;
        out += encodeVlq(seg.originalLine - originalLine); originalLine = seg.originalLine;
        out += encodeVlq(seg.originalColumn - originalColumn); originalColumn = seg.originalColumn;
        if (seg.nameIndex !== undefined) { out += encodeVlq(seg.nameIndex - nameIndex); nameIndex = seg.nameIndex; }
      }
      return out;
    }).join(',');
  }).join(';');
}

const sourceMapDocument = () => ({
  version: 3, file: 'out.js',
  sources: ['src/alpha.ts', 'src/beta.ts'],
  names: ['first', 'second', 'third'],
  sourcesContent: ['export const a = 1;\n', null],
  mappings: buildMappings([
    [{ generatedColumn: 0, sourceIndex: 0, originalLine: 0, originalColumn: 0, nameIndex: 0 },
     { generatedColumn: 9, sourceIndex: 0, originalLine: 0, originalColumn: 6 },
     { generatedColumn: 40, sourceIndex: 1, originalLine: 12, originalColumn: 2, nameIndex: 1 }],
    [],
    [{ generatedColumn: 4, sourceIndex: 1, originalLine: 300, originalColumn: 45 },
     { generatedColumn: 2000, sourceIndex: 0, originalLine: 7, originalColumn: 0, nameIndex: 2 }],
    [{ generatedColumn: 0 }],
    [{ generatedColumn: 1, sourceIndex: 0, originalLine: 1, originalColumn: 1 }],
  ]),
});

test('source map mappings decode to the same entries as Node built-in SourceMap', () => {
  const document = sourceMapDocument();
  const mine = parseSourceMap(JSON.stringify(document));
  assert.equal(mine.supported, true);
  assert.deepEqual(mine.limitations, []);
  assert.equal(mine.entries.length, 7);

  // Every field is a delta against running state, and only generatedColumn resets per line, so a
  // decoder that reset the others would produce plausible but wrong origins.
  const oracle = new mod.SourceMap(document);
  for (const entry of mine.entries) {
    const found = oracle.findEntry(entry.generatedLine, entry.generatedColumn);
    assert.ok(found, JSON.stringify(entry));
    assert.equal(found.generatedLine, entry.generatedLine);
    assert.equal(found.generatedColumn, entry.generatedColumn);
    assert.equal(found.originalSource ?? null, entry.originalSource);
    assert.equal(found.originalLine ?? null, entry.originalLine);
    assert.equal(found.originalColumn ?? null, entry.originalColumn);
  }
});

test('a four-field segment carries no name, where Node carries the previous one forward', () => {
  // This is a deliberate, proven divergence from the oracle rather than a gap. Source Map
  // Revision 3 gives a segment a name only when it has a fifth field; Node's entry
  // reconstruction reports the running name on a four-field segment too. The field count is
  // counted here rather than asserted, so the claim does not rest on reading the spec.
  const mappings = encodeVlq(0) + encodeVlq(0) + encodeVlq(0) + encodeVlq(0) + encodeVlq(0)
    + ',' + encodeVlq(5) + encodeVlq(0) + encodeVlq(0) + encodeVlq(5);
  const segments = mappings.split(',');
  assert.deepEqual(segments.map(fieldCount), [5, 4]);

  const document = { version: 3, file: 'o.js', sources: ['a.ts'], names: ['NAMED'], mappings };
  const mine = parseSourceMap(JSON.stringify(document));
  assert.equal(mine.entries[0].name, 'NAMED');
  assert.equal(mine.entries[1].name, null, 'the four-field segment must carry no name');

  const oracle = new mod.SourceMap(document);
  assert.equal(oracle.findEntry(0, 0).name, 'NAMED');
  // Recorded so a later change that "fixes" this to match Node is caught as a regression.
  assert.equal(oracle.findEntry(0, 5).name, 'NAMED');
});

test('source map reading summarises sources, and a generated position attributes to a mapping', (t) => {
  const { dir, context } = workspace(t);
  write(dir, 'out.js.map', JSON.stringify(sourceMapDocument()));
  const read = tools.get('artifact.sourceMap').execute({ path: 'out.js.map' }, context);
  assert.equal(read.supported, true);
  assert.deepEqual(read.sources, ['src/alpha.ts', 'src/beta.ts']);
  assert.equal(read.mappingCount, 7);
  assert.equal(read.generatedLines, 5);
  assert.equal(read.embeddedSources, 1);
  assert.deepEqual(read.perSource, [
    { source: 'src/alpha.ts', mappings: 4, hasContent: true, contentChars: 20 },
    { source: 'src/beta.ts', mappings: 2, hasContent: false, contentChars: null },
  ]);

  const locate = tools.get('artifact.sourceLocation');
  const exact = locate.execute({ path: 'out.js.map', line: 0, column: 40 }, context);
  assert.equal(exact.entry.originalSource, 'src/beta.ts');
  assert.equal(exact.entry.originalLine, 12);
  assert.deepEqual(exact.limitations, []);
  // Mappings are sparse, so a position between them attributes to the preceding mapping and
  // says so rather than implying an exact hit.
  const between = locate.execute({ path: 'out.js.map', line: 0, column: 5 }, context);
  assert.equal(between.entry.generatedColumn, 0);
  assert.ok(between.limitations.some((l) => /nearest preceding mapping/.test(l)));

  const recover = tools.get('artifact.recoverSources');
  const got = recover.execute({ path: 'out.js.map', source: 'src/alpha.ts' }, context);
  assert.equal(got.content, 'export const a = 1;\n');
  assert.equal(got.sources[0].sha256.length, 64);
  // A map that embeds no content for a source cannot recover it, which is distinct from the
  // source not being named at all.
  assert.equal(recover.execute({ path: 'out.js.map', source: 'src/beta.ts' }, context).reason, 'content_absent');
  assert.equal(recover.execute({ path: 'out.js.map', source: 'src/nope.ts' }, context).reason, 'source_absent');

  write(dir, 'bad.map', JSON.stringify({ version: 2, mappings: '' }));
  assert.equal(tools.get('artifact.sourceMap').execute({ path: 'bad.map' }, context).reason, 'version_unsupported');
  write(dir, 'index.map', JSON.stringify({ version: 3, sections: [] }));
  assert.equal(tools.get('artifact.sourceMap').execute({ path: 'index.map' }, context).reason, 'index_map_unsupported');
  write(dir, 'plain.map', 'not json at all');
  assert.equal(tools.get('artifact.sourceMap').execute({ path: 'plain.map' }, context).reason, 'not_json');
});

test('the lexical scan is not fooled by its own input', (t) => {
  const { dir, context } = workspace(t);
  // Each case hides the word `import` somewhere a naive regex would match. Only the real
  // declaration must be reported, and the line numbers must still refer to the real file.
  const cases = [
    ['// import x from "evil"\nimport a from "real";', 'line comment'],
    ['/* import x from "evil" */ import a from "real";', 'block comment'],
    ['const s = "import x from \'evil\'";\nimport a from "real";', 'string'],
    ['const t = `import x from "evil"`;\nimport a from "real";', 'template literal'],
    ['const r = /"[^"]*"/g;\nimport a from "real";', 'regular expression'],
    ['const n = a / b; const m = c / d;\nimport a from "real";', 'division, not a regex'],
  ];
  for (const [source, label] of cases) {
    write(dir, 'm.js', source);
    const read = tools.get('artifact.moduleImports').execute({ path: 'm.js' }, context);
    assert.deepEqual(read.specifiers, ['real'], label);
  }
  // Offsets are preserved, so a blanked region keeps its newlines and later lines stay correct.
  const source = '/* a\nmultiline\ncomment */\nimport a from "real";';
  assert.equal(stripNonCode(source).split('\n').length, source.split('\n').length);
  write(dir, 'lines.js', source);
  assert.equal(tools.get('artifact.moduleImports').execute({ path: 'lines.js' }, context).imports[0].line, 4);
});

test('import and export forms are recovered, including re-exports and CommonJS', (t) => {
  const { dir, context } = workspace(t);
  write(dir, 'mod.js', [
    'import def from "./a.js";',
    'import * as ns from "pkg";',
    'import { x, y as z } from "./b.js";',
    'import "./side.js";',
    'export * from "./c.js";',
    'export * as star from "./d.js";',
    'export { x as renamed };',
    'export default function main() {}',
    'export const value = 1;',
    'export class Thing {}',
    'export async function* gen() {}',
    'const lazy = await import("./lazy.js");',
    'const cjs = require("./legacy.js");',
  ].join('\n'));

  const imports = tools.get('artifact.moduleImports').execute({ path: 'mod.js' }, context);
  assert.deepEqual(imports.counts, { import: 4, reexport: 2, 'dynamic-import': 1, require: 1 });
  assert.deepEqual(imports.bareSpecifiers, ['pkg']);
  assert.deepEqual(imports.specifiers,
    ['./a.js', './b.js', './c.js', './d.js', './lazy.js', './legacy.js', './side.js', 'pkg']);
  assert.ok(imports.limitations.some((l) => /lexical scan rather than a parse/.test(l)));

  const exports = tools.get('artifact.jsExports').execute({ path: 'mod.js' }, context);
  const kinds = exports.exports.map((entry) => entry.kind + ':' + entry.name).sort();
  assert.deepEqual(kinds, ['class:Thing', 'default:default', 'function:gen', 'named:renamed',
    'star-as:star', 'star:*', 'variable:value']);
  assert.equal(exports.moduleKind, 'module');
  // A star re-export forwards names this file never declares, so the shape is incomplete.
  assert.ok(exports.limitations.some((l) => /forwards names declared elsewhere/.test(l)));

  write(dir, 'cjs.js', 'exports.one = 1;\nmodule.exports = {};\n');
  assert.equal(tools.get('artifact.jsExports').execute({ path: 'cjs.js' }, context).moduleKind, 'commonjs');
});

test('semantic constructs, bundler markers and HTML scripts are reported without leaking secrets', (t) => {
  const { dir, context } = workspace(t);
  write(dir, 'risky.js', 'eval("x");\nnew Function("y");\nel.innerHTML = s;\nsetTimeout("z", 1);\n// eval("in a comment")\n');
  const semantics = tools.get('artifact.jsSemantics').execute({ path: 'risky.js' }, context);
  // The eval inside a comment must not be counted, which is the whole point of the strip pass.
  assert.deepEqual(semantics.counts, { eval: 1, 'function-constructor': 1, 'inner-html': 1, 'timer-string': 1 });
  assert.equal(semantics.findings[0].line, 1);
  assert.ok(semantics.limitations.some((l) => /whether it is reachable is a separate question/.test(l)));

  write(dir, 'bundle.js', '(function(){__webpack_require__(1);})();\n//# sourceMappingURL=bundle.js.map\n');
  const bundle = tools.get('artifact.webBundle').execute({ path: 'bundle.js' }, context);
  assert.deepEqual(bundle.bundlers, ['webpack']);
  assert.equal(bundle.sourceMappingUrl, 'bundle.js.map');
  assert.equal(bundle.inlineSourceMap, false);
  write(dir, 'plain.js', 'const a = 1;\n');
  const unknown = tools.get('artifact.webBundle').execute({ path: 'plain.js' }, context);
  assert.deepEqual(unknown.bundlers, []);
  // Absence of a marker means this reader does not identify the bundler, not that none was used.
  assert.ok(unknown.limitations.some((l) => /does not identify it rather than/.test(l)));

  write(dir, 'page.html', '<html><script src="/a.js" integrity="sha384-x" defer></script>\n'
    + '<script type="module">import "./m.js";</script>\n<script nonce="SUPERSECRET">var a=1;</script></html>');
  const scripts = tools.get('artifact.htmlScripts').execute({ path: 'page.html' }, context);
  assert.deepEqual(scripts.counts, { total: 3, inline: 2, external: 1, modules: 1, withIntegrity: 1 });
  assert.equal(scripts.scripts[0].defer, true);
  assert.equal(scripts.scripts[1].module, true);
  // A nonce defeats CSP if it is copied out, so only its presence is reported.
  assert.equal(scripts.scripts[2].hasNonce, true);
  assert.equal(JSON.stringify(scripts).includes('SUPERSECRET'), false);
  assert.equal(scripts.scripts[1].bodySha256.length, 64);
});

test('HTTP archives are summarised without copying header, cookie or body values', (t) => {
  const { dir, context } = workspace(t);
  const har = { log: { version: '1.2', creator: { name: 'probe' }, entries: [
    { startedDateTime: '2026-01-01T00:00:00Z', time: 12.5,
      request: { method: 'GET', url: 'https://example.com/a', headers: [{ name: 'Cookie', value: 'session=TOPSECRET' }], cookies: [{ name: 'session', value: 'TOPSECRET' }] },
      response: { status: 200, bodySize: 100, content: { size: 120, mimeType: 'text/html; charset=utf-8' }, headers: [] } },
    { request: { method: 'POST', url: 'https://api.example.com/v1/x', headers: [], cookies: [] },
      response: { status: 404, content: { size: 0, mimeType: 'application/json' }, headers: [] } },
  ] } };
  write(dir, 'cap.har', JSON.stringify(har));
  const read = tools.get('artifact.harCapture').execute({ path: 'cap.har' }, context);
  assert.equal(read.supported, true);
  assert.deepEqual(read.summary, {
    entryCount: 2, origins: ['https://api.example.com', 'https://example.com'],
    byStatus: { '2xx': 1, '4xx': 1 }, byType: { 'text/html': 1, 'application/json': 1 }, totalBodyBytes: 120,
  });
  // A capture routinely carries credentials: presence is reported, values never are.
  assert.equal(JSON.stringify(read).includes('TOPSECRET'), false);
  assert.equal(read.entries[0].hasRequestCookies, true);
  assert.equal(read.entries[0].requestHeaderCount, 1);
  assert.ok(read.limitations.some((l) => /routinely carries credentials/.test(l)));
  // The charset parameter is dropped so a type groups with its peers.
  assert.equal(read.entries[0].mimeType, 'text/html');

  write(dir, 'notahar.json', JSON.stringify({ something: 1 }));
  assert.equal(tools.get('artifact.harCapture').execute({ path: 'notahar.json' }, context).reason, 'not_a_har');
});

test('the comparisons state what they cannot distinguish', () => {
  const left = { exports: [{ name: 'kept', kind: 'variable' }, { name: 'gone', kind: 'function' }] };
  const right = { exports: [{ name: 'kept', kind: 'variable' }, { name: 'fresh', kind: 'class' }] };
  const diff = tools.get('artifact.compareJsExports').execute({ left, right });
  assert.deepEqual(diff.summary, { added: 1, removed: 1, unchanged: 1 });

  const bundleDiff = tools.get('artifact.compareSourceToBundle').execute({
    source: { exports: [{ name: 'kept', kind: 'variable' }, { name: 'renamedAway', kind: 'function' }] },
    bundle: { exports: [{ name: 'kept', kind: 'variable' }, { name: 'a', kind: 'variable' }] },
  });
  assert.deepEqual(bundleDiff.summary, { present: 1, absent: 1, bundleOnly: 1 });
  // Minification renaming an export looks exactly like removal, so absence is not evidence.
  assert.ok(bundleDiff.limitations.some((l) => /not evidence of removal/.test(l)));

  const capture = (entries) => ({ entries });
  const harDiff = tools.get('artifact.compareHar').execute({
    left: capture([
      { method: 'GET', origin: 'https://a.test', pathname: '/same', status: 200, mimeType: 'text/html' },
      { method: 'GET', origin: 'https://a.test', pathname: '/changed', status: 200, mimeType: 'text/html' },
      { method: 'GET', origin: 'https://a.test', pathname: '/twice', status: 200, mimeType: 'text/css' },
      { method: 'GET', origin: 'https://a.test', pathname: '/twice', status: 200, mimeType: 'text/css' },
    ]),
    right: capture([
      { method: 'GET', origin: 'https://a.test', pathname: '/same', status: 200, mimeType: 'text/html' },
      { method: 'GET', origin: 'https://a.test', pathname: '/changed', status: 500, mimeType: 'text/html' },
      { method: 'GET', origin: 'https://a.test', pathname: '/twice', status: 200, mimeType: 'text/css' },
      { method: 'GET', origin: 'https://a.test', pathname: '/new', status: 204, mimeType: null },
    ]),
  });
  assert.deepEqual(harDiff.summary, { added: 1, removed: 0, changed: 1, unchanged: 1, countDiffers: 1 });
  // A repeated request is normal, so a differing count is its own observation.
  assert.equal(harDiff.changes.find((change) => change.request.includes('/twice')).state, 'count-differs');
});

test('the module graph follows relative specifiers and leaves packages unfollowed', (t) => {
  const { dir, context } = workspace(t);
  write(dir, 'app/index.js', 'import { a } from "./lib.js";\nimport "left-pad";\nimport { c } from "./missing.js";\n');
  write(dir, 'app/lib.js', 'export const a = 1;\nimport "./deep/inner.js";\n');
  write(dir, 'app/deep/inner.js', 'export const inner = 2;\n');
  const graph = tools.get('artifact.jsApplication').execute({ entry: 'app/index.js' }, context);
  assert.equal(graph.supported, true);
  // Transitive: index reaches inner only through lib.
  assert.deepEqual(graph.modules.map((entry) => entry.file), ['app/index.js', 'app/lib.js', 'app/deep/inner.js']);
  assert.deepEqual(graph.edges.map((edge) => edge.from + ' -> ' + edge.to),
    ['app/index.js -> app/lib.js', 'app/lib.js -> app/deep/inner.js']);
  // A bare specifier is a package rather than a file, so it is recorded and not followed.
  assert.deepEqual(graph.externalPackages, ['left-pad']);
  assert.deepEqual(graph.unresolved, [{ from: 'app/index.js', specifier: './missing.js' }]);
  assert.ok(graph.modules.every((entry) => entry.readable));

  // An extensionless specifier resolves through the tried extensions.
  write(dir, 'app/ext.js', 'import "./lib";\n');
  const resolved = tools.get('artifact.jsApplication').execute({ entry: 'app/ext.js' }, context);
  assert.deepEqual(resolved.unresolved, []);
  assert.ok(resolved.edges.some((edge) => edge.to === 'app/lib.js'));

  const missing = tools.get('artifact.jsApplication').execute({ entry: 'app/nope.js' }, context);
  assert.equal(missing.supported, false);
  assert.equal(missing.reason, 'entry_unreadable');
});
