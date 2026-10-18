import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { canonical, parseJson } from '../src/value.mjs';

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const upstream = path.join(root, 'upstream');
const acquisition = parseJson(fs.readFileSync(path.join(upstream, 'manifest.json'), 'utf8'));
const lock = parseJson(fs.readFileSync(path.join(root, 'sources.lock.json'), 'utf8'));
const sourceFiles = [], capabilities = [], repositories = [];
const hash = b => createHash('sha256').update(b).digest('hex');
for (const source of acquisition) {
  const sourceRoot = path.join(root, source.directory);
  const catalogEntry = lock.sources.find(s => s.repository === source.repository);
  let files = 0, bytes = 0, lfsPointers = 0;
  function walk(directory, relative = '') {
    for (const entry of fs.readdirSync(directory, { withFileTypes: true }).sort((a, b) => a.name < b.name ? -1 : a.name > b.name ? 1 : 0)) {
      const rel = relative ? relative + '/' + entry.name : entry.name;
      const full = path.join(directory, entry.name);
      if (entry.isSymbolicLink()) throw new Error('Unexpected live link in acquired source');
      if (entry.isDirectory()) { walk(full, rel); continue; }
      if (!entry.isFile()) throw new Error('Unexpected non-file in source');
      const data = fs.readFileSync(full);
      files++; bytes += data.length;
      const sha256 = hash(data);
      sourceFiles.push({ sourceId: catalogEntry.id, path: rel, bytes: data.length, sha256 });
      if (data.length < 4096 && data.toString('utf8').startsWith('version https://git-lfs.github.com/spec/v1')) lfsPointers++;
      if (data.length > 1048576 || !/\.(md|mdx)$/i.test(rel)) continue;
      const text = data.toString('utf8');
      const headings = [...text.matchAll(/^#{1,4}\s+(.+)$/gm)].map(m => m[1].replace(/<[^>]+>/g, '').trim());
      const skill = /(?:^|\/)SKILL\.md$/i.test(rel);
      const command = /(?:^|\/)(?:commands|agents|plugins)\//.test(rel);
      const primaryDoc = /(?:^|\/)README(?:\.[a-z-]+)?\.md$/i.test(rel) || /(?:^|\/)docs?\//i.test(rel);
      if (skill || command || primaryDoc) capabilities.push({
        id: catalogEntry.id + ':' + rel, sourceId: catalogEntry.id,
        kind: skill ? 'skill' : command ? 'agent-command-plugin' : 'documentation',
        title: headings[0] ?? rel, headings,
        path: source.directory + '/' + rel, sourceSha256: sha256,
        sourceUrl: catalogEntry.url + '/blob/' + source.revision + '/' + rel.split('/').map(encodeURIComponent).join('/'),
        executable: false, status: 'source-available-unreviewed'
      });
    }
  }
  walk(sourceRoot);
  repositories.push({ sourceId: catalogEntry.id, repository: source.repository, revision: source.revision, files, bytes, lfsPointers, inertSymlinks: source.symlinksMaterializedAsText });
}
// A locally installed hermes carries capabilities its pinned upstream snapshot does not. Those are
// folded in here rather than by a separate pass, because this script rewrites the whole lock: a
// post-processing step would be silently discarded on the next run. Acquisition is out of band
// (scripts/acquire-hermes-local.py); this only reads the inert surface file it leaves behind.
//
// Effects are classified by explicit ordered rule. `effectBasis` records which rule matched so a
// reviewer can audit a classification instead of trusting it, and a name matching no rule is left
// unclassified rather than assigned a plausible-looking effect.
const EFFECT_RULES = [
  [/^(terminal|close_terminal|read_terminal|process_manage|execute_code|computer_use|delegate_task)$/, 'process', 'spawns or controls a process'],
  [/^browser_/, 'process', 'drives a browser process'],
  [/^meet_/, 'process', 'spawns a headless Chromium subprocess to scrape live captions'],
  [/^manage_catalog$/, 'process', 'installs catalog plugins and hub skills'],
  [/^(retaindb_|brv_)/, 'network', 'memory plugin backed by an HTTP client'],
  [/^(message_agent|react_to_message)$/, 'network', 'posts to a messaging platform or a peer gateway'],
  [/^(desktop_project|setup_beat)$/, 'write', 'mutates workspace or onboarding state'],
  [/^(web_search|web_extract|x_search|vision_analyze|image_generate|video_analyze|video_generate|text_to_speech|manage_connections)$/, 'network', 'calls a remote service'],
  [/^(feishu_|yb_|discord|xai_)/, 'network', 'calls a platform API'],
  [/^(write_file|patch)$/, 'write', 'mutates workspace files'],
  [/^kanban_(create|complete|block|unblock|comment|link|attach|attach_url|request_review|request_changes|heartbeat|schedule)$/, 'write', 'mutates the task board'],
  [/^(memory|todo_list|skill_manage|cronjob_manage|set_theme|annotate_preview|close_preview)$/, 'write', 'mutates persistent state'],
  [/^(read_file|search_files|skills_list|skill_view|session_search|kanban_show|kanban_list|kanban_attachments|read_window_below|focus_pane|desktop_preview|drive_preview)$/, 'read', 'reads without mutating'],
  [/^(clarify|show_tip|gui_tour)$/, 'read', 'prompts the operator; no workspace effect'],
];
const classify = (name) => {
  for (const [pattern, effect, basis] of EFFECT_RULES) if (pattern.test(name)) return { effect, basis };
  return { effect: null, basis: 'unclassified: no explicit rule matched this name' };
};

const localSurfacePath = path.join(upstream, 'hermes-local-surface.json');
let localSummary = null;
if (fs.existsSync(localSurfacePath)) {
  const surface = parseJson(fs.readFileSync(localSurfacePath, 'utf8'));
  if (surface.schemaVersion !== 1) throw new Error('Unsupported hermes-local surface schemaVersion');
  const entry = lock.sources.find(s => s.id === 'hermes-local');
  if (!entry) throw new Error('sources.lock.json is missing the hermes-local source entry');
  const revision = surface.install.commit;
  if (typeof revision !== 'string' || !/^[0-9a-f]{40}$/.test(revision)) throw new Error('hermes-local surface has no usable install commit');
  if (surface.install.dirty !== false) throw new Error('Refusing to catalog a dirty hermes install: its content corresponds to no commit');
  const webhookSafe = new Set(surface.posture.webhookSafe);
  const core = new Set(surface.posture.core);

  for (const skill of surface.skills) {
    const rel = skill.path === '.' ? 'skills/SKILL.md' : 'skills/' + skill.path + '/SKILL.md';
    capabilities.push({
      id: 'hermes-local:' + rel, sourceId: 'hermes-local', kind: 'skill',
      title: skill.name ?? skill.headings[0] ?? rel, headings: skill.headings,
      summary: skill.description ?? '',
      path: rel, sourceSha256: skill.sha256,
      sourceUrl: entry.url + '/blob/' + revision + '/' + rel.split('/').map(encodeURIComponent).join('/'),
      executable: false, status: 'local-install-unreviewed',
    });
  }
  for (const tool of surface.tools) {
    const { effect, basis } = classify(tool.name);
    capabilities.push({
      id: 'hermes-local:tool/' + tool.name, sourceId: 'hermes-local', kind: 'tool',
      title: tool.name, headings: tool.parameters, summary: tool.description,
      path: tool.module, sourceSha256: hash(Buffer.from(canonical(tool))),
      sourceUrl: entry.url + '/blob/' + revision + '/' + tool.module.split('/').map(encodeURIComponent).join('/'),
      executable: false, status: 'local-install-unreviewed',
      effect, effectBasis: basis, required: tool.required,
      inCoreToolset: core.has(tool.name), untrustedInputSafe: webhookSafe.has(tool.name),
    });
  }
  repositories.push({
    sourceId: 'hermes-local', repository: entry.repository, revision,
    files: surface.skills.length + surface.tools.length,
    bytes: surface.skills.reduce((n, s) => n + s.bytes, 0),
    lfsPointers: 0, inertSymlinks: [],
    acquisition: 'local-install-static-analysis',
    toolCount: surface.tools.length, skillCount: surface.skills.length,
    displayVersion: surface.install.displayVersion,
  });
  localSummary = { tools: surface.tools.length, skills: surface.skills.length, revision,
    unclassified: surface.tools.filter(t => classify(t.name).effect === null).length };
} else if (lock.sources.some(s => s.id === 'hermes-local')) {
  // upstream/ is git-ignored, so a fresh clone has the source entry but not the surface file.
  // Rewriting the lock now would silently drop every hermes-local capability. Say so loudly
  // rather than reporting a smaller catalog as if it were complete.
  localSummary = { skipped: 'upstream/hermes-local-surface.json is absent, so hermes-local capabilities were NOT written. Run scripts/acquire-hermes-local.py against a hermes installation first, or restore capabilities.lock.json.' };
  console.error('WARNING: ' + localSummary.skipped);
}

// REA declares each tool by calling toolContractMetadata("<name>"), so its surface is recovered
// from the clone already walked above rather than by a separate acquisition step.
//
// `internalizable` is the load-bearing field. A REA tool that reads bytes can be reimplemented
// inside Concord; one that drives adb, frida, gdb, rizin, cutter, JEB, objdump, Ghidra, a browser
// or a live process cannot, and not because it is unbuilt: replay requires a tool's output to be a
// pure function of its declared input, and a device or process read is not. `implementedBy` names
// the Concord tool that now provides the capability, where one does.
const REA_RULES = [
  [/_adb_|^(list_adb|collect_adb|read_adb)/, 'process', false, 'drives adb against a connected device'],
  [/_frida_|^(instrument_with_frida|load_frida_script|unload_frida_script)$/, 'process', false, 'drives Frida against a live process'],
  [/_gdb_|^gdb_console$/, 'process', false, 'drives a GDB session'],
  [/_rizin_|^rizin_debug_command$/, 'process', false, 'drives a Rizin session'],
  [/^cutter_command$|_cutter_/, 'process', false, 'drives a Cutter session'],
  [/_jeb_|^decompile_jeb_item$/, 'process', false, 'drives JEB'],
  [/^inspect_with_objdump$/, 'process', false, 'drives objdump'],
  [/^(observe|capture)_|_screenshot|^list_(browser|electron|javascript_runtime)_targets$|^discover_webmcp_tools$|^inspect_(electron_page|web_page|web_event_listeners)$|^reconcile_javascript_runtime$/, 'process', false, 'observes a live browser, Electron or runtime target'],
  [/^(close|resume|open)_|_session_status$/, 'process', false, 'manages a live provider session'],
  [/^inspect_(apktool|pcap|jeb)_client$/, 'read', false, 'reports an external provider installation'],
  [/^decode_android_resources$|^inspect_android_|^search_android_classes$|^trace_android_references$/, 'read', true, 'static analysis of packaged Android artifacts'],
  [/^compare_|^evaluate_reconstruction_coverage$|^build_reconstruction_obligation_ledger$/, 'pure', true, 'compares or tallies evidence already supplied as input'],
  [/^(inspect|identify|extract|analyze|project|trace|recover|export|import|decode|verify)_/, 'read', true, 'static analysis of bytes or text on disk'],
];
const REA_IMPLEMENTED = new Map([
  ['inspect_wasm_artifact', 'artifact.wasmInterface'],
  ['compare_wasm_interfaces', 'artifact.compareWasmInterfaces'],
  ['inspect_evm_interface', 'artifact.evmInterface'],
  ['inspect_binary_layout', 'artifact.inspect'],
  ['inspect_sqlite_database', 'artifact.sqlite'],
  ['inspect_packet_capture', 'artifact.pcap'],
  ['inspect_pcap_capture', 'artifact.pcap'],
  ['inspect_packet_fields', 'artifact.packetFields'],
  ['inspect_pe_resources', 'artifact.peResources'],
  ['inspect_go_binary', 'artifact.goBuildInfo'],
  ['inspect_android_package', 'artifact.apk'],
  ['inspect_android_class', 'artifact.dexClass'],
  ['inspect_android_method', 'artifact.dexMethod'],
  ['search_android_classes', 'artifact.dexSearch'],
  ['trace_android_references', 'artifact.dexReferences'],
  ['decode_android_resources', 'artifact.androidManifest'],
  ['project_android_application_graph', 'artifact.dexGraph'],
  ['inspect_managed_artifact', 'artifact.managed'],
  ['inspect_managed_members', 'artifact.managedMembers'],
  ['compare_managed_members', 'artifact.compareManagedMembers'],
  ['inspect_managed_native_boundaries', 'artifact.managedNativeBoundaries'],
  ['verify_managed_native_boundaries', 'artifact.verifyManagedNativeBoundaries'],
  ['project_managed_application_graph', 'artifact.managedGraph'],
  ['import_managed_reconstruction', 'artifact.importManagedReconstruction'],
]);
const classifyRea = (name) => {
  for (const [pattern, effect, internalizable, basis] of REA_RULES) {
    if (pattern.test(name)) return { effect, internalizable, basis };
  }
  return { effect: null, internalizable: null, basis: 'unclassified: no explicit rule matched this name' };
};

const reaEntry = lock.sources.find(s => s.id === 'rea');
const reaSource = acquisition.find(s => s.repository === 'morluto/rea');
let reaSummary = null;
if (reaEntry && reaSource && fs.existsSync(path.join(root, reaSource.directory, 'src'))) {
  const srcRoot = path.join(root, reaSource.directory, 'src');
  const declarations = new Map();
  (function sweep(directory) {
    for (const entry of fs.readdirSync(directory, { withFileTypes: true }).sort((a, b) => a.name < b.name ? -1 : 1)) {
      const full = path.join(directory, entry.name);
      if (entry.isDirectory()) { sweep(full); continue; }
      if (!entry.name.endsWith('.ts') || entry.name.includes('.test.')) continue;
      const text = fs.readFileSync(full, 'utf8');
      for (const m of text.matchAll(/toolContractMetadata\("([a-z0-9_]+)"/g)) {
        if (!declarations.has(m[1])) {
          declarations.set(m[1], path.relative(path.join(root, reaSource.directory), full).split(path.sep).join('/'));
        }
      }
    }
  })(srcRoot);

  for (const name of [...declarations.keys()].sort()) {
    const module = declarations.get(name);
    const { effect, internalizable, basis } = classifyRea(name);
    const implementedBy = REA_IMPLEMENTED.get(name) ?? null;
    capabilities.push({
      id: 'rea:tool/' + name, sourceId: 'rea', kind: 'tool',
      title: name, headings: [], summary: `REA investigation tool declared in ${module}.`,
      path: reaSource.directory + '/' + module,
      sourceSha256: hash(Buffer.from(canonical({ name, module }))),
      sourceUrl: reaEntry.url + '/blob/' + reaSource.revision + '/' + module.split('/').map(encodeURIComponent).join('/'),
      executable: false, status: 'source-available-unreviewed',
      effect, effectBasis: basis, internalizable, implementedBy,
    });
  }
  // The contract table src/reverse.mjs compiles into live tools. Emitted here so the tool list has
  // one source of truth -- the pinned clone -- rather than a hand-transcribed copy that can drift.
  const providerOf = (name) => {
    for (const [pattern, provider] of [
      [/_adb_|^(list_adb|collect_adb|read_adb)/, 'adb'],
      [/^frida_|_frida_|^(instrument_with_frida|load_frida_script|unload_frida_script)$/, 'frida'],
      [/^gdb_|_gdb_/, 'gdb'],
      [/^rizin_|_rizin_/, 'rizin'],
      [/^cutter_command$|_cutter_/, 'cutter'],
      [/_jeb_|^decompile_jeb_item$/, 'jeb'],
      [/^inspect_with_objdump$/, 'objdump'],
      [/^inspect_apktool_client$/, 'apktool'],
      [/^inspect_pcap_client$/, 'pcap'],
      [/^(observe|capture)_|_screenshot|^list_(browser|electron|javascript_runtime)_targets$|^discover_webmcp_tools$|^inspect_(electron_page|web_page|web_event_listeners)$|^reconcile_javascript_runtime$/, 'browser'],
    ]) if (pattern.test(name)) return provider;
    return null;
  };
  const table = [...declarations.keys()].sort().map((name) => {
    const { effect, internalizable, basis } = classifyRea(name);
    return { name, module: declarations.get(name), effect, internalizable, basis,
      provider: providerOf(name), implementedBy: REA_IMPLEMENTED.get(name) ?? null };
  });
  fs.writeFileSync(path.join(root, 'reverse-tools.json'),
    canonical({ schemaVersion: 1, sourceId: 'rea', revision: reaSource.revision, tools: table }) + '\n');

  reaSummary = { tools: declarations.size,
    providerBacked: table.filter(t => t.provider).length,
    unassigned: table.filter(t => !t.provider && t.internalizable !== true).length,
    internalizable: [...declarations.keys()].filter(n => classifyRea(n).internalizable === true).length,
    implemented: [...declarations.keys()].filter(n => REA_IMPLEMENTED.has(n)).length,
    unclassified: [...declarations.keys()].filter(n => classifyRea(n).effect === null).length };
}

const catalog = { schemaVersion: 1, note: 'Source features and ideas are indexed as untrusted data. A source entry is not a working Concord implementation.', repositories, capabilities };
fs.writeFileSync(path.join(root, 'capabilities.lock.json'), canonical(catalog) + '\n');
fs.writeFileSync(path.join(upstream, 'files.sha256.json'), canonical({ schemaVersion: 1, files: sourceFiles }) + '\n');
console.log(JSON.stringify({ repositories: repositories.length, files: sourceFiles.length, capabilities: capabilities.length, skills: capabilities.filter(c => c.kind === 'skill').length, tools: capabilities.filter(c => c.kind === 'tool').length, hermesLocal: localSummary, rea: reaSummary, catalogSha256: hash(Buffer.from(canonical(catalog))) }, null, 2));
