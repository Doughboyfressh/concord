import fs from 'node:fs';
import path from 'node:path';

/**
 * The input fields nothing ever passed.
 *
 * A new axis in the gap report found thirty-one declared input fields across twenty-three tools
 * that no plan had ever supplied - the output-key axis from the other side, and the same kind of
 * blind spot: a field no plan passes is a code path the suite has never entered, and a place
 * where the declaration and the implementation can disagree without anything failing. That is
 * not hypothetical. artifact.managedMembers accepted a `limit` its schema does not declare, and
 * the only thing that caught it was compiling a plan.
 *
 * Nearly all of them are filters, and a filter is testable without knowing any absolute value:
 * each exercise below runs the same tool twice in one plan, once plainly and once with the field
 * supplied, and states the relation between the two answers. That makes the prediction about the
 * field rather than about the fixture - a limit truncates the tail and keeps the head, an entry
 * list reproduces the default walk, a filter by kind returns only that kind - and it keeps the
 * exercises useful when a fixture grows another file.
 *
 * Two of them are not relations but reversals, which are the sharpest of the set:
 * recoverSources returns content only when a single source is named, and jsApplication's
 * maxFiles turns a two-module graph into a one-module one.
 *
 * These exercises read fixtures written by families spread before this one into the same
 * workspace - the toy SLEIGH table, the three-packet capture, the source map, the module graph,
 * the managed assembly. That is how the round already works, and it is stated here because it is
 * the one thing that would break if this family were moved earlier in the list.
 */

const ASSEMBLY_PRESENT = (() => {
  try { return fs.statSync('C:/Windows/Microsoft.NET/Framework64/v4.0.30319/System.Linq.dll').isFile(); }
  catch { return false; }
})();

const RANKABLE = [
  { id: 'greet', text: 'Greet the world politely and say hello to whoever is there.' },
  { id: 'build', text: 'Run a reviewed build target and report its receipt.' },
  { id: 'disassemble', text: 'Decode instructions from a compiled table.' },
];

/**
 * A minimal Mach-O, written to the specification, and a bundle plist that names it.
 *
 * Sixty-four bit header, two load commands: an LC_UUID and an LC_LOAD_DYLIB naming libSystem.
 * Small enough to write by hand and real enough for the reader, which says in its own
 * limitations that it takes link edges from the dylib path strings in the image rather than from
 * decoded load commands - so this image is honest about being exactly what that disclosure
 * describes, and the exercise asserts the disclosure alongside the edge it produced.
 */
const le32 = (value) => { const out = Buffer.alloc(4); out.writeUInt32LE(value); return out; };
const DYLIB_PATH = Buffer.from('/usr/lib/libSystem.B.dylib' + String.fromCharCode(0).repeat(6));
const MACH_O = Buffer.concat([
  // magic (64-bit little-endian), arm64, no subtype, MH_EXECUTE, two commands
  Buffer.from([0xcf, 0xfa, 0xed, 0xfe]), le32(0x0100000c), le32(0), le32(2), le32(2),
  le32(24 + 24 + DYLIB_PATH.length), le32(0x00200085), le32(0),
  le32(0x1b), le32(24), Buffer.from([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]),
  le32(0x0c), le32(24 + DYLIB_PATH.length), le32(24), le32(0), le32(0x10000), le32(0x10000), DYLIB_PATH,
]);
const BUNDLE_PLIST = [
  '<?xml version="1.0" encoding="UTF-8"?>',
  '<plist version="1.0">', '<dict>',
  '  <key>CFBundleIdentifier</key><string>com.example.concord</string>',
  '  <key>CFBundleExecutable</key><string>app.bin</string>',
  '</dict>', '</plist>', '',
].join(String.fromCharCode(10));
const bundleFixture = (dir) => {
  if (!fs.existsSync(path.join(dir, 'app.bin'))) fs.writeFileSync(path.join(dir, 'app.bin'), MACH_O);
  if (!fs.existsSync(path.join(dir, 'bundle-Info.plist'))) fs.writeFileSync(path.join(dir, 'bundle-Info.plist'), BUNDLE_PLIST);
};

const twice = (name, tool, plain, filtered, extra = []) => ({
  version: 1, name, tasks: [
    { id: 'plain', tool, input: plain },
    { id: 'filtered', tool, input: filtered },
    ...extra,
  ],
});

export function filterExercises(skill = null) {
  return [
    {
      family: 'filters', tool: 'capabilities.search',
      plan: twice('search-filters', 'capabilities.search',
        { query: 'agent skill debugging', limit: 20 },
        { query: 'agent skill debugging', limit: 20, kind: 'skill' },
        [{ id: 'bySource', tool: 'capabilities.search', input: { query: 'agent skill debugging', limit: 20, sourceId: 'ecc' } }]),
      expect: (r) => r.results.plain.totalMatches >= r.results.filtered.totalMatches
        && r.results.filtered.results.every((entry) => entry.kind === 'skill')
        && r.results.bySource.results.every((entry) => entry.sourceId === 'ecc')
        && r.results.plain.results.length > 0
        // The filter narrows what is returned and what is counted, together: a totalMatches that
        // ignored the filter would make a caller page through matches it can never be shown.
        && r.results.filtered.totalMatches <= r.results.plain.totalMatches,
      lesson: 'Filtering the capability index by kind or by source narrows the count as well as the page. Those are two different numbers and a tool that filtered only one of them would be worse than one that filtered neither: a totalMatches that ignored the filter tells a caller to page through matches it will never be shown. The filters are applied before ranking rather than after, so a narrow search is not a wide search with rows deleted.',
    },
    {
      family: 'filters', tool: 'peer.inbox', workspace: 'temp',
      plan: twice('inbox-filters', 'peer.inbox', {}, { limit: 1 },
        [{ id: 'forOperator', tool: 'peer.inbox', input: { for: 'operator' } },
          { id: 'afterFirst', tool: 'peer.inbox', input: { after: 1, limit: 5 } }]),
      expect: (r) => r.results.filtered.returned <= 1
        // The page shrinks and the box does not: total is a fact about the mailbox, returned a
        // fact about this page, and collapsing them would make a limit look like a deletion.
        && r.results.filtered.total === r.results.plain.total
        && r.results.filtered.latestSeq === r.results.plain.latestSeq
        && r.results.forOperator.messages.every((message) => message.for === 'operator')
        && r.results.afterFirst.messages.every((message) => message.seq > 1)
        && r.results.afterFirst.returned <= 5,
      lesson: 'The mailbox pages by sequence and filters by addressee, and the two counts it reports stay distinct under both: total is a fact about the box, returned a fact about the page. `after` is exclusive, so paging with the last sequence seen never re-reads a letter - which is what makes a reader that polls able to make progress rather than re-reading the oldest page forever.',
    },
    {
      family: 'filters', tool: 'skills.rank', workspace: 'temp',
      // skills.rank is pure: the candidates are an argument, not a store it reads. Three of them,
      // so a limit of one has a tail to drop and a head to keep.
      plan: twice('rank-limit', 'skills.rank',
        { query: 'greet the world politely', skills: RANKABLE },
        { query: 'greet the world politely', skills: RANKABLE, limit: 1 }),
      expect: (r) => r.results.filtered.ranked.length <= 1
        && r.results.plain.ranked.length >= 1
        // A limit truncates the tail and keeps the head: the top-ranked skill is the same one
        // either way, which is the only thing that makes a limited ranking usable.
        && r.results.filtered.ranked[0].id === r.results.plain.ranked[0].id
        && r.results.filtered.strategy === r.results.plain.strategy,
      lesson: 'A limit on a ranking truncates the tail and leaves the head alone - the same skill ranks first whether one row is asked for or all of them. Stated as an equivalence rather than as a value because it is the property that matters: a limit that changed the order would make a caller asking for the best match get something else, and the strategy name travels with both answers so a caller can tell they were ranked the same way.',
    },
    {
      family: 'filters', tool: 'schedule.due', workspace: 'temp',
      plan: twice('due-limit', 'schedule.due',
        { now: '2027-01-01T00:00:00Z' }, { now: '2027-01-01T00:00:00Z', limit: 1 }),
      expect: (r) => r.results.filtered.due.length <= 1
        // Pending counts everything still owed, due only what the page showed, so a limit cannot
        // make work look finished.
        && r.results.filtered.pending === r.results.plain.pending
        && r.results.filtered.due.length <= r.results.plain.due.length,
      lesson: 'Limiting what schedule.due returns never changes what it says is pending. The two numbers answer different questions - what is owed, and what this call is showing - and a limit that reduced the pending count would turn paging into forgetting, which for a schedule is the one failure that looks like success.',
    },
    {
      family: 'filters', tool: 'artifact.jsApplication', workspace: 'temp',
      plan: twice('application-maxfiles', 'artifact.jsApplication',
        { entry: 'entry.js' }, { entry: 'entry.js', maxFiles: 1 }),
      expect: (r) => r.results.plain.modules.length === 2 && r.results.plain.edges.length === 1
        // One file read, so the import is still named but the module behind it is not reached.
        && r.results.filtered.modules.length === 1
        && r.results.filtered.limitations.length >= r.results.plain.limitations.length,
      lesson: 'maxFiles bounds how much of a module graph is walked, and the bound is reported rather than silently applied: the truncated walk carries at least as many limitations as the complete one. A graph cut short that did not say so would be indistinguishable from an application that really has one module, which is the difference between evidence and an artefact of a budget.',
    },
    {
      family: 'filters', tool: 'artifact.recoverSources', workspace: 'temp',
      plan: twice('recover-one-source', 'artifact.recoverSources',
        { path: 'app.js.map' }, { path: 'app.js.map', source: 'src/greet.ts' }),
      expect: (r) => r.results.plain.content === null
        // Naming one source is what turns a listing into a recovery.
        && typeof r.results.filtered.content === 'string'
        && r.results.filtered.content.includes('greet')
        && r.results.filtered.sources.length === r.results.plain.sources.length,
      lesson: 'recoverSources lists every source it could give back and returns the text of exactly one, named by the caller. Content is null until then, which is what keeps a listing of a large bundle from being a copy of it, and the list itself is the same either way - so a caller decides what to pay for after seeing what is available rather than before.',
    },
    {
      family: 'filters', tool: 'artifact.packetFields', workspace: 'temp',
      plan: twice('fields-offset', 'artifact.packetFields',
        { path: 'three-packets.pcap', limit: 8 }, { path: 'three-packets.pcap', limit: 8, offset: 1 }),
      expect: (r) => r.results.plain.frames.length === 3
        && r.results.filtered.frames.length <= r.results.plain.frames.length
        && r.results.filtered.decoded <= r.results.plain.decoded
        && r.results.filtered.sha256 === r.results.plain.sha256,
      lesson: 'An offset into a capture changes which frames are decoded and not which file was read: the digest is of the whole file either way, because it answers "what did I examine" and not "what did I return". A reader whose digest moved with its window would make two quotations of the same capture impossible to reconcile.',
    },
    {
      family: 'filters', tool: 'artifact.controlFlow', workspace: 'temp',
      plan: twice('flow-entries', 'artifact.controlFlow',
        { table: 'toy-decode.sla', path: 'toy-flow.bin', address: '0x0' },
        { table: 'toy-decode.sla', path: 'toy-flow.bin', address: '0x0', entries: ['0x0'], followCalls: true }),
      expect: (r) => r.results.plain.supported === true && r.results.filtered.supported === true
        // Naming the entry the walk would have started from anyway reproduces it exactly, and
        // following calls changes nothing in a region that makes none.
        && r.results.filtered.blocks.length === r.results.plain.blocks.length
        && r.results.filtered.instructions.length === r.results.plain.instructions.length
        && r.results.filtered.sha256 === r.results.plain.sha256,
      lesson: 'Naming the entry point a control-flow walk would have chosen by default reproduces that walk exactly, and asking it to follow calls changes nothing in a region that makes none. Both are stated as equivalences, which is the only useful form: the value of an explicit entry list is that a caller can walk from somewhere else, and that is only trustworthy if walking from the same place gives the same answer.',
    },
    {
      family: 'filters', tool: 'artifact.callGraph', workspace: 'temp',
      plan: twice('calls-entries', 'artifact.callGraph',
        { table: 'toy-decode.sla', path: 'toy-calls.bin', address: '0x0' },
        { table: 'toy-decode.sla', path: 'toy-calls.bin', address: '0x0', entries: ['0x0'] }),
      expect: (r) => r.results.plain.supported === true && r.results.filtered.supported === true
        && r.results.filtered.nodes.length === r.results.plain.nodes.length
        && r.results.filtered.regions.length === r.results.plain.regions.length
        && r.results.filtered.edges.length === r.results.plain.edges.length
        && r.results.filtered.sha256 === r.results.plain.sha256,
      lesson: 'The same equivalence for a call graph: an explicit entry list containing the default entry recovers the same nodes, regions and edges. Worth proving separately from the control-flow walk because the two tools discover functions differently - one follows flow within a region, the other follows calls between them - and an entry list that meant different things to each would make a composed plan that passes the same entries to both quietly inconsistent.',
    },
    {
      family: 'filters', tool: 'artifact.dataflow', workspace: 'temp',
      plan: twice('dataflow-entries', 'artifact.dataflow',
        { table: 'toy-decode.sla', path: 'toy-flow.bin', address: '0x0' },
        { table: 'toy-decode.sla', path: 'toy-flow.bin', address: '0x0', entries: ['0x0'] }),
      expect: (r) => r.results.plain.supported === true && r.results.filtered.supported === true
        && r.results.filtered.sha256 === r.results.plain.sha256
        && JSON.stringify(r.results.filtered.counts) === JSON.stringify(r.results.plain.counts),
      lesson: 'And for the dataflow analysis, where the equivalence is stated over its counts rather than its lists: the same region lifted from the same entry produces the same number of operations, loads and stores. Comparing counts rather than contents is deliberate - it is the strongest claim that stays true if the analysis later reports more detail per operation.',
    },
    {
      family: 'filters', tool: 'sources.catalog',
      plan: twice('catalog-by-source', 'sources.catalog', {}, { sourceId: 'ecc' },
        [{ id: 'byRole', tool: 'sources.catalog', input: { role: 'skills' } }]),
      expect: (r) => r.results.plain.sources.length === 14
        && r.results.filtered.sources.length === 1
        && r.results.filtered.sources[0].id === 'ecc'
        // A role is a many-to-many fact - a source carries several and several sources carry one -
        // so filtering by it selects a subset without the one-to-one shape an id filter has.
        && r.results.byRole.sources.length >= 1
        && r.results.byRole.sources.length <= r.results.plain.sources.length
        && r.results.byRole.sources.every((entry) => entry.roles.includes('skills')),
      lesson: 'Asking the source catalogue for one source returns one entry out of fourteen, and the entry is the one asked for. A catalogue filter is the cheapest thing in this system to get wrong in a way nobody notices, because a filter that silently matched nothing and a source that genuinely has nothing look identical in an empty list - so the exercise asserts the identity of what came back rather than only its size.',
    },
    {
      family: 'filters', tool: 'rea.catalog',
      plan: twice('rea-filters', 'rea.catalog', {}, { provider: 'frida' },
        [{ id: 'availableOnly', tool: 'rea.catalog', input: { availableOnly: true } }]),
      expect: (r) => r.results.plain.tools.length > 0
        && r.results.filtered.tools.every((entry) => entry.provider === 'frida')
        && r.results.filtered.matched <= r.results.plain.matched
        // availableOnly cannot return more than the catalogue says is available now, and the
        // total it reports is still the whole catalogue: a filter on availability is a view, not
        // a smaller catalogue.
        && r.results.availableOnly.tools.length <= r.results.plain.availableNow
        && r.results.availableOnly.total === r.results.plain.total,
      lesson: 'The reverse-engineering catalogue filters by provider and by whether a tool is installed here, and keeps three numbers apart while doing it: total is the whole reviewed catalogue, availableNow how many of those are present on this machine, and matched how many the filter selected. A catalogue that collapsed them would make "this machine cannot do it" indistinguishable from "nobody reviewed it", which is the one distinction an operator needs before installing anything.',
    },
    {
      family: 'filters', tool: 'foreign.catalog',
      plan: twice('foreign-filters', 'foreign.catalog', {}, { source: 'rea-repo' },
        [{ id: 'availableOnly', tool: 'foreign.catalog', input: { availableOnly: true } }]),
      // Asserted as relations rather than as counts: how many foreign tools this round sees
      // depends on which catalogue file the registry was built from, and the properties below
      // are the ones that have to hold whether that is seventy-four tools or none.
      expect: (r) => r.results.plain.matched === r.results.plain.total
        && r.results.plain.availableNow <= r.results.plain.total
        && r.results.filtered.total === r.results.plain.total
        && r.results.filtered.matched <= r.results.plain.matched
        && r.results.filtered.tools.every((entry) => entry.source === 'rea-repo')
        && r.results.availableOnly.tools.every((entry) => entry.available === true)
        && r.results.availableOnly.total === r.results.plain.total,
      lesson: 'The foreign catalogue answers the same two questions as the reverse one and reports them the same way, which is the point of their sharing a shape: a caller choosing between a reviewed foreign tool and a reviewed local one compares like with like. Filtering by source narrows the tools and never the total, because the catalogue is what was reviewed and the filter is only what this question was about - and an unfiltered call matches everything it holds, which is the identity that makes matched worth reporting at all.',
    },
    {
      family: 'filters', tool: 'artifact.ghidraLanguageMatch', workspace: 'temp',
      plan: twice('language-match-filters', 'artifact.ghidraLanguageMatch',
        { opinion: 'toy.opinion', languages: 'toy.ldefs', primary: '334' },
        { opinion: 'toy.opinion', languages: 'toy.ldefs', primary: '334', loader: 'Portable Executable (PE)', secondary: 'default' }),
      expect: (r) => r.results.plain.supported === true && r.results.filtered.supported === true
        // rows is how many the .ldefs holds, not how many matched, so it cannot move with the
        // query - and the query comes back echoed, with the hints that were not given as null.
        && r.results.filtered.rows === r.results.plain.rows
        && r.results.plain.query.loader === null && r.results.plain.query.secondary === null
        && r.results.filtered.query.loader === 'Portable Executable (PE)'
        && r.results.filtered.query.secondary === 'default'
        && r.results.filtered.query.primary === '334'
        // A narrower query can only match fewer rows, never more.
        && r.results.filtered.counts.matched <= r.results.plain.counts.matched
        // And a secondary constraint against a row that declares no secondary is reported as
        // unconstrained rather than as a match or a miss.
        && r.results.filtered.matched[0].secondaryMatch === 'unconstrained',
      lesson: 'Matching a loader opinion against a language definition file accepts three narrowing hints - the loader that produced the opinion, and a primary and secondary language constraint - and a narrower query can only match fewer languages than a wider one. That monotonicity is the whole claim worth making about a matcher: a hint that could add a match would mean the unhinted query was already wrong. Two details measured rather than assumed - rows counts what the .ldefs holds and so does not move with the query, and a secondary constraint against a row that declares no secondary comes back as unconstrained rather than as a match or a miss, which is the only answer that does not invent agreement.',
    },
    {
      family: 'filters', tool: 'artifact.dexSearch', workspace: 'temp',
      plan: { version: 1, name: 'selectors-on-a-refusal', tasks: [
        { id: 'method', tool: 'artifact.dexMethod', input: { path: 'notmine.bin', descriptor: 'La/B;', name: 'go' } },
        { id: 'search', tool: 'artifact.dexSearch', input: { path: 'notmine.bin', query: 'anything', limit: 3 } },
        { id: 'references', tool: 'artifact.dexReferences', input: { path: 'notmine.bin', type: 'La/B;', limit: 3 } },
        { id: 'graph', tool: 'artifact.dexGraph', input: { path: 'notmine.bin', prefix: 'La/' } },
        { id: 'managed', tool: 'artifact.managedGraph', input: { path: 'notmine.bin', namespace: 'System' } },
      ] },
      expect: (r) => ['method', 'search', 'references', 'graph', 'managed'].every((id) => {
        const value = r.results[id];
        return value.supported === false && typeof value.reason === 'string' && value.untrusted === true;
      })
        // And the selector changes nothing about what is returned in place of findings: the same
        // empty shapes the unselected refusal gives, rather than a null where a list belongs.
        && r.results.method.methods.length === 0
        && r.results.search.matches.length === 0 && r.results.search.totalMatches === 0
        && r.results.references.methods.length === 0 && r.results.references.fields.length === 0
        && r.results.graph.edges.length === 0 && r.results.graph.roots.length === 0
        && r.results.managed.edges.length === 0 && r.results.managed.roots.length === 0,
      lesson: 'A selector supplied to a reader that cannot parse the file changes nothing about the refusal: the same supported:false, the same stated reason, and the same empty shapes in place of findings. Worth proving because the alternative is easy to write by accident - a filter applied before the format check, or a selector that turns an empty list into a null because nothing matched it. These five readers all take a name, a prefix, a namespace or a limit, and none of them lets it reach the answer before the file has been understood.',
    },
    {
      family: 'filters', tool: 'artifact.appleGraph', workspace: 'temp', fixture: bundleFixture,
      plan: twice('bundle-with-and-without-its-binary', 'artifact.appleGraph',
        { plist: 'bundle-Info.plist' }, { plist: 'bundle-Info.plist', binary: 'app.bin' }),
      expect: (r) => r.results.plain.supported === true && r.results.filtered.supported === true
        // The bundle is read from the plist, so naming the binary adds to the answer without
        // changing what was already there.
        && r.results.filtered.bundle.identifier === r.results.plain.bundle.identifier
        && r.results.filtered.bundle.executable === 'app.bin'
        && r.results.filtered.bundle.plistFormat === 'xml'
        && r.results.plain.edges.length === 0
        // And the binary is what turns a description into a graph.
        && r.results.filtered.edges.length === 1
        && r.results.filtered.edges[0].from === 'app.bin'
        && r.results.filtered.edges[0].to === '/usr/lib/libSystem.B.dylib'
        && r.results.filtered.edges[0].kind === 'links'
        && r.results.filtered.edges[0].system === true
        && r.results.filtered.externalFrameworks === 0
        // One more disclosure than the plist-only read, naming how the edges were found.
        && r.results.filtered.limitations.length === r.results.plain.limitations.length + 1
        && r.results.filtered.limitations.some((note) => note.includes('path strings')),
      lesson: 'A bundle plist describes an application and its binary describes what that application links, and appleGraph keeps them separable: naming the binary adds edges without changing anything the plist already said. A system dylib is marked as one rather than counted as an external framework, which is the distinction that matters when the question is what a bundle brings with it. And the reader states how it found the edges - from the dylib path strings in the image rather than from decoded load commands - which is exactly why a hand-written header with two load commands is enough to exercise it, and exactly what would make an unusual install name invisible.',
    },
    ...(skill ? [
      {
        family: 'filters', tool: 'skills.snapshot', workspace: 'temp', needsCorpus: skill.path,
        plan: { version: 1, name: 'snapshot-verifies-its-own-digest', tasks: [
          { id: 'first', tool: 'skills.snapshot', input: { path: skill.path, sourceId: skill.sourceId } },
          // The second snapshot is handed the digest the first produced, in the same run, through
          // a task reference. Nothing types a digest in: the tool is asked to agree with itself.
          { id: 'again', tool: 'skills.snapshot', dependsOn: ['first'], input: {
            path: skill.path, sourceId: skill.sourceId,
            expectedDigest: { $task: 'first', path: '/snapshotDigest' },
          } },
        ] },
        expect: (r) => r.results.first.snapshotDigest === r.results.again.snapshotDigest
          && /^[a-f0-9]{64}$/.test(r.results.first.snapshotDigest)
          && r.results.again.digestAlgorithm === 'sha256-canonical-json-v1'
          && r.results.again.fileCount === r.results.first.fileCount
          && r.results.again.trust === 'unreviewed-data',
        lesson: 'expectedDigest is what turns a snapshot from a reading into a check, and the cheapest honest way to exercise it is to have the tool agree with itself: one task snapshots a reviewed skill, the next snapshots it again with the first digest passed in by reference. Nothing types a digest in, so the exercise cannot be satisfied by a stale constant - and it states the property the whole catalogue rests on, that a snapshot of unchanged bytes is the same snapshot. The algorithm is named in the answer because a digest without its canonicalisation is not reproducible by anyone else.',
      },
      {
        family: 'filters', tool: 'skills.installed', workspace: 'temp',
        plan: twice('installed-by-source', 'skills.installed', {}, { sourceId: skill.sourceId }),
        expect: (r) => r.results.filtered.count <= r.results.plain.count
          && r.results.filtered.installed.every((entry) => entry.sourceId === skill.sourceId)
          && r.results.filtered.installed.length === r.results.filtered.count
          // Whatever the store holds, the count and the list it returns agree with each other.
          && r.results.plain.installed.length === r.results.plain.count,
        lesson: 'Filtering the installed-skill store by source narrows the list and the count together, and the exercise states that agreement rather than any particular number - the store is whatever earlier exercises left in it, and a prediction about its size would be a prediction about exercise ordering. A count that disagreed with its own list is the failure worth catching here, because every caller that pages uses one to decide how far to read the other.',
      },
    ] : []),
    ...(ASSEMBLY_PRESENT ? [{
      family: 'filters', tool: 'artifact.managedMembers', workspace: 'temp',
      plan: twice('members-by-type', 'artifact.managedMembers',
        { path: 'assembly.dll' }, { path: 'assembly.dll', type: '<Module>' }),
      expect: (r) => r.results.plain.types.length === 1
        && r.results.filtered.types.length === 1
        && r.results.filtered.types[0].fullName === '<Module>'
        && r.results.filtered.sha256 === r.results.plain.sha256,
      lesson: 'Naming a type that exists returns that type and nothing else; on a facade with exactly one type that is the same answer as the unfiltered read, which is the point - the filter selects rather than transforms. The digest is unchanged because it is of the assembly, not of the selection.',
    }] : []),
  ];
}
