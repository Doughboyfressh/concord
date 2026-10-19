import fs from 'node:fs';
import path from 'node:path';

/**
 * The compositional tools: the ones that take other tools' output as their input.
 *
 * A reader answers "what is in this file". These answer "what does the evidence support", and the
 * distinction they all turn on is the same one: a claim is not an observation, and an observation
 * is not a replay. Every tool here keeps the three apart rather than collapsing them into a
 * verdict, and declines to decide when the inputs cannot decide it.
 *
 * Two of these predictions are wrong on the obvious reading, which is why the exercises exist.
 * `verifyManagedNativeBoundaries` takes a list of *module* names, so a satisfied boundary means the
 * module was available and never that the named import exists inside it. And an obligation closed
 * on inferred evidence reports `unknown`, not `covered`: a passing verifier cannot promote coverage
 * if the thing it relied on was itself inferred. Both were measured here, not reasoned about.
 */

const DIGEST_A = 'a'.repeat(64);
const DIGEST_B = 'b'.repeat(64);

/** One task, one tool, run through the real kernel like every other exercise. */
const one = (tool, input) => ({ version: 1, name: 't', tasks: [{ id: 'a', tool, input }] });

export function evidenceExercises() {
  return [
    {
      family: 'evidence', tool: 'artifact.analysisView', workspace: 'temp',
      plan: one('artifact.analysisView', {
        view: { records: [
          { id: 'r1', kind: 'export', source: 'a.js', sha256: DIGEST_A, authority: 'replay' },
          { id: 'r2', kind: 'export', source: 'a.js', authority: 'inferred' },
          { id: 'r1', kind: 'import', source: 'b.js', authority: 'observed' },
        ] },
        references: ['r1', 'r404'],
      }),
      expect: (r) => {
        const kinds = r.results.a.issues.map((issue) => issue.issue);
        return kinds.includes('duplicate-id-different-digest') && kinds.includes('no-digest')
          && kinds.includes('reference-not-in-view') && r.results.a.summary.dangling === 1
          && r.results.a.summary.distinctIds === 2 && r.results.a.summary.withDigest === 1;
      },
      lesson: 'artifact.analysisView checks a record set against itself and names each problem separately: one id reused for two different digests, a record carrying no digest, and a reference to something the view never contained. It says outright that a pure tool reaches nothing, so it can prove internal consistency and never authenticity.',
    },
    {
      family: 'readers', tool: 'artifact.appleGraph', workspace: 'temp',
      fixture: (dir) => fs.writeFileSync(path.join(dir, 'notplist.bin'), 'this is not a plist'),
      plan: one('artifact.appleGraph', { plist: 'notplist.bin' }),
      expect: (r) => r.results.a.supported === false && r.results.a.reason === 'not_a_plist'
        && r.results.a.bundle === null && Array.isArray(r.results.a.edges),
      lesson: 'artifact.appleGraph refuses a file that declares no plist element with supported:false and a reason, and returns a null bundle with an empty edge list rather than a half-built graph. A partial graph that looked real would be worse than no graph.',
    },

    // ---- comparisons: what changed, and when that cannot be decided ---------------------
    {
      family: 'evidence', tool: 'artifact.compareApplicationVersions', workspace: 'temp',
      plan: one('artifact.compareApplicationVersions', {
        left: { version: '1', entries: [{ name: 'same', sha256: DIGEST_A }, { name: 'gone', sha256: DIGEST_B }] },
        right: { version: '2', entries: [{ name: 'same', sha256: DIGEST_A }, { name: 'added', sha256: DIGEST_B }] },
      }),
      expect: (r) => r.results.a.summary.added === 1 && r.results.a.summary.removed === 1
        && r.results.a.summary.unchanged === 1 && r.results.a.summary.presentBoth === 0,
      lesson: 'artifact.compareApplicationVersions keys entries by kind and name and, with a digest on both sides, separates added, removed, changed and unchanged. An entry with no declared kind is keyed as unspecified rather than silently matched against a differently-kinded one.',
    },
    {
      family: 'evidence', tool: 'artifact.compareApplicationVersions', workspace: 'temp',
      plan: one('artifact.compareApplicationVersions', {
        left: { version: '1', entries: [{ name: 'n', kind: 'class', sha256: DIGEST_A }] },
        right: { version: '2', entries: [{ name: 'n', kind: 'class' }] },
      }),
      expect: (r) => r.results.a.summary.presentBoth === 1 && r.results.a.summary.unchanged === 0
        && r.results.a.summary.changed === 0 && r.results.a.changes[0].state === 'present-both',
      lesson: 'artifact.compareApplicationVersions reports present-both, not unchanged, when only one side carries a digest: both versions declare the entry but a change cannot be decided. Calling that unchanged would turn a missing digest into a false claim of equality.',
    },
    {
      family: 'evidence', tool: 'artifact.compareHar', workspace: 'temp',
      plan: one('artifact.compareHar', {
        left: { entries: [{ method: 'GET', origin: 'https://x', pathname: '/a' }, { method: 'GET', origin: 'https://x', pathname: '/gone' }] },
        right: { entries: [{ method: 'GET', origin: 'https://x', pathname: '/a' }, { method: 'POST', origin: 'https://x', pathname: '/new' }] },
      }),
      expect: (r) => r.results.a.summary.added === 1 && r.results.a.summary.removed === 1
        && r.results.a.summary.unchanged === 1
        && r.results.a.changes.some((change) => change.request === 'POST https://x/new'),
      lesson: 'artifact.compareHar consumes the flat entries artifact.harCapture emits and keys a request by method, origin and path only. Query strings, timing and bodies are deliberately outside the key, so two calls differing only in a query parameter compare as the same request.',
    },
    {
      family: 'evidence', tool: 'artifact.compareJsExports', workspace: 'temp',
      plan: one('artifact.compareJsExports', {
        left: { exports: [{ name: 'keep', kind: 'const' }, { name: 'retype', kind: 'const' }] },
        right: { exports: [{ name: 'keep', kind: 'const' }, { name: 'retype', kind: 'function' }] },
      }),
      expect: (r) => r.results.a.summary.unchanged === 1 && r.results.a.summary.added === 1
        && r.results.a.summary.removed === 1,
      lesson: 'artifact.compareJsExports keys an export by name and kind together, so the same name re-exported as a different kind reads as one removal plus one addition rather than a change. It states that a different value or signature behind an unchanged name is invisible to it.',
    },
    {
      family: 'evidence', tool: 'artifact.compareManagedMembers', workspace: 'temp',
      plan: one('artifact.compareManagedMembers', {
        left: { members: [{ declaringType: 'T', name: 'attrs', kind: 'method', attributes: ['public'] }] },
        right: { members: [{ declaringType: 'T', name: 'attrs', kind: 'method', attributes: ['private'] }] },
      }),
      expect: (r) => r.results.a.summary.changed === 1 && r.results.a.changes[0].state === 'changed'
        && Array.isArray(r.results.a.changes[0].left) && Array.isArray(r.results.a.changes[0].right),
      lesson: 'artifact.compareManagedMembers keys a member by declaring type, name and kind, and reports an attribute change as changed while showing both attribute lists. Signatures are not part of the key, so an overload set collapses to one member.',
    },
    {
      family: 'evidence', tool: 'artifact.compareSourceToBundle', workspace: 'temp',
      plan: one('artifact.compareSourceToBundle', {
        source: { exports: [{ name: 'declared', kind: 'const' }, { name: 'onlySource', kind: 'function' }] },
        bundle: { exports: [{ name: 'declared', kind: 'const' }, { name: 'onlyBundle', kind: 'function' }] },
      }),
      expect: (r) => r.results.a.summary.present === 1 && r.results.a.summary.absent === 1
        && r.results.a.summary.bundleOnly === 1
        && r.results.a.findings.some((finding) => finding.state === 'absent' && /minifier/.test(finding.reason ?? '')),
      lesson: 'artifact.compareSourceToBundle separates present, absent and bundle-only, and attaches to every absence the reason that a minifier renaming the export would look identical. Absence of an export from a bundle is therefore never reported as evidence that it was removed.',
    },
    {
      family: 'evidence', tool: 'artifact.compareWasmInterfaces', workspace: 'temp',
      plan: one('artifact.compareWasmInterfaces', {
        left: { state: 'complete', entries: [{ direction: 'import', module: 'env', name: 'keep', kind: 'func' }] },
        right: { state: 'partial', entries: [{ direction: 'import', module: 'env', name: 'keep', kind: 'func' }] },
        select: 'both',
      }),
      expect: (r) => r.results.a.summary.unknown === 1 && r.results.a.summary.unchanged === 0
        && r.results.a.limitations.some((note) => /partial/.test(note)),
      lesson: 'artifact.compareWasmInterfaces reports unknown rather than unchanged when a signature on either side was never decoded, and when one interface is partial it says plainly that an absence there is not evidence of removal. Equality is only ever concluded from two complete readings.',
    },

    // ---- the evidence ledger: a claim is not an observation ------------------------------
    {
      family: 'evidence', tool: 'artifact.importManagedReconstruction', workspace: 'temp',
      plan: one('artifact.importManagedReconstruction', {
        observed: { members: [{ declaringType: 'T', name: 'real', kind: 'method' }, { declaringType: 'T', name: 'alsoReal', kind: 'field' }] },
        reconstruction: [
          { declaringType: 'T', name: 'real', kind: 'method', source: 'void real() {}' },
          { declaringType: 'T', name: 'invented', kind: 'method', source: 'void invented() {}' },
          { declaringType: 'T', name: 'alsoReal', kind: 'method', source: 'wrong kind' },
        ],
      }),
      expect: (r) => r.results.a.accepted.length === 1 && r.results.a.rejected.length === 2
        && r.results.a.summary.coverage === 0.5 && r.results.a.summary.uncovered === 1
        && r.results.a.rejected.every((entry) => /declares no such member/.test(entry.reason)),
      lesson: 'artifact.importManagedReconstruction accepts a reconstructed member only where the observed artifact declares one with the same name and kind, so a member nobody observed is rejected and a member reconstructed under the wrong kind is rejected too. Coverage counts names, and the tool says outright that it is no statement about behavioural correctness.',
    },
    {
      family: 'evidence', tool: 'artifact.obligationLedger', workspace: 'temp',
      plan: one('artifact.obligationLedger', {
        facts: [
          { id: 'o1', subject: 'S', kind: 'static', required: true, claim: 'holds' },
          { id: 'o2', subject: 'S', kind: 'runtime', required: true, claim: 'holds' },
          { id: 'o3', subject: 'S', kind: 'static', required: true, claim: 'holds' },
          { id: 'o4', subject: 'S', kind: 'static', required: false, claim: 'optional' },
        ],
        verifiers: [
          { obligationIds: ['o1'], result: 'pass', authority: 'replay', evidenceIds: ['e1'] },
          { obligationIds: ['o2'], result: 'fail', authority: 'observed', evidenceIds: ['e2'] },
          { obligationIds: ['o3'], result: 'pass', authority: 'inferred', evidenceIds: [] },
        ],
      }),
      expect: (r) => {
        const status = new Map(r.results.a.obligations.map((entry) => [entry.id, entry.status]));
        return status.get('o1') === 'closed' && status.get('o2') === 'open'
          && status.get('o3') === 'open' && status.get('o4') === 'candidate'
          && r.results.a.summary.closed === 1 && r.results.a.summary.open === 2;
      },
      lesson: 'artifact.obligationLedger closes an obligation only for a passing verifier with replay authority that cited evidence. A passing verifier whose authority is merely inferred leaves it open, a failing verifier leaves it open, and a static fact with nothing to verify it raises a candidate rather than a conclusion.',
    },
    {
      family: 'evidence', tool: 'artifact.reconstructionCoverage', workspace: 'temp',
      plan: one('artifact.reconstructionCoverage', {
        boundaryId: 'B',
        obligations: [{ id: 'a', status: 'closed', boundaryId: 'B' }, { id: 'z', status: 'closed', boundaryId: 'OTHER' }],
        observations: [{ obligationId: 'a', authority: 'replay' }],
      }),
      expect: (r) => r.results.a.status === 'covered' && r.results.a.counts.obligations === 1
        && r.results.a.reasons.length === 0 && r.results.a.probes.length === 0,
      lesson: 'artifact.reconstructionCoverage reports covered only when every obligation scoped to the named boundary is closed and backed by a replay observation, and it scopes strictly: an obligation belonging to another boundary is not counted either for or against this one.',
    },
    {
      family: 'evidence', tool: 'artifact.reconstructionCoverage', workspace: 'temp',
      plan: one('artifact.reconstructionCoverage', {
        boundaryId: 'B',
        obligations: [{ id: 'a', status: 'closed', boundaryId: 'B' }],
        observations: [{ obligationId: 'a', authority: 'inferred' }],
      }),
      expect: (r) => r.results.a.status === 'unknown' && r.results.a.counts.inferredOnly === 1
        && r.results.a.probes.some((probe) => /replay observation/.test(probe)),
      lesson: 'artifact.reconstructionCoverage answers unknown, never covered, for an obligation closed on an inferred observation, and names the probe that would settle it: replace the inference with a replay observation. An inferred observation can never promote coverage, which is what keeps a chain of plausible reasoning from being mistaken for evidence.',
    },
    {
      family: 'evidence', tool: 'artifact.reconstructionCoverage', workspace: 'temp',
      plan: one('artifact.reconstructionCoverage', {
        boundaryId: 'B',
        obligations: [{ id: 'a', status: 'closed', boundaryId: 'B' }],
        observations: [],
      }),
      expect: (r) => r.results.a.status === 'unknown' && r.results.a.counts.unobserved === 1
        && r.results.a.probes.some((probe) => /Supply the observation/.test(probe)),
      lesson: 'artifact.reconstructionCoverage distinguishes an obligation closed on weak evidence from one closed on evidence nobody supplied: both are unknown rather than covered, but each names its own probe, so the reason coverage failed is never guesswork.',
    },
    {
      family: 'evidence', tool: 'artifact.traceFeature', workspace: 'temp',
      plan: one('artifact.traceFeature', {
        feature: 'login',
        inventory: { version: '1', entries: [
          { name: 'LoginController', kind: 'class', source: 'auth/login.js' },
          { name: 'handleLogin', kind: 'function', source: 'auth/login.js' },
          { name: 'unrelated', kind: 'function', source: 'other.js' },
        ] },
        limit: 10,
      }),
      expect: (r) => r.results.a.matches.length === 2 && r.results.a.summary.scanned === 3
        && r.results.a.summary.allTermsMatched === true
        && r.results.a.limitations.some((note) => /not a dataflow or call trace/.test(note)),
      lesson: 'artifact.traceFeature matches a feature term against names and source paths in a supplied inventory, case-insensitively, and reports each match as a candidate to look at. It states that it is not a dataflow or call trace: a match never establishes that an entry implements the feature, and an absence means only that the inventory does not mention the term.',
    },
    {
      family: 'evidence', tool: 'artifact.verifyManagedNativeBoundaries', workspace: 'temp',
      plan: one('artifact.verifyManagedNativeBoundaries', {
        boundaries: [
          { importName: 'ok', module: 'present.dll', moduleResolved: true },
          { importName: 'absent', module: 'missing.dll', moduleResolved: true },
          { importName: 'unresolved', module: null, moduleResolved: false },
        ],
        available: ['present.dll'],
      }),
      expect: (r) => r.results.a.summary.satisfied === 1 && r.results.a.summary.missing === 1
        && r.results.a.summary.unknown === 1
        && r.results.a.limitations.some((note) => /not that the named export exists/.test(note)),
      lesson: 'artifact.verifyManagedNativeBoundaries checks each boundary against a list of available module names, so satisfied means the module was present and explicitly not that the named export exists inside it. A boundary naming no module at all is unknown rather than missing, because there was nothing to check it against.',
    },
  ];
}
