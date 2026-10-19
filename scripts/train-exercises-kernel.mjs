import { runPlan, replayPlan, attenuatePolicy } from '../src/engine.mjs';
import { canonical, digest, parseJson, validateSchema } from '../src/value.mjs';
import { makeCapabilityTools } from '../src/capabilities.mjs';
import { makeReverseTools } from '../src/reverse.mjs';
import { makeForeignTools } from '../src/foreign.mjs';
import { makeMailboxTools } from '../src/peer.mjs';
import { makeSourceTools } from '../src/sources.mjs';
import { makeSkillStoreTools, skillSlug } from '../src/skillstore.mjs';
import { boundedByRelevance } from '../src/chat-data.mjs';
import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';

/**
 * The kernel's own guarantees, and the refusals a plan cannot reach.
 *
 * Everything else in this suite is a plan. That shape cannot express the promises the rest of the
 * system rests on: that a policy can only ever be narrowed, that a journal which has been edited
 * will not replay, that a factory refuses configuration it cannot vouch for. Those were left
 * unexercised because they did not fit, which is the worst reason to leave the load-bearing parts
 * untested, so there is now a second shape — an exercise that is a function call.
 *
 * It is held to the same standard. There is no journal to replay, so reproducibility is paid by
 * invoking twice and requiring the same refusal both times, and the evidence says it was proven by
 * repetition rather than by replay.
 *
 * Every code below was raised for real before being written down here. That matters more than
 * usual on this file, because reading the source and guessing produced two wrong names: the refusal
 * for a tampered output receipt is REPLAY_CHAIN rather than REPLAY_OUTPUT, and the one for a moved
 * workspace is REPLAY_CONTEXT rather than REPLAY_ROOT. Both guesses were plausible and both were
 * wrong, which is the argument for probing.
 *
 * The replay checks are exercised against a re-signed journal rather than a corrupted one, which
 * is a stronger claim. An earlier version of this file said REPLAY_LIMIT, REPLAY_OUTPUT and
 * REPLAY_TRANSITION were out of reach because getting to them needed "a forgery rather than a
 * corruption". That was a description of the work, not a reason to skip it — the forgery is the
 * adversary the checks exist for, and building it took one function.
 */

const PLAN = { version: 1, name: 't', tasks: [{ id: 'a', tool: 'json.hash', input: { value: { a: 1 } } }] };

/** A clean journal to corrupt, produced by the same kernel the replay checks defend. */
const journalFor = ({ registry, policy, sourceLock, workspaceRoot }) =>
  runPlan({ plan: PLAN, policy, registry, sourceLock, approvals: [], workspaceRoot });

/** Clone a journal so a tamper never mutates the original. */
const copy = (journal) => JSON.parse(JSON.stringify(journal));

/**
 * Rebuild a journal's hash chain after editing it: the adversary these checks actually face.
 *
 * eventHash is digest({previous, seq, type, data}) and digest is exported, so anyone holding the
 * source can re-sign a journal they have altered. Corrupting one byte and watching REPLAY_CHAIN
 * fire therefore proves less than it appears to — it only shows the chain detects damage, not that
 * the semantic checks behind it hold against a forgery. Re-signing is what reaches those, and the
 * checks that fire afterwards are the ones carrying the real weight.
 *
 * Re-signing an otherwise untouched journal reproduces the original hashes exactly and still
 * replays, which is the expected result rather than a hole: identical input, identical chain.
 */
function resign(journal) {
  let previous = digest(journal.header);
  journal.events.forEach((event, seq) => {
    event.seq = seq;
    event.previous = previous;
    event.hash = digest({ previous, seq, type: event.type, data: event.data });
    previous = event.hash;
  });
  journal.root = previous;
  return journal;
}

export function kernelExercises() {
  return [
    // ---- policy: the allow lists, and attenuation that can only narrow ------------------
    {
      family: 'kernel', tool: 'engine.compile', expectThrow: 'UNKNOWN_TOOL', workspace: 'temp',
      plan: { version: 1, name: 't', tasks: [{ id: 'a', tool: 'nobody.here', input: {} }] },
      lesson: 'A plan naming a tool the registry does not hold is refused UNKNOWN_TOOL while compiling, before any task runs. The registry is the whole of what exists, so an unknown name is a defect in the plan rather than a capability to be looked for elsewhere.',
    },
    {
      family: 'kernel', tool: 'engine.compile', expectThrow: 'POLICY_DENIED', workspace: 'temp',
      narrow: { allowedEffects: ['pure', 'read'] },
      plan: { version: 1, name: 't', tasks: [{ id: 'a', tool: 'files.write', input: { path: 'x.json', content: { a: 1 } } }] },
      lesson: 'A task whose effect is outside allowedEffects is refused POLICY_DENIED at compile time, not blocked for an approval. This is the distinction the whole authority model turns on: a write that is merely ungranted can be approved, while a write the policy does not permit at all can never be, so it must fail before it becomes something a person could be asked to allow.',
    },
    {
      family: 'kernel', tool: 'engine.compile', expectThrow: 'POLICY_DENIED', workspace: 'temp',
      narrow: { allowedTools: ['files.read'] },
      plan: { version: 1, name: 't', tasks: [{ id: 'a', tool: 'json.hash', input: { value: 1 } }] },
      lesson: 'A tool absent from allowedTools is refused POLICY_DENIED even when it is registered and even when its effect is pure. Being harmless is not the same as being permitted, and a policy that let pure tools through unlisted would not be an allow list at all.',
    },
    {
      // The round's own policy grants every effect, so there is nothing left to add to it. Narrowed
      // first, deliberately: asking for an effect the caller already holds is a duplicate rather
      // than a widening, and it is refused by a different check. Round 037 learned that by
      // predicting POLICY_NOT_ATTENUATED here and getting INVALID_POLICY.
      family: 'kernel', tool: 'engine.attenuatePolicy', expectThrow: 'POLICY_NOT_ATTENUATED',
      narrow: { allowedEffects: ['pure', 'read'] },
      call: ({ policy }) => attenuatePolicy(policy, { allowedEffects: ['pure', 'read', 'write'] }),
      lesson: 'attenuatePolicy refuses POLICY_NOT_ATTENUATED when asked for an effect the caller does not hold. Delegation can only ever hand down less authority than it was given, so the function refuses rather than returning a quietly widened policy that would look like the real thing.',
    },
    {
      family: 'kernel', tool: 'engine.attenuatePolicy', expectThrow: 'INVALID_POLICY',
      call: ({ policy }) => attenuatePolicy(policy, { allowedEffects: [...policy.allowedEffects, policy.allowedEffects[0]] }),
      lesson: 'A policy listing the same effect twice is refused INVALID_POLICY for the duplicate, and that check runs before the narrowing check. So re-requesting an effect already held is reported as a malformed policy rather than as an attempted widening — the two mistakes are different, and the order means the shape of a policy is settled before anything is concluded about its authority.',
    },
    {
      family: 'kernel', tool: 'engine.attenuatePolicy', expectThrow: 'POLICY_NOT_ATTENUATED',
      call: ({ policy }) => attenuatePolicy(policy, { maxTasks: policy.maxTasks + 1 }),
      lesson: 'attenuatePolicy refuses a numeric bound raised by even one, so narrowing is checked field by field rather than judged overall. A policy that was stricter about effects and looser about task count would otherwise pass as an attenuation of the one it came from.',
    },

    // ---- approvals and workspace: the arguments runPlan will not take ------------------
    {
      family: 'kernel', tool: 'engine.runPlan', expectThrow: 'INVALID_APPROVAL',
      call: ({ registry, policy, sourceLock, workspaceRoot }) =>
        runPlan({ plan: PLAN, policy, registry, sourceLock, approvals: ['not-a-request-hash'], workspaceRoot }),
      lesson: 'An approvals list holding anything that is not a SHA-256 request hash is refused INVALID_APPROVAL before the plan runs. An approval is only meaningful as an exact hash, so a malformed entry is rejected rather than ignored — ignoring it would let a caller submit noise and have the run proceed as though nothing had been asked for.',
    },
    {
      family: 'kernel', tool: 'engine.runPlan', expectThrow: 'INVALID_APPROVAL',
      call: ({ registry, policy, sourceLock, workspaceRoot }) =>
        runPlan({ plan: PLAN, policy, registry, sourceLock, approvals: ['a'.repeat(64), 'a'.repeat(64)], workspaceRoot }),
      lesson: 'The same request hash listed twice is refused INVALID_APPROVAL: approvals must be unique. One grant authorises one request, so a duplicate is either a mistake or an attempt to make a single approval count more than once.',
    },
    {
      family: 'kernel', tool: 'engine.runPlan', expectThrow: 'INVALID_WORKSPACE',
      call: ({ registry, policy, sourceLock }) =>
        runPlan({ plan: PLAN, policy, registry, sourceLock, approvals: [], workspaceRoot: 'a/relative/path' }),
      lesson: 'A workspace root that is not absolute is refused INVALID_WORKSPACE. Every path a tool accepts is resolved against this root, so a relative root would make the workspace boundary depend on the current directory of whatever process happened to start the run.',
    },

    // ---- replay: a journal that was edited does not verify ------------------------------
    {
      family: 'kernel', tool: 'engine.replayPlan', expectThrow: 'REPLAY_CHAIN',
      call: async (context) => {
        const journal = copy(await journalFor(context));
        const completed = journal.events.find((event) => event.type === 'completed');
        completed.data.output = { digest: 'a value nobody computed' };
        return replayPlan({ journal, plan: PLAN, policy: context.policy, registry: context.registry, sourceLock: context.sourceLock, approvals: [], workspaceRoot: context.workspaceRoot });
      },
      lesson: 'Editing a recorded output breaks replay with REPLAY_CHAIN, not with a mismatched-output error: every event carries the hash of the one before it, so changing any payload invalidates the chain from that point on. The chain is what makes the journal evidence — a receipt that could be edited afterwards would only be a claim about what happened.',
    },
    {
      family: 'kernel', tool: 'engine.replayPlan', expectThrow: 'REPLAY_CHAIN',
      call: async (context) => {
        const journal = copy(await journalFor(context));
        journal.events.splice(1, 0, { ...journal.events[1] });
        return replayPlan({ journal, plan: PLAN, policy: context.policy, registry: context.registry, sourceLock: context.sourceLock, approvals: [], workspaceRoot: context.workspaceRoot });
      },
      lesson: 'Duplicating an event breaks replay with REPLAY_CHAIN as well, because each event commits to its own sequence number as well as to its predecessor. Inserting or reordering is caught by the same check that catches editing, so there is one guarantee to reason about rather than three.',
    },
    {
      family: 'kernel', tool: 'engine.replayPlan', expectThrow: 'REPLAY_CONTEXT',
      call: async (context) => {
        const journal = await journalFor(context);
        return replayPlan({ journal, plan: PLAN, policy: context.policy, registry: context.registry, sourceLock: context.sourceLock, approvals: [], workspaceRoot: context.workspaceRoot + '-elsewhere' });
      },
      lesson: 'An untouched journal replayed against a different workspace root is refused REPLAY_CONTEXT. The header commits to the plan, the policy, the source lock, the tool registry and the workspace together, so a run is only reproducible in the setting it actually happened in; verifying it somewhere else would be answering a different question.',
    },
    {
      family: 'kernel', tool: 'engine.replayPlan', expectThrow: 'REPLAY_ROOT',
      call: async (context) => {
        const journal = copy(await journalFor(context));
        journal.root = 'b'.repeat(64);
        return replayPlan({ journal, plan: PLAN, policy: context.policy, registry: context.registry, sourceLock: context.sourceLock, approvals: [], workspaceRoot: context.workspaceRoot });
      },
      lesson: 'Replacing the journal root while leaving every event intact is refused REPLAY_ROOT: the root must equal the hash the event chain actually ends on. The chain proves the events agree with each other and the root is the single value committing to all of them, so both are checked rather than one standing in for the other.',
    },

    /**
     * The same three checks again, this time against a journal whose chain was rebuilt.
     *
     * These are the ones that matter. REPLAY_CHAIN catches damage; everything below catches someone
     * who knew the format and fixed the hashes afterwards, which is the only attacker worth
     * modelling for a record that is meant to be evidence.
     */
    {
      family: 'kernel', tool: 'engine.replayPlan', expectThrow: 'REPLAY_OUTPUT',
      call: async (context) => {
        const journal = copy(await journalFor(context));
        const completed = journal.events.find((event) => event.type === 'completed');
        completed.data.unexpected = true;
        return replayPlan({ journal: resign(journal), plan: PLAN, policy: context.policy, registry: context.registry, sourceLock: context.sourceLock, approvals: [], workspaceRoot: context.workspaceRoot });
      },
      lesson: 'A re-signed journal whose output receipt carries an extra field is refused REPLAY_OUTPUT. The receipt must have exactly taskId, output and outputHash, so the shape is asserted rather than merely read — an unrecognised field is the shape of someone having added something, and a checker that ignored unknown keys would accept it.',
    },
    {
      family: 'kernel', tool: 'engine.replayPlan', expectThrow: 'REPLAY_OUTPUT',
      call: async (context) => {
        const journal = copy(await journalFor(context));
        const completed = journal.events.find((event) => event.type === 'completed');
        completed.data.output = { digest: 'a value nobody computed' };
        return replayPlan({ journal: resign(journal), plan: PLAN, policy: context.policy, registry: context.registry, sourceLock: context.sourceLock, approvals: [], workspaceRoot: context.workspaceRoot });
      },
      lesson: 'Rewriting a recorded output and re-signing the chain is still refused, now as REPLAY_OUTPUT, because the receipt commits to the digest of its own output. So the chain is not the only thing binding a result: even with every hash rebuilt, the output has to be the one its own receipt claims. Replay never re-executes the tool, which is exactly why this inner check has to exist.',
    },
    {
      family: 'kernel', tool: 'engine.replayPlan', expectThrow: 'REPLAY_TRANSITION',
      call: async (context) => {
        const journal = copy(await journalFor(context));
        journal.events[1].type = 'blocked';
        return replayPlan({ journal: resign(journal), plan: PLAN, policy: context.policy, registry: context.registry, sourceLock: context.sourceLock, approvals: [], workspaceRoot: context.workspaceRoot });
      },
      lesson: 'A re-signed journal claiming a task was blocked where an intent belongs is refused REPLAY_TRANSITION, naming the event type it expected. The order of events is part of the contract, not an accident of how they were written, so a sequence that is internally consistent but describes an impossible run is still rejected.',
    },
    {
      family: 'kernel', tool: 'engine.replayPlan', expectThrow: 'REPLAY_LIMIT',
      // Large enough to run and then be inflated past the same bound: the header commits to the
      // policy, so replaying under a smaller budget would fail REPLAY_CONTEXT first and prove
      // nothing about the journal's size.
      narrow: { maxJournalBytes: 8192 },
      call: async (context) => {
        const journal = copy(await journalFor(context));
        journal.events.splice(1, 0, { ...journal.events[1], type: 'note', data: { filler: 'z'.repeat(16384) } });
        return replayPlan({ journal: resign(journal), plan: PLAN, policy: context.policy, registry: context.registry, sourceLock: context.sourceLock, approvals: [], workspaceRoot: context.workspaceRoot });
      },
      lesson: 'A journal padded past the replay budget is refused REPLAY_LIMIT before any event is verified, so verification cannot be used to make a reader do unbounded work. The budget is checked against the header and events together, and the header is unchanged by padding, which is why the size check has to be separate from the context check.',
    },

    /**
     * Compaction, which is the one place determinism is load-bearing and invisible.
     *
     * A context that varied between runs would make a recorded turn unreplayable with nothing
     * looking wrong — the journal would verify and the prompt it was produced from would be gone.
     * So this asserts the bound, the declared omission, and that two calls agree exactly, with an
     * input far larger than any real instruction set.
     */
    {
      family: 'kernel', tool: 'chat-data.boundedByRelevance',
      call: () => boundedByRelevance(
        Array.from({ length: 20000 }, (unused, index) => ({
          id: 'lesson-' + String(index).padStart(6, '0'),
          text: index % 7 === 0
            ? 'reconstruction coverage inferred observation ' + index + ' ' + 'filler '.repeat(20)
            : 'unrelated matter ' + index + ' ' + 'filler '.repeat(20),
        })),
        { query: 'reconstruction coverage inferred observation', maxBytes: 12288 },
      ),
      expect: (r) => Buffer.byteLength(canonical(r.items)) <= 12288
        && r.items.length > 0 && r.omittedCount === r.totalCount - r.items.length
        && r.totalCount === 20000 && r.omittedIds.length === r.omittedCount
        && /^[0-9a-f]{64}$/.test(r.fullDigest) && r.strategy === 'lexical-overlap-v1'
        // Everything kept is relevant: the budget is spent on the query, not on the first items.
        && r.items.every((item) => /reconstruction coverage/.test(item.text)),
      lesson: 'Context compaction selects by lexical relevance to the current message and fits a declared byte budget, so twenty thousand candidate lessons still produce a payload under twelve kilobytes — and every one kept matches the query rather than merely coming first. What is dropped is declared, not hidden: the count, the digest of the whole set, and the id of each omitted item, so an omission is auditable and the omitted material can be fetched back by id. Two calls with the same inputs return byte-identical results, which is what lets a turn whose context was compacted still replay. Compaction by asking a model to summarise cannot offer that, because summarising is a fresh inference each time and replay would verify a run against a context that no longer exists.',
    },

    // ---- value: the JSON domain the kernel can record ----------------------------------
    {
      family: 'kernel', tool: 'value.canonical', expectThrow: 'INVALID_JSON',
      call: () => canonical({ present: undefined }),
      lesson: 'canonical refuses INVALID_JSON for a key holding undefined, because undefined is outside the JSON domain and has no canonical form. This is the refusal that turns an overlooked optional field into a visible failure: JSON.stringify would silently drop the key and the value would travel on as though it had never been there.',
    },
    {
      family: 'kernel', tool: 'value.canonical', expectThrow: 'INVALID_JSON',
      call: () => canonical({ fn: () => 1 }),
      lesson: 'canonical refuses a function for the same reason it refuses undefined: the domain is data that can be hashed and replayed, and anything that cannot be written down cannot be committed to by a receipt.',
    },
    {
      family: 'kernel', tool: 'value.parseJson', expectThrow: 'INVALID_JSON',
      call: () => parseJson('{ not actually json'),
      lesson: 'parseJson raises INVALID_JSON rather than returning null or undefined for malformed text, so a configuration file that was corrupted on disk fails where it is read instead of becoming an empty object several layers further in.',
    },
    {
      family: 'kernel', tool: 'value.validateSchema', expectThrow: 'INVALID_SCHEMA',
      call: () => validateSchema({}, { type: 'a-type-that-does-not-exist' }),
      lesson: 'validateSchema separates a bad schema from bad data: an unrecognised type raises INVALID_SCHEMA, not a validation failure about the value. A schema nobody can evaluate would otherwise read as a value that failed to satisfy it, which is the error report most likely to send someone looking in the wrong place.',
    },

    // ---- factories: configuration a registry will not be built from --------------------
    {
      family: 'kernel', tool: 'capabilities.factory', expectThrow: 'INVALID_CAPABILITIES',
      call: () => makeCapabilityTools({ capabilities: 'not an array' }),
      lesson: 'makeCapabilityTools refuses INVALID_CAPABILITIES rather than building a registry over an inventory it cannot read. Configuration is checked when the registry is assembled, not when a tool is first called, so a malformed lock file fails at startup instead of halfway through somebody using it.',
    },
    {
      family: 'kernel', tool: 'reverse.factory', expectThrow: 'REVERSE_TABLE_INVALID',
      call: () => makeReverseTools({ tools: 'not an array' }, {}),
      lesson: 'makeReverseTools refuses REVERSE_TABLE_INVALID for a malformed tool table. The table decides which external commands exist at all, so accepting a shape it could only partly understand would mean a registry whose contents nobody had reviewed.',
    },
    {
      family: 'kernel', tool: 'foreign.factory', expectThrow: 'FOREIGN_MANIFEST_INVALID',
      call: () => makeForeignTools({ schemaVersion: 'not a number', sources: [] }, {}),
      lesson: 'makeForeignTools refuses FOREIGN_MANIFEST_INVALID for a manifest whose schema version is not a number, before any foreign server is contacted. A manifest describes executables that will run on this machine, so it is validated at build time where a person can still read the error.',
    },
    {
      family: 'kernel', tool: 'peer.factory', expectThrow: 'PEER_CONFIG',
      call: () => makeMailboxTools({ directory: 'a/relative/mailbox' }),
      lesson: 'makeMailboxTools refuses PEER_CONFIG for a relative mailbox directory, the same reason runPlan refuses a relative workspace root: a location that depends on the current directory is not a location. The mailbox holds messages between agents, so where it lives has to be settled before anything is written to it.',
    },
    {
      family: 'kernel', tool: 'sources.factory', expectThrow: 'SOURCE_LOCK_INVALID',
      call: () => makeSourceTools({ sources: 'not an array' }),
      lesson: 'makeSourceTools refuses SOURCE_LOCK_INVALID for a malformed source lock. The lock is the record of which upstream sources were reviewed and at which digests, so a registry built over an unreadable one would claim a provenance nobody had established.',
    },

    /**
     * Tool refusals that need an inventory this round's registry does not carry.
     *
     * The registry is built from the committed capabilities lock, so a corpus that disagrees with
     * its recorded digest cannot be staged through a plan — the lock would have to be edited first.
     * These build a small store over a fixture instead, which is the same thing the skillstore
     * tests do, and is the only way to see the digest check actually refuse.
     */
    {
      family: 'skills', tool: 'skills.install', expectThrow: 'SKILL_DIGEST',
      call: ({ workspaceRoot }) => {
        const body = '# Greeting\n\nSay hello.\n';
        const relative = 'upstream/example/skills/greeting/SKILL.md';
        const file = path.join(workspaceRoot, relative);
        fs.mkdirSync(path.dirname(file), { recursive: true });
        fs.writeFileSync(file, body);
        const inventory = { capabilities: [{
          id: 'example:skills/greeting/SKILL.md', kind: 'skill', path: relative, sourceId: 'example',
          title: 'Greeting', status: 'source-available-unreviewed',
          sourceSha256: createHash('sha256').update(Buffer.from(body)).digest('hex'),
        }] };
        const store = makeSkillStoreTools(inventory);
        // Somebody edited the corpus after it was indexed, which is exactly what the digest is for.
        fs.writeFileSync(file, '# Greeting\n\nSomething else entirely.\n');
        return store.find((tool) => tool.name === 'skills.install')
          .execute({ id: 'example:skills/greeting/SKILL.md' }, { workspaceRoot, policy: { maxOutputBytes: 1048576, timeoutMs: 10000 } });
      },
      lesson: 'skills.install refuses SKILL_DIGEST when the corpus file no longer hashes to what the inventory recorded, and refuses before copying anything. An import that skipped this would be a copy rather than an adoption, and a lock over unchecked copies locks nothing at all.',
    },
    {
      family: 'skills', tool: 'skills.install', expectThrow: 'SKILL_SOURCE',
      call: ({ workspaceRoot }) => {
        const inventory = { capabilities: [{
          id: 'example:skills/absent/SKILL.md', kind: 'skill', path: 'upstream/example/skills/absent/SKILL.md',
          sourceId: 'example', title: 'Absent', status: 'source-available-unreviewed', sourceSha256: 'c'.repeat(64),
        }] };
        return makeSkillStoreTools(inventory).find((tool) => tool.name === 'skills.install')
          .execute({ id: 'example:skills/absent/SKILL.md' }, { workspaceRoot, policy: { maxOutputBytes: 1048576, timeoutMs: 10000 } });
      },
      lesson: 'skills.install separates SKILL_SOURCE from SKILL_UNKNOWN: an id the inventory never listed is unknown, while an id it did list whose file is not on disk means the index has outlived the tree it indexed. Collapsing the two into one error would leave an operator unable to tell a typo from a missing checkout.',
    },
    {
      family: 'skills', tool: 'skills.slug', expectThrow: 'SKILL_ID',
      call: () => skillSlug('///'),
      lesson: 'An inventory id that reduces to no usable filename characters is refused SKILL_ID rather than turned into an empty or punctuation-only name. The slug becomes a real path on disk, so a name that cannot be written is caught where it is derived.',
    },

    // ---- tool refusals a plan does reach, once the write is granted ---------------------
    {
      family: 'scheduling', tool: 'schedule.declare', expectCode: 'SCHEDULE_ID', grant: true, workspace: 'temp',
      plan: { version: 1, name: 't', tasks: [{ id: 'a', tool: 'schedule.declare', input: { id: 'Not A Slug', dueAt: '2027-01-01T00:00:00Z', plan: { version: 1, tasks: [] } } }] },
      lesson: 'schedule.declare refuses SCHEDULE_ID for an identifier that is not a lower-case slug, and the refusal arrives only after the write is granted because the approval gate sits in front of the tool. The id names a stored record that will be matched exactly later, so a loose spelling now is a schedule nobody can reliably replace.',
    },
    {
      family: 'exchange', tool: 'peer.post', expectCode: 'PEER_MAILBOX', grant: true,
      plan: { version: 1, name: 't', tasks: [{ id: 'a', tool: 'peer.post', input: { message: 'A reply to a message that was never posted.', replyTo: 9999 } }] },
      lesson: 'peer.post refuses PEER_MAILBOX when replyTo names a sequence number the mailbox does not hold, rather than filing an orphan reply. The reply link is what lets peer.inbox tell an answered question from an open one, so a link to nothing would quietly corrupt that distinction.',
    },
    // ---- bounds that need a workspace already at its limit, or a tool of our own --------
    {
      family: 'kernel', tool: 'engine.runPlan', expectThrow: 'JOURNAL_LIMIT',
      narrow: { maxJournalBytes: 1024 },
      call: ({ registry, policy, sourceLock, workspaceRoot }) =>
        runPlan({ plan: PLAN, policy, registry, sourceLock, approvals: [], workspaceRoot }),
      lesson: 'A journal budget too small for the receipts a plan must write is refused JOURNAL_LIMIT as the budget is exhausted, and the message says to inspect any pending intent before retrying. The journal is written as the run proceeds, so the bound is enforced event by event rather than estimated in advance — which is why the refusal names a partial journal rather than rejecting the plan outright.',
    },
    {
      family: 'kernel', tool: 'engine.runPlan', expectCode: 'TIMEOUT',
      narrow: { timeoutMs: 1 },
      call: ({ registry, policy, sourceLock, workspaceRoot }) => {
        // A tool of our own, because the deadline needs something reliably slower than it is.
        // Giving a real tool a one-millisecond budget was measured as flaky: TIMEOUT twice and a
        // different refusal on the third run, which would make this exercise report phantom
        // findings. The code still comes out of the real journal.
        const slow = new Map(registry);
        slow.set('kernel.slow', {
          name: 'kernel.slow', version: '1.0.0', effect: 'pure', outputKeys: ['done'],
          inputSchema: { type: 'object', properties: {}, additionalProperties: false },
          execute: () => new Promise((resolve) => setTimeout(() => resolve({ done: true }), 250)),
        });
        return runPlan({
          plan: { version: 1, name: 't', tasks: [{ id: 'a', tool: 'kernel.slow', input: {} }] },
          policy: { ...policy, allowedTools: [...slow.keys()].sort() },
          registry: slow, sourceLock, approvals: [], workspaceRoot,
        });
      },
      lesson: 'A tool that outruns the policy deadline is recorded as a failed task whose engine code is TOOL_FAILED and whose tool code is TIMEOUT, and the signal it was handed is aborted at the same moment. The deadline is enforced by the kernel racing the tool rather than by the tool checking a clock, so a tool that ignores its signal entirely still cannot overrun the budget.',
    },
    {
      family: 'scheduling', tool: 'schedule.declare', expectThrow: 'SCHEDULE_LIMIT', workspace: 'temp',
      call: ({ registry, workspaceRoot }) => {
        // Its own directory, because `workspace: 'temp'` is one directory shared by the whole
        // round. Round 041 filled the shared one with five hundred and twelve schedules and broke
        // three later exercises that had every right to expect an empty store.
        const own = fs.mkdtempSync(path.join(workspaceRoot, 'schedule-limit-'));
        // Written straight to disk rather than declared one at a time: five hundred and twelve
        // granted writes would take the round far longer than the bound is worth proving.
        const directory = path.join(own, 'schedules');
        fs.mkdirSync(directory, { recursive: true });
        for (let index = 0; index < 512; index += 1) {
          const id = 'filler-' + String(index).padStart(4, '0');
          fs.writeFileSync(path.join(directory, id + '.json'), JSON.stringify({ id, dueAt: '2027-01-01T00:00:00Z', plan: { version: 1, tasks: [] }, planHash: 'f'.repeat(64) }) + '\n');
        }
        return registry.get('schedule.declare').execute(
          { id: 'one-too-many', dueAt: '2027-01-01T00:00:00Z', plan: { version: 1, tasks: [] } },
          { workspaceRoot: own, policy: { maxOutputBytes: 1048576, timeoutMs: 10000 } },
        );
      },
      lesson: 'Declaring a schedule when the bound is already full is refused SCHEDULE_LIMIT, reporting how many exist. Re-declaring an id that is already present is still allowed at the limit, because replacing a schedule is how a finished one is advanced and refusing that would wedge a full store permanently.',
    },
    {
      family: 'skills', tool: 'skills.install', expectThrow: 'SKILL_LIMIT', workspace: 'temp',
      call: ({ workspaceRoot: shared }) => {
        // Its own directory: the shared temp workspace is reused by every exercise in the round,
        // and a lock holding five hundred and twelve rows is not something the next one should
        // inherit.
        const workspaceRoot = fs.mkdtempSync(path.join(shared, 'skill-limit-'));
        // A real, matching corpus file is required to get this far: round 041 predicted the limit
        // would be reported first and got SKILL_UNKNOWN, because the id is resolved and its digest
        // verified before the lock is even read. So the fixture has to be genuinely installable.
        const body = '# Filler\n\nA real file whose digest matches what the inventory records.\n';
        const relative = 'upstream/example/skills/filler/SKILL.md';
        const file = path.join(workspaceRoot, relative);
        fs.mkdirSync(path.dirname(file), { recursive: true });
        fs.writeFileSync(file, body);
        const id = 'example:skills/filler/SKILL.md';
        const inventory = { capabilities: [{
          id, kind: 'skill', path: relative, sourceId: 'example', title: 'Filler',
          status: 'source-available-unreviewed', sourceSha256: createHash('sha256').update(Buffer.from(body)).digest('hex'),
        }] };

        const directory = path.join(workspaceRoot, 'skills');
        fs.mkdirSync(directory, { recursive: true });
        const installed = Array.from({ length: 512 }, (unused, index) => ({
          id: 'filler:skills/' + index + '/SKILL.md', sourcePath: 'upstream/filler/' + index + '/SKILL.md',
          installedAs: 'skills/filler-' + index + '.md', sha256: 'e'.repeat(64), sourceId: 'filler',
        }));
        fs.writeFileSync(path.join(directory, 'installed.json'), JSON.stringify({ version: 1, installed }) + '\n');

        return makeSkillStoreTools(inventory).find((tool) => tool.name === 'skills.install')
          .execute({ id }, { workspaceRoot, policy: { maxOutputBytes: 1048576, timeoutMs: 10000 } });
      },
      lesson: 'skills.install refuses SKILL_LIMIT once the installed lock holds as many skills as the bound permits, but only after the id has been resolved and its file verified against the recorded digest. So a full store reached with a bad id reports the id, not the limit: the checks run in order of what the operator most needs to hear. Re-installing something already present stays allowed at the limit, by the same reasoning that lets a full schedule store replace an entry.',
    },

    {
      family: 'skills', tool: 'skills.rank', expectCode: 'INVALID_SKILLS', workspace: 'temp',
      plan: { version: 1, name: 't', tasks: [{ id: 'a', tool: 'skills.rank', input: { query: 'greeting', skills: [
        { id: 'same', text: 'first entry' },
        { id: 'same', text: 'second entry under the same id' },
      ] } }] },
      lesson: 'skills.rank refuses INVALID_SKILLS when two entries share an id, because a ranking keyed by id cannot report two different texts under one name. Its schema requires both id and text on every entry and forbids unknown fields, so a malformed entry is refused as SCHEMA_MISMATCH at compile and never reaches the tool — a direct call to execute would crash instead, which is a fact about bypassing the engine rather than about the tool.',
    },
  ];
}
