import { canonical } from '../src/value.mjs';
import { makeBuiltinTools } from '../src/builtins.mjs';

/**
 * The last three tools, all writes, and each one a different thing the grant has to survive.
 *
 * A write exercise is worth more than a read one here, because the approval gate sits in front of
 * the tool rather than inside it. That ordering is load-bearing and counter-intuitive: a write tool
 * asked to do something impossible still blocks first, so the refusal only arrives after the grant.
 * Round 022 learned that by predicting a refusal and getting a block; these keep it proven.
 *
 * memory.promote is the interesting one. Its candidateHash binds the lesson to its evidence, so the
 * exercises assert both directions: an untouched draft promotes, and the same hash carrying an
 * edited lesson is refused. Without the second, the hash would just be a field that travels along.
 */

/** The real candidate tool, used exactly as the harness itself uses it, never reimplemented. */
const candidate = makeBuiltinTools().find((tool) => tool.name === 'memory.candidate');

const draft = candidate.execute({
  lesson: 'A training exercise proved that memory.promote stores a lesson under the digest of its own content.',
  evidence: [{ exercise: 'memory.promote', family: 'memory', reproducible: true }],
});

/**
 * The exact budget at which memory.promote's OUTPUT_LIMIT is reachable, and the only one.
 *
 * Two checks sit on nearly the same bytes. The engine admits a task only if its resolved input
 * canonicalises to at most maxOutputBytes, and memory.promote then writes canonical(candidate)
 * plus a newline — one byte more than the input it was handed, because for this tool the candidate
 * *is* the input. So the write exceeds the budget only when the input exactly equals it: one byte
 * less and the engine refuses the input first, one byte more and the write fits.
 *
 * Computed rather than written down, so it stays on the boundary if the candidate shape ever
 * changes. A hardcoded number here would silently stop testing anything.
 */
const PROMOTE_DRAFT = candidate.execute({
  lesson: 'A lesson sized so that writing it costs exactly one byte more than the budget that admitted it.',
  evidence: [{ exercise: 'memory.promote', boundary: 'output-limit' }],
});
const PROMOTE_EXACT_BUDGET = Buffer.byteLength(canonical(PROMOTE_DRAFT));

export function writeExercises() {
  return [
    {
      family: 'memory', tool: 'memory.promote', expectCode: 'OUTPUT_LIMIT',
      grant: true, workspace: 'temp', maxOutputBytes: PROMOTE_EXACT_BUDGET,
      plan: { version: 1, name: 't', tasks: [{ id: 'a', tool: 'memory.promote', input: PROMOTE_DRAFT }] },
      lesson: 'memory.promote refuses OUTPUT_LIMIT when writing the candidate would exceed the output budget, and this is reachable at exactly one budget: the value equal to the canonicalised input. A byte below it the engine rejects the input as INPUT_LIMIT before the tool runs, and a byte above it the write fits, so the two bounds meet without leaving a gap where an oversized write could slip through. The same guard inside files.write cannot be reached from any plan at all, because there the input carries the content plus a wrapper of key names and so always trips the input bound strictly earlier.',
    },
    {
      family: 'memory', tool: 'memory.promote', grant: true, workspace: 'temp', expectApprovals: 1,
      plan: { version: 1, name: 't', tasks: [{ id: 'a', tool: 'memory.promote', input: draft }] },
      expect: (r) => r.results.a.promoted === true
        && r.results.a.candidateHash === draft.candidateHash
        && r.results.a.path === 'memory/' + draft.candidateHash + '.json',
      lesson: 'memory.promote is a write and takes a grant like any other, and it files a lesson under the digest of its own content. Promoting the same candidate twice writes the same bytes to the same path rather than a second copy, so a memory cannot accumulate duplicates of one lesson. It creates the memory directory when it is absent, so a fresh workspace needs no preparation.',
    },
    {
      family: 'memory', tool: 'memory.promote', expectCode: 'MEMORY_INVALID', grant: true, workspace: 'temp',
      plan: { version: 1, name: 't', tasks: [{ id: 'a', tool: 'memory.promote', input: { ...draft, lesson: 'An edited lesson travelling under the original hash.' } }] },
      lesson: 'memory.promote recomputes the candidate hash from the content it was handed and refuses MEMORY_INVALID when they disagree, so a lesson cannot be edited after the fact while keeping the identity of the evidence that earned it. The refusal arrives only after the write is granted, because the approval gate precedes the tool.',
    },
    {
      family: 'exchange', tool: 'peer.post', grant: true, expectApprovals: 1,
      plan: { version: 1, name: 't', tasks: [{ id: 'a', tool: 'peer.post', input: { message: 'Posted by a training exercise to prove the mailbox records a message and assigns it a sequence number. No reply is needed.', subject: 'training exercise', for: 'agent' } }] },
      expect: (r) => Number.isInteger(r.results.a.seq) && r.results.a.seq >= 1
        && typeof r.results.a.id === 'string' && r.results.a.for === 'agent'
        && r.results.a.replyTo === null,
      lesson: 'peer.post is how Concord reaches a reader it cannot call: it writes the message to a mailbox, assigns a monotonic sequence number, and records whether the message is addressed to an agent or to the operator. A post with no replyTo is an opening message rather than an answer, which is what lets peer.inbox tell an unanswered question from a settled one.',
    },
    {
      family: 'skills', tool: 'skills.remove', expectCode: 'SKILL_UNKNOWN', grant: true, workspace: 'temp',
      plan: { version: 1, name: 't', tasks: [{ id: 'a', tool: 'skills.remove', input: { id: 'nobody:such/skill.md' } }] },
      lesson: 'skills.remove refuses an id that is not in the installed lock with SKILL_UNKNOWN rather than reporting a vacuous success, and like every write it blocks for a grant before it can say so. Removing something that was never installed is a mistake worth hearing about, not a no-op to absorb quietly.',
    },
  ];
}
