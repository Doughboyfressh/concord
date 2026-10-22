import fs from 'node:fs';
import path from 'node:path';
import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import { createSession, makeDecompilerTools, protocol } from '../src/decompiler.mjs';
import { GHIDRA, REAL_FILES } from './train-exercises-ghidra.mjs';

/**
 * The decompiler's eight refusals, and why none of them needs a decompiler.
 *
 * This block sat unproven longer than any other, on a judgement that turned out to be wrong in an
 * interesting way. The reasoning was: these are protocol failures, so proving them with a stub
 * would prove something about the stub. That is true of exactly one of the eight. The other seven
 * are not about decompiling at all:
 *
 *   DECOMPILE_EXITED      the child process is gone
 *   DECOMPILE_BUSY        a command is already outstanding on this session
 *   DECOMPILE_TIMEOUT     nothing came back before the deadline
 *   DECOMPILE_TRANSPORT   the write to its stdin failed
 *   DECOMPILE_PROTOCOL    bytes arrived that are not an element
 *   DECOMPILE_PATH        the configured executable cannot be resolved
 *   DECOMPILE_EXECUTABLE  it resolves, but it is not a regular file or its digest is wrong
 *
 * Every one of those is the session's own bookkeeping or the parser's own contract. In four of
 * them the child does nothing whatsoever - it is started and then sits there - which is precisely
 * the condition under test. `createSession` takes `spawn` as an argument for this reason: the
 * process is a parameter, not a secret, and supplying one that does nothing is using the seam as
 * designed rather than working around it.
 *
 * SETACTION is the one that needs a word from the other side, and it needs exactly one: the
 * decompiler answers `t` or `f`, and the guard fires on `f`. That single frame is written with the
 * module's own `stringFrame` and `burst`, so the bytes are the real protocol's bytes - a stub
 * decompiler would be a program that decompiles wrongly, and this is a response that says no.
 *
 * The two configuration refusals do need the real corpus, because the tool reads the target file
 * before it ever looks at the executable - so they are gated on the Ghidra install like the rest
 * of the real-corpus exercises, and they refuse a real binary with a fake decompiler rather than
 * the reverse.
 */

/** A process that starts and then does nothing, unless told to fail its own stdin. */
const inertChild = ({ writeThrows = false } = {}) => {
  const child = new EventEmitter();
  child.stdout = new PassThrough();
  child.stderr = new PassThrough();
  child.stdin = { write: writeThrows ? () => { throw new Error('the pipe is gone'); } : () => true };
  return child;
};

const sessionOn = (child, over = {}) => createSession({
  spawn: () => child, callbacks: { answer: () => protocol.answerNothing() }, timeoutMs: 5000, ...over,
});

/**
 * Hold the event loop open while an unref'd deadline runs.
 *
 * The session's timer is unref'd on purpose - a hung decompiler must not be able to keep the
 * process alive - so a test that only awaits the command exits before the deadline can fire. This
 * is the caller supplying the liveness the kernel deliberately does not.
 */
async function awaiting(work) {
  const hold = setInterval(() => {}, 25);
  try { return await work(); }
  finally { clearInterval(hold); }
}

const REAL_INPUT = {
  path: 'program.exe', table: 'x86-64.sla',
  processorSpec: 'x86-64.pspec', compilerSpec: 'x86-64-win.cspec', address: '0x14000a8bc',
};
const realFixture = (dir) => {
  for (const [name, relative] of Object.entries(REAL_FILES)) {
    const target = path.join(dir, name);
    if (!fs.existsSync(target)) fs.copyFileSync(path.join(GHIDRA, relative), target);
  }
  const impostor = path.join(dir, 'not-a-decompiler.txt');
  if (!fs.existsSync(impostor)) fs.writeFileSync(impostor, 'a regular file that is not the decompiler\n');
};

const decompileWith = (settings) => makeDecompilerTools({ timeoutMs: 5000, ...settings })
  .find((tool) => tool.name === 'artifact.decompile');

export function decompilerExercises() {
  return [
    {
      family: 'decompiler', tool: 'decompiler.decodePacked', expectThrow: 'DECOMPILE_PROTOCOL',
      call: () => protocol.decodePacked(Buffer.from([0x00, 0x01, 0x02, 0x03])),
      lesson: 'Bytes that do not begin an element are refused DECOMPILE_PROTOCOL rather than decoded as far as they go. The packed format is self-describing by header bits, so a stream that is misaligned by one byte decodes into a structure that is entirely wrong while looking entirely plausible - which is why the element close record is checked against the element that opened it too. An empty buffer is the same refusal, because a query with no body is a question this module failed to read rather than a question about nothing.',
    },
    {
      family: 'decompiler', tool: 'decompiler.session', expectThrow: 'DECOMPILE_EXITED',
      call: async () => {
        const child = inertChild();
        const session = sessionOn(child);
        child.emit('exit', 1);
        await new Promise((resolve) => setImmediate(resolve));
        return session.setAction({});
      },
      lesson: 'A command issued after the child has exited is refused DECOMPILE_EXITED immediately, carrying the exit code, instead of being written to a pipe with nothing on the other end. Exit code 1 with no message is the decompiler’s own segv handler, which calls _Exit(1) so the operating system shows no dialog - so the exit code is the only evidence that exists for the most common way this process dies, and the session reports it rather than reporting a timeout twenty seconds later.',
    },
    {
      family: 'decompiler', tool: 'decompiler.session', expectThrow: 'DECOMPILE_BUSY',
      call: async () => {
        const session = sessionOn(inertChild());
        // The first command is never answered, which is the point: it stays outstanding.
        const outstanding = session.setAction({});
        outstanding.catch(() => { /* settles later by its own deadline */ });
        return session.setAction({});
      },
      lesson: 'A second command while the first is still outstanding is refused DECOMPILE_BUSY. The protocol is strictly one command and one response over a single pair of pipes, with no request identifiers to match answers to questions, so two commands in flight would make the next response attributable to either - and a decompilation attributed to the wrong request is worse than a refused one. The session holds exactly one pending slot, which makes the constraint structural rather than advisory.',
    },
    {
      family: 'decompiler', tool: 'decompiler.session', expectThrow: 'DECOMPILE_TIMEOUT',
      call: () => awaiting(() => sessionOn(inertChild(), { timeoutMs: 150 }).setAction({})),
      lesson: 'A command that is never answered is refused DECOMPILE_TIMEOUT with the name of the command that hung. Measured along the way: the deadline timer is unref’d, so a hung decompiler cannot keep the process alive - which also means the deadline only fires while something else is still running, and a program whose only remaining work is this command exits rather than waiting. That is the right trade for a harness, and it is invisible until a test does nothing but wait.',
    },
    {
      family: 'decompiler', tool: 'decompiler.session', expectThrow: 'DECOMPILE_TRANSPORT',
      call: () => sessionOn(inertChild({ writeThrows: true })).setAction({}),
      lesson: 'A command whose write to the child’s stdin fails is refused DECOMPILE_TRANSPORT, and the pending slot is released rather than left occupied. The distinction from DECOMPILE_EXITED is worth keeping: exited means the session knows the process is gone and can say with what code, while transport means the write failed for a reason this side cannot name. Collapsing them would report a confident cause for an unexplained failure.',
    },
    {
      family: 'decompiler', tool: 'decompiler.session', expectThrow: 'DECOMPILE_SETACTION',
      call: () => awaiting(() => {
        const child = inertChild();
        const answered = sessionOn(child, { timeoutMs: 2000 }).setAction({ action: 'not-an-action', print: 'c' });
        // One string and a response terminator, written with the protocol's own frame writers:
        // 'f' is the whole of what the decompiler says when it refuses an action.
        setImmediate(() => {
          child.stdout.write(protocol.stringFrame('f'));
          child.stdout.write(protocol.burst(protocol.BURST.RESPONSE_END));
        });
        return answered;
      }),
      lesson: 'An action the decompiler refuses is reported DECOMPILE_SETACTION rather than treated as a no-op, and the refusal is one character: the answer is t or f. This matters more than its size suggests, because setAction is not optional and is silently so - DecompileAt::rawAction emits C only when the send-C flag is set and the current action is named decompile, neither of which holds by default, so a session that ignored a refused action would complete successfully and return an empty result.',
    },
    ...(GHIDRA ? [
      {
        family: 'decompiler', tool: 'artifact.decompile', expectThrow: 'DECOMPILE_PATH',
        workspace: 'temp', fixture: realFixture,
        call: ({ workspaceRoot }) => decompileWith({ executable: path.join(workspaceRoot, 'no-such-decompiler.exe') })
          .execute(REAL_INPUT, { workspaceRoot, policy: { timeoutMs: 5000, maxOutputBytes: 1_048_576 } }),
        lesson: 'A configured decompiler executable that cannot be resolved is refused DECOMPILE_PATH - after the target file has been read, which is the ordering a measurement established rather than a guess. The tool reads what it was asked about first and reaches for the process last, so a plan naming a file that is not there is told about the file and a plan on a machine with no decompiler is told about the decompiler, instead of one masking the other.',
      },
      {
        family: 'decompiler', tool: 'artifact.decompile', expectThrow: 'DECOMPILE_EXECUTABLE',
        workspace: 'temp', fixture: realFixture,
        call: ({ workspaceRoot }) => decompileWith({
          executable: path.join(workspaceRoot, 'not-a-decompiler.txt'), executableSha256: 'a'.repeat(64),
        }).execute(REAL_INPUT, { workspaceRoot, policy: { timeoutMs: 5000, maxOutputBytes: 1_048_576 } }),
        lesson: 'An executable that resolves but whose digest does not match the reviewed one is refused DECOMPILE_EXECUTABLE before it is spawned. The same code covers a path that is not a regular file and a path that resolves through an alias to somewhere else, and the digest is the part that makes the other two worth checking: a reviewed process identified only by where it lives is a reviewed process until something else is put there.',
      },
    ] : []),
  ];
}
