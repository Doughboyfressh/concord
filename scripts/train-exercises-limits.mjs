import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { deflateSync } from 'node:zlib';
import { loadLanguage, decodeInstruction, decodeRange } from '../src/sleigh.mjs';
import { openSla } from '../src/ghidra.mjs';
import { recoverControlFlow } from '../src/control-flow.mjs';
import { analyseDataflow } from '../src/dataflow.mjs';
import { makeBuildTools } from '../src/build.mjs';
import { GHIDRA, REAL_FILES } from './train-exercises-ghidra.mjs';

/**
 * The bounds that live below the tool boundary.
 *
 * Four refusals here, and finding them settled something the frontier could not see on its own:
 * a reader tool and the analysis underneath it refuse differently on purpose. Ask
 * `artifact.controlFlow` for a region with too many basic blocks and it answers
 * `supported:false, reason:'flow_limit'`; call `recoverControlFlow` directly with the same bytes
 * and it raises FLOW_LIMIT. Both are correct. A reader exists to report what can and cannot be
 * said about a file, so "this region is larger than the analysis builds" is a finding about the
 * file and belongs in the answer; the analysis is a function with a contract, and a contract that
 * returned a sentinel would make the caller check for it. DATAFLOW_SLICE established the pattern
 * and cost a finding to learn; DATAFLOW_LIMIT, FLOW_LIMIT and SLEIGH_CONTEXT are three more of
 * the same shape, measured rather than predicted this time.
 *
 * So these are proven where they are raised, at the analysis layer, and the envelope the tool
 * converts them into is proven separately from a plan. Proving only one of the two would leave
 * either a code nobody can reach or a reason nobody can explain.
 *
 * The bytes are chosen for what they do to a control-flow walk rather than for what they compute:
 *
 *   0x74 0x00   `jz +0` - branches and falls through to the very next instruction, so every two
 *               bytes starts a new basic block. 2100 of them pass MAX_BLOCKS, and the
 *               instruction cap is 4096, so the block bound is genuinely the first one reached.
 *   0xff 0xc0   `inc eax` - falls through, so thousands of them are one long block that lifts to
 *               far more p-code than MAX_OPS tracks. The distinction matters: a region of
 *               returns would trip the block bound first and never reach the operation bound.
 *
 * One code resisted proof here too. WORKER_TRANSPORT needs a write to a live child's stdin to
 * fail, and it cannot be arranged: a child that exits is reported WORKER_PROTOCOL before any
 * write is attempted, and a child that destroys its own stdin leaves the parent's end of the pipe
 * writable, so the deadline reports WORKER_TIMEOUT instead. Both measured. It joins
 * FOREIGN_SPAWN_FAILED and BROWSER_PROCESS as a guard for a transport failure this platform will
 * not produce on demand - all three documented in their own source for the same reason.
 */

const TABLE = GHIDRA ? path.join(GHIDRA, REAL_FILES['x86-64.sla']) : null;
let language = null;
/** Loaded once and shared: the real table is 490 KB and every exercise here wants the same one. */
const realLanguage = () => (language ??= loadLanguage(fs.readFileSync(TABLE)));

const repeating = (pair, count) => Buffer.from(Array.from({ length: count * pair.length }, (unused, index) => pair[index % pair.length]));
const BRANCHES = repeating([0x74, 0x00], 2100);
const INCREMENTS = repeating([0xff, 0xc0], 4500);

/**
 * The real table, inflated, cut short, and compressed again.
 *
 * Nothing simpler reaches the guard worth proving. A truncated `.sla` file fails to inflate and is
 * refused by the header check with reason not_a_sla or inflate_failed - a different site, the same
 * code. Recompressing a prefix of the decompressed stream produces a file that inflates perfectly
 * and then runs out mid-element, which is the case the tree decoder exists to catch. One per cent
 * of four and a half megabytes is plenty and keeps the exercise cheap.
 */
const cutTable = () => {
  const real = fs.readFileSync(TABLE);
  const opened = openSla(real);
  return Buffer.concat([real.subarray(0, 4), deflateSync(opened.flat.subarray(0, Math.floor(opened.flat.length / 100)))]);
};

/** A build target whose declared input set is larger than the digest walk will read. */
const MANY = 'many-inputs';
const manyFixture = (dir) => {
  const root = path.join(dir, MANY);
  if (fs.existsSync(root) && fs.readdirSync(root).length > 4000) return;
  fs.mkdirSync(root, { recursive: true });
  for (let index = 0; index < 4100; index += 1) fs.writeFileSync(path.join(root, `f${index}.c`), 'int x;\n');
};

const manyTarget = () => makeBuildTools({
  targets: [{
    name: MANY, system: 'make', executable: process.execPath, args: ['-e', 'console.log("built")'],
    executableSha256: createHash('sha256').update(fs.readFileSync(process.execPath)).digest('hex'),
    inputs: [MANY], artifacts: [], diagnostics: 'none', timeoutMs: 20_000,
  }],
}).find((tool) => tool.name === 'build.run');

export function limitExercises() {
  return [
    {
      family: 'limits', tool: 'build.run', expectThrow: 'BUILD_INPUT_LIMIT', workspace: 'temp',
      fixture: manyFixture,
      call: ({ workspaceRoot }) => manyTarget().execute({ target: MANY },
        { workspaceRoot, policy: { timeoutMs: 20_000, maxOutputBytes: 1_048_576 } }),
      lesson: 'A build target declaring more than four thousand input files is refused BUILD_INPUT_LIMIT during the digest walk, before the compiler is spawned. The walk is what makes a build receipt mean anything - it is the record of exactly which bytes went in - so a path set too large to digest is a receipt that cannot be produced, and running anyway would hand back an artifact with no statement of what it was built from. The bound is on files rather than bytes because the cost being refused is the walk itself.',
    },
    ...(GHIDRA ? [
      {
        family: 'limits', tool: 'sleigh.loadLanguage', expectThrow: 'SLEIGH_TABLE',
        call: () => loadLanguage(cutTable()),
        lesson: 'A compiled table that inflates cleanly and then ends mid-element is refused SLEIGH_TABLE with details.at naming where it ended - truncated, overflowed, or invalid. Two sites raise this one code and the details are what tell them apart: the header check refuses a file that is not a .sla or will not inflate at all, and the tree decoder refuses a stream that decompressed fine and then stopped making sense. The second is the one worth a guard, because a partially decoded language would disassemble with a subset of the processor’s constructors and report instructions that are wrong rather than absent.',
      },
      {
        family: 'limits', tool: 'sleigh.decodeInstruction', expectThrow: 'SLEIGH_DECODE',
        // Fifteen 0x66 operand-size prefixes and then an instruction that still wants a
        // displacement: x86 lets a caller pad prefixes until the instruction cannot fit.
        call: () => decodeInstruction(realLanguage(),
          Buffer.from([...Array(15).fill(0x66), 0x0f, 0x1f, 0x84, 0x00, 0x11, 0x22, 0x33, 0x44]), { address: 0n }),
        lesson: 'An instruction that reads past sixteen bytes is refused SLEIGH_DECODE, because ParserContext::buf in Ghidra is sixteen bytes and throws past it - this reader refuses at the same boundary rather than reading further and producing an answer Ghidra itself could not. x86 makes the case reachable from input alone: prefixes can be repeated, so fifteen operand-size prefixes before an instruction that still wants a displacement runs off the end. Measured at the boundary too - a twelve-prefix sequence decoding to exactly sixteen bytes is accepted, so the guard sits where the window ends and not before it.',
      },
      {
        family: 'limits', tool: 'control-flow.recover', expectThrow: 'FLOW_LIMIT',
        call: () => recoverControlFlow(realLanguage(), BRANCHES, { address: 0n, limit: 4096 }),
        lesson: 'A region with more basic blocks than the analysis builds raises FLOW_LIMIT from recoverControlFlow, while artifact.controlFlow answers the same bytes with supported:false and a reason. The difference is deliberate and it is not an inconsistency: a reader reports what can be said about a file, so an unanalysable region is a finding about the file; the analysis is a function whose contract is a flow graph, and returning a sentinel instead would push the check onto every caller. The block bound is reached before the instruction cap because a branch that falls through to the next instruction starts a block every two bytes - which is also why a region of returns would never reach it.',
      },
      {
        family: 'limits', tool: 'dataflow.analyse', expectThrow: 'DATAFLOW_LIMIT',
        call: () => analyseDataflow(realLanguage(), INCREMENTS, { address: 0n, limit: 4096 }),
        lesson: 'A region lifting to more p-code operations than the analysis tracks raises DATAFLOW_LIMIT, counted as the operations are lifted rather than estimated from the instruction count. One machine instruction becomes several operations and the ratio is not fixed, so a bound on instructions would be a guess at the real cost: this counts the thing it is bounding. The tool above it converts the same refusal into reason:dataflow_limit, which is the third guard in this subsystem to work that way.',
      },
      {
        family: 'limits', tool: 'sleigh.decodeInstruction', expectThrow: 'SLEIGH_CONTEXT',
        call: () => decodeInstruction(realLanguage(), Buffer.from([0xc3]), { address: 0n, contextValues: { nosuchfield: 1 } }),
        lesson: 'A context field the language does not declare is refused SLEIGH_CONTEXT rather than ignored. Dropping it silently would decode in the wrong processor mode and return instructions that look entirely correct - the single most expensive kind of wrong answer a disassembler can give, because nothing downstream can tell. Measured at the layer that refuses: decodeRange catches the same failure and ends the range, and the tool above that reports one unresolved instruction, so the name of the mistake only exists here.',
      },
      {
        family: 'limits', tool: 'sleigh.decodeRange',
        call: () => {
          const decoded = decodeRange(realLanguage(), Buffer.from([0xc3, 0xc3, 0xc3]), { address: 0n, contextValues: { nosuchfield: 1 } });
          return { count: decoded.instructions.length, decoded: decoded.instructions.map((entry) => entry.decoded) };
        },
        expect: (r) => r.count === 1 && r.decoded[0] === false,
        lesson: 'decodeRange answers an undeclared context field with a single undecoded instruction and stops, rather than raising the SLEIGH_CONTEXT its own decoder raised. A range decoder cannot distinguish bytes it failed to decode from bytes that are not instructions - data in the middle of a function looks exactly the same - so ending the range is the only answer it can give honestly, and the count of one is how a caller sees that it ended early rather than finding nothing.',
      },
    ] : []),
  ];
}
