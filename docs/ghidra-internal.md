# Taking Ghidra's capabilities internally

Ghidra is 876 MB across 5,219 files. The instruction was to internalize all of it, engine included,
and the honest result is a split, because the distribution is two different kinds of thing wearing
one name.

Most of what Ghidra knows about machines is **data**. Fifty-one `.ldefs` files name 189 languages
across 59 processor families; 86 `.pspec` files describe each processor's registers, entry points
and memory-mapped ranges; 105 `.cspec` files describe each compiler's calling conventions; 29
`.opinion` files map a binary's header fields onto a language; and 137 `.sla` files carry the
compiled decode tables. None of that is code. All of it is provable from bytes, so all of it is
read natively here, by eight tools in `src/ghidra.mjs`, with no dependency of any kind — and so is
the decoder that consumes it, in `src/sleigh.mjs`.

The rest is **an engine that needs a Java runtime**, and it cannot come inside. That is the part
worth being precise about, because it looks like it should be possible.

## Why the engine cannot be internalized, and what "zero dependency" would have cost

`analyzeHeadless` is a batch script that launches a JVM. The 202 shipped jars are 127.9 MB of Java.
Vendoring Ghidra into Concord would therefore not preserve the zero-dependency rule — it would
trade an npm dependency, which the kernel can at least pin and inspect, for a Java runtime it can
neither install nor verify. That is a strictly worse dependency, not an absent one.

`decompile.exe` looks like the way around this and is not. It is 2.5 MB of native code with no Java
in sight, but `ghidra_process.cc` shows it is a *slave* of the JVM host: it reads a burst-message
protocol on stdin and calls back to Ghidra for memory bytes, symbols and specifications. Using it
means implementing the host side of that protocol, which is more work than running headless and
yields the same dependency. `sleigh.exe` *is* standalone, but it is the specification compiler —
`.slaspec` to `.sla` — and all 137 `.sla` files already ship compiled.

So the engine is reached the way every other foreign engine is reached: as a reviewed provider
under the `process` effect, with a pinned executable digest and a fixed argv, which
`src/reverse.mjs` already compiles. What a provider cannot do is invent its own argv.

The one place the internalized data makes the gated engine better is language selection. Rather
than letting Ghidra guess an architecture, `artifact.ghidraLanguageMatch` resolves the binary's
header fields against the `.opinion` tables and passes `-processor` and `-cspec` explicitly. A
guessed architecture would make the same input produce different analyses on different days, which
the approval hash cannot describe; a resolved one is deterministic.

## What is read natively

| Tool | Reads | Answers |
| --- | --- | --- |
| `artifact.ghidraLanguages` | `.ldefs` | Which languages exist, their ids, and which `.sla`/`.pspec`/`.cspec` each needs |
| `artifact.ghidraProcessorSpec` | `.pspec` | Program counter, registers, entry-point vectors, volatile ranges, context fields |
| `artifact.ghidraCompilerSpec` | `.cspec` | Calling conventions in allocation order, data model, callee-saved and clobbered sets |
| `artifact.ghidraLoaderOpinion` | `.opinion` | The flattened header-field to language decision table |
| `artifact.ghidraLanguageMatch` | `.opinion` + `.ldefs` | Which installed language a machine type selects |
| `artifact.sleighSource` | `.slaspec`, `.sinc` | Declarations with their preprocessor guards intact |
| `artifact.sleighCompiled` | `.sla` | Endianness, alignment, address spaces, registers, userops, subtables, provenance |
| `artifact.compareSleighSource` | `.sla` + `.slaspec` | Whether a compiled table and a source file agree |
| `artifact.disassemble` | `.sla` + bytes | The instructions those bytes decode to, and with `pcode:true` what each one does |
| `artifact.controlFlow` | `.sla` + bytes | Basic blocks and their edges for one region, from the entry points given |
| `artifact.callGraph` | `.sla` + bytes | Every region a call can reach, and the graph of calls between them |
| `artifact.dataflow` | `.sla` + bytes | Which storage a region reads before writing, which it writes, and what each value derives from |

All twelve are `read` effects over bytes already inside the workspace. None spawns a process or
reaches the network, so none needs an approval.

### The `.sla` format

A compiled table is the four bytes `sla` plus a one-byte format version, then a single zlib stream.
Node inflates that with a built-in. Inside is Ghidra's `PackedFormat`: three record types
discriminated by the top two bits, seven attribute type codes, and seven bits of integer payload
per byte. The element and attribute id tables are not stored in the file, so a reader has to carry
them; they are transcribed from `slaformat.cc` and the encoding from `marshal.hh`.

Format version 4 is asserted rather than assumed. A version 5 file would still inflate and still
produce element ids, which is exactly why guessing is worse than refusing: the ids would be read
against the wrong table and every fact would be confidently wrong.

### Why SLEIGH source is not evaluated

A `.slaspec` does not state its own meaning. `define endian=$(ENDIAN);` is how the whole ARM family
declares endianness, and the value arrives from whichever thin variant file did the `@include`.
ARM's one source tree describes 22 languages.

So `artifact.sleighSource` reports every declaration together with the exact `@if` stack guarding
it, and never resolves a condition it was not given. A register block gated on `T_VARIANT` is
reported as gated. An endianness that is still a macro is reported as the macro it is. Reading the
file as though the preprocessor had run would attribute one variant's registers to all 22.

`artifact.compareSleighSource` therefore has three outcomes rather than two: agreement,
disagreement, and *unstated*. A source file that says `$(ENDIAN)` has not disagreed with the
compiled table — it has not spoken, and recording that as a mismatch would manufacture a finding
out of the preprocessor.

## What the corpus proved, and what it corrected

Every reader was run over every file of its type: 745 files, 0 failures, every declared output key
present on every path. The aggregate counts were then checked against counts measured without this
code, and the disagreements were the useful part.

Three of them said the reference was wrong. A grep finds 190 `<language>` elements, 176
`<prototype>` elements and 13,868 `<symbol>` elements; the readers find 189, 174 and 13,802,
because `CR16.ldefs`, two Atmel `.cspec` files and `m8c.pspec` each have one commented out. A
parser that agreed with the grep would have been wrong.

Four were real bugs, and each was a case of SLEIGH spending a character twice:

- **`;` is not only a statement terminator.** Inside a constructor it is the sequential-token
  operator, and inside `[ ... ]` it separates disassembly actions. Splitting on every `;` chopped
  constructors into fragments and glued the next declaration onto one, losing 4,843 of the corpus's
  7,082 `define pcodeop` declarations — everything except declarations with nothing before them.
- **`#` is not only a comment.** It is the immediate marker in 68000, ARM and MSP430 assembly, and
  appears quoted in display sections: `:addq.b "#"^quick,eab is ...`. Cutting at the first `#`
  truncated the line to `:addq.b "` and lost the constructor.
- **`{` is not only a semantic body.** ARM writes a register list as `"{"^reglist^"}"`, and `with`
  blocks group constructors under a shared pattern. Counting either as a body hid every constructor
  inside, which cost 4,915 constructors between them.
- **A dot is a legal identifier character** (`slghscan.l:514`), and Loongarch, the MIPS DSP
  extension and the RISC-V custom sets rely on it: `define pcodeop xvfmadd.s;`.

With those fixed, the reader's constructor count equals the independently measured 27,774 exactly,
per file as well as in total, and `define pcodeop` equals 7,044 against a comment-aware count of
the same. Across all 137 `.sla`/`.slaspec` pairs, `artifact.compareSleighSource` reports 78
agreements and **no disagreements**, which checks the binary decoder and the text reader against
each other rather than only against the corpus.

## Attribution

Ghidra is licensed under the Apache License 2.0. The specification files carry no per-file license
header and inherit the distribution `LICENSE`. `src/ghidra.mjs` transcribes the element and
attribute id tables from `Ghidra/Features/Decompiler/src/decompile/cpp/slaformat.cc` and the wire
encoding from `marshal.hh`, so it is a derivative work: preserve this attribution and the upstream
`NOTICE` when redistributing. The entry in `sources.lock.json` records the same, pinned to release
`ghidra_12.1.4_PUBLIC_20260921`.

## The decode engine

The specification corpus is half the story. The other half is the engine that turns bytes into
instructions, and that one *is* portable: `src/sleigh.mjs` is a SLEIGH decoder in Node with no
dependency of any kind, driven by the same 137 compiled tables the readers above decode.

The reason it is worth porting is the ratio. The decode and lift layer is roughly 12,000 lines of
Ghidra's C++ — `sleigh.cc`, `slghpattern.cc`, `context.cc`, `marshal.cc` — against ~157,000 for the
decompiler proper. And it is table-driven, so one engine plus the shipped tables is instruction
decode for 189 language variants across 59 processor families rather than 59 hand-written backends.

The algorithms are Ghidra's, because faithfulness is the whole requirement:

| Here | Ghidra |
| --- | --- |
| bit-indexed decision descent, linear scan at the leaf | `DecisionNode::resolve`, slghsymbol.cc:2344 |
| `(mask & data) == value`, 32 bits at a time | `PatternBlock::isInstructionMatch`, slghpattern.cc:464 |
| the iterative operand walk | `Sleigh::resolve`, sleigh.cc:609 |
| absolute offsets, relative lengths | `ParserWalkerChange::calcCurrentLength`, context.cc |
| big-endian read then byte-swap if little | `TokenField::getValue`, slghpatexpress.cc |

Two facts about the format shape everything else. The instruction buffer is filled with raw memory
bytes and never byte-swapped — `loadFill` does no swapping — so pattern matching always reads the
stream big-endian-wise and a language's endianness lives entirely in token field extraction. And
operand offsets are absolute from the start of the instruction while lengths are relative to their
constructor; conflating those is the standard way to get variable-length decode subtly wrong.

`artifact.disassemble` exposes it as a `read` effect over two workspace files, the table and the
bytes. It needs no approval and is a pure function of its input, so a recorded run replays. Each
line reports the constructors that matched, so a disassembly can be traced back to the SLEIGH that
produced it instead of being taken on trust, and addresses leave as hex strings because a 64-bit
address exceeds the safe integer range and `canonical` rejects a BigInt outright.

### Context is not in the table

The one input the compiled table does not carry is the initial context, and it is not optional.
x86 selects its operand size from the `opsize` and `addrsize` context fields, so a table decoded
with context left at zero reports `PUSH BP` where the 32-bit language means `PUSH EBP` — correct
for the bits it was given and wrong about the program. Those defaults are declared in the `.pspec`
`context_data` block, which `artifact.ghidraProcessorSpec` already reads, so the caller supplies
them by name and a name the language does not declare is refused rather than ignored.

### What the engine was checked against

Twenty-nine instruction encodings whose disassembly is known independently, across ten
architectures, all decoding correctly:

```
6502      ea -> NOP            a942 -> LDA #0x42       4c3412 -> JMP 0x1234
x86-32    55 -> PUSH EBP       89e5 -> MOV EBP,ESP     b878563412 -> MOV EAX,0x12345678
x86-64    4889e5 -> MOV RBP,RSP                        0f05 -> SYSCALL
ARM7      1eff2fe1 -> bx lr    010080e2 -> add r0,r0,#0x1
AARCH64   1f2003d5 -> nop      c0035fd6 -> ret
MIPS32    00000000 -> nop      03e00008 -> jr ra
PowerPC   4e800020 -> blr      60000000 -> ori r0,r0,0x0
JVM, 8051, Z80                 nop, RET, iadd
```

Two of those answers corrected the expectation rather than the code. PowerPC declares no `nop`
constructor anywhere in its module, so `ori r0,r0,0x0` is what the table really says; and ARM's
`ARMinstructions.sinc:2695` defines `:cpy^COND Rd,rm` for `E1A00000` under `VERSION_6`, which ARM7
defines, with a comment calling `cpy` a pre-UAL synonym for `mov`. Both times the engine was right
and the reference was wrong.

All 137 shipped tables also load and probe without a single failure or exception — 130,872
constructors, 15,139 subtables, 83,339 register varnodes and 24,794 userops, at 22 ms per table.
The constructor total equals the count the reader reports from element frequencies alone, which
checks the engine's symbol table walk against the reader's independent one.

## P-code lifting

Decode says what an instruction is called. Lifting says what it does, and that is where the value
is, because p-code is architecture-independent: one analysis written against ~70 operations works
on every one of the 189 variants.

`PcodeBuilder::build` walks a constructor's semantic template. A BUILD directive recurses into an
operand's own template, which is how a nested constructor's semantics are spliced in at the point
the parent asked for them. A varnode whose offset lives in another address space becomes an
explicit LOAD before the operation or a STORE after it, exactly as `SleighBuilder::dump` generates
them.

Lifting needs a second pass over the same parse, and that is structural rather than a convenience:
a varnode template can name another operand's handle — its space, its offset, its size, or its
offset adjusted by a truncation amount — and that handle is not known until the operand's own
constructor has been resolved. `Sleigh::resolveHandles` does the same pass for the same reason.

### The slot reuse that would have made the output nonsense

Five opcode values mean one thing in a compiled table and another in the decompiler's own IR.
`semantics.hh:26-30`:

```c
#define BUILD      CPUI_MULTIEQUAL   // 60
#define DELAY_SLOT CPUI_INDIRECT     // 61
#define MACROBUILD CPUI_CAST         // 64
#define LABELBUILD CPUI_PTRADD       // 65
#define CROSSBUILD CPUI_PTRSUB       // 66
```

So opcode 60 inside a `.sla` is "build this operand's p-code here", not a phi node. Taking the
names from the `OpCode` enum would emit MULTIEQUAL and INDIRECT operations that no instruction
performs — output that looks like p-code while describing nothing. The directives are consumed by
the builder and never appear in a result, which is asserted across every shipped table.

### Two things lifting reports rather than invents

A **delay slot** means the following instruction executes as part of this one. Decoding one range
cannot splice that in, so the directive is reported and the limitation says the p-code is not the
whole effect. A **constructor with no template** is not an instruction that does nothing — it is an
effect the table does not model, and the two are distinguished by an UNIMPLEMENTED directive.
Collapsing them would report a halt as a no-op.

### Checked against real instructions

```
6502    LDA #0x42   A = COPY 0x42 ; Z = INT_EQUAL A,0 ; N = INT_SLESS A,0
x86     PUSH EBP    tmp = COPY EBP ; ESP = INT_SUB ESP,4 ; STORE ram,ESP,tmp
x86     SUB ESP,16  CF/OF/SF/ZF, then PF via POPCOUNT — Ghidra's own x86 idiom
x86     RET         EIP = LOAD ram,ESP ; ESP = INT_ADD ESP,4 ; RETURN EIP
ARM     bx lr       INT_AND lr,1 ; CALLOTHER ; INT_AND lr,0xfffffffe ; RETURN
MIPS    jal 0x1000  ra = COPY 0x1004 ; CALL ram:0x1000   + DELAY_SLOT
```

The 6502 flag registers land at `0x30` and `0x35`, which is exactly where
`define register offset=0x30 [N V B D I Z C]` puts N and Z. The MIPS return address is `inst_next`,
computed after the length is known.

Across all 137 tables, sweeping the leading byte of every language: **27,886 instructions lifted,
183,419 p-code operations, 57 distinct opcodes, zero directives leaked into output**, and three
refusals — a Dalvik probe reading past Ghidra's own 16-byte instruction window, and two JVM switch
probes exceeding its 32-deep operand nesting. All three are the bounds Ghidra enforces, reported as
named refusals.

That sweep also found a real defect. A subtable operand that resolved to nothing used to leave the
decode running with the operand's minimum length, dropping it from the display while still
reporting a successful decode — an instruction missing an operand, presented as complete. Ghidra
raises `BadDataError` there, and so does this now: the instruction reports
`unresolved_subtable` rather than a confident partial answer. That one change took the exception
count from 4,137 to 3.

## Control flow

P-code is architecture-independent, and this is where that stops being a claim and starts being
leverage. `src/control-flow.mjs` reads only six operations — BRANCH, CBRANCH, BRANCHIND, CALL,
CALLIND and RETURN — so one implementation recovers basic blocks and a call graph for all 189
language variants. The file does not mention a single architecture.

The rules are Ghidra's, from `FlowInfo::processInstruction` in flow.cc:270-370, and three of them
are the opposite of a plausible guess:

- **A call is not a control-flow edge.** `flow.cc` sets `startbasic` for CBRANCH, BRANCH, BRANCHIND
  and RETURN only, so a call neither ends a basic block nor stops fallthrough. Treating it as a
  jump splits a block and loses the return after it.
- **A branch into the constant space is not an address.** It is a p-code-relative branch inside
  that one instruction — used for conditional execution and string operations — and reading it as
  an address invents a jump to a tiny number.
- **A delay slot belongs to its branch.** The following instruction executes before the branch
  takes effect, so it is attributed to the branch and flow resumes past it rather than treating it
  as the successor.

A fourth rule came out of writing it rather than reading it. A block that ends only because the
next instruction is a branch target — the join after a conditional — still has a fallthrough edge.
Deciding successors while partitioning instructions loses that edge, and the block then reads as
unreachable code rather than as the path into a join. Successors are therefore read off each
block's last instruction in a second pass.

Reachability is followed from entry points, not swept linearly, so an address that appears in the
result is one the analysis can explain. An indirect branch is reported as unresolved rather than
omitted, because reading a jump table needs the table — which Ghidra also defers to a separate pass
— and a missing edge looks like dead code.

### Checked against real code

```
x86    test/jz/mov/ret     3 blocks; the join block keeps its fallthrough into the return
x86    dec/jnz loop + call back edge 0x2006->0x2005; the call is a call edge, block runs on to RET
x86    jmp eax             1 block, kind indirect, reported unresolved, no invented edge
MIPS   beq + delay slot    block spans 8 bytes; the nop is the branch's, and 0x4008 is unreachable
ARM    sub/cmp/bne loop    back edge to 0x5000, fallthrough to the bx lr
```

`artifact.controlFlow` exposes it as a `read` effect. Its base address is validated inside
`execute` rather than by the input schema: the kernel's schema subset is explicit and
`validateSchema` refuses any keyword outside it, so a `pattern` constraint would make every plan
using the tool fail with `INVALID_SCHEMA` at compile time instead of producing a refusal that names
what was wrong.

## The call graph, across regions

One entry point grows into the whole reachable program. A **region** is all code reachable from one
entry *without* following a call — the only definition here that needs no guessing — and its call
targets become regions of their own.

The hard part is where a region stops, and it is worth saying plainly why this takes two passes.

A tail call, `jmp other_function`, is indistinguishable from an ordinary branch by looking at the
instruction. Ghidra does convert some jumps into calls, but that happens in its Java
function-boundary analysis, which is not shipped as source; the conversion in `flow.cc` applies
only to an *indirect* jump whose table could not be recovered. So there is no rule to port, and a
heuristic that silently reclassified a jump as a call would make this output a guess wearing the
shape of a fact.

What is available is evidence rather than heuristic: **an address that is called from somewhere is
a function entry.** So the first pass follows calls and collects every direct call target. The
second pass re-analyses each region treating those addresses as boundaries — flow reaching one is
recorded as leaving the region instead of traversed. A branch or a fallthrough into a called
address is then reported as a `tail` edge, explicitly marked `candidate`, because the structure
(flow leaves here, arrives at a known entry) is certain while the intent (tail call, or two
functions placed next to each other) is not.

Without that pass, one tail call swallows its callee into the caller and the graph comes back
nearly empty — the wrong answer in the shape of a plausible one.

Three smaller decisions follow the same principle of not overstating:

- **Two call sites to one callee are two edges.** The site is where a caller looks for the
  arguments, so collapsing them loses the thing being asked about.
- **Recursion is reachability, not self-edges.** Mutual recursion between two regions that never
  call themselves is still reported, which a self-edge test would miss entirely.
- **An indirect call creates no node.** The edge exists and its destination does not, so every
  graph here is a lower bound on what is reachable rather than a census. A call target outside the
  analysed range becomes an `external` node: the edge is real even though the callee was not read.

### Checked against constructed programs

```
three functions chained    3 regions, 2 edges, 1 leaf; callee counted as calledBy=2 for 2 sites
mutual recursion           both nodes RECURSIVE, and neither calls itself directly
tail call jmp 0x20         the jumping region stays 1 instruction; edge marked tail candidate
fallthrough into neighbour the same fact by fallthrough rather than branch, reported the same way
external + indirect        0x1000 becomes an external node; the indirect call creates none
```

## Dataflow

Which write supplies the value each read observes. This is what register-use recovery and taint
analysis are built on, and like the layers under it, it reads only p-code.

It is a classic forward fixpoint, **not** Ghidra's SSA. `heritage.cc` — 2,872 lines, and it is
shipped as source — builds static single assignment with phi nodes and does serious work on memory
aliasing. This computes reaching definitions and leaves a join as what it is: a read with more than
one reaching definition. That is weaker, and saying so is the point. A read with three reaching
definitions honestly describes a merge; inventing a phi node would imply an analysis nobody ran.

### The kill rule decides whether this is right or merely plausible

From `Varnode::contains` and `Varnode::characterizeOverlap` in varnode.cc:105-170:

> A definition kills a previous one **only if it fully covers it.** Storage that merely overlaps is
> left alive and reported as partially overwritten.

This is the classic register-dataflow bug. On x86, `mov al,1` must not kill EAX — three of EAX's
bytes still hold what they held. A kill rule based on "same space and overlapping" discards the
surviving definition and then reports the value as coming from the wrong place, confidently. The
toy language carries a one-byte write (`setlow`) purely so this rule is tested in the repository
and not only against the distribution: a kill rule based on overlap passes every other test.

### What is deliberately outside, and declared

- **The constant space is not storage.** varnode.cc returns "non-comparable" for it; a literal has
  no definition to reach.
- **Memory through a computed pointer is not resolved.** No LOAD is attributed to any STORE. Ghidra
  spends much of heritage.cc on exactly this, and claiming a resolution that was not performed
  would be the worst error available here. A slice therefore *ends* at a loaded value and says so.
- **Unique-space temporaries are instruction-local.** A language that needs them distinct across
  instructions declares a `uniqmask`; most declare none, so a unique definition is not followed
  past the instruction that made it.

### Checked against real x86

```
mov eax,0x2a ; ret            inputs: ESP          outputs: EAX, ESP, EIP
mov eax,[ebp+8] ; add ; ret   inputs: ESP, EBP     outputs: EAX, flags, EIP
mov al,1 ; inc eax ; ret      EAX stays an input, read shows partiallyOverwritten
conditional, then inc eax     INT_ADD reads EAX from 0x4004:0 and 0x400b:0  (both paths)
```

The last line is the fixpoint working: a value defined on two paths reaches its read as two
definitions. And the `__cdecl` cross-check agrees with `x86gcc.cspec` read independently — it
declares stack arguments and an EAX return; the analysis finds EBP/ESP frame access and EAX as an
output.

Two of my own errors were caught by that comparison rather than by a test. The summary merged
*adjacent* ranges, which glued ESP at `register:0x10` and EBP at `register:0x14` into one
eight-byte location nothing reads; only genuinely overlapping ranges collapse now. And a BRANCH's
first input is a destination *address*, not a value fetched from it, so counting it as a read
reported phantom `ram` inputs on regions that touch no memory.

## What this does not do

It does not decompile. Lifting p-code to C is the other ~157,000 lines of the decompiler, and
`ruleaction.cc` alone is 11,000 lines of accumulated simplification rules — institutional knowledge
rather than architecture, which cannot be shortened and does not degrade gracefully. A
half-implemented version produces confidently wrong C, which in a reverse-engineering tool is worse
than producing none. For decompiled C, run the gated provider.

It also does not follow `@include`. A fact declared in an included file is reported as unstated
rather than as a disagreement, and the includes are listed so a caller can follow them.
