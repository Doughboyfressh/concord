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
| `artifact.disassemble` | `.sla` + bytes | The instructions those bytes decode to under that language |

All nine are `read` effects over bytes already inside the workspace. None spawns a process or
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

## What this does not do

It does not decompile. Lifting p-code to C is the other ~157,000 lines of the decompiler, and
`ruleaction.cc` alone is 11,000 lines of accumulated simplification rules — institutional knowledge
rather than architecture, which cannot be shortened and does not degrade gracefully. A
half-implemented version produces confidently wrong C, which in a reverse-engineering tool is worse
than producing none. For decompiled C, run the gated provider.

It also does not follow `@include`. A fact declared in an included file is reported as unstated
rather than as a disagreement, and the includes are listed so a caller can follow them.
