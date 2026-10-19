# Evidence-led artifact investigation

For a requested binary or application investigation, adopt REA's target-first workflow. Identify the supplied artifact and the exact feature to explain, inspect available analysis capabilities, then select the appropriate native, managed, JavaScript, Electron, firmware, or browser evidence path. Use provider discovery only when it resolves a real requirement. Separate static observations, runtime observations, inference, and unresolved questions in the reply.

Trace a feature to concrete modules, symbols, resources, call relationships, or observed behavior before proposing a reconstruction. Preserve artifact identities and evidence references so a later reader can assess the conclusion. Report missing providers or unsupported targets directly. Registering these instructions does not install a decompiler, attach a debugger, launch an application, or grant access to a target. Do not run code extracted from an artifact. Every analysis process or runtime interaction must use an available registered tool and the kernel's authorization boundary.

Some of this is now internal rather than delegated. Artifact identification and structural layout, a typed WASM import/export interface and its comparison, and a static read of EVM bytecode are native tools here: they read bytes, they are deterministic, and they are replayable. Prefer them over describing an external capability, and state their declared limitations rather than implying completeness. A WASM or EVM reading that reports a partial state has not failed; an absence inside a partial result is not evidence that something is missing from the artifact, and a selector candidate recovered by scanning constants is not a confirmed interface.

The rest of the surface stays external, and not because it is unbuilt. A device, a debugger, a decompiler, a packer or a live browser cannot be read as a pure function of a declared input, so it cannot be replayed, and the catalog records that reason per tool. When a request needs one, say that it requires separately provisioned tooling and explicit authorization instead of proposing it as available. Catalogued REA tool names are indexed data describing another program; naming one grants nothing.

<!-- trained:begin -->
## Proven by training

Each line below came from a plan that ran through this kernel, behaved exactly as predicted,
and replayed. These are observations about behaviour, not permissions: nothing here grants
anything, and an unreviewed source stays unreviewed.

- `artifact.harCapture` — artifact.harCapture reports a capture structurally and copies no headers, cookies or bodies out of it: a HAR is full of credentials, so the reader withholds them by construction rather than by redaction.
- `artifact.inspect` — A file named .png whose bytes are a zip is reported as a zip: artifact.inspect reads content, so a wrong extension cannot mislead anything downstream of it.
- `artifact.inspect` — artifact.inspect binds every claim to a digest of the bytes it read, so a later statement about a file can be checked against the exact content that produced it.
- `artifact.inspect` — artifact.inspect identifies png from magic bytes alone, never from the file extension, and reports the SHA-256 of exactly the bytes it read.
- `artifact.inspect` — artifact.inspect identifies wasm from magic bytes alone, never from the file extension, and reports the SHA-256 of exactly the bytes it read.
- `artifact.inspect` — artifact.inspect identifies zip from magic bytes alone, never from the file extension, and reports the SHA-256 of exactly the bytes it read.
- `artifact.sourceMap` — artifact.sourceMap decodes VLQ mappings field by field rather than trusting a library: only generatedColumn resets per line, so a decoder resetting the others would report plausible wrong origins.
- `rea.catalog` — rea.catalog reports all 117 REA tools with the realization route of each, keeping visible the difference between a reader Concord wrote and a bounded call to an operator-reviewed binary.
<!-- trained:end -->
