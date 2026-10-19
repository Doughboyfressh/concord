# Capability training round

Exercises run: **235**. Lessons earned and promoted: **132**. Findings: **1**. Tools exercised: **79/79**. Wall clock: **3.5s**. Stored lessons now: **187**.

Of those exercises, **104** were generated from the tools' own declarations rather than written by hand, across **2** derived contracts, **2** of which held for every tool they apply to. A generated check cannot discover that a declaration is wrong, only that a tool and its declaration disagree, so each contract earns one lesson rather than one per tool.

Instruction modules deepened: **0** (none). Skill corpus verified against its index: **1330** files match, **0** drifted, **98** not in this workspace.

Every lesson below came from a plan that ran through the real kernel, behaved exactly as predicted, and then replayed. A prediction that did not hold wrote nothing to memory and is listed as a finding instead: a surprise is something to investigate, not something to memorise.

## Earned

| Family | Tool | Lesson |
| --- | --- | --- |
| readers | `artifact.androidManifest` | artifact.androidManifest answers a file that is not its format with supported:false and a stated reason, never by throwing, and still reports the SHA-256 of exactly the bytes it examined alongside the path it was given. It returns every key it declares even when it could parse nothing, so a caller never branches on whether a key is present, and it marks the result untrusted because bytes from a file are evidence about that file and nothing more. |
| readers | `artifact.apk` | artifact.apk answers a file that is not its format with supported:false and a stated reason, never by throwing, and still reports the SHA-256 of exactly the bytes it examined alongside the path it was given. It returns every key it declares even when it could parse nothing, so a caller never branches on whether a key is present, and it marks the result untrusted because bytes from a file are evidence about that file and nothing more. |
| readers | `artifact.coreDump` | artifact.coreDump answers a file that is not its format with supported:false and a stated reason, never by throwing, and still reports the SHA-256 of exactly the bytes it examined alongside the path it was given. It returns every key it declares even when it could parse nothing, so a caller never branches on whether a key is present, and it marks the result untrusted because bytes from a file are evidence about that file and nothing more. |
| readers | `artifact.dartSnapshot` | artifact.dartSnapshot answers a file that is not its format with supported:false and a stated reason, never by throwing, and still reports the SHA-256 of exactly the bytes it examined alongside the path it was given. It returns every key it declares even when it could parse nothing, so a caller never branches on whether a key is present, and it marks the result untrusted because bytes from a file are evidence about that file and nothing more. |
| readers | `artifact.dex` | artifact.dex answers a file that is not its format with supported:false and a stated reason, never by throwing, and still reports the SHA-256 of exactly the bytes it examined alongside the path it was given. It returns every key it declares even when it could parse nothing, so a caller never branches on whether a key is present, and it marks the result untrusted because bytes from a file are evidence about that file and nothing more. |
| readers | `artifact.dexGraph` | artifact.dexGraph answers a file that is not its format with supported:false and a stated reason, never by throwing, and still reports the SHA-256 of exactly the bytes it examined alongside the path it was given. It returns every key it declares even when it could parse nothing, so a caller never branches on whether a key is present, and it marks the result untrusted because bytes from a file are evidence about that file and nothing more. |
| readers | `artifact.electronFuses` | artifact.electronFuses answers a file that is not its format with supported:false and a stated reason, never by throwing, and still reports the SHA-256 of exactly the bytes it examined alongside the path it was given. It returns every key it declares even when it could parse nothing, so a caller never branches on whether a key is present, and it marks the result untrusted because bytes from a file are evidence about that file and nothing more. |
| readers | `artifact.flutterBuild` | artifact.flutterBuild answers a file that is not its format with supported:false and a stated reason, never by throwing, and still reports the SHA-256 of exactly the bytes it examined alongside the path it was given. It returns every key it declares even when it could parse nothing, so a caller never branches on whether a key is present, and it marks the result untrusted because bytes from a file are evidence about that file and nothing more. |
| readers | `artifact.goBuildInfo` | artifact.goBuildInfo answers a file that is not its format with supported:false and a stated reason, never by throwing, and still reports the SHA-256 of exactly the bytes it examined alongside the path it was given. It returns every key it declares even when it could parse nothing, so a caller never branches on whether a key is present, and it marks the result untrusted because bytes from a file are evidence about that file and nothing more. |
| readers | `artifact.harmonyGraph` | artifact.harmonyGraph answers a file that is not its format with supported:false and a stated reason, never by throwing, and still reports the SHA-256 of exactly the bytes it examined alongside the path it was given. It returns every key it declares even when it could parse nothing, so a caller never branches on whether a key is present, and it marks the result untrusted because bytes from a file are evidence about that file and nothing more. |
| readers | `artifact.managed` | artifact.managed answers a file that is not its format with supported:false and a stated reason, never by throwing, and still reports the SHA-256 of exactly the bytes it examined alongside the path it was given. It returns every key it declares even when it could parse nothing, so a caller never branches on whether a key is present, and it marks the result untrusted because bytes from a file are evidence about that file and nothing more. |
| readers | `artifact.managedGraph` | artifact.managedGraph answers a file that is not its format with supported:false and a stated reason, never by throwing, and still reports the SHA-256 of exactly the bytes it examined alongside the path it was given. It returns every key it declares even when it could parse nothing, so a caller never branches on whether a key is present, and it marks the result untrusted because bytes from a file are evidence about that file and nothing more. |
| readers | `artifact.managedMembers` | artifact.managedMembers answers a file that is not its format with supported:false and a stated reason, never by throwing, and still reports the SHA-256 of exactly the bytes it examined alongside the path it was given. It returns every key it declares even when it could parse nothing, so a caller never branches on whether a key is present, and it marks the result untrusted because bytes from a file are evidence about that file and nothing more. |
| readers | `artifact.managedNativeBoundaries` | artifact.managedNativeBoundaries answers a file that is not its format with supported:false and a stated reason, never by throwing, and still reports the SHA-256 of exactly the bytes it examined alongside the path it was given. It returns every key it declares even when it could parse nothing, so a caller never branches on whether a key is present, and it marks the result untrusted because bytes from a file are evidence about that file and nothing more. |
| readers | `artifact.packetFields` | artifact.packetFields answers a file that is not its format with supported:false and a stated reason, never by throwing, and still reports the SHA-256 of exactly the bytes it examined alongside the path it was given. It returns every key it declares even when it could parse nothing, so a caller never branches on whether a key is present, and it marks the result untrusted because bytes from a file are evidence about that file and nothing more. |
| readers | `artifact.pcap` | artifact.pcap answers a file that is not its format with supported:false and a stated reason, never by throwing, and still reports the SHA-256 of exactly the bytes it examined alongside the path it was given. It returns every key it declares even when it could parse nothing, so a caller never branches on whether a key is present, and it marks the result untrusted because bytes from a file are evidence about that file and nothing more. |
| readers | `artifact.peResources` | artifact.peResources answers a file that is not its format with supported:false and a stated reason, never by throwing, and still reports the SHA-256 of exactly the bytes it examined alongside the path it was given. It returns every key it declares even when it could parse nothing, so a caller never branches on whether a key is present, and it marks the result untrusted because bytes from a file are evidence about that file and nothing more. |
| readers | `artifact.plist` | artifact.plist answers a file that is not its format with supported:false and a stated reason, never by throwing, and still reports the SHA-256 of exactly the bytes it examined alongside the path it was given. It returns every key it declares even when it could parse nothing, so a caller never branches on whether a key is present, and it marks the result untrusted because bytes from a file are evidence about that file and nothing more. |
| readers | `artifact.recoverSources` | artifact.recoverSources answers a file that is not its format with supported:false and a stated reason, never by throwing, and still reports the SHA-256 of exactly the bytes it examined alongside the path it was given. It returns every key it declares even when it could parse nothing, so a caller never branches on whether a key is present, and it marks the result untrusted because bytes from a file are evidence about that file and nothing more. |
| readers | `artifact.rustBinary` | artifact.rustBinary answers a file that is not its format with supported:false and a stated reason, never by throwing, and still reports the SHA-256 of exactly the bytes it examined alongside the path it was given. It returns every key it declares even when it could parse nothing, so a caller never branches on whether a key is present, and it marks the result untrusted because bytes from a file are evidence about that file and nothing more. |
| readers | `artifact.sqlite` | artifact.sqlite answers a file that is not its format with supported:false and a stated reason, never by throwing, and still reports the SHA-256 of exactly the bytes it examined alongside the path it was given. It returns every key it declares even when it could parse nothing, so a caller never branches on whether a key is present, and it marks the result untrusted because bytes from a file are evidence about that file and nothing more. |
| readers | `artifact.dexClass` | artifact.dexClass takes an argument beyond the path, and still refuses a file that is not its format with supported:false, a reason, and its full declared output shape. The extra argument narrows what is being asked; it never loosens what is accepted. |
| readers | `artifact.dexMethod` | artifact.dexMethod takes an argument beyond the path, and still refuses a file that is not its format with supported:false, a reason, and its full declared output shape. The extra argument narrows what is being asked; it never loosens what is accepted. |
| readers | `artifact.dexReferences` | artifact.dexReferences takes an argument beyond the path, and still refuses a file that is not its format with supported:false, a reason, and its full declared output shape. The extra argument narrows what is being asked; it never loosens what is accepted. |
| readers | `artifact.dexSearch` | artifact.dexSearch takes an argument beyond the path, and still refuses a file that is not its format with supported:false, a reason, and its full declared output shape. The extra argument narrows what is being asked; it never loosens what is accepted. |
| readers | `artifact.sourceLocation` | artifact.sourceLocation takes an argument beyond the path, and still refuses a file that is not its format with supported:false, a reason, and its full declared output shape. The extra argument narrows what is being asked; it never loosens what is accepted. |
| readers | `artifact.jsExports` | artifact.jsExports is a lexical scan, so supported:true means only that the text could be scanned and never that the file is what you hoped. It blanks comments, strings, template literals and regular expressions first while preserving every byte offset, so a match cannot fire on a keyword inside a comment and a reported position still refers to the real file. |
| readers | `artifact.moduleImports` | artifact.moduleImports is a lexical scan, so supported:true means only that the text could be scanned and never that the file is what you hoped. It blanks comments, strings, template literals and regular expressions first while preserving every byte offset, so a match cannot fire on a keyword inside a comment and a reported position still refers to the real file. |
| readers | `artifact.htmlScripts` | artifact.htmlScripts is a lexical scan, so supported:true means only that the text could be scanned and never that the file is what you hoped. It blanks comments, strings, template literals and regular expressions first while preserving every byte offset, so a match cannot fire on a keyword inside a comment and a reported position still refers to the real file. |
| readers | `artifact.jsSemantics` | artifact.jsSemantics reports constructs it recognised by scanning and says plainly that it is a scan rather than a parse: it describes what the text contains, not what the program does when it runs. |
| readers | `artifact.webBundle` | artifact.webBundle looks for bundler markers in text and reports which it saw. A marker is evidence that a bundler touched the file, not proof of which one or of what it did. |
| readers | `artifact.firmware` | artifact.firmware scans for known magics and reports what it found and where. Some signatures are only meaningful at a fixed offset, so an anchored magic appearing elsewhere is deliberately not treated as a hit. |
| readers | `artifact.wasmInterface` | artifact.wasmInterface reads a module header and its section table directly rather than instantiating anything, so a module is described without ever being run. It reports its own state, because a module it could only partly decode must not read as one it decoded fully. |
| readers | `artifact.evmInterface` | artifact.evmInterface digests the carrier file and the decoded bytecode separately, and the two digests genuinely differ for hex input: the same contract delivered as hex text and as raw bytes is one bytecode in two different files, and only the bytecode digest identifies the contract. |
| readers | `artifact.firmwareRegion` | artifact.firmwareRegion reads a declared window of a file rather than the whole of it, and echoes back the offset and length it actually read, so an unknown blob can be examined in bounded pieces without ever loading it entirely. |
| readers | `artifact.jsApplication` | artifact.jsApplication walks a module graph from a single entry and resolves the files it reaches, reporting resolved modules, external packages and unresolved specifiers as separate lists, so a dependency it could not find is never quietly counted as one that was not there. |
| evidence | `judgment.gate` | judgment.gate refuses with JUDGMENT_REJECTED when the score is below the declared threshold, rather than returning accepted:false for a caller to overlook. A gate that answered softly would let a failing score pass through as a value someone forgot to check. |
| evidence | `experiment.compare` | experiment.compare confirms a single condition and warns SINGLE_CONDITION in the same breath: the comparison passed, and one condition still cannot isolate a cause. The warning rides along with a successful result rather than replacing it, because the finding is real and the inference from it is not. |
| evidence | `experiment.compare` | experiment.compare warns UNVARIED_CONDITIONS when two conditions vary nothing between them, naming them, because that is one data point recorded twice rather than two. Both still confirm, so the count of passes is exactly the misleading number the warning exists to qualify. |
| evidence | `experiment.compare` | experiment.compare sets discriminating:false when every condition declares the same expectation, because such a test reads identically whether or not the varied factor mattered. It is the one warning that also flips a top-level field, so a caller checking a single boolean still cannot miss that the experiment could not have failed. |
| evidence | `artifact.analysisView` | artifact.analysisView checks a record set against itself and names each problem separately: one id reused for two different digests, a record carrying no digest, and a reference to something the view never contained. It says outright that a pure tool reaches nothing, so it can prove internal consistency and never authenticity. |
| readers | `artifact.appleGraph` | artifact.appleGraph refuses a file that declares no plist element with supported:false and a reason, and returns a null bundle with an empty edge list rather than a half-built graph. A partial graph that looked real would be worse than no graph. |
| evidence | `artifact.compareApplicationVersions` | artifact.compareApplicationVersions keys entries by kind and name and, with a digest on both sides, separates added, removed, changed and unchanged. An entry with no declared kind is keyed as unspecified rather than silently matched against a differently-kinded one. |
| evidence | `artifact.compareApplicationVersions` | artifact.compareApplicationVersions reports present-both, not unchanged, when only one side carries a digest: both versions declare the entry but a change cannot be decided. Calling that unchanged would turn a missing digest into a false claim of equality. |
| evidence | `artifact.compareHar` | artifact.compareHar consumes the flat entries artifact.harCapture emits and keys a request by method, origin and path only. Query strings, timing and bodies are deliberately outside the key, so two calls differing only in a query parameter compare as the same request. |
| evidence | `artifact.compareJsExports` | artifact.compareJsExports keys an export by name and kind together, so the same name re-exported as a different kind reads as one removal plus one addition rather than a change. It states that a different value or signature behind an unchanged name is invisible to it. |
| evidence | `artifact.compareManagedMembers` | artifact.compareManagedMembers keys a member by declaring type, name and kind, and reports an attribute change as changed while showing both attribute lists. Signatures are not part of the key, so an overload set collapses to one member. |
| evidence | `artifact.compareSourceToBundle` | artifact.compareSourceToBundle separates present, absent and bundle-only, and attaches to every absence the reason that a minifier renaming the export would look identical. Absence of an export from a bundle is therefore never reported as evidence that it was removed. |
| evidence | `artifact.compareWasmInterfaces` | artifact.compareWasmInterfaces reports unknown rather than unchanged when a signature on either side was never decoded, and when one interface is partial it says plainly that an absence there is not evidence of removal. Equality is only ever concluded from two complete readings. |
| evidence | `artifact.importManagedReconstruction` | artifact.importManagedReconstruction accepts a reconstructed member only where the observed artifact declares one with the same name and kind, so a member nobody observed is rejected and a member reconstructed under the wrong kind is rejected too. Coverage counts names, and the tool says outright that it is no statement about behavioural correctness. |
| evidence | `artifact.obligationLedger` | artifact.obligationLedger closes an obligation only for a passing verifier with replay authority that cited evidence. A passing verifier whose authority is merely inferred leaves it open, a failing verifier leaves it open, and a static fact with nothing to verify it raises a candidate rather than a conclusion. |
| evidence | `artifact.reconstructionCoverage` | artifact.reconstructionCoverage reports covered only when every obligation scoped to the named boundary is closed and backed by a replay observation, and it scopes strictly: an obligation belonging to another boundary is not counted either for or against this one. |
| evidence | `artifact.reconstructionCoverage` | artifact.reconstructionCoverage answers unknown, never covered, for an obligation closed on an inferred observation, and names the probe that would settle it: replace the inference with a replay observation. An inferred observation can never promote coverage, which is what keeps a chain of plausible reasoning from being mistaken for evidence. |
| evidence | `artifact.reconstructionCoverage` | artifact.reconstructionCoverage distinguishes an obligation closed on weak evidence from one closed on evidence nobody supplied: both are unknown rather than covered, but each names its own probe, so the reason coverage failed is never guesswork. |
| evidence | `artifact.traceFeature` | artifact.traceFeature matches a feature term against names and source paths in a supplied inventory, case-insensitively, and reports each match as a candidate to look at. It states that it is not a dataflow or call trace: a match never establishes that an entry implements the feature, and an absence means only that the inventory does not mention the term. |
| evidence | `artifact.verifyManagedNativeBoundaries` | artifact.verifyManagedNativeBoundaries checks each boundary against a list of available module names, so satisfied means the module was present and explicitly not that the named export exists inside it. A boundary naming no module at all is unknown rather than missing, because there was nothing to check it against. |
| memory | `memory.promote` | memory.promote refuses OUTPUT_LIMIT when writing the candidate would exceed the output budget, and this is reachable at exactly one budget: the value equal to the canonicalised input. A byte below it the engine rejects the input as INPUT_LIMIT before the tool runs, and a byte above it the write fits, so the two bounds meet without leaving a gap where an oversized write could slip through. The same guard inside files.write cannot be reached from any plan at all, because there the input carries the content plus a wrapper of key names and so always trips the input bound strictly earlier. |
| memory | `memory.promote` | memory.promote is a write and takes a grant like any other, and it files a lesson under the digest of its own content. Promoting the same candidate twice writes the same bytes to the same path rather than a second copy, so a memory cannot accumulate duplicates of one lesson. It creates the memory directory when it is absent, so a fresh workspace needs no preparation. |
| memory | `memory.promote` | memory.promote recomputes the candidate hash from the content it was handed and refuses MEMORY_INVALID when they disagree, so a lesson cannot be edited after the fact while keeping the identity of the evidence that earned it. The refusal arrives only after the write is granted, because the approval gate precedes the tool. |
| exchange | `peer.post` | peer.post is how Concord reaches a reader it cannot call: it writes the message to a mailbox, assigns a monotonic sequence number, and records whether the message is addressed to an agent or to the operator. A post with no replyTo is an opening message rather than an answer, which is what lets peer.inbox tell an unanswered question from a settled one. |
| skills | `skills.remove` | skills.remove refuses an id that is not in the installed lock with SKILL_UNKNOWN rather than reporting a vacuous success, and like every write it blocks for a grant before it can say so. Removing something that was never installed is a mistake worth hearing about, not a no-op to absorb quietly. |
| composition | `artifact.compareJsExports` | Two artifact.jsExports scans feed artifact.compareJsExports through /exports pointers in one plan, so the comparison is computed from bytes this run actually read rather than from a summary someone typed in. A JSON pointer selects part of an upstream output, which is what lets a tool expecting a narrow shape consume a tool that returns a wide one. |
| composition | `json.value` | A reference with no path resolves to the whole upstream output, so a task can take another task entire. The resolved value is a clone: a downstream task cannot reach back and mutate the output a receipt was already written for. |
| composition | `memory.promote` | memory.candidate derives a lesson and memory.promote commits it inside one plan, the whole candidate passed by a single reference. This is the self-improvement primitive, and it is still gated: the write blocks for an approval whose hash binds the resolved candidate, so granting it approves the lesson that was actually derived rather than a plan that promised to derive one. |
| composition | `files.read` | A pure result can be written and read back within one plan, and the file that comes back is still marked untrusted with its own digest reported. Content this run computed itself is given no more standing than content found on disk, because the tool that reads a file cannot know who wrote it. |
| composition | `json.value` | A reference written as a quoted string is refused with INVALID_REFERENCE rather than passed through as text, and the message says to place the object unquoted as the value. Silently treating it as a literal string is the failure mode this guard exists to prevent: the plan would run, do the wrong thing, and look successful. |
| composition | `json.value` | A reference to a task that dependsOn does not declare is refused with INVALID_REFERENCE even though the task exists and would have run first. The edge has to be declared, so the dependency graph can be read off the plan without executing it, and an ordering that only happened to work is never mistaken for one that was stated. |
| composition | `json.value` | A path that is not an RFC 6901 JSON pointer is refused with INVALID_REFERENCE while compiling: a bare key like "digest" is rejected where "/digest" is accepted. Guessing that a bare key meant a top-level one would make the pointer syntax ambiguous exactly where it has to be exact. |
| composition | `json.hash` | A task declaring itself as its own dependency is refused with INVALID_PLAN at compile time, so a cycle is caught by reading the plan rather than by hanging while running it. |
| composition | `json.value` | The same dependency declared twice is refused with INVALID_PLAN rather than quietly deduplicated. A duplicated edge means the plan was assembled by something that lost track of what it had already written, and accepting it would hide that. |
| composition | `json.value` | A well-formed pointer into a key the upstream output does not have fails the task with INPUT_INVALID and the reason that the reference path does not exist. It cannot be caught while compiling, because only the output can say which keys it has; so the plan is legal and the task is the thing that fails. |
| composition | `json.value` | A pointer naming __proto__, prototype or constructor is refused as an unsafe reference key rather than resolved. A pointer is attacker-reachable input in a plan Concord did not write, and without this a reference would be a route to the prototype chain; it shares INPUT_INVALID with a merely absent key, so only the reason distinguishes a typo from an attempt. |
| kernel | `engine.compile` | A plan naming a tool the registry does not hold is refused UNKNOWN_TOOL while compiling, before any task runs. The registry is the whole of what exists, so an unknown name is a defect in the plan rather than a capability to be looked for elsewhere. |
| kernel | `engine.compile` | A task whose effect is outside allowedEffects is refused POLICY_DENIED at compile time, not blocked for an approval. This is the distinction the whole authority model turns on: a write that is merely ungranted can be approved, while a write the policy does not permit at all can never be, so it must fail before it becomes something a person could be asked to allow. |
| kernel | `engine.compile` | A tool absent from allowedTools is refused POLICY_DENIED even when it is registered and even when its effect is pure. Being harmless is not the same as being permitted, and a policy that let pure tools through unlisted would not be an allow list at all. |
| kernel | `engine.attenuatePolicy` | attenuatePolicy refuses a numeric bound raised by even one, so narrowing is checked field by field rather than judged overall. A policy that was stricter about effects and looser about task count would otherwise pass as an attenuation of the one it came from. |
| kernel | `engine.runPlan` | An approvals list holding anything that is not a SHA-256 request hash is refused INVALID_APPROVAL before the plan runs. An approval is only meaningful as an exact hash, so a malformed entry is rejected rather than ignored — ignoring it would let a caller submit noise and have the run proceed as though nothing had been asked for. |
| kernel | `engine.runPlan` | The same request hash listed twice is refused INVALID_APPROVAL: approvals must be unique. One grant authorises one request, so a duplicate is either a mistake or an attempt to make a single approval count more than once. |
| kernel | `engine.runPlan` | A workspace root that is not absolute is refused INVALID_WORKSPACE. Every path a tool accepts is resolved against this root, so a relative root would make the workspace boundary depend on the current directory of whatever process happened to start the run. |
| kernel | `engine.replayPlan` | Editing a recorded output breaks replay with REPLAY_CHAIN, not with a mismatched-output error: every event carries the hash of the one before it, so changing any payload invalidates the chain from that point on. The chain is what makes the journal evidence — a receipt that could be edited afterwards would only be a claim about what happened. |
| kernel | `engine.replayPlan` | Duplicating an event breaks replay with REPLAY_CHAIN as well, because each event commits to its own sequence number as well as to its predecessor. Inserting or reordering is caught by the same check that catches editing, so there is one guarantee to reason about rather than three. |
| kernel | `engine.replayPlan` | An untouched journal replayed against a different workspace root is refused REPLAY_CONTEXT. The header commits to the plan, the policy, the source lock, the tool registry and the workspace together, so a run is only reproducible in the setting it actually happened in; verifying it somewhere else would be answering a different question. |
| kernel | `engine.replayPlan` | Replacing the journal root while leaving every event intact is refused REPLAY_ROOT: the root must equal the hash the event chain actually ends on. The chain proves the events agree with each other and the root is the single value committing to all of them, so both are checked rather than one standing in for the other. |
| kernel | `value.canonical` | canonical refuses INVALID_JSON for a key holding undefined, because undefined is outside the JSON domain and has no canonical form. This is the refusal that turns an overlooked optional field into a visible failure: JSON.stringify would silently drop the key and the value would travel on as though it had never been there. |
| kernel | `value.canonical` | canonical refuses a function for the same reason it refuses undefined: the domain is data that can be hashed and replayed, and anything that cannot be written down cannot be committed to by a receipt. |
| kernel | `value.parseJson` | parseJson raises INVALID_JSON rather than returning null or undefined for malformed text, so a configuration file that was corrupted on disk fails where it is read instead of becoming an empty object several layers further in. |
| kernel | `value.validateSchema` | validateSchema separates a bad schema from bad data: an unrecognised type raises INVALID_SCHEMA, not a validation failure about the value. A schema nobody can evaluate would otherwise read as a value that failed to satisfy it, which is the error report most likely to send someone looking in the wrong place. |
| kernel | `capabilities.factory` | makeCapabilityTools refuses INVALID_CAPABILITIES rather than building a registry over an inventory it cannot read. Configuration is checked when the registry is assembled, not when a tool is first called, so a malformed lock file fails at startup instead of halfway through somebody using it. |
| kernel | `reverse.factory` | makeReverseTools refuses REVERSE_TABLE_INVALID for a malformed tool table. The table decides which external commands exist at all, so accepting a shape it could only partly understand would mean a registry whose contents nobody had reviewed. |
| kernel | `foreign.factory` | makeForeignTools refuses FOREIGN_MANIFEST_INVALID for a manifest whose schema version is not a number, before any foreign server is contacted. A manifest describes executables that will run on this machine, so it is validated at build time where a person can still read the error. |
| kernel | `peer.factory` | makeMailboxTools refuses PEER_CONFIG for a relative mailbox directory, the same reason runPlan refuses a relative workspace root: a location that depends on the current directory is not a location. The mailbox holds messages between agents, so where it lives has to be settled before anything is written to it. |
| kernel | `sources.factory` | makeSourceTools refuses SOURCE_LOCK_INVALID for a malformed source lock. The lock is the record of which upstream sources were reviewed and at which digests, so a registry built over an unreadable one would claim a provenance nobody had established. |
| determinism | `json.hash` | json.hash hashes its entire input and, in a plan, that input IS the value: the {value: ...} wrapper exists only on the MCP surface, where a tool whose schema is not an object schema gets wrapped. A plan passing {value: X} hashes the wrapper, not X. Key order never matters either way, because canonicalisation happens first. |
| determinism | `json.assert` | json.assert returns a verdict carrying an evidence hash rather than a bare boolean, so a validation result can be cited later by that hash. |
| refusal | `json.assert` | A failing json.assert fails the task rather than returning passed:false, so a plan cannot continue past a violated invariant by ignoring a boolean. |
| values | `json.value` | json.value returns its input unchanged after canonical validation, which makes it the way to pin a literal into a plan that later tasks can depend on. |
| values | `json.mergeShallow` | json.mergeShallow takes a values array and merges it as a disjoint union, not as a patch applied over a base: there is no last-writer-wins, which is why it needs no notion of order. |
| values | `text.concat` | text.concat is bounded at 1000 values of 65536 characters each, so building a string inside a plan cannot become an unbounded allocation. |
| sources | `sources.catalog` | sources.catalog reports 13 pinned upstream sources as inert provenance: listing a source is not a claim that its runtime is installed or that its tools exist here. |
| knowledge | `capabilities.search` | capabilities.search answers from an inert index and states grantsCapabilities:false on every reply: finding a capability is never the same as acquiring one. |
| ranking | `skills.rank` | skills.rank is lexical-overlap-v1, not semantic: it scores shared tokens, so a corpus entry matching on one common word can outrank a relevant entry sharing none. Near-duplicate entries therefore crowd the top of a result list. |
| catalog | `rea.catalog` | rea.catalog reports all 117 REA tools with the realization route of each, keeping visible the difference between a reader Concord wrote and a bounded call to an operator-reviewed binary. |
| foreign | `foreign.catalog` | foreign.catalog reports availableNow:0 until an operator both configures a server and allow-lists a tool: importing a capability manifest grants nothing by itself. |
| formats | `artifact.inspect` | artifact.inspect identifies zip from magic bytes alone, never from the file extension, and reports the SHA-256 of exactly the bytes it read. |
| formats | `artifact.inspect` | artifact.inspect identifies png from magic bytes alone, never from the file extension, and reports the SHA-256 of exactly the bytes it read. |
| formats | `artifact.inspect` | artifact.inspect identifies wasm from magic bytes alone, never from the file extension, and reports the SHA-256 of exactly the bytes it read. |
| formats | `artifact.inspect` | A file named .png whose bytes are a zip is reported as a zip: artifact.inspect reads content, so a wrong extension cannot mislead anything downstream of it. |
| evidence | `artifact.inspect` | artifact.inspect binds every claim to a digest of the bytes it read, so a later statement about a file can be checked against the exact content that produced it. |
| readers | `artifact.sourceMap` | artifact.sourceMap decodes VLQ mappings field by field rather than trusting a library: only generatedColumn resets per line, so a decoder resetting the others would report plausible wrong origins. |
| readers | `artifact.harCapture` | artifact.harCapture reports a capture structurally and copies no headers, cookies or bodies out of it: a HAR is full of credentials, so the reader withholds them by construction rather than by redaction. |
| governance | `hooks.evaluate` | hooks.evaluate returns the strictest matching decision, so an allow rule never cancels a deny that also matched. It reports a decision and enforces nothing. |
| delegation | `agent.delegate` | agent.delegate hands its sub-plan no approvals, so a write inside returns a recorded blocked event naming the tool rather than failing to compile or running on borrowed authority. |
| scheduling | `schedule.due` | schedule.due answers against a time the caller supplies, never a clock the kernel reads, which is what keeps a scheduling answer reproducible on replay. |
| scheduling | `schedule.declare` | schedule.declare is a write and takes a grant like any other, and it stores the plan hash: re-declaring the same id replaces it, which is how a finished schedule is advanced. |
| judgment | `judgment.gate` | judgment.gate reports accepted rather than passed, and states grantsCapabilities:false on the way out: clearing a quality bar is a judgement about a score, never permission to do anything. |
| comparison | `experiment.compare` | experiment.compare is a hypothesis test across named conditions, not a diff. confirmed, refuted and untestable are arrays of condition names rather than booleans, so an untested condition can never read as a passing one. |
| comparison | `experiment.compare` | experiment.compare warns NONDISCRIMINATING_EXPECTATION and reports discriminating:false when every condition declares the same expectation: an experiment whose conditions all expect the same outcome cannot distinguish the factor it varied from one that would pass regardless, so a green result there proves nothing. |
| memory | `memory.candidate` | memory.candidate is pure and yields only a content hash: nothing is remembered until memory.promote writes it under its own exact grant, so drafting a lesson costs no authority. |
| memory | `memory.recall` | memory.recall is lexical, and it counts stored entries it could not parse rather than skipping them silently: a corrupted lesson is reported, not hidden. |
| exchange | `peer.inbox` | peer.inbox reports open questions without consuming them: reading never removes a letter, because a tool that quietly drained the mailbox would make a lost message look like one that was never sent. |
| skills | `skills.snapshot` | skills.snapshot reads one named file and requires both its path and its sourceId: it is a read of a specific reviewed artefact rather than a browse, so a snapshot always says which source it came from. |
| skills | `skills.installed` | skills.installed reads an empty store as empty rather than failing, and separates a changed local copy from a changed upstream so a local edit is never reported as an update. |
| approval | `files.write` | A write blocks once with an exact request hash and runs only when that same hash is granted; the hash binds the resolved input, so an approval can never be reused for a different write. |
| skills | `skills.install` | skills.install verifies a file against the digest the inventory recorded before copying it, so an adopted skill is provably the reviewed bytes rather than whatever happens to be on disk now. |
| refusal | `json.mergeShallow` | json.mergeShallow refuses a key appearing in two inputs with MERGE_COLLISION rather than letting one silently win. A merge that picks a winner hides the disagreement that made two values exist. |
| refusal | `files.read` | files.read refuses a path climbing out of the workspace with PATH_DENIED, checked segment by segment, so containment never depends on the caller having normalised anything. |
| refusal | `files.read` | An absolute path is refused as PATH_DENIED rather than read: only unambiguous relative workspace paths are accepted, which is what makes the workspace boundary mean anything. |
| refusal | `skills.install` | skills.install refuses an unknown id with SKILL_UNKNOWN, but only once the write is granted: the approval gate sits in front of the tool, so a write tool blocks before it can tell you the request was nonsense. Round 022 learned this by predicting the refusal and getting a block instead. |
| refusal | `schedule.declare` | schedule.declare refuses a time it cannot parse as an instant with SCHEDULE_TIME, because a schedule compared as text rather than as an instant would come due at the wrong moment. |
| refusal | `agent.delegate` | agent.delegate refuses an empty sub-plan with DELEGATE_PLAN rather than returning a vacuous success, so a delegation that would have done nothing is reported as the mistake it is. |
| contract | `schema-refusal` | Every tool that declares required input refuses input that omits it, raising SCHEMA_MISMATCH while the plan is still compiling. This holds for write tools too, which means input is validated before the approval gate is ever reached: a malformed write is refused outright rather than turned into an approval request, so nobody is ever asked to approve a write that could not have run. It is the mirror of the gate sitting in front of a tool for well-formed input, and both are now proven rather than assumed. |
| contract | `absolute-path-refusal` | Every read tool that takes a workspace path refuses an absolute one with PATH_DENIED rather than reading it. The refusal is uniform across all of them, which is what makes the workspace boundary a property of the system instead of a habit each tool observes separately. |

## Findings

| Family | Tool | What happened |
| --- | --- | --- |
| kernel | `engine.attenuatePolicy` | expected POLICY_NOT_ATTENUATED from a direct call, got INVALID_POLICY |

## Where the training is still blind

Derived from the source and from the predictions themselves, not recorded by hand. Tool
coverage is saturated, so these are the axes that still discriminate.

**Refusal codes.** 143 distinct codes are thrown across `src/`. 27 are named by a prediction and 30 were actually raised during this round, leaving 114 whose reachability from a plan is unproven. A further 6 codes only ever appear as data in an object literal, mixing the engine's own failure codes with warnings a tool returns inside a successful answer; they are excluded from the count above because a warning cannot be reached by refusing anything. Of what remains, much is raised while building a registry or driving a browser, where no plan reaches it, so this is a frontier rather than a failing grade — but it is not all unreachable, and the list below is where to look.

**Output keys.** 226/418 declared output keys are read by some prediction. A key no prediction reads has never been checked against a real run.

**Composition.** 8 tools appear in a plan with more than one task; 83 are exercised only alone. The kernel exists to compose tools, so this is the axis where a high tool count is most misleading.

### Raised by a run, named by no prediction

The cheapest exercises to add next: a real run already raised these, so reachability is
settled and only the assertion is missing.

- `EFFECT_INDETERMINATE`
- `INVALID_POLICY`
- `TOOL_FAILED`

### Declared output keys no prediction reads

- `skills.install` — `id`, `installedAs`, `sourceId`, `title`, `status`, `bytes`, `limitations`
- `artifact.sourceMap` — `path`, `sha256`, `supported`, `mappingCount`, `limitations`, `untrusted`
- `rea.catalog` — `schemaVersion`, `revision`, `availableNow`, `tools`, `matched`, `grantsCapabilities`
- `agent.delegate` — `results`, `taskCount`, `root`, `rejection`, `authority`, `limitations`
- `memory.candidate` — `evidenceHashes`, `executable`, `lesson`, `status`, `version`
- `artifact.evmInterface` — `bytecodeBytes`, `selectorCandidates`, `opcodes`, `metadata`, `limitations`
- `artifact.harCapture` — `path`, `sha256`, `supported`, `summary`, `limitations`
- `artifact.firmwareRegion` — `path`, `sha256`, `preview`, `limitations`, `untrusted`
- `foreign.catalog` — `schemaVersion`, `sources`, `total`, `tools`, `matched`
- `peer.inbox` — `messages`, `returned`, `total`, `latestSeq`, `limitations`
- `skills.remove` — `id`, `removed`, `fileRemoved`, `remaining`, `limitations`
- `experiment.compare` — `hypothesis`, `verdicts`, `refuted`, `untestable`
- `artifact.dexSearch` — `path`, `sha256`, `matches`, `totalMatches`
- `artifact.dexReferences` — `path`, `sha256`, `methods`, `fields`
- `artifact.firmware` — `path`, `sha256`, `counts`, `limitations`
- `skills.installed` — `changed`, `missing`, `upstreamChanged`, `limitations`
- `hooks.evaluate` — `matched`, `evaluated`, `reasons`, `limitations`
- `schedule.due` — `pending`, `total`, `now`, `limitations`
- `files.write` — `contentHash`, `created`, `path`
- `memory.recall` — `matchedCount`, `results`, `totalEntries`
- `artifact.inspect` — `bytes`, `path`, `untrusted`
- `artifact.wasmInterface` — `counts`, `limitations`, `sha256`
- `artifact.dexClass` — `path`, `sha256`, `class`
- `artifact.dexMethod` — `path`, `sha256`, `methods`
- `artifact.sourceLocation` — `path`, `sha256`, `entry`

### Refusal codes not yet shown reachable from a plan

- `CHAT_CONFIG (src/app.mjs:57)`
- `CHAT_STORE (src/app.mjs:125)`
- `BROWSER_POLICY (src/browser.mjs:28)`
- `BROWSER_ABORTED (src/browser.mjs:30)`
- `BROWSER_CONFIG (src/browser.mjs:40)`
- `BROWSER_TIMEOUT (src/browser.mjs:58)`
- `BROWSER_CDP (src/browser.mjs:72)`
- `BROWSER_EXECUTABLE (src/browser.mjs:285)`
- `BROWSER_PATH (src/browser.mjs:289)`
- `BROWSER_PROCESS (src/browser.mjs:300)`
- `BROWSER_OUTPUT_LIMIT (src/browser.mjs:310)`
- `BROWSER_INPUT (src/browser.mjs:365)`
- `INVALID_SKILLS (src/builtins.mjs:63)`
- `CHAT_CONTEXT (src/chat-context.mjs:16)`
- `CHAT_INPUT (src/chat.mjs:532)`
- `CHAT_APPROVAL (src/chat.mjs:559)`
- `CHAT_PLAN (src/chat.mjs:567)`
- `CHAT_REPLAY (src/chat.mjs:575)`
- `INPUT_LIMIT (src/cli.mjs:45)`
- `CLI_USAGE (src/cli.mjs:67)`
- `INVALID_REGISTRY (src/cli.mjs:94)`
- `DESKTOP_URL (src/desktop.mjs:38)`
- `LOCALAPPDATA (src/desktop.mjs:55)`
- `DESKTOP_BROWSER (src/desktop.mjs:96)`
- `DESKTOP_PROFILE (src/desktop.mjs:116)`
- `DESKTOP_WINDOW (src/desktop.mjs:118)`
- `DESKTOP_LAUNCH (src/desktop.mjs:150)`
- `JOURNAL_LIMIT (src/engine.mjs:240)`
- `TIMEOUT (src/engine.mjs:286)`
- `REPLAY_LIMIT (src/engine.mjs:336)`
- `REPLAY_TRANSITION (src/engine.mjs:349)`
- `REPLAY_OUTPUT (src/engine.mjs:400)`
- `FOREIGN_CONFIG (src/foreign.mjs:65)`
- `FOREIGN_ABORTED (src/foreign.mjs:133)`
- `FOREIGN_TIMEOUT (src/foreign.mjs:134)`
- `FOREIGN_SPAWN_FAILED (src/foreign.mjs:141)`
- `FOREIGN_OUTPUT_LIMIT (src/foreign.mjs:148)`
- `FOREIGN_HANDSHAKE_FAILED (src/foreign.mjs:167)`
- `FOREIGN_CALL_FAILED (src/foreign.mjs:169)`
- `FOREIGN_INPUT_LIMIT (src/foreign.mjs:292)`


