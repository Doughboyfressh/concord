# Unified architecture and feature synthesis

The goal is to carry forward the features and ideas of every supplied project into a novel deterministic harness. Concord retains all acquired source files, including features outside the first kernel. **Source availability**, **design adoption**, **adapter fixture validation**, and **native runtime validation** are distinct states.

## Integration mechanism

A plan is a frozen DAG. Nodes name a tool, JSON input, direct dependencies and optional output schema. References resolve only from committed direct-dependency results. The kernel validates the graph before effects, then runs ready nodes serially with a stable tie-break.

Operation identity binds the plan, normalized policy, source catalog, tool configuration, function declarations and explicit workspace. The CLI also binds exact Concord source bytes and Node runtime identity. Corpus selection binds the capability inventory digest. External binaries and model weights need their own content/version pins.

The model proposes; the structured judge advises; the kernel authorizes and schedules. Verification and postconditions determine whether dependents proceed. Experience produces an inert memory candidate. Promotion is a separate write under an exact grant, keeping learned text from becoming authority.

```mermaid
flowchart LR
  U[Goal and immutable context] --> P[Model or worker proposal]
  S[Pinned sources and skills] --> P
  P --> C[Concord compiler]
  J[TypeSafe evidence] --> C
  R[Reviewed policy and grants] --> C
  C --> E[Serial effect broker]
  E --> W[Browser / analysis / desktop / agents]
  W --> L[Intent and receipt journal]
  L --> V[Postconditions]
  V --> M[Memory candidate]
  L --> Q[Offline replay verifier]
```

## Feature synthesis

| Source | Features and ideas retained | Concord implementation status |
| --- | --- | --- |
| ECC | Research, planning, specialized agents, TDD, hooks, reviews, evaluation, memory, continuous learning | Source corpus; inert imports; verification and memory primitives. Host hook execution deferred. |
| ego-lite | Logged-in browser context, task spaces, snapshots, element references, screenshots, CDP | Source corpus; browser receipt boundary designed; native host unverified. |
| REA | Native/managed/JS/browser inspection, provider discovery, normalized evidence, bundles, provenance | Source corpus; process bridge available; dedicated MCP/session adapter deferred. |
| 21st and 21st.dev | Registry, previews, shadcn acquisition, search, dependency/license metadata | Repository corpus; asset acquisition deferred. Hosted components retain individual terms. |
| Vercel skills | Cross-agent discovery, imports, scopes, updates, locks, removal | Source corpus; snapshots/expected digests implemented; global lifecycle deferred. |
| Orca | Worktrees, agents, terminals, browser, desktop/mobile/SSH, review, orchestration | Source corpus; process bridge; native running ADE not installed. |
| TypeSafe | Choice/score/yes-no judgments, confidence, distributions, model routing | Version-pinned HTTP adapter tested with local fixtures; live service not called. |
| Hermes | Persistent agents, skills, learning, memory, delegation, schedules, channels, terminal backends, evaluations | Source corpus; memory primitives; daemon-aware ACP bridge deferred. |
| DeepSeek Harness | Plugins, model/tool services, sessions, events, SDK, ACP, model fixtures | Source corpus; SDK lifecycle adapter fixture-tested; native provider unverified. |
| awesome-cyber-skills | Security skill definitions, procedures, references, taxonomy | Full source corpus and feature inventory; procedures never execute on import. |
| Awesome-Hacking | Tools, learning resources, labs, categorized links | Source corpus and reference inventory; linked projects remain independent. |

The harvested inventory names individual skills, commands, agent/plugin definitions and documentation headings, including capabilities not reimplemented by Concord. Entries explicitly say `source-available-unreviewed`.

## Runtime ownership

Hermes, DeepSeek and Orca have different session, scheduler and state assumptions. Concord owns the graph and treats delegated workers as approved process effects. Worker internal actions remain outside per-tool enforcement unless a future bridge mediates them. The process contract is an explicit aggregate capability, not a sandbox.

## Reproducibility

1. **Plan determinism:** identical validated inputs, policy, declarations and snapshots give the same order and authorization decisions.
2. **Recorded replay:** identical context plus an anchored journal yields the same accepted recorded result without effects.
3. **Live repeatability:** not guaranteed for models, browsers, servers or devices.
4. **Environment reproduction:** requires pinned binaries, dependencies, model artifacts and isolated machines beyond the kernel.

Canonical JSON is Concord's JavaScript JSON domain, not an implementation claim for RFC 8785 or cross-language numeric canonicalization. Live deadlines produce recorded outcomes. Website observations cannot stand in for immutable asset snapshots.

## Durability

With `--journal`, the kernel exclusively creates a JSONL sink and fsyncs the header and each event. The CLI reserves the final run file before effects. A crash may leave an empty envelope and a partial intent log. Partial logs are forensic evidence; replay accepts complete settled envelopes only. Automatic retry/resume of interrupted effects is absent. Future durable retries need idempotency keys and reconciliation.

## Remaining modules

Preserving sources does not complete a port of every upstream feature. Next dedicated adapters: REA MCP handshake/evidence export; ego task-space lifecycle; Orca task/dispatch receipts; Hermes daemon-aware ACP; 21st asset/license acquisition. Further modules include worker isolation, queue/schedule persistence, review UI, provider adapters, persistent memory stores, eval suites, remote channels and reviewed skill updates. Each must preserve the kernel contract and pass native runtime tests before being called operational.

The novelty is this particular integration kernel and consistent evidence/authorization boundary. It is not a claim of an unprecedented AI algorithm or deterministic fresh inference.
