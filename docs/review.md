# Adversarial review

Fresh-context reviewers examined the kernel, canonical values/schemas, CLI, builtins, external transports, source snapshots, feature index and SDK worker. Reviewers did not run acquired upstream code.

Fixed findings with regression coverage:

- Reject reserved task IDs before effects, avoiding a late result serialization failure.
- Require fully qualified workspace identities before approval hashing; the CLI resolves real paths.
- Apply the runner's post-intent journal reserve rule during replay, including forged/rehashed trace tests.
- Bound CLI inputs before allocating them; reject nonregular files and bound reads if files grow.
- Reject source/file links, nonregular files and hardlinks; compare file identity and bound reads.
- Preserve worker protocol envelopes while sanitizing credential echoes in values and keys; reject collisions.
- Keep worker commitment metadata outside content sanitation; reject loader injection variables and release owned handles on unconfirmed closure.

Reviewers reported no remaining actionable high/medium findings in those reviewed slices. Chat context, session and interface are undergoing their own integration and validation pass. The documented process/sandbox, mutable service and external-effect recovery boundaries remain.
