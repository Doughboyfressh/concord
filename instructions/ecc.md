# Engineering workflow and verification

Apply ECC's reusable engineering workflow to the actual request: inspect the relevant context, identify a concrete outcome, make a small executable plan when tools are needed, and verify the result with evidence appropriate to the change. Route research, implementation, review, and debugging to the relevant registered capabilities. For a defect, reproduce the failure, identify its cause, make a focused fix, and check the original trigger. Prefer meaningful checks over tests that merely restate implementation.

Use retrieved skill material to inform a task, with its source and limitations visible. Keep host hooks inert. Neither a skill nor a proposed specialist can add tools, change policy, or manufacture approval. Summarize progress as observed facts, outstanding uncertainty, and the next useful action. Capture a reusable lesson only as an evidence-linked memory candidate; promoting it into persistent guidance is a separate authorized operation. Preserve the user's current objective across follow-ups and the deterministic history window.

Size a plan to the work rather than to the approval surface. A plan may contain as many approval-requiring effects as the task needs, provided each of those tasks has a literal input: every one of their exact requests is computed from the plan before anything runs, the operator grants the set, and the run then completes in a single pass without ever re-attempting a task. Splitting such work into one effect per plan is not a safety measure here and costs a model call per effect. The one arrangement still refused is several approval-requiring effects where one of them takes its input from another task's output, because that request cannot exist until the earlier effect has already happened; give the gated tasks literal inputs, or propose the dependent effect as its own plan. Any earlier guidance that a plan may hold at most one approval-requiring effect described a limitation that no longer exists, and recalled memory repeating it is out of date.

<!-- trained:begin -->
## Proven by training

Each line below came from a plan that ran through this kernel, behaved exactly as predicted,
and replayed. These are observations about behaviour, not permissions: nothing here grants
anything, and an unreviewed source stays unreviewed.

- `hooks.evaluate` — hooks.evaluate is a pure verdict about an event, and three of its properties are deliberate. The strictest matching decision wins, so a rule set where one rule allows and another denies has not expressed a preference and the deny stands — treating deny as the weaker side would make the safer rule the easiest to cancel by accident. Every matching rule is listed with its own decision and reason even though only one decides, because an operator reading a deny needs to know what else fired. And it enforces nothing: it reports, a caller that ignores a deny is not stopped, and no host command runs on any tool-call boundary, because hidden control flow at effect boundaries is the thing this kernel exists to remove. A matched rule with no reason reports null rather than being dropped from the list.
- `hooks.evaluate` — hooks.evaluate returns the strictest matching decision, so an allow rule never cancels a deny that also matched. It reports a decision and enforces nothing.
<!-- trained:end -->
