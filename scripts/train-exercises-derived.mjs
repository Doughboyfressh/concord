/**
 * Exercises nobody wrote, derived from what the tools declare about themselves.
 *
 * Every other exercise in this suite is hand-authored: a plan, a prediction, a lesson. That is the
 * right shape for a claim about behaviour, because a prediction is only worth something if someone
 * who could have been wrong committed to it in advance. It is also the reason coverage stalls — the
 * suite grows one tool at a time, by hand, and a tool added tomorrow is exercised by nothing.
 *
 * These are the other kind. Each is generated from a tool's own declaration, and the prediction is
 * entailed by that declaration rather than guessed at:
 *
 *   schema-refusal          a tool that declares required input must refuse input lacking it
 *   absolute-path-refusal   a read tool taking a workspace path must refuse an absolute one
 *
 * So a tool added to the registry is exercised against both contracts the moment it exists, with
 * nobody writing anything. That is the part of this that improves itself.
 *
 * The honest boundary, and it is the whole reason these are kept separate: a prediction derived
 * from a declaration cannot discover that the declaration is wrong. It checks consistency between
 * what a tool says and what it does, which is real and worth automating, and it is not the same
 * thing as learning something new about the world. Nothing here can replace a hand-written
 * prediction that might have failed.
 *
 * They carry no lesson of their own, deliberately. One lesson per contract is promoted once the
 * contract has held across every tool it applies to, with the tool count as its evidence — because
 * "every tool refuses malformed input" is one fact about the system, and writing it down seventy-two
 * times would crowd the memory it is supposed to improve.
 */

/** What each contract proves, written once, promoted only if it held everywhere it applied. */
export const CONTRACTS = {
  'schema-refusal': 'Every tool that declares required input refuses input that omits it, raising SCHEMA_MISMATCH while the plan is still compiling. This holds for write tools too, which means input is validated before the approval gate is ever reached: a malformed write is refused outright rather than turned into an approval request, so nobody is ever asked to approve a write that could not have run. It is the mirror of the gate sitting in front of a tool for well-formed input, and both are now proven rather than assumed.',
  'absolute-path-refusal': 'Every read tool that takes a workspace path refuses an absolute one with PATH_DENIED rather than reading it. The refusal is uniform across all of them, which is what makes the workspace boundary a property of the system instead of a habit each tool observes separately.',
};

/** An absolute path, matching the one the hand-written refusal exercise already uses. */
const ABSOLUTE = 'C:/Windows/win.ini';

export function derivedExercises(registry) {
  const generated = [];
  if (!registry || typeof registry.entries !== 'function') return generated;

  for (const [name, tool] of registry) {
    const required = tool.inputSchema?.required;
    if (!Array.isArray(required) || !required.length) continue;
    generated.push({
      family: 'contract', tool: name, contract: 'schema-refusal',
      expectThrow: 'SCHEMA_MISMATCH', workspace: 'temp',
      plan: { version: 1, name: 't', tasks: [{ id: 'a', tool: name, input: {} }] },
    });
  }

  for (const [name, tool] of registry) {
    const properties = tool.inputSchema?.properties;
    // Only tools where a path is the whole input: anything else would need an argument invented
    // for it, and an invented argument is a guess rather than something the declaration entails.
    const othersRequired = (tool.inputSchema?.required ?? []).filter((key) => key !== 'path');
    if (tool.effect !== 'read' || !properties?.path || othersRequired.length) continue;
    generated.push({
      family: 'contract', tool: name, contract: 'absolute-path-refusal',
      expectCode: 'PATH_DENIED', workspace: 'temp',
      plan: { version: 1, name: 't', tasks: [{ id: 'a', tool: name, input: { path: ABSOLUTE } }] },
    });
  }

  return generated;
}
