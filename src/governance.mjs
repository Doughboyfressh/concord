import fs from 'node:fs';
import path from 'node:path';
import { canonical, digest, parseJson, HarnessError } from './value.mjs';
import { runPlan, attenuatePolicy } from './engine.mjs';
import { workspaceFile } from './workspace-fs.mjs';

/**
 * Who does the work, when it is due, and whether it may run at all.
 *
 * Three capabilities Concord had described and not implemented, each from a source it already
 * pins: delegation and scheduling from hermes, hook rules from ECC. None of them needed a
 * dependency. What they needed was a shape that survives this kernel's contract, and in every
 * case that shape is the same one `dsh.run` already uses — the whole operation inside one bounded
 * call, rather than state held open between two of them.
 *
 * Delegation is the interesting one. A delegated agent that could do anything its caller can do
 * is not delegation, it is a second caller. Here the sub-plan runs against a registry without
 * this tool in it, under a policy narrowed to match, and — the part that actually binds — with an
 * empty approvals list. So a delegate can research, rank, read and compute; it cannot write,
 * reach the network, start a process, or delegate again. An effectful step inside comes back as a
 * recorded `blocked` event, as data for whoever asked to escalate deliberately, rather than
 * running on borrowed authority.
 *
 * Scheduling records intent and nothing else. Concord has no daemon and does not read the clock:
 * the caller says what time it is, and the answer is which declared schedules that makes due.
 * A schedule here never fires by itself, and the tool says so rather than implying a timer.
 *
 * Hooks decide; they do not execute. A rule set plus an event yields the decisions that match,
 * which a caller may then honour. Running host commands on a tool-call boundary is exactly the
 * hidden control flow this kernel exists to remove.
 */

const SCHEDULE_DIR = 'schedules';
const MAX_SCHEDULES = 512;
const MAX_RULES = 256;
const MAX_TASKS = 32;

const fail = (code, message, detail) => { throw new HarnessError(code, message, detail); };
const isObject = (value) => Boolean(value) && typeof value === 'object' && !Array.isArray(value);

/** ISO-8601 instants only, and compared as instants rather than as text. */
function instant(value, field) {
  if (typeof value !== 'string') fail('SCHEDULE_TIME', `${field} must be an ISO-8601 timestamp`);
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) fail('SCHEDULE_TIME', `${field} is not a usable ISO-8601 timestamp`, { value });
  return parsed;
}

const scheduleId = (value) => {
  if (typeof value !== 'string' || !/^[a-z][a-z0-9-]{1,63}$/.test(value)) {
    fail('SCHEDULE_ID', 'A schedule id must be a portable lower-case identifier');
  }
  return value;
};

/**
 * The schedules directory, created if absent.
 *
 * workspaceFile() guards a *file* path: it tolerates a missing final segment and rejects a
 * directory outright, so it cannot name this and cannot be asked to make a parent. The constant
 * is ours and contains no caller input, so joining it to the real root is the containment here.
 */
function scheduleDir(root) {
  const directory = path.join(fs.realpathSync(root), SCHEDULE_DIR);
  fs.mkdirSync(directory, { recursive: true });
  return directory;
}

function readSchedules(root) {
  const directory = path.join(fs.realpathSync(root), SCHEDULE_DIR);
  let names;
  try { names = fs.readdirSync(directory); }
  catch (error) {
    if (error && error.code === 'ENOENT') return [];
    throw error;
  }
  const out = [];
  for (const name of names.filter((entry) => /^[a-z][a-z0-9-]{1,63}\.json$/.test(entry)).sort()) {
    try { out.push(parseJson(fs.readFileSync(path.join(directory, name), 'utf8'))); }
    catch { /* a schedule that cannot be read is skipped rather than failing the whole listing */ }
  }
  return out;
}

/**
 * Does one rule match this event?
 *
 * Every condition present must hold. An absent condition is not a wildcard anyone has to reason
 * about — it is simply not asked.
 */
function ruleMatches(rule, event) {
  const when = rule.when ?? {};
  if (when.tool !== undefined && when.tool !== event.tool) return false;
  if (when.effect !== undefined && when.effect !== event.effect) return false;
  if (when.toolPrefix !== undefined && !String(event.tool).startsWith(when.toolPrefix)) return false;
  if (when.pathPrefix !== undefined) {
    const target = isObject(event.input) ? event.input.path : undefined;
    if (typeof target !== 'string' || !target.startsWith(when.pathPrefix)) return false;
  }
  return true;
}

export function makeGovernanceTools({ registry, sourceLock } = {}) {
  const planSchema = { type: 'object', additionalProperties: true };

  const tools = [
    {
      // Pure: a decision about an event, computed from rules the caller supplied. It reads no
      // file, consults no host, and runs nothing.
      name: 'hooks.evaluate', version: '1.0.0', effect: 'pure',
      outputKeys: ['decision', 'matched', 'evaluated', 'reasons', 'limitations'],
      inputSchema: {
        type: 'object', additionalProperties: false, required: ['rules', 'event'],
        properties: {
          rules: {
            type: 'array', minItems: 1, maxItems: MAX_RULES,
            items: {
              type: 'object', additionalProperties: false, required: ['id', 'decision'],
              properties: {
                id: { type: 'string', minLength: 1, maxLength: 128 },
                decision: { type: 'string', enum: ['allow', 'warn', 'deny'] },
                reason: { type: 'string', maxLength: 1024 },
                when: {
                  type: 'object', additionalProperties: false,
                  properties: {
                    tool: { type: 'string', maxLength: 128 },
                    toolPrefix: { type: 'string', maxLength: 128 },
                    effect: { type: 'string', enum: ['pure', 'read', 'write', 'network', 'process'] },
                    pathPrefix: { type: 'string', maxLength: 512 },
                  },
                },
              },
            },
          },
          event: {
            type: 'object', additionalProperties: false, required: ['tool'],
            properties: {
              tool: { type: 'string', minLength: 1, maxLength: 128 },
              effect: { type: 'string', enum: ['pure', 'read', 'write', 'network', 'process'] },
              input: { type: 'object', additionalProperties: true },
            },
          },
        },
      },
      execute(input) {
        const matched = input.rules.filter((rule) => ruleMatches(rule, input.event));
        // The strictest matching decision wins. A rule set where one rule allows and another
        // denies has not expressed a preference; treating deny as weaker would make the safer
        // rule the one easiest to cancel by accident.
        const order = { deny: 3, warn: 2, allow: 1 };
        const decision = matched.reduce((worst, rule) => (order[rule.decision] > order[worst] ? rule.decision : worst), 'allow');
        return {
          decision,
          matched: matched.map((rule) => ({ id: rule.id, decision: rule.decision, reason: rule.reason ?? null })),
          evaluated: input.rules.length,
          reasons: matched.filter((rule) => rule.reason).map((rule) => rule.reason),
          limitations: [
            'This reports a decision; it does not enforce one. A caller that ignores a deny is not stopped by this tool',
            'No host command is run on any tool-call boundary: hidden control flow is the thing this kernel exists to remove',
          ],
        };
      },
    },
    {
      name: 'schedule.declare', version: '1.0.0', effect: 'write',
      outputKeys: ['id', 'dueAt', 'planHash', 'replaced', 'limitations'],
      inputSchema: {
        type: 'object', additionalProperties: false, required: ['id', 'dueAt', 'plan'],
        properties: {
          id: { type: 'string', minLength: 2, maxLength: 64 },
          dueAt: { type: 'string', minLength: 4, maxLength: 64 },
          plan: planSchema,
          note: { type: 'string', maxLength: 1024 },
        },
      },
      execute(input, context) {
        const id = scheduleId(input.id);
        instant(input.dueAt, 'dueAt');
        const existing = readSchedules(context.workspaceRoot);
        const replaced = existing.some((entry) => entry.id === id);
        if (!replaced && existing.length >= MAX_SCHEDULES) {
          fail('SCHEDULE_LIMIT', 'As many schedules are declared as the bound permits', { schedules: existing.length });
        }
        const record = {
          id, dueAt: input.dueAt, plan: input.plan,
          ...(input.note === undefined ? {} : { note: input.note }),
          planHash: digest(input.plan),
        };
        // Parent first: workspaceFile tolerates only a missing final segment.
        scheduleDir(context.workspaceRoot);
        const file = workspaceFile(context.workspaceRoot, SCHEDULE_DIR + '/' + id + '.json');
        fs.writeFileSync(file, canonical(record) + '\n', 'utf8');
        return {
          id, dueAt: input.dueAt, planHash: record.planHash, replaced,
          limitations: [
            'Declaring a schedule runs nothing and starts no timer: Concord has no daemon and does not read the clock',
            'Re-declaring the same id replaces it, which is also how a completed schedule is advanced',
          ],
        };
      },
    },
    {
      // A read rather than a pure tool: it looks at the workspace. The time comes from the
      // caller, which is what keeps the answer reproducible — the kernel never reads a clock.
      name: 'schedule.due', version: '1.0.0', effect: 'read',
      outputKeys: ['due', 'pending', 'total', 'now', 'limitations'],
      inputSchema: {
        type: 'object', additionalProperties: false, required: ['now'],
        properties: { now: { type: 'string', minLength: 4, maxLength: 64 }, limit: { type: 'integer', minimum: 1, maximum: 100 } },
      },
      execute(input, context) {
        const now = instant(input.now, 'now');
        const limit = input.limit ?? 50;
        const all = readSchedules(context.workspaceRoot);
        const due = [];
        let pending = 0;
        for (const entry of all) {
          let at;
          try { at = instant(entry.dueAt, 'dueAt'); } catch { continue; }
          if (at <= now) { if (due.length < limit) due.push(entry); }
          else pending += 1;
        }
        return {
          due, pending, total: all.length, now: input.now,
          limitations: [
            'Being due is a statement about the time you supplied, not an event: nothing here executes a due plan',
          ],
        };
      },
    },
  ];

  // The registry, counted rather than remembered.
  //
  // Asked what it could do, Concord answered from the tool contracts in its context and said
  // ninety when the registry held ninety-three. The receipt under that reply correctly read
  // "nothing ran, so there is nothing to verify" -- the harness was honest that the answer was
  // unverified, but nothing could make it verifiable, because counting the registry was something
  // only the model could do, by reading a list. Counting a long list is what a model is worst at
  // and a tool is best at, so this is a tool.
  //
  // It reports `allowed` against the policy in force rather than hiding what the policy forbids:
  // "the registry holds 93 and this turn's authority permits 93" is a different and more useful
  // statement than either number alone. Only name, version and effect are read from a descriptor,
  // never `config`, which can hold executable paths and environment variable names.
  if (registry instanceof Map) {
    const GATED = ['write', 'network', 'process'];
    tools.push({
      name: 'tools.catalog', version: '1.0.0', effect: 'pure',
      outputKeys: ['count', 'allowedCount', 'gatedCount', 'names', 'tools', 'byEffect', 'byPrefix', 'limitations'],
      // `tools` is opt-in because a chat observation bounds one task output at 8 KiB and the full
      // detail for this registry is about 9.6 KiB: returned by default it was replaced by its own
      // digest, so the model got a commitment it could not read and still could not state the
      // number. Names and counts are the answer to the question actually being asked, and they
      // fit. Two keys rather than one whose element type changes with the input.
      inputSchema: {
        type: 'object', additionalProperties: false,
        properties: {
          prefix: { type: 'string', maxLength: 64 },
          effect: { enum: ['pure', 'read', 'write', 'network', 'process'] },
          detail: { type: 'boolean' },
        },
      },
      execute(input, context) {
        const permitted = Array.isArray(context?.policy?.allowedTools)
          ? new Set(context.policy.allowedTools) : null;
        let entries = [...registry.entries()]
          .map(([name, tool]) => ({
            name,
            version: typeof tool.version === 'string' ? tool.version : '',
            effect: typeof tool.effect === 'string' ? tool.effect : 'pure',
            gated: GATED.includes(tool.effect),
            allowed: permitted ? permitted.has(name) : true,
          }))
          .sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
        if (input?.prefix) entries = entries.filter((entry) => entry.name.split('.')[0] === input.prefix);
        if (input?.effect) entries = entries.filter((entry) => entry.effect === input.effect);
        const byEffect = {};
        const byPrefix = {};
        for (const entry of entries) {
          byEffect[entry.effect] = (byEffect[entry.effect] ?? 0) + 1;
          const prefix = entry.name.split('.')[0];
          byPrefix[prefix] = (byPrefix[prefix] ?? 0) + 1;
        }
        return {
          count: entries.length,
          allowedCount: entries.filter((entry) => entry.allowed).length,
          gatedCount: entries.filter((entry) => entry.gated).length,
          names: entries.map((entry) => entry.name),
          tools: input?.detail === true ? entries : [],
          byEffect,
          byPrefix,
          limitations: [
            'The registry as assembled in this process. A different configuration registers a different set, so this describes this session and not the project.',
            'Effects are what each tool declares, not an analysis of what it does.',
            'A tool the policy in force does not permit is listed with allowed:false rather than omitted, so the difference between existing and being permitted stays visible.',
            'tools is empty unless detail:true was asked for. With detail:true the result can exceed the 8 KiB a chat observation keeps per task output, in which case the observation carries its digest instead of its content; the run record still holds the whole thing.',
          ],
        };
      },
    });
  }

  // Delegation needs the registry it will run against. Without one the tool is not registered at
  // all, rather than registered and always failing.
  if (registry instanceof Map && sourceLock) {
    tools.push({
      /**
       * A sub-agent with strictly less authority than its caller.
       *
       * Read, because a delegate may read; never more, because the policy it runs under permits
       * only pure and read effects and it is handed no approvals. That is what makes this safe to
       * leave ungated: a delegate can do nothing its caller could not already do without a grant.
       */
      name: 'agent.delegate', version: '1.0.0', effect: 'read',
      outputKeys: ['status', 'results', 'blocked', 'taskCount', 'root', 'rejection', 'authority', 'limitations'],
      inputSchema: {
        type: 'object', additionalProperties: false, required: ['plan'],
        properties: { plan: planSchema, note: { type: 'string', maxLength: 1024 } },
      },
      async execute(input, context) {
        const tasks = Array.isArray(input.plan?.tasks) ? input.plan.tasks : null;
        if (!tasks || !tasks.length) fail('DELEGATE_PLAN', 'A delegated plan needs at least one task');
        if (tasks.length > MAX_TASKS) fail('DELEGATE_PLAN', 'That plan has more tasks than the bound permits', { tasks: tasks.length });

        // The delegate cannot delegate. Recursion here would be a way to spend a caller's whole
        // budget on bookkeeping, and nothing needs it.
        const narrowed = new Map([...registry].filter(([name]) => name !== 'agent.delegate'));
        // The empty approvals list below is the real guarantee, so the effect list is left alone
        // on purpose. Attenuating it to pure and read would make a write *fail to compile*
        // (POLICY_DENIED, thrown) instead of reaching the approval gate and coming back as a
        // recorded `blocked` event. Both are equally unable to run; only one says what was tried.
        const authority = attenuatePolicy(context.policy, { allowedTools: [...narrowed.keys()] });

        let result;
        try {
          result = await runPlan({
            plan: input.plan,
            policy: authority,
            registry: narrowed,
            sourceLock,
            approvals: [],
            workspaceRoot: context.workspaceRoot,
          });
        } catch (error) {
          // A plan that cannot compile is a fact about that plan, not a failure of delegating.
          // Reported rather than thrown, so a caller gets the same kind of answer either way.
          return {
            status: 'rejected', results: {}, blocked: [], taskCount: tasks.length, root: null,
            rejection: { code: error instanceof HarnessError ? error.code : 'DELEGATE_FAILED', message: error.message },
            authority: { allowedTools: narrowed.size, approvals: 0 },
            limitations: ['The delegated plan was refused before anything ran'],
          };
        }

        const blocked = result.events.filter((event) => event.type === 'blocked')
          .map((event) => ({ taskId: event.data.taskId, tool: event.data.tool, effect: event.data.effect }));

        return {
          status: result.outcome.status,
          results: result.results,
          blocked,
          taskCount: tasks.length,
          root: result.root ?? null,
          rejection: null,
          authority: { allowedTools: narrowed.size, approvals: 0 },
          limitations: [
            'The delegate was handed no approvals, so a write, network or process step comes back blocked rather than performed',
            'It cannot delegate again, and its results are recorded here as data rather than adopted: nothing it produced has authority over the caller',
          ],
        };
      },
    });
  }

  return tools;
}
