# Browser snapshot

`makeBrowserTools(config)` in `src/browser.mjs` registers `browser.snapshot`, a `process`-effect
tool. It is ego-lite's browser-automation role implemented natively, as one real, bounded
capability — not a port of ego-lite's own code, and not a general automation framework. Registration
is skipped entirely when `config` is `undefined`.

## What it does

Given `{url}` (restricted to `http:`/`https:` — `file:`, `chrome:`, `javascript:`, and `data:` are
rejected before any process is launched), one call:

1. Launches the configured Chrome/Chromium binary headless with a fresh, isolated
   `--user-data-dir` and an OS-assigned `--remote-debugging-port=0`.
2. Discovers the real assigned port by polling the profile directory's `DevToolsActivePort` file
   (the standard mechanism Chromium itself writes this to; polling tolerates the brief window
   where the file is still being created, bounded by the configured timeout).
3. Fetches `/json/list` on that port and re-verifies the returned `webSocketDebuggerUrl`'s host is
   loopback before connecting — the discovered endpoint is never trusted blindly.
4. Opens one CDP WebSocket session, sends `Page.navigate`, polls `document.readyState` until
   `complete`, then runs one `Runtime.evaluate` to extract `{title, url, text}` (`text` is
   `document.body.innerText`, bounded).
5. Guarantees teardown: kills the browser process, waits for it to actually exit (Windows releases
   a killed process's file handles asynchronously, so cleanup waits and retries before touching the
   profile directory), and deletes the temp profile.

One call owns the browser's entire lifetime. There is no click, type, or multi-step scripting in
this version — it is one real capability (open a page, extract its text), not a browser-automation
framework.

## Timeout and cancellation cover the whole session, not just the open

Every in-flight CDP call is tracked in a pending-response map. A single `stop()` function —
triggered by the configured deadline, an abort signal, or the socket closing/erroring — rejects
every pending call and closes the socket. This matters concretely: a page whose JavaScript blocks
the renderer's main thread forever (an infinite loop) would otherwise leave an in-flight
`Runtime.evaluate` call waiting for a CDP response that never arrives, which would leave
`execute()` itself hanging forever and the surrounding cleanup (kill the process, delete the
profile) unreached — leaking a running browser process and its open local debug port
indefinitely. `test/browser.test.mjs` exercises this exact scenario against a real browser and a
page that hangs on purpose.

## browser.automate

A second `process`-effect tool, sibling to `browser.snapshot` and sharing its launch/discover/
teardown scaffold. Input is `{url, actions}`, where `actions` is a bounded list (at most 20) of
`{type: 'click'|'fill'|'wait'|'extract', selector?, value?}`. The entire action sequence runs
inside **one** CDP session — one launch, one attach, one teardown — exactly like `dsh.run`'s own
multi-step protocol (initialize→prompt→wait→shutdown) runs inside one call. That is deliberate,
not a shortcut: Concord's kernel requires every tool's output to be a pure function of its
declared input so a recorded run can be independently replayed, and a browser session held open
*across* two separately approved calls would break that guarantee — see
[the architecture notes](architecture.md) on why a persistent multi-call session was rejected in
favor of this shape.

`click` and `fill` never string-interpolate the caller's `selector`/`value` into executable CDP
expression text (the way the snapshot's own `maxChars` is interpolated above — safe there only
because it is a server-controlled integer, never caller text). Instead, the tool resolves
`document`'s CDP object handle once, then calls a **fixed** `Runtime.callFunctionOn` function
body with the selector/value passed only as CDP `arguments` (JSON values). CDP serializes
`arguments` as data, never as source, so a crafted selector like `'); window.x=1; //` can never
break out of the function body — it just fails to match any element, or throws an ordinary
"selector not found" inside the function, surfaced as a clean `BROWSER_ACTION` error. The session
attaches to exactly one CDP target for the whole sequence and never re-discovers mid-script, so a
page that opens a popup via `window.open()` cannot pull the automation onto a different target.

`extract` returns the `innerText` of the matched selector (or the whole page body if `selector` is
omitted), bounded per call and contributing to the same `maxOutputBytes` ceiling as everything
else in the result. `wait` polls for a selector to exist in the DOM, bounded by the same overall
deadline as the rest of the call — there is no open-ended arbitrary sleep action.

`extractForm` reads every named `<input>`/`<select>`/`<textarea>` inside the matched selector's
container (not only a real `<form>` element) and returns `{fieldName: value}`. It uses the same
`Runtime.callFunctionOn`, arguments-only call path as click/fill — no new injection surface. Both
the field count (`MAX_FORM_FIELDS`, 500) and each field's name *and* value length are bounded
**inside the browser-side function itself**, before CDP ever serializes the return value — not
only at the outer `maxOutputBytes` check — so one pathological hidden field can't balloon the CDP
response before that check runs. A field literally named `__proto__`, `prototype`, or
`constructor` is skipped outright, matching the reserved-name denylist used elsewhere in this
codebase (`engine.mjs`'s reference resolver, `json.mergeShallow`) — not only because a naive
assignment would hit `Object.prototype`'s accessor and silently vanish with no own key at all, but
because returning such a key through CDP's own `returnByValue` was found, empirically, to hang the
DevTools protocol response entirely rather than erroring; skipping it avoids that failure mode
outright rather than working around a browser-internal quirk. Deliberately scoped out of
`extractForm`: `<table>`-to-row-object extraction (real header-detection and colspan/rowspan
judgment calls that fail *silently* — misaligned data — rather than throwing, which doesn't belong
in the same unambiguous-key shape `extractForm` has) and multi-step wizards (would need cross-call
state, breaking the "no session held open across two separate calls" guarantee below).

**`fill` values are journaled as ordinary task input, in plaintext, like every other tool's
input, and `extractForm` reads password- and hidden-type fields back with no type filtering —
the same plaintext journaling applies symmetrically to whatever it reads.** Never type or read
back credentials through this tool; there is no redaction path for action values the way there is
for named credential environment variables elsewhere in this codebase.

## What is and isn't covered

- **Covered, tested against a real browser:** launch, port discovery, loopback re-verification,
  navigation, text extraction, timeout/abort mid-session, teardown, independent profiles across
  sequential calls (`browser.snapshot`); a click→fill→extract round trip, a crafted
  injection-shaped selector proving `Runtime.callFunctionOn` argument-passing prevents script
  breakout, a `window.open()` popup leaving the session attached to the original target, the same
  hang/timeout/cleanup guarantee mid-sequence, and `extractForm` reading every named field —
  including one filled earlier in the same sequence — its no-matching-container failure mode, a
  reserved field name (`__proto__`) being skipped rather than hanging the call, and an oversized
  field name being truncated to the same bound already applied to values (`browser.automate`).
- **Not covered:** screenshots, shared logins or persisted cookies/storage across calls (a fresh
  profile is used and deleted every time), accessibility-tree extraction (this returns rendered
  text, not an AX tree), drag/drop or keyboard-only interaction, `<table>` extraction and
  multi-step wizards (see above), and any session held open across two separate tool calls (a
  deliberate boundary, not an oversight — see above).
- **Residual, disclosed risk:** the local DevTools port is unauthenticated for the lifetime of one
  call — any other local process that reaches it during that window could attach. This is the same
  exposure class every other `process`-effect tool in this codebase already discloses, bounded by
  `policy.timeoutMs`, not eliminated. If the Node parent process itself is hard-killed (not a normal
  abort/timeout/error path), the child browser process and its profile directory are an accepted
  residual gap, matching the disclosure posture already documented for `dsh.run` in
  [agent workers](agent-workers.md). A persistent profile-directory cleanup failure (e.g. antivirus
  or disk contention outlasting the retry budget) is surfaced as `profileCleanupFailed: true` on
  the returned snapshot rather than silently discarded — but the call itself still succeeds.

## Configuration

```json
{
  "browser": {
    "executable": "C:/Program Files/Google/Chrome/Application/chrome.exe",
    "executableSha256": null,
    "timeoutMs": 20000,
    "maxOutputBytes": 1048576
  }
}
```

`executable` must be an absolute path to a real local binary — never auto-downloaded.
`executableSha256` is optional (unlike `process.run`, where it is mandatory): browsers update
often, and pinning an exact digest for every update is impractical for most operators. Omit it to
skip that check, or supply it to pin a specific reviewed build.
