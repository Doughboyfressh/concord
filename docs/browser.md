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

## What is and isn't covered

- **Covered, tested against a real browser:** launch, port discovery, loopback re-verification,
  navigation, text extraction, timeout/abort mid-session, teardown, independent profiles across
  sequential calls.
- **Not covered:** click/type/scripted multi-step interaction, screenshots, shared logins or
  persisted cookies/storage across calls (a fresh profile is used and deleted every time),
  accessibility-tree extraction (this returns rendered text, not an AX tree).
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
