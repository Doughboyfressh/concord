# Concord as a desktop application

```powershell
npm run desktop
```

Or double-click `Concord.lnk` (committed, and wired to the live model) or `Concord.cmd`. Or put
it in the Start Menu once and launch it from there:

```powershell
pwsh scripts/install-shortcut.ps1          # Start Menu; add -Desktop, or -Live for the live model
pwsh scripts/install-shortcut.ps1 -InRepo  # regenerate the committed Concord.lnk
pwsh scripts/install-shortcut.ps1 -Remove  # and that undoes all of them
```

**`Concord.lnk` is machine-specific, and that is a property of the format, not a bug to report.**
A Windows shortcut stores absolute paths, and `WScript.Shell`'s `RelativePath` does not persist —
verified: the `HasRelativePath` flag stays clear whatever order it is set in. The committed link
targets `Concord.cmd` inside the repository rather than an absolute `node.exe`, so only the path
prefix is wrong in a clone elsewhere, not the interpreter. Regenerate it in one command with
`-InRepo`.

A window opens with no tab strip and no address bar. Closing it stops Concord. That lifecycle is
the whole difference between this and `npm run chat`: an application is something you close, not
something you have to remember to stop.

## What it actually is

Concord installs no dependencies, ever, so there is no Electron and no Tauri here. The window is
an already-installed Chromium opened in application mode against the loopback server
[the local interface](chat-ui.md) already describes — the same page, the same five JSON routes,
the same token authorization, the same policy and approvals.

That rule is a real constraint with real consequences, so they are worth stating plainly rather
than leaving to be discovered:

| | |
| --- | --- |
| Download size | nothing; no runtime is bundled |
| Needs | Node 22+, and Chrome, Edge, Brave or Chromium for a window |
| Without a Chromium | still runs, but opens a browser tab and says so |
| Window chrome | none: application mode has no tab strip or omnibox |
| Shares with your browser | nothing — separate profile, no cookies, history or extensions |
| Offline | entirely; the server is bound to loopback |

## The launchers

| | Starts | Port |
| --- | --- | --- |
| `npm run chat` | server only, prints a URL | 8787 |
| `npm run desktop` | server plus a window | ephemeral |
| `Concord.cmd` | the same as `npm run desktop` | ephemeral |
| `Concord.lnk` | the same, minimised, **live model** | ephemeral |
| Start Menu shortcut | the same, minimised | ephemeral |

Both launchers call one function, `startChatServer` in `src/app.mjs`. That matters more than it
looks: a difference in which tools register, which policy is defaulted, or what the source lock
records would be a difference in what an approval authorizes. There is one assembly, and both
launchers take it.

The desktop launcher defaults to port 0 rather than 8787 because the window is handed its URL
directly. There is no reason to contend for a fixed port or to leave a predictable one listening.

Every flag `scripts/chat.mjs` accepts works here too — `--workspace`, `--policy`,
`--integrations`, `--workers`, `--browser`, `--reverse`, `--foreign`, `--store`, `--port` — plus
`--window-size W,H` and `--no-window`.

## The live model

`Concord.lnk` passes `--integrations config/concord-live.json`, which registers `model.propose`
and puts the harness in live mode — 71 tools instead of 70. Every model call is still a `network`
effect needing its own exact grant; configuring a model grants nothing by itself.

That file points at an OpenAI-compatible server on loopback. As measured here: a llama.cpp server
on `http://127.0.0.1:11434` serving `qwen3.8-flash`.

**The credential.** The adapter requires a credential to exist for every request, and a model
server on loopback checks none. So when the configured origin is loopback *and* the variable is
unset, the launcher supplies a fixed, obviously non-secret placeholder for that process only and
prints that it did. It never does this for a remote origin, and never over a value you actually
set — a real `CONCORD_MODEL_API_KEY` always wins. Off loopback with no credential, the launcher
says plainly that calls will refuse with `INTEGRATION_CREDENTIAL` rather than letting you discover
it as an unexplained failure.

**Timing, measured rather than assumed.** The chat system prompt is about 58 KB, around 15,000
tokens. On this machine that model answered in **218 seconds cold** and **15-136 seconds** once
the prompt cache was warm. Two bounds were wrong for that reality and are now fixed:

- `config/concord-live.json` asked for 60 seconds, so every live turn died at 60.
- The default policy also defaulted to 60 seconds, and the *lower* of the two bounds wins — so
  raising only the adapter would have changed nothing. The default now never undercuts a
  configured adapter, and never exceeds `POLICY_MAX_TIMEOUT_MS`, the kernel's own 300-second
  ceiling from the policy schema in `src/engine.mjs`. A policy above it is rejected outright,
  which fails every plan rather than one call.

A cold first turn can still exceed 300 seconds and fail with `EFFECT_INDETERMINATE`. That is the
kernel's hard ceiling meeting a large prompt on a local model, not a wiring fault; the next turn,
with a warm cache, succeeds. Point the config at a faster model or a smaller prompt if that
matters more than locality.

**Model compliance is checked, not trusted.** A live model that returns `"citations": null` where
the schema declares an array is refused with `MODEL_PROPOSAL_INVALID` and a reason naming the
field. That is the design working. The instruction text now says explicitly that omitting a
property means leaving it out rather than setting it to null, because a small local model read
"omit" as "send null" — the fix was to say which one was meant, never to accept both.

## What the shell is allowed to open

The window is a browser pointed at a URL, which makes the URL worth guarding. `checkAppUrl`
accepts a loopback `http` origin at the application root and refuses everything else: a remote
host, a hostname that merely resolves to loopback, `https`, credentials in the URL, any path below
the root, and — deliberately — `localhost`, because the server authorizes a request by exact
`Host` match against the interface it bound, so a `localhost` window would render and then have
every request denied. Refusing the URL beats shipping a window that silently cannot talk to its
own server.

It also refuses a query string and a fragment. A browser command line is readable by every process
on the machine, and that refusal is what makes a session token structurally incapable of reaching
the process table: the page fetches its token from `/api/state` over the socket, so no secret is
ever an argument.

The command line is built in exactly one reviewed place, `appWindowArgv`, and is asserted whole in
`test/desktop.test.mjs`:

```
--app=<loopback url>  --user-data-dir=<private profile>  --no-first-run
--no-default-browser-check  --disable-extensions  --window-size=W,H
```

Nothing that weakens the renderer or opens a second control channel can appear there: no
`--remote-debugging-port`, no `--disable-web-security`, no `--proxy-server`, no
`--load-extension`. The test asserts their absence rather than trusting the construction.

The private profile under `runs/desktop-profile` is what keeps the window out of your own cookies,
history, sessions and extensions. It persists between launches so the window remembers its size
and position, and it is git-ignored because it is local state.

Not to be confused with `src/browser.mjs`, which launches headless Chromium with a throwaway
profile and a debugging port to implement the `browser.snapshot` tool. That is a page reader under
an approval gate. This is a window for a person, and it is not a tool at all: the desktop shell
registers nothing and grants nothing.

## Choosing the browser

Chrome, then Edge, then Brave, then Chromium, at each platform's usual location — Chrome first
because Edge is always present on Windows, so probing it first would mean never choosing the
browser you actually installed. `CONCORD_BROWSER` overrides the search with an exact path; if that
path is not there it is an error rather than a quiet fall back to a browser you did not name.

If no Chromium is installed at all, the launcher opens your default browser and says plainly that
this is a tab rather than an application window, instead of reporting it as the same thing.

## The icon

`app/concord.ico` is committed, so a fresh clone has one. It is generated by
`node scripts/make-icon.mjs`, which writes the ICO container and its four images byte by byte —
16, 32, 48 and 64 pixels — in the interface's own colours. No image toolchain to install, for the
same reason there is no Electron.
