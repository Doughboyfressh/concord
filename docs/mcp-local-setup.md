# Local live MCP connection

Concord is registered as the enabled `concord` MCP server in Codex's user configuration. It uses
the absolute Node executable and `src/mcp.mjs`, with this repository as the tool workspace and
`config/concord-live.json` as its integration configuration.

The existing local provider advertises `qwen3.8-27b`, owned by `llamacpp`, at
`http://127.0.0.1:11434/v1/models`. Live chat uses `/v1/chat/completions`. The named
`CONCORD_MODEL_API_KEY` value configured for this unauthenticated local endpoint is a non-secret
placeholder (`concord-local`); no API account key was discovered, copied, or exposed.

Verification completed through the actual stdio MCP protocol: initialize, initialized notification,
tool discovery (22 tools), `concord_chat`, exact network request approval through `concord_approve`,
live model reply, and `concord_replay` with a verified terminal commitment.

Conversation evidence: `runs/live-mcp-1792209381424.json`. The live model introduced Concord,
listed its actual registered capabilities, and recommended adding a browsing capability. No proposed
plan was executed.

After registration, the app refreshed its native tool catalog. Native `concord_chat` and `concord_approve`
then produced a live reply in this chat. Native replay verified run `5ff85b72a7c0091a9f540c7d`, with terminal
root `a980056520e2d9171d8eef20d675ad9618b2540f18fd17f6d202be0c0451b828` and four events. Concord is
available through this chat's MCP tools. Running server processes retain their imported code; a fresh
MCP process is used to verify code changes.

Codex's supported server registration and shared configuration are documented in
[OpenAI's MCP setup guide](https://learn.chatgpt.com/docs/extend/mcp?surface=cli).
