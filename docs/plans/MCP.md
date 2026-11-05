# MCP in OpsClaw

Status: design, not built. This depends on `dcpr-agent`'s `mcp` feature
(0.2.0) and on OpsClaw tools being `dcpr_agent::Tool`s, which is done (see
`tools::Ops`).

There are two directions. They have very different risk, so they're
separate decisions.

## A. Serve OpsClaw's tools over MCP (recommended first)

Other agents (Claude Code, Codex, your own) connect to OpsClaw as an MCP
server and use its tools. **Every call still goes through `policy::execute`**,
because the tools themselves call it. So the same safety applies to every
caller:
- autonomy levels and approvals;
- the emergency stop and rate caps;
- scope checks;
- the hash-chained audit log;
- output scrubbing.

That makes OpsClaw the safe gateway to Example's infrastructure for any
agent, not only its own.

What's needed:

- **Transport:** rmcp's streamable HTTP, mounted on the daemon's axum
  server at `/mcp`. It inherits the localhost-only bind and TLS guidance
  (DESIGN §4).
- **Auth:** the existing `ops_` CLI bearer tokens. Each MCP session gets a
  new `Principal` variant, `Principal::Mcp { token_id }`, so audit rows say
  which client did what, and autonomy can be set lower for MCP callers.
- **Which tools:** the same registry an interactive turn gets. Behind a
  config switch, offer only the heartbeat (read-only) subset at first.
- **Code:** `dcpr_agent::mcp::ToolServer::new(registry, ctx)`. `ToolCtx` is
  built per session with the MCP principal. The opsclaw side is small.

Risk: low, because nothing bypasses the policy layer. The new attack surface
is the endpoint itself, which is covered by token auth and the localhost
bind.

### Access

No caller sees more than they are entitled to: SSO, grants, labels on
derived data, and the export rules for someone's own agent. See
[ACCESS.md](ACCESS.md).

## B. Use external MCP servers as tools (needs a policy decision)

Plug in, say, a Kubernetes or Azure MCP server instead of writing tools by
hand. **The danger:** an MCP server runs its own commands. OpsClaw would see
only "called tool X", not the `kubectl` or `az` command behind it. So:
- `policy::execute` never classifies the command;
- autonomy, the emergency stop and scope can't be enforced on what actually
  runs;
- the audit log records the MCP call, not the real action.

That breaks OpsClaw's core promise: one choke point for every command
against a target.

If we do it, it has to be fenced:

1. **Each server is a node** in the topology (`kind = "service"`,
   `opsclaw.resource_type = "mcp"`), so its calls get a target, an autonomy
   level and an audit row.
2. **Every MCP call goes through `policy::execute`** as an endpoint command
   (`mcp:<server>:<tool> <args>`), with its risk taken from the tool's MCP
   annotations:
   - `readOnlyHint: true` → Read;
   - `destructiveHint: true` → High;
   - no annotation → High, never trusted.

   Annotations are the server's own claim, so they can only *lower* risk
   for servers you've marked trusted in config.
3. **Results stay fenced as untrusted.** dcpr's `McpTool` already does this
   by default.
4. **Start read-only:** register only `readOnlyHint` tools from servers marked
   `trusted = true`, and refuse all others at boot.

Risk: medium. Even fenced, a "read-only" tool is only as honest as its
server.

## Recommendation

Build A first: it's small, safe, and immediately useful (Claude Code can
query Example's clusters through OpsClaw's audit trail). Leave B until a
concrete server is worth the fencing work, and then add it read-only.
