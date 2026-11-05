# Access in an enterprise: SSO, least privilege, bring-your-own agent

Status: built (2026-11-05). See "What is built" at the end for what works
today and what is still to come. This supersedes the "Access grants"
sketch in MCP.md.

## The problem in one line

OpsClaw holds broad credentials. Each person should see and do only what
they are entitled to, whether they use the web UI, the CLI, OpsClaw's own
chat, or their own agent over MCP. That includes **OpsClaw's own findings**:
incidents, reports and memory.

## Principles

1. **One identity, from whatever IdP the company uses.** Entra ID, Okta,
   Google Workspace, Keycloak, Auth0, and so on. The only OpsClaw-local
   account is a single audited break-glass admin.
2. **Effective access = OpsClaw's ceiling ∩ the person's grant.** OpsClaw
   never extends beyond what it holds itself.
3. **Every surface uses the same check.** Web, CLI, chat and MCP all reach
   tools through `policy::execute`, and that is where the check sits.
4. **Findings are permissioned in their own right.** On top of that, they
   inherit the sensitivity of the data they were built from.
5. **Agent turns run as the person who asked.** The LLM never sees what that
   person couldn't.
6. **Deny by default, and audit every decision**, including refusals.

## 0. Built for different enterprises: fixed mechanisms, configurable policy

Every enterprise wants something different. A bank wants approvals through
ServiceNow and nothing leaving the EU. A startup wants Google SSO and one
group. So OpsClaw **hard-codes the mechanisms and makes every policy
configurable.**

**Fixed: these hold in every deployment.**
- Every call goes through `policy::execute`. There is no other path.
- Deny by default.
- Secret values are never returned.
- Every decision is audited, hash-chained.
- Findings carry the labels of the data they came from.

**Configurable: each one is a plug-in point with sensible built-ins.**

| Concern | Built-in | Enterprise options |
|---|---|---|
| Sign-in | local, Hanko, any OIDC IdP | SAML through a bridge. SCIM for provisioning and instant deprovisioning |
| Who is who | groups or roles from the IdP token | any claim mapping; attributes such as department, region, on-call status |
| **Decisions** | the TOML grants below, compiled to **Cedar** policies | write Cedar directly, or delegate to an external engine (**OPA**, or the company's own) over HTTP |
| Data classes | `state`, `metrics`, `changes`, `config`, `logs`, `messages` | add custom classes (`pci`, `phi`, `hr`), and remap which tool or resource returns which class |
| Redaction | emails, phones, IBANs, tokens | custom patterns, per class and per jurisdiction (NI numbers, SSNs, BSNs), or an external DLP service |
| Elevation | none / self with reason / approval in OpsClaw | an external workflow: ServiceNow, Jira, Entra PIM, or a webhook that says yes or no |
| Findings levels | none / summary / full | custom levels, and default visibility per environment |
| Bring-your-own agent | logs and messages redacted unless elevated | per class: allow, redact or deny. Allowlist of MCP clients |
| **Which LLM may see what** | one provider for everything | per data class and per environment, e.g. "logs only to Azure OpenAI in the EU; never to a US endpoint" |
| Credentials model | broker (OpsClaw's own) | per target: on-behalf-of (Entra today; others where the backend supports token exchange) |
| Audit | local hash-chained log | also syslog, Splunk HEC, Sentinel, S3/Blob with retention lock |
| Retention | keep | per class: chat, findings and memory expire after N days; legal hold |

**Why Cedar:**
- it is a policy language built for exactly this (principal, action,
  resource, context);
- it has a native Rust crate, so decisions stay in-process and fast;
- it can be analysed: "can anyone in group X ever read raw logs in prod?"
  has a provable answer.

The simple TOML grants compile to Cedar, so small teams never see it, and
large ones can write their own. OPA is the escape hatch for companies that
already standardise on it.

**What OpsClaw supplies to the decision**, every time:
- **Principal:** the person's IdP subject, groups and claims, plus the
  client (web, CLI, or MCP client ID).
- **Action:** the tool and verb, its risk class, and whether it is a read,
  a request or an approval.
- **Resource:** the target's URN path (project, environment, cluster,
  resource), its data classes, and for findings their labels.
- **Context:** time, elevation in force, source IP, and the LLM provider
  the data would flow to.

**Presets**, so nobody starts from a blank page:
- `solo`: one operator, everything visible. What runs today.
- `team`: SSO; findings and logs by group, redacted.
- `regulated`: raw access only through elevation with approval, external
  audit sink, LLM routing by class, and retention on.

## 1. Identity: any OIDC IdP

OpsClaw speaks **standard OIDC**, so it isn't tied to Entra.

```toml
[auth]
provider = "oidc"
issuer = "https://login.microsoftonline.com/<tenant>/v2.0"   # or Okta, Google, Keycloak…
client_id = "…"
client_secret = "store:oidc-client-secret"
groups_claim = "roles"    # "groups" for Okta and Keycloak; Google needs the Directory API
```

- **Discovery** uses `/.well-known/openid-configuration`. Tokens are
  checked with the IdP's JWKS.
- **SAML-only IdPs** connect through an OIDC bridge such as Keycloak, or
  Hanko where it fits. OpsClaw does not implement SAML.
- **The existing `local` and `hanko` providers stay**, for small setups.

**OpsClaw is its own OAuth authorization server for its clients**, and
federates login to the configured IdP.
- **Why:** IdPs differ in what they support. Entra has no dynamic client
  registration, and Google's groups need an extra API call. MCP clients
  expect a standard OAuth 2.1 server.
- **How:**
  - The CLI and MCP clients run a normal OAuth flow against OpsClaw:
    browser sign-in or device code, with PKCE.
  - OpsClaw sends the person to their IdP, then issues its **own
    short-lived tokens** (about an hour) for OpsClaw's API.
  - It publishes the MCP-required metadata (RFC 9728 and RFC 8414). MCP
    clients register through client ID metadata documents or a fixed
    public client.
- **Offboarding:** each refresh re-checks the IdP (the refresh token, or
  userinfo). A person disabled there loses OpsClaw within the hour.
  Never-expiring `ops_` tokens are retired.

## 2. Authorisation: OpsClaw is the broker

Supporting any IdP settles the model:
- **The core is the broker.** OpsClaw uses its own credentials and enforces
  grants derived from the person's IdP groups or roles. It works the same
  for every IdP and every backend.
- **Optional, Entra only:** on-behalf-of for Azure and AKS. OpsClaw
  exchanges the person's Entra token, so Azure's own RBAC decides as well.
  This is defence in depth, configured per target; it is not required.

A consequence: under the broker, OpsClaw *can* let someone see more than
they could reach directly, for example prod read-only for on-call. Whether
it does is a grant decision, per environment.

## 3. Grants

A grant comes from IdP groups or roles. Several grants combine as their
union, which is then intersected with OpsClaw's ceiling.

```toml
[[access.role]]
idp_group = "opsclaw-sandbox-readers"
where     = ["example::sandbox"]          # target prefixes (topology URNs later)
data      = ["state", "metrics", "changes"]
findings  = "summary"                     # none | summary | full
actions   = "none"                        # none | request | approve

[[access.role]]
idp_group = "opsclaw-sandbox-oncall"
where     = ["example::sandbox", "example::dev"]
data      = ["state", "metrics", "changes", "logs"]   # logs: redacted
findings  = "full"
actions   = "request"

[[access.role]]
idp_group = "opsclaw-data-investigators"
where     = ["example::sandbox"]
data      = ["logs:raw", "messages:raw"]  # raw only with elevation, see §4
elevation = "approval"                    # none | self (with reason) | approval
```

**Data classes.** Each tool and each resource declares which classes it
returns.

| Class | Examples | Default |
|---|---|---|
| `state` | pods, events, deployments, Azure resource metadata | by grant |
| `metrics` | Prometheus | by grant |
| `changes` | Argo CD history, ReplicaSet revisions, Azure activity log | by grant |
| `config` | ConfigMaps, app settings | opt-in |
| `logs` | pod logs, Elasticsearch | **opt-in, redacted** |
| `messages` | Service Bus peeks, EventStore events | **opt-in, redacted** |

**Never exposed, whatever the grant:** secret values and blob contents.

## 4. Protecting logs and messages

These classes carry personal data (payroll, contracts, identity checks). The
people who need them still get them, at three levels:

1. **No access**, the default. Tools that return logs or messages don't
   appear, and calls to them are refused.
2. **Redacted (`logs`, `messages`).** Results pass through a personal-data
   redactor first: emails, phone numbers, IBANs, national ID formats, and
   JWT or bearer strings (the secret scrubber already handles the last).
   Error messages, stack traces, counts and timestamps survive, and that is
   what diagnosis mostly needs.
3. **Raw (`logs:raw`, `messages:raw`).** Never on standing access.
   - **Time-boxed elevation:** the person states a reason, gets a window (say
     4 hours) scoped to one environment, and, if `elevation = "approval"`,
     someone else approves it.
   - The window shows in the UI and expires on its own.

**Whatever the level:**
- every read is audited with its query or stream, its target and the
  person's level;
- raw reads appear in a weekly access report for the data owner;
- over MCP, results are **always redacted unless the person is elevated**,
  because their agent sends them on to its own LLM provider.

## 5. Findings: their own permission, plus inherited sensitivity

OpsClaw *produces* information from privileged reads: incidents, scan
reports, chat answers, postmortems and memory.

**Who may see findings at all.** `findings` on a grant, per target:
- `none`: no incidents or reports for that target.
- `summary`: title, severity, status, affected resource, timeline. No
  evidence.
- `full`: everything, subject to the label rule below.

**Labels.**
- Every tool call in a turn records its `(target, data class)`, and the
  finding carries all of those labels.
- Each piece of evidence is shown only if the reader holds that class.
  Otherwise it shows "evidence hidden: needs logs on sandbox". Log evidence
  shows redacted unless the reader is elevated.
- A finding can also be **restricted by hand**, for example a security
  incident, to named people or a group. That overrides everything else.

**Where the labels apply:**
- **Chat rooms** show each message only to those allowed to see it.
- **Memory (Hindsight):** every retained fact is tagged with its labels, and
  recall filters by the asker's grant. The fallback is one memory bank per
  (environment, sensitivity).
- **Notifications** (Slack, email, push) count as reads. A channel gets only
  the findings level its least-privileged member holds, normally a summary
  plus a link.
- **Scheduled scans** run with OpsClaw's own scope. Their outputs are
  labelled the same way.

## 6. Bring-your-own agent (MCP)

Same identity, same grant, same `policy::execute`.

- **`tools/list` is filtered.** A caller sees only the tools and targets
  their grant allows.
- **Findings are MCP resources**, filtered by the same rules as in the UI.
- **Logs and messages are redacted** unless the caller is elevated (§4).
- **Rate cap per person.** Their agent drives the load and OpsClaw pays no
  LLM cost, so the cap protects the backends.
- **Actions from MCP are always `request`**, never direct, whatever the
  autonomy level.

## 7. Actions and approvals

- Requesting needs `actions = "request"` on the target.
- Approving needs `actions = "approve"` on the target.
- The requester can never approve their own request (four eyes).
- Elevation approvals follow the same rule.

## 8. Audit

Every decision (allowed, refused, elevated, approved) records:
- who: the IdP subject and email;
- the client: web, CLI, or an MCP client ID;
- the tool, target, data class and redaction level;
- the grant that decided it.

The audit chain stays hash-chained and is exportable to a SIEM.

## 9. Build order

1. **Generic OIDC sign-in**, with OpsClaw as the OAuth server for the CLI.
   Retire never-expiring tokens.
2. **`Principal::User`, data classes, and the decision point** in
   `policy::execute`. This uses Cedar, with the TOML grants compiled to
   Cedar and the presets. Turns run as the asking user. Leave room for an
   external engine (OPA), but don't build it yet.
3. **Findings permissions and labels**, and filtered reads for incidents,
   chat, SSE and notifications.
4. **The redactor**, and time-boxed elevation for raw logs and messages.
5. **The MCP server** on top: filtered tools, findings as resources.
6. **Labelled memory in Hindsight.** Optional Entra on-behalf-of for Azure
   and AKS.
7. **As enterprises ask:**
   - routing to an LLM by data class;
   - external elevation workflows;
   - SIEM sinks;
   - retention;
   - SCIM;
   - OPA.

   Each is a plug-in behind an interface that exists from step 2.

Steps 1–3 come before anyone but the operator uses OpsClaw. Steps 4–5 are
what "use your own agent" needs.

## Open question

None for the design: whether grants may cover prod for people without
their own prod access is now a policy each enterprise sets. For Example
that's for later, since prod is out of scope for now.

## What is built

**Configure it** (`config.toml`):

```toml
[auth]
provider = "oidc"
[auth.oidc]
issuer = "https://login.microsoftonline.com/<tenant>/v2.0"
client_id = "…"
client_secret = "store:oidc-client-secret"
redirect_url = "https://opsclaw.example.com/api/auth/oidc/callback"
groups_claim = "roles"          # Entra app roles; "groups" for Okta/Keycloak
auto_create = true
allowed_domains = ["example.com"]
# session_hours = 8, cli_token_hours = 24

[access]
preset = "team"                 # solo | team | regulated
# cedar_policies = "access.cedar"   # extra Cedar; forbids win

[access.mcp]
enabled = true
# calls_per_minute = 60, allowed_hosts = ["opsclaw.example.com"], raw = "elevated"

[[access.role]]
name = "sandbox-oncall"
idp_groups = ["OpsClaw.Sandbox.Oncall"]   # or members = ["alice@example.com"]
where = ["example::sandbox"]
data = ["state", "metrics", "changes", "logs"]
findings = "full"
actions = "request"

[[access.role]]
name = "investigators"
idp_groups = ["OpsClaw.Investigators"]
where = ["example::sandbox"]
data = ["logs:raw", "messages:raw"]
elevation = "approval"
```

**Working now:**
- **Access check** in `policy::execute` for every command, as the asker,
  with the class computed from the composed command (`access::classes`).
  Refusals are audited as `denied`.
- **Cedar** (`cedar-policy`): roles compile to Cedar, plus built-ins
  (secrets never, presets, MCP raw rule) and an optional custom file.
  `opsclaw-cli access policies` prints the result; `access explain` names
  the policy that decided.
- **Redaction** of redacted classes (`config`, `logs`, `messages`, `host`,
  custom): emails, phone numbers, IBANs (mod-97 checked), card numbers
  (Luhn checked), UK NI numbers, US SSNs, JWTs, bearer tokens, and custom
  patterns.
- **Elevations:** `/api/access/elevations` (request, approve, deny,
  revoke). Self-service or approval per role, never your own approval,
  window capped by `[access.elevation] max_hours`, every step audited.
- **Labels on findings:** incidents and chat answers record what they were
  built from. Incident API, the `list_incidents` tool, chat history, the
  live web stream and chat replay to the model all show each reader what
  they may see (hidden, redacted, or in full). Environment chat rooms need
  access to that environment. Incidents can be restricted by hand
  (`opsclaw-cli access restrict`). Outside `solo`, pages carry only a
  summary.
- **Memory:** outside `solo`, what goes into Hindsight is redacted first.
- **SSO:** generic OIDC (code + PKCE, ID token verified against JWKS), with
  account creation on first sign-in, groups stored at each sign-in, short
  web sessions, and expiring CLI tokens.
- **MCP** at `/mcp` (streamable HTTP, off by default): `ops_` bearer
  token from `opsclaw-cli login`, a filtered `tools/list`, calls as the
  person with `via = mcp`, redacted unless elevated, mutations always
  queued for approval, a rate cap per person, and an optional client
  allowlist.

**Not built yet:**
- OpsClaw as a full OAuth authorization server for MCP clients (RFC 9728
  metadata, client registration). Today MCP clients use the CLI token.
- Hindsight memory labelled per fact. Today it is redacted at retain.
- External decision engines (OPA), external elevation workflows
  (ServiceNow, PIM), SIEM sinks, retention, SCIM, Entra on-behalf-of.
- Routing data to an LLM by class. A Cedar `forbid` on
  `OpsClaw::Agent` already stops the agent reading a class.
- The MCP client id in the audit row (it is in the logs).
- Web UI screens for elevations and access (the API exists).

