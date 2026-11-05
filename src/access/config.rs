//! `[access]`: who may see and do what (docs/plans/ACCESS.md).
//!
//! Absent, the preset is `solo`: every signed-in operator sees everything,
//! which is exactly what a deployment predating `[access]` does.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
pub struct AccessCfg {
    pub preset: Preset,
    #[serde(rename = "role", skip_serializing_if = "Vec::is_empty")]
    pub roles: Vec<RoleCfg>,
    /// Custom data classes, in addition to the built-ins.
    #[serde(rename = "class", skip_serializing_if = "Vec::is_empty")]
    pub classes: Vec<ClassCfg>,
    /// Remap which tool calls return which class. First match wins, before
    /// the built-in classification.
    #[serde(rename = "class_rule", skip_serializing_if = "Vec::is_empty")]
    pub class_rules: Vec<ClassRuleCfg>,
    /// Extra redaction patterns.
    #[serde(rename = "redact", skip_serializing_if = "Vec::is_empty")]
    pub redact: Vec<RedactCfg>,
    /// Built-in redaction patterns to switch off, by name.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub disable_builtin_redaction: Vec<String>,
    pub mcp: McpAccessCfg,
    pub elevation: ElevationCfg,
    /// A file of extra Cedar policies, evaluated with the compiled roles.
    /// `forbid`s here override every role.
    pub cedar_policies: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Preset {
    /// One operator: every account sees and does everything (no roles).
    #[default]
    Solo,
    /// Roles decide. Logs and messages are redacted unless a role grants
    /// `:raw`; over MCP, raw needs an elevation.
    Team,
    /// As `team`, and raw data always needs an approved elevation.
    Regulated,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleCfg {
    pub name: String,
    /// IdP groups or app roles (from the token's groups claim) that hold
    /// this role.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub idp_groups: Vec<String>,
    /// Account emails that hold this role, for IdPs without groups (or
    /// local accounts).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub members: Vec<String>,
    /// Target path prefixes: `project`, `project::env`,
    /// `project::env::target`, or `*` for everything.
    #[serde(rename = "where")]
    pub scopes: Vec<String>,
    /// Data classes. `logs` is redacted; `logs:raw` is unredacted (subject
    /// to `elevation`) and implies `logs`.
    #[serde(default)]
    pub data: Vec<String>,
    #[serde(default)]
    pub findings: FindingsLevel,
    #[serde(default)]
    pub actions: ActionsLevel,
    /// How the `:raw` classes of this role are reached.
    #[serde(default)]
    pub elevation: ElevationMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum FindingsLevel {
    #[default]
    None,
    /// Title, severity, status, resource and timeline; no evidence.
    Summary,
    /// Everything, with each piece of evidence still subject to its class.
    Full,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ActionsLevel {
    #[default]
    None,
    /// Ask for mutations (still subject to autonomy and approvals).
    Request,
    /// Request, and decide other people's approvals and elevations.
    Approve,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ElevationMode {
    /// Raw is standing access.
    None,
    /// Raw needs an elevation the person opens themselves, with a reason.
    #[serde(rename = "self")]
    SelfService,
    /// Raw needs an elevation someone else approves.
    #[default]
    Approval,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClassCfg {
    pub name: String,
    /// Results of this class pass through the redactor unless raw.
    #[serde(default)]
    pub redact: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClassRuleCfg {
    /// Tool name, exactly (`kubernetes`, `elasticsearch_search`, …).
    pub tool: String,
    /// Optional substring of the composed command.
    pub contains: Option<String>,
    /// Optional target path prefix the rule is limited to.
    pub r#where: Option<String>,
    pub class: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedactCfg {
    pub name: String,
    /// A regular expression (Rust `regex` syntax).
    pub pattern: String,
    /// Classes it applies to; empty means every redacted class.
    #[serde(default)]
    pub classes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct McpAccessCfg {
    /// Serve OpsClaw's tools over MCP at `/mcp`. Off by default.
    pub enabled: bool,
    /// Tool calls per person per minute (0: unlimited).
    pub calls_per_minute: u32,
    /// Host names MCP clients may use besides loopback (DNS-rebinding
    /// protection), e.g. `opsclaw.example.com`.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub allowed_hosts: Vec<String>,
    /// Raw data over MCP: `elevated` (default outside `solo`), `never`, or
    /// `allow` (default in `solo`).
    pub raw: Option<McpRaw>,
    /// MCP client ids allowed to connect; empty allows any.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub clients: Vec<String>,
}

impl Default for McpAccessCfg {
    fn default() -> Self {
        McpAccessCfg {
            enabled: false,
            calls_per_minute: 60,
            allowed_hosts: Vec::new(),
            raw: None,
            clients: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum McpRaw {
    Allow,
    Elevated,
    Never,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ElevationCfg {
    /// The longest elevation anyone can open.
    pub max_hours: u32,
}

impl Default for ElevationCfg {
    fn default() -> Self {
        ElevationCfg { max_hours: 4 }
    }
}

impl AccessCfg {
    pub fn mcp_raw(&self) -> McpRaw {
        self.mcp.raw.unwrap_or(match self.preset {
            Preset::Solo => McpRaw::Allow,
            _ => McpRaw::Elevated,
        })
    }
}
