//! Roles compiled to Cedar, plus the built-in policies, and evaluation.
//!
//! Entities:
//! - principals: `OpsClaw::User::"<account uuid>"` (parents: the
//!   `OpsClaw::Role`s it holds and its `OpsClaw::Group`s),
//!   `OpsClaw::Agent::"opsclaw"`, `OpsClaw::System::"daemon"`;
//! - actions: `OpsClaw::Action::"read" | "request" | "approve" |
//!   "view_findings" | "elevate"`;
//! - resources: `OpsClaw::Scope::"<fq path>"`, whose ancestors are every
//!   shorter prefix and finally `OpsClaw::Scope::"*"`.
//!
//! Context, always present: `class`, `raw`, `elevated`,
//! `elevation_approved`, `client` (`internal|web|cli|mcp|channel`) and
//! `level` (findings: `summary|full`).

use std::collections::{HashMap, HashSet};
use std::str::FromStr;

use cedar_policy::{
    Authorizer, Context, Decision, Entities, Entity, EntityId, EntityTypeName, EntityUid,
    PolicySet, Request, RestrictedExpression,
};

use super::config::{AccessCfg, ActionsLevel, ElevationMode, FindingsLevel, McpRaw, Preset};

pub(super) fn lit(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}

fn list(items: &[String]) -> String {
    format!("[{}]", items.iter().map(|s| lit(s)).collect::<Vec<_>>().join(", "))
}

/// The Cedar source for `cfg`: built-ins, then roles, then nothing else
/// (a custom file is appended by the caller).
pub(super) fn compile(cfg: &AccessCfg) -> String {
    let mut out = String::from(
        "// Built in.\n\
         @id(\"builtin:agent\")\n\
         permit(principal is OpsClaw::Agent, action, resource);\n\
         @id(\"builtin:system\")\n\
         permit(principal is OpsClaw::System, action, resource);\n\
         @id(\"builtin:never-secrets\")\n\
         forbid(principal is OpsClaw::User, action, resource) when { context.class == \"secrets\" };\n",
    );
    if cfg.preset == Preset::Solo {
        out.push_str(
            "@id(\"preset:solo\")\npermit(principal is OpsClaw::User, action, resource);\n",
        );
    }
    if cfg.preset == Preset::Regulated {
        out.push_str(
            "@id(\"preset:regulated:raw-needs-approval\")\n\
             forbid(principal is OpsClaw::User, action == OpsClaw::Action::\"read\", resource) \
             when { context.raw && !context.elevation_approved };\n",
        );
    }
    match cfg.mcp_raw() {
        McpRaw::Allow => {}
        McpRaw::Elevated => out.push_str(
            "@id(\"mcp:raw-needs-elevation\")\n\
             forbid(principal, action == OpsClaw::Action::\"read\", resource) \
             when { context.client == \"mcp\" && context.raw && !context.elevated };\n",
        ),
        McpRaw::Never => out.push_str(
            "@id(\"mcp:never-raw\")\n\
             forbid(principal, action == OpsClaw::Action::\"read\", resource) \
             when { context.client == \"mcp\" && context.raw };\n",
        ),
    }

    for role in &cfg.roles {
        let who = format!("principal in OpsClaw::Role::{}", lit(&role.name));
        let redacted: Vec<String> = {
            let mut v: Vec<String> =
                role.data.iter().map(|d| d.strip_suffix(":raw").unwrap_or(d).to_string()).collect();
            v.sort();
            v.dedup();
            v
        };
        let raw: Vec<String> =
            role.data.iter().filter_map(|d| d.strip_suffix(":raw")).map(String::from).collect();
        for scope in &role.scopes {
            let res = format!("resource in OpsClaw::Scope::{}", lit(scope));
            let tag = |what: &str| lit(&format!("role:{}:{what}:{scope}", role.name));
            if !redacted.is_empty() {
                out.push_str(&format!(
                    "@id({})\npermit({who}, action == OpsClaw::Action::\"read\", {res}) \
                     when {{ {}.contains(context.class) && !context.raw }};\n",
                    tag("read"),
                    list(&redacted)
                ));
            }
            if !raw.is_empty() {
                let cond = match role.elevation {
                    ElevationMode::None => "",
                    ElevationMode::SelfService => " && context.elevated",
                    ElevationMode::Approval => " && context.elevation_approved",
                };
                out.push_str(&format!(
                    "@id({})\npermit({who}, action == OpsClaw::Action::\"read\", {res}) \
                     when {{ {}.contains(context.class) && context.raw{cond} }};\n",
                    tag("raw"),
                    list(&raw)
                ));
                if role.elevation != ElevationMode::None {
                    out.push_str(&format!(
                        "@id({})\npermit({who}, action == OpsClaw::Action::\"elevate\", {res}) \
                         when {{ {}.contains(context.class) }};\n",
                        tag("elevate"),
                        list(&raw)
                    ));
                }
            }
            match role.findings {
                FindingsLevel::None => {}
                FindingsLevel::Summary => out.push_str(&format!(
                    "@id({})\npermit({who}, action == OpsClaw::Action::\"view_findings\", {res}) \
                     when {{ context.level == \"summary\" }};\n",
                    tag("findings")
                )),
                FindingsLevel::Full => out.push_str(&format!(
                    "@id({})\npermit({who}, action == OpsClaw::Action::\"view_findings\", {res});\n",
                    tag("findings")
                )),
            }
            match role.actions {
                ActionsLevel::None => {}
                ActionsLevel::Request => out.push_str(&format!(
                    "@id({})\npermit({who}, action == OpsClaw::Action::\"request\", {res});\n",
                    tag("request")
                )),
                ActionsLevel::Approve => out.push_str(&format!(
                    "@id({})\npermit({who}, action in [OpsClaw::Action::\"request\", \
                     OpsClaw::Action::\"approve\"], {res});\n",
                    tag("approve")
                )),
            }
        }
    }
    out
}

pub(super) fn parse(src: &str) -> crate::Result<PolicySet> {
    PolicySet::from_str(src)
        .map_err(|e| crate::Error::Config(format!("access policies do not parse: {e}")))
}

fn type_name(t: &str) -> EntityTypeName {
    EntityTypeName::from_str(t).expect("static entity type parses")
}

pub(super) fn uid(t: &str, id: &str) -> EntityUid {
    EntityUid::from_type_name_and_id(type_name(t), EntityId::new(id))
}

/// Who is asking, as Cedar sees it.
pub(super) struct CedarPrincipal {
    pub uid: EntityUid,
    pub roles: Vec<String>,
    pub groups: Vec<String>,
    pub email: Option<String>,
}

pub(super) struct Ask<'a> {
    pub action: &'a str,
    pub scope: &'a str,
    pub class: &'a str,
    pub raw: bool,
    pub elevated: bool,
    pub elevation_approved: bool,
    pub client: &'a str,
    pub level: &'a str,
}

/// The answer, with the policy ids that decided it (for audit and
/// `access explain`).
pub(super) struct Answer {
    pub allowed: bool,
    pub because: Vec<String>,
    pub errors: Vec<String>,
}

fn scope_chain(scope: &str) -> Vec<String> {
    let parts: Vec<&str> = scope.split("::").collect();
    let mut chain: Vec<String> = (1..=parts.len()).map(|n| parts[..n].join("::")).collect();
    chain.reverse();
    if scope != "*" {
        chain.push("*".into());
    }
    chain
}

pub(super) fn ask(policies: &PolicySet, who: &CedarPrincipal, q: &Ask<'_>) -> Answer {
    let mut entities = Vec::new();
    let mut parents = HashSet::new();
    for r in &who.roles {
        let u = uid("OpsClaw::Role", r);
        entities.push(Entity::new_no_attrs(u.clone(), HashSet::new()));
        parents.insert(u);
    }
    for g in &who.groups {
        let u = uid("OpsClaw::Group", g);
        entities.push(Entity::new_no_attrs(u.clone(), HashSet::new()));
        parents.insert(u);
    }
    let mut attrs = HashMap::new();
    if let Some(email) = &who.email {
        attrs.insert("email".to_string(), RestrictedExpression::new_string(email.clone()));
    }
    match Entity::new(who.uid.clone(), attrs, parents) {
        Ok(e) => entities.push(e),
        Err(e) => {
            return Answer { allowed: false, because: vec![], errors: vec![e.to_string()] };
        }
    }
    let chain = scope_chain(q.scope);
    for (i, s) in chain.iter().enumerate() {
        let parent: HashSet<EntityUid> =
            chain.get(i + 1).map(|p| uid("OpsClaw::Scope", p)).into_iter().collect();
        entities.push(Entity::new_no_attrs(uid("OpsClaw::Scope", s), parent));
    }
    let entities = match Entities::from_entities(entities, None) {
        Ok(e) => e,
        Err(e) => return Answer { allowed: false, because: vec![], errors: vec![e.to_string()] },
    };
    let s = |v: &str| RestrictedExpression::new_string(v.to_string());
    let b = RestrictedExpression::new_bool;
    let context = Context::from_pairs([
        ("class".to_string(), s(q.class)),
        ("raw".to_string(), b(q.raw)),
        ("elevated".to_string(), b(q.elevated)),
        ("elevation_approved".to_string(), b(q.elevation_approved)),
        ("client".to_string(), s(q.client)),
        ("level".to_string(), s(q.level)),
    ])
    .expect("static context keys are unique");
    let request = match Request::new(
        who.uid.clone(),
        uid("OpsClaw::Action", q.action),
        uid("OpsClaw::Scope", q.scope),
        context,
        None,
    ) {
        Ok(r) => r,
        Err(e) => return Answer { allowed: false, because: vec![], errors: vec![e.to_string()] },
    };
    let response = Authorizer::new().is_authorized(&request, policies, &entities);
    let because = response
        .diagnostics()
        .reason()
        .map(|id| {
            policies
                .policy(id)
                .and_then(|p| p.annotation("id").map(str::to_string))
                .unwrap_or_else(|| id.to_string())
        })
        .collect();
    let errors = response.diagnostics().errors().map(|e| e.to_string()).collect();
    Answer { allowed: response.decision() == Decision::Allow, because, errors }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_chains_run_up_to_the_root() {
        assert_eq!(scope_chain("a::b::c"), vec!["a::b::c", "a::b", "a", "*"]);
        assert_eq!(scope_chain("*"), vec!["*"]);
    }

    #[test]
    fn literals_escape_quotes() {
        assert_eq!(lit(r#"a"b\c"#), r#""a\"b\\c""#);
    }
}
