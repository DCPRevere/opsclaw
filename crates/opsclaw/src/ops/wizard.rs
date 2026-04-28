//! Composable interactive wizards for adding projects, environments,
//! and targets. The three CLI verbs (`config project add`,
//! `config env add`, `config target add`) all call into this module
//! at different entry points; each wizard offers to walk into the next
//! step inline so users don't have to remember the right command order.
//!
//! Hierarchy: project > environment > target. Targets always live under
//! an environment; environments always live under a project.

use anyhow::{Context, Result, bail};
use console::style;
use dialoguer::{Confirm, Input, Select};

use crate::ops::setup::{
    load_existing_config, opsclaw_config_path, step_autonomy, step_connection_type,
    step_kubernetes_target, step_local_target, step_ssh_target, step_target_context,
};
use crate::ops_config::{ConnectionType, EnvironmentConfig, OpsConfig, ProjectConfig};

const NEW_SENTINEL: &str = "+ Create new";

/// Pick an existing project by name, or signal that the user wants
/// to create one inline. Returns `None` for "create new" (or when
/// the list is empty — in which case we announce that and fall
/// through to the create-new path).
fn pick_project_or_new(cfg: &OpsConfig, prompt: &str) -> Result<Option<String>> {
    if cfg.projects.is_empty() {
        println!(
            "  {} No projects configured yet — let's create one first.",
            style("›").cyan()
        );
        return Ok(None);
    }
    let mut items: Vec<String> = cfg.projects.iter().map(|p| p.name.clone()).collect();
    items.push(NEW_SENTINEL.into());
    let idx = Select::new()
        .with_prompt(prompt)
        .items(&items)
        .default(0)
        .interact()?;
    if idx == items.len() - 1 {
        Ok(None)
    } else {
        Ok(Some(items[idx].clone()))
    }
}

/// Pick an existing environment under `project_name`, or signal "create
/// new". Returns `None` for "create new" (or when the list is empty —
/// in which case we announce that and fall through).
fn pick_env_or_new(cfg: &OpsConfig, project_name: &str, prompt: &str) -> Result<Option<String>> {
    let project = cfg
        .projects
        .iter()
        .find(|p| p.name == project_name)
        .with_context(|| format!("project '{project_name}' not found"))?;
    if project.environments.is_empty() {
        println!(
            "  {} Project '{project_name}' has no environments yet — let's create one.",
            style("›").cyan()
        );
        return Ok(None);
    }
    let mut items: Vec<String> = project
        .environments
        .iter()
        .map(|e| e.name.clone())
        .collect();
    items.push(NEW_SENTINEL.into());
    let idx = Select::new()
        .with_prompt(prompt)
        .items(&items)
        .default(0)
        .interact()?;
    if idx == items.len() - 1 {
        Ok(None)
    } else {
        Ok(Some(items[idx].clone()))
    }
}

/// Prompt for a project name + optional description, then push a new
/// `ProjectConfig` into the config in memory. Does not save.
fn prompt_new_project(cfg: &mut OpsConfig) -> Result<String> {
    println!();
    println!("  {}", style("Add Project").cyan().bold());
    let name: String = Input::new().with_prompt("Project name").interact_text()?;
    if cfg.projects.iter().any(|p| p.name == name) {
        bail!("A project named '{name}' already exists.");
    }
    let description: String = Input::new()
        .with_prompt("Description (leave blank to skip)")
        .allow_empty(true)
        .interact_text()?;
    cfg.projects.push(ProjectConfig {
        name: name.clone(),
        description: if description.is_empty() {
            None
        } else {
            Some(description)
        },
        context_file: None,
        owners: None,
        environments: Vec::new(),
    });
    Ok(name)
}

/// Prompt for an environment name (with default `default`) and push a
/// new `EnvironmentConfig` under `project_name`. Does not save.
fn prompt_new_env(cfg: &mut OpsConfig, project_name: &str) -> Result<String> {
    println!();
    println!("  {}", style("Add Environment").cyan().bold());
    let name: String = Input::new()
        .with_prompt("Environment name")
        .default("default".into())
        .interact_text()?;
    let project = cfg
        .projects
        .iter_mut()
        .find(|p| p.name == project_name)
        .expect("project must exist by this point");
    if project.environments.iter().any(|e| e.name == name) {
        bail!("Environment '{name}' already exists in project '{project_name}'.");
    }
    project.environments.push(EnvironmentConfig {
        name: name.clone(),
        ..EnvironmentConfig::default()
    });
    Ok(name)
}

/// Prompt for a fresh target's connection details, autonomy, and optional
/// context, then push it under `project_name::env_name`. Does not save.
async fn prompt_new_target(
    cfg: &mut OpsConfig,
    project_name: &str,
    env_name: &str,
) -> Result<String> {
    println!();
    println!("  {}", style("Add Target").cyan().bold());

    let connection_type = step_connection_type()?;
    let mut target_result = match connection_type {
        ConnectionType::Ssh => step_ssh_target().await?,
        ConnectionType::Local => step_local_target()?,
        ConnectionType::Kubernetes => step_kubernetes_target()?,
    };
    target_result.config.context_file = step_target_context(&target_result.config.name)?;
    target_result.config.autonomy = step_autonomy()?;
    let target_name = target_result.config.name.clone();

    let project = cfg
        .projects
        .iter_mut()
        .find(|p| p.name == project_name)
        .expect("project must exist by this point");
    let env = project
        .environments
        .iter_mut()
        .find(|e| e.name == env_name)
        .expect("env must exist by this point");

    if env.targets.iter().any(|t| t.name == target_name) {
        bail!("A target named '{target_name}' already exists in {project_name}::{env_name}.",);
    }

    env.targets.push(target_result.config);
    Ok(target_name)
}

/// Persist `cfg` to disk and print a confirmation tied to `summary`.
async fn save_with_summary(cfg: &mut OpsConfig, summary: &str) -> Result<()> {
    let path = opsclaw_config_path()?;
    cfg.config_path = path.clone();
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    cfg.save().await?;
    println!(
        "  {} {}  →  {}",
        style("✓").green().bold(),
        summary,
        style(path.display()).underlined()
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Public entry points: composable wizards
// ---------------------------------------------------------------------------

/// `config project add` — create a project, then optionally chain into
/// env + target creation. End state: as much of the project/env/target
/// trio as the user opted in to, all written in one save.
pub async fn run_project_add() -> Result<()> {
    let path = opsclaw_config_path()?;
    let mut cfg = load_existing_config(&path);
    cfg.config_path = path.clone();

    let project_name = prompt_new_project(&mut cfg)?;

    let mut summary = format!("Project '{project_name}' added");

    let want_env = Confirm::new()
        .with_prompt("Add a first environment now?")
        .default(true)
        .interact()?;
    if want_env {
        let env_name = prompt_new_env(&mut cfg, &project_name)?;
        summary = format!("{project_name}::{env_name} added");

        let want_target = Confirm::new()
            .with_prompt("Add a first target now?")
            .default(true)
            .interact()?;
        if want_target {
            let target_name = prompt_new_target(&mut cfg, &project_name, &env_name).await?;
            summary = format!("{project_name}::{env_name}::{target_name} added");
        }
    }

    save_with_summary(&mut cfg, &summary).await
}

/// `config env add` — pick a project (or create one inline), then
/// create an env, then optionally chain into a target.
pub async fn run_env_add() -> Result<()> {
    let path = opsclaw_config_path()?;
    let mut cfg = load_existing_config(&path);
    cfg.config_path = path.clone();

    let project_name = match pick_project_or_new(&cfg, "Project")? {
        Some(name) => name,
        None => prompt_new_project(&mut cfg)?,
    };

    let env_name = prompt_new_env(&mut cfg, &project_name)?;

    let mut summary = format!("{project_name}::{env_name} added");

    let want_target = Confirm::new()
        .with_prompt("Add a first target now?")
        .default(true)
        .interact()?;
    if want_target {
        let target_name = prompt_new_target(&mut cfg, &project_name, &env_name).await?;
        summary = format!("{project_name}::{env_name}::{target_name} added");
    }

    save_with_summary(&mut cfg, &summary).await
}

/// `config target add` — pick a project (or create one), pick an env
/// under it (or create one), then add the target.
pub async fn run_target_add() -> Result<()> {
    let path = opsclaw_config_path()?;
    let mut cfg = load_existing_config(&path);
    cfg.config_path = path.clone();

    let project_name = match pick_project_or_new(&cfg, "Project")? {
        Some(name) => name,
        None => prompt_new_project(&mut cfg)?,
    };

    let env_name = match pick_env_or_new(&cfg, &project_name, "Environment")? {
        Some(name) => name,
        None => prompt_new_env(&mut cfg, &project_name)?,
    };

    let target_name = prompt_new_target(&mut cfg, &project_name, &env_name).await?;
    let summary = format!("{project_name}::{env_name}::{target_name} added");

    save_with_summary(&mut cfg, &summary).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg_with(projects: Vec<(&str, Vec<&str>)>) -> OpsConfig {
        let mut cfg = OpsConfig::default();
        for (pname, envs) in projects {
            cfg.projects.push(ProjectConfig {
                name: pname.into(),
                description: None,
                context_file: None,
                owners: None,
                environments: envs
                    .into_iter()
                    .map(|e| EnvironmentConfig {
                        name: e.into(),
                        ..EnvironmentConfig::default()
                    })
                    .collect(),
            });
        }
        cfg
    }

    #[test]
    fn pick_project_returns_none_when_empty() {
        let cfg = cfg_with(vec![]);
        // Empty cfg short-circuits before any UI; safe to call.
        let result = pick_project_or_new(&cfg, "test").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn pick_env_short_circuits_when_project_has_no_envs() {
        let cfg = cfg_with(vec![("sacra", vec![])]);
        let result = pick_env_or_new(&cfg, "sacra", "test").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn pick_env_errors_on_missing_project() {
        let cfg = cfg_with(vec![("sacra", vec!["prod"])]);
        let err = pick_env_or_new(&cfg, "missing", "test").unwrap_err();
        assert!(err.to_string().contains("missing"));
    }
}
