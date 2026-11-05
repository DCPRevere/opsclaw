//! What a reader may see of a finding (an incident).

use super::{Access, FindingsLevel, Label, Via};
use crate::domain::{Incident, Principal};

/// An incident as one reader may see it. `None` from [`incident_view`]
/// means they may not know it exists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncidentView {
    pub level: FindingsLevel,
    /// Evidence, hypothesis and recommendation, or `None` when withheld.
    pub signals: Option<String>,
    pub hypothesis: Option<String>,
    pub recommended_action: Option<String>,
    /// Why something is withheld, for the reader.
    pub note: Option<String>,
}

pub async fn incident_view(
    access: &Access,
    repo: &dyn crate::db::AccessRepo,
    principal: &Principal,
    via: Via,
    incident: &Incident,
) -> Option<IncidentView> {
    let id = incident.id.to_string();
    if let Ok(Some(list)) = repo.restricted("incident", &id).await
        && !access.is_listed(principal, &list).await
    {
        return None;
    }
    let labels: Vec<Label> = repo.labels("incident", &id).await.unwrap_or_default();
    let target = incident.target.to_string();
    let view = access.view(principal, via, &target, &labels).await;
    match view.level {
        FindingsLevel::None => None,
        FindingsLevel::Summary => Some(IncidentView {
            level: FindingsLevel::Summary,
            signals: None,
            hypothesis: None,
            recommended_action: None,
            note: Some("evidence withheld: you have summary access to findings here".into()),
        }),
        FindingsLevel::Full => {
            if let Some(l) = view.hidden.first() {
                return Some(IncidentView {
                    level: FindingsLevel::Full,
                    signals: None,
                    hypothesis: None,
                    recommended_action: None,
                    note: Some(format!(
                        "evidence withheld: it was built from {} on {}, which you don't have \
                         access to",
                        l.class, l.target
                    )),
                });
            }
            let mut classes: Vec<&str> = view.redact.iter().map(|l| l.class.as_str()).collect();
            classes.sort();
            classes.dedup();
            let redact = |text: &str| {
                let mut out = text.to_string();
                for c in &classes {
                    out = access.redact(c, &out);
                }
                out
            };
            Some(IncidentView {
                level: FindingsLevel::Full,
                signals: Some(redact(&incident.signals)),
                hypothesis: Some(redact(&incident.hypothesis)),
                recommended_action: incident.recommended_action.as_deref().map(redact),
                note: (!classes.is_empty())
                    .then(|| format!("personal data redacted ({})", classes.join(", "))),
            })
        }
    }
}
