use std::fmt::Write;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::tools::monitoring::{Alert, AlertSeverity, HealthCheck};

/// A single inline keyboard button for Telegram-style interactive messages.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InlineButton {
    pub text: String,
    pub callback_data: String,
}

impl InlineButton {
    pub fn new(text: impl Into<String>, callback_data: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            callback_data: callback_data.into(),
        }
    }
}

/// Delivers alerts and health-check summaries to an external notification channel.
#[async_trait]
pub trait AlertNotifier: Send + Sync {
    /// Send a single alert for a target.
    async fn notify_alert(&self, target_name: &str, alert: &Alert) -> anyhow::Result<()>;

    /// Send a health-check summary (only when there are alerts above the configured threshold).
    async fn notify(&self, target_name: &str, health: &HealthCheck) -> anyhow::Result<()>;

    /// Send a plain-text alert message (for event streams and one-off alerts).
    async fn notify_text(&self, target_name: &str, message: &str) -> anyhow::Result<()>;

    /// Send a message with inline keyboard buttons.
    ///
    /// Channels that don't support buttons fall back to `notify_text` with a
    /// plain-text hint asking the user to reply with one of the button labels.
    async fn notify_with_buttons(
        &self,
        target_name: &str,
        message: &str,
        buttons: &[InlineButton],
    ) -> anyhow::Result<()> {
        // Default: append button labels as text hints and send as plain text.
        let hints: Vec<&str> = buttons.iter().map(|b| b.text.as_str()).collect();
        let fallback = format!("{message}\n\nReply with one of: {}", hints.join(" / "));
        self.notify_text(target_name, &fallback).await
    }
}

// ---------------------------------------------------------------------------
// Telegram implementation
// ---------------------------------------------------------------------------

pub struct TelegramNotifier {
    pub bot_token: String,
    pub chat_id: String,
    pub min_severity: AlertSeverity,
    client: reqwest::Client,
}

impl TelegramNotifier {
    pub fn new(bot_token: String, chat_id: String, min_severity: AlertSeverity) -> Self {
        Self {
            bot_token,
            chat_id,
            min_severity,
            client: reqwest::Client::new(),
        }
    }

    async fn send_message(&self, text: &str) -> anyhow::Result<()> {
        let url = format!("https://api.telegram.org/bot{}/sendMessage", self.bot_token);
        let resp = self
            .client
            .post(&url)
            .json(&serde_json::json!({
                "chat_id": self.chat_id,
                "text": text,
                "parse_mode": "Markdown",
            }))
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("Telegram API error {status}: {body}");
        }
        Ok(())
    }

    /// Send a message with an inline keyboard (one row of buttons).
    async fn send_message_with_buttons(
        &self,
        text: &str,
        buttons: &[InlineButton],
    ) -> anyhow::Result<()> {
        let url = format!("https://api.telegram.org/bot{}/sendMessage", self.bot_token);

        let keyboard_buttons: Vec<serde_json::Value> = buttons
            .iter()
            .map(|b| {
                serde_json::json!({
                    "text": b.text,
                    "callback_data": b.callback_data,
                })
            })
            .collect();

        let resp = self
            .client
            .post(&url)
            .json(&serde_json::json!({
                "chat_id": self.chat_id,
                "text": text,
                "parse_mode": "Markdown",
                "reply_markup": {
                    "inline_keyboard": [keyboard_buttons]
                }
            }))
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("Telegram API error {status}: {body}");
        }
        Ok(())
    }
}

#[async_trait]
impl AlertNotifier for TelegramNotifier {
    async fn notify_alert(&self, target_name: &str, alert: &Alert) -> anyhow::Result<()> {
        if !severity_meets_threshold(&alert.severity, &self.min_severity) {
            return Ok(());
        }
        let text = format_alert(target_name, alert);
        self.send_message(&text).await
    }

    async fn notify(&self, target_name: &str, health: &HealthCheck) -> anyhow::Result<()> {
        let relevant: Vec<&Alert> = health
            .alerts
            .iter()
            .filter(|a| severity_meets_threshold(&a.severity, &self.min_severity))
            .collect();

        if relevant.is_empty() {
            return Ok(());
        }

        let text = format_health_check(target_name, &relevant);
        self.send_message(&text).await
    }

    async fn notify_text(&self, target_name: &str, message: &str) -> anyhow::Result<()> {
        let text = format!(
            "\u{1f534} *{}*\n{}",
            escape_markdown(target_name),
            escape_markdown(message)
        );
        self.send_message(&text).await
    }

    async fn notify_with_buttons(
        &self,
        target_name: &str,
        message: &str,
        buttons: &[InlineButton],
    ) -> anyhow::Result<()> {
        let text = format!(
            "\u{1f534} *{}*\n{}",
            escape_markdown(target_name),
            escape_markdown(message)
        );
        self.send_message_with_buttons(&text, buttons).await
    }
}

// ---------------------------------------------------------------------------
// Null implementation (for tests)
// ---------------------------------------------------------------------------

pub struct NullNotifier;

#[async_trait]
impl AlertNotifier for NullNotifier {
    async fn notify_alert(&self, _target_name: &str, _alert: &Alert) -> anyhow::Result<()> {
        Ok(())
    }

    async fn notify(&self, _target_name: &str, _health: &HealthCheck) -> anyhow::Result<()> {
        Ok(())
    }

    async fn notify_text(&self, _target_name: &str, _message: &str) -> anyhow::Result<()> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Formatting helpers
// ---------------------------------------------------------------------------

pub fn severity_meets_threshold(severity: &AlertSeverity, threshold: &AlertSeverity) -> bool {
    severity_rank(severity) >= severity_rank(threshold)
}

fn severity_rank(s: &AlertSeverity) -> u8 {
    match s {
        AlertSeverity::Info => 0,
        AlertSeverity::Warning => 1,
        AlertSeverity::Critical => 2,
    }
}

pub fn format_alert(target_name: &str, alert: &Alert) -> String {
    let (icon, label) = severity_icon_label(&alert.severity);
    format!(
        "{icon} *{label}* — {target_name}\n{msg}",
        msg = alert.message
    )
}

pub fn format_health_check(target_name: &str, alerts: &[&Alert]) -> String {
    let mut buf = String::new();
    let issue_word = if alerts.len() == 1 { "issue" } else { "issues" };

    let _ = writeln!(
        buf,
        "\u{1f6a8} *{target_name}* health check — {} {issue_word}",
        alerts.len()
    );

    for a in alerts {
        let _ = writeln!(buf, "\n\u{2022} {}", a.message);
    }
    buf
}

fn escape_markdown(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if matches!(c, '*' | '_' | '`' | '[' | ']') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

fn severity_icon_label(s: &AlertSeverity) -> (&'static str, &'static str) {
    match s {
        AlertSeverity::Critical => ("\u{1f6a8}", "CRITICAL"),
        AlertSeverity::Warning => ("\u{26a0}\u{fe0f}", "WARNING"),
        AlertSeverity::Info => ("\u{2139}\u{fe0f}", "INFO"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tools::monitoring::AlertCategory;
    use std::sync::{Arc, Mutex};

    #[test]
    fn format_alert_message_includes_target_name() {
        let alert = Alert {
            severity: AlertSeverity::Critical,
            category: AlertCategory::ContainerDown,
            message: "container vanished".to_string(),
        };
        let text = format_alert("prod-web-1", &alert);
        assert!(text.contains("prod-web-1"));
    }

    /// A notifier that records the text it receives, using only the default
    /// `notify_with_buttons` implementation (which falls back to `notify_text`).
    struct CapturingNotifier {
        captured: Arc<Mutex<Vec<String>>>,
    }

    #[async_trait]
    impl AlertNotifier for CapturingNotifier {
        async fn notify_alert(&self, _target_name: &str, _alert: &Alert) -> anyhow::Result<()> {
            Ok(())
        }
        async fn notify(&self, _target_name: &str, _health: &HealthCheck) -> anyhow::Result<()> {
            Ok(())
        }
        async fn notify_text(&self, _target_name: &str, message: &str) -> anyhow::Result<()> {
            self.captured.lock().unwrap().push(message.to_string());
            Ok(())
        }
        // NOTE: notify_with_buttons is NOT overridden, so the default
        // trait implementation (fallback to notify_text) is used.
    }

    #[tokio::test]
    async fn notify_with_buttons_falls_back_to_text() {
        let captured = Arc::new(Mutex::new(Vec::new()));
        let notifier = CapturingNotifier {
            captured: Arc::clone(&captured),
        };

        let buttons = vec![
            InlineButton::new("Approve", "approve"),
            InlineButton::new("Reject", "reject"),
        ];
        notifier
            .notify_with_buttons("my-target", "something happened", &buttons)
            .await
            .unwrap();

        let msgs = captured.lock().unwrap();
        assert_eq!(msgs.len(), 1);
        assert!(msgs[0].contains("something happened"));
        assert!(msgs[0].contains("Approve"));
        assert!(msgs[0].contains("Reject"));
    }
}
