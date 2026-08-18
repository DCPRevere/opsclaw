//! Daemon logging setup shared by both binary entry points.

use std::sync::Once;

/// Install the scrubbed tracing subscriber. `OPSCLAW_LOG_FORMAT=json` emits
/// one JSON object per line with current-span fields for production log tools;
/// every other value keeps the human-readable development format.
pub fn init_daemon() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| "opsclaw=info,tower_http=info".into());
    let writer =
        crate::policy::ScrubbingMakeWriter::stdout(crate::policy::Scrubber::global().clone());
    if std::env::var("OPSCLAW_LOG_FORMAT").as_deref() == Ok("json") {
        tracing_subscriber::fmt()
            .json()
            .flatten_event(true)
            .with_current_span(true)
            .with_span_list(false)
            .with_env_filter(filter)
            .with_writer(writer)
            .init();
    } else {
        tracing_subscriber::fmt().with_env_filter(filter).with_writer(writer).init();
    }
    install_panic_hook();
}

/// Route panics through tracing before chaining the normal hook. The current
/// request/turn span is retained, so JSON logs keep the correlation fields.
fn install_panic_hook() {
    static INSTALL: Once = Once::new();
    INSTALL.call_once(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            let message = info
                .payload()
                .downcast_ref::<&str>()
                .map(|value| value.to_string())
                .or_else(|| info.payload().downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "panic (non-string payload)".to_string());
            let location =
                info.location().map(ToString::to_string).unwrap_or_else(|| "?".to_string());
            tracing::error!(panic_location = %location, "panic: {message}");
            previous(info);
        }));
    });
}

#[cfg(test)]
mod tests {
    use tracing_subscriber::layer::SubscriberExt;

    #[test]
    fn json_logs_include_current_span_and_scrub_secrets() {
        let scrubber = std::sync::Arc::new(crate::policy::Scrubber::new());
        scrubber.register("TEST_TOKEN", "secret-value");
        let (writer, captured) = crate::policy::ScrubbingMakeWriter::capturing(scrubber);
        let subscriber = tracing_subscriber::registry().with(
            tracing_subscriber::fmt::layer()
                .json()
                .flatten_event(true)
                .with_current_span(true)
                .with_span_list(false)
                .with_writer(writer),
        );
        tracing::subscriber::with_default(subscriber, || {
            let span = tracing::info_span!("request", trace_id = "trace-42");
            let _guard = span.enter();
            tracing::info!(value = "secret-value", "checked");
        });
        let lines = captured.lock().unwrap();
        let value: serde_json::Value = serde_json::from_str(lines.last().unwrap()).unwrap();
        assert_eq!(value["span"]["trace_id"], "trace-42");
        assert!(!lines.last().unwrap().contains("secret-value"));
        assert!(lines.last().unwrap().contains("<redacted:TEST_TOKEN>"));
    }
}
