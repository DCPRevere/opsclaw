#[test]
fn opentelemetry_otlp_uses_blocking_reqwest_client() {
    // The opentelemetry-otlp dependency lives in zeroclaw (the runtime crate),
    // not in opsclaw directly. We check the zeroclaw Cargo.toml.
    let manifest = include_str!("../../../zeroclaw/Cargo.toml");
    let otlp_line = manifest
        .lines()
        .find(|line: &&str| line.trim_start().starts_with("opentelemetry-otlp ="))
        .expect("Cargo.toml must define opentelemetry-otlp dependency");

    assert!(
        otlp_line.contains("\"reqwest-blocking-client\""),
        "opentelemetry-otlp must include reqwest-blocking-client to avoid Tokio reactor panics"
    );
    assert!(
        !otlp_line.contains("\"reqwest-client\""),
        "opentelemetry-otlp must not include async reqwest-client in this runtime mode"
    );
}
