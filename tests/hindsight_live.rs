//! Live check of OpsClaw's Hindsight client against a running Hindsight,
//! covering every call the daemon makes. Use it before bumping the pinned
//! Hindsight image, or to try a new memory LLM.
//!
//! Self-skips unless `OPSCLAW_LIVE_HINDSIGHT` is set to the base URL:
//!
//!   OPSCLAW_LIVE_HINDSIGHT=http://127.0.0.1:8888 \
//!     cargo test --test hindsight_live -- --nocapture
//!
//! It writes to a throwaway bank (`opsclaw-live-<random>`) and deletes it at
//! the end.

use std::time::Duration;

use opsclaw::memory::hindsight::{HindsightClient, RetainOpts};

const FACT: &str = "scan of example::sandbox::aks observed: pod example-api-7f9c is in \
                    CrashLoopBackOff; its previous container was OOMKilled at its 512Mi \
                    memory limit";

#[tokio::test]
async fn every_call_the_daemon_makes_works_against_a_live_hindsight() {
    let Ok(url) = std::env::var("OPSCLAW_LIVE_HINDSIGHT") else {
        eprintln!("hindsight live check skipped: set OPSCLAW_LIVE_HINDSIGHT to a base URL");
        return;
    };
    let team = format!("live-{}", uuid::Uuid::new_v4().simple());
    let client = HindsightClient::new(url, None, &team);

    client.health().await.expect("health");
    client.ensure_configured().await.expect("ensure_configured (PATCH bank config)");
    client
        .retain(
            FACT,
            &RetainOpts {
                document_id: Some("live-check-1".into()),
                timestamp: Some(chrono::Utc::now().to_rfc3339()),
                context: Some("scan finding".into()),
            },
        )
        .await
        .expect("retain (async)");

    // Retain is asynchronous: extraction runs in the background.
    let mut facts = Vec::new();
    for _ in 0..40 {
        facts = client.list(None, 50).await.expect("list");
        if !facts.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
    assert!(!facts.is_empty(), "no fact was extracted within 2 minutes (check Hindsight's logs)");
    eprintln!("extracted {} fact(s), e.g. {:?}", facts.len(), facts[0].fact);

    let hits = client.recall("why is example-api crashing", 500).await.expect("recall");
    assert!(!hits.is_empty(), "recall found nothing for a fact that was just stored");
    eprintln!("recall top hit: {:?}", hits[0].fact);

    let answer = client.reflect("Why does example-api keep restarting?").await.expect("reflect");
    assert!(!answer.trim().is_empty(), "reflect returned an empty answer");
    eprintln!("reflect: {}", answer.chars().take(200).collect::<String>());

    client.invalidate(&facts[0].id, "live check cleanup").await.expect("invalidate");
    client.delete_bank().await.expect("delete_bank");
}
