mod config_persistence;
mod config_schema;
mod dockerignore_test;
mod gateway;
mod otel_dependency_feature_regression;
mod provider_resolution;
mod provider_schema;
mod reply_target_field_regression;
mod secret_store;
mod security;
mod target_config;
mod whatsapp_webhook_security;

// OpsClaw Phase 1 tests — will fail to compile until implementations exist.
// Uncomment each module as the corresponding feature is built.
//
// mod target_config;       // 1a: [[targets]] config schema
// mod secret_store;        // 1b: encrypted credential storage
// mod ssh_tool;            // 1c: SshTool trait implementation
// mod discovery_scan;      // 1d: target discovery and snapshot parsing
// mod monitoring_loop;     // 1f: health check cron job construction
