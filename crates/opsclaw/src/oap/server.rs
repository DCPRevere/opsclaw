use super::types::{
    AgentStatus, CatalogueEntry, CloudEvent, CommandAccepted, CommandCatalogue, ErrorResponse,
    EventList, OapAgentDescriptor, OapAuthentication, OapCapability, OapEndpoint, OapManifest,
    OapRestTransport, OapRoot, OapService, QueryCatalogue,
};
use crate::ops_config::{OapServerConfig, OpsConfig};
use anyhow::{Context, Result};
use axum::{
    Json, Router,
    extract::{Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use chrono::{Duration as ChronoDuration, Utc};
use parking_lot::Mutex;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    net::SocketAddr,
    sync::Arc,
};
use uuid::Uuid;

const QUERY_NAME: &str = "get-agent-status";
const QUERY_VERSION: &str = "1.0";
const COMMAND_NAME: &str = "run-health-check";
const COMMAND_VERSION: &str = "1.0";
const COMMAND_TYPE: &str = "RunHealthCheck";
const EVENT_TYPE: &str = "HealthCheckRequested";
const EVENT_LOG_LIMIT: usize = 1000;
const COMMAND_IDEMPOTENCY_LIMIT: usize = 1000;
const COMMAND_IDEMPOTENCY_TTL_SECS: i64 = 24 * 60 * 60;
const OAP_VERSION: &str = "0.4.16";
const SERVICE_KEY: &str = "io.opsclaw.sre";

#[derive(Clone)]
struct OapState {
    config: OapServerConfig,
    ops_config: Arc<OpsConfig>,
    commands: Arc<Mutex<HashMap<String, CommandRecord>>>,
    events: Arc<Mutex<VecDeque<CloudEvent>>>,
}

#[derive(Debug, Clone)]
struct CommandRecord {
    payload_hash: Vec<u8>,
    correlation_id: String,
    accepted_at: chrono::DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct EventFilters {
    #[serde(rename = "type")]
    event_type: Option<String>,
    correlation_id: Option<String>,
}

pub async fn run_oap_server(config: OapServerConfig, ops_config: OpsConfig) -> Result<()> {
    let addr: SocketAddr = format!("{}:{}", config.bind, config.port)
        .parse()
        .context("invalid OAP server bind address")?;
    validate_oap_security(&config, &addr)?;
    let app = build_router(config, ops_config);

    tracing::info!("OAP server listening on {addr}");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .context("OAP server error")
}

fn build_router(config: OapServerConfig, ops_config: OpsConfig) -> Router {
    let state = OapState {
        config,
        ops_config: Arc::new(ops_config),
        commands: Arc::new(Mutex::new(HashMap::new())),
        events: Arc::new(Mutex::new(VecDeque::with_capacity(EVENT_LOG_LIMIT))),
    };

    Router::new()
        .route("/.well-known/oap", get(handle_manifest))
        .route("/queries", get(handle_queries))
        .route(
            "/queries/get-agent-status/1.0",
            get(handle_agent_status_descriptor),
        )
        .route("/queries/get-agent-status", get(handle_agent_status))
        .route("/commands", get(handle_commands).post(handle_command_post))
        .route(
            "/commands/run-health-check/1.0",
            get(handle_health_check_descriptor),
        )
        .route("/events", get(handle_events))
        .with_state(state)
}

async fn handle_manifest(State(state): State<OapState>) -> impl IntoResponse {
    Json(manifest(&state))
}

async fn handle_queries(State(state): State<OapState>, headers: HeaderMap) -> Response {
    if let Err(resp) = authorize(&state, &headers) {
        return resp;
    }
    Json(QueryCatalogue {
        queries: vec![CatalogueEntry {
            schema: QUERY_NAME.to_string(),
            version: QUERY_VERSION.to_string(),
            dataschema: format!(
                "{}/queries/{QUERY_NAME}/{QUERY_VERSION}",
                base_url(&state.config)
            ),
            description: Some("Return safe status for this OpsClaw instance".to_string()),
        }],
    })
    .into_response()
}

async fn handle_agent_status_descriptor(
    State(state): State<OapState>,
    headers: HeaderMap,
) -> Response {
    if let Err(resp) = authorize(&state, &headers) {
        return resp;
    }
    Json(json!({
        "description": "Return safe status for this OpsClaw instance.",
        "parameters": {
            "type": "object",
            "additionalProperties": false,
            "properties": {}
        },
        "response": agent_status_schema()
    }))
    .into_response()
}

async fn handle_agent_status(State(state): State<OapState>, headers: HeaderMap) -> Response {
    if let Err(resp) = authorize(&state, &headers) {
        return resp;
    }
    Json(agent_status(&state)).into_response()
}

async fn handle_commands(State(state): State<OapState>, headers: HeaderMap) -> Response {
    if let Err(resp) = authorize(&state, &headers) {
        return resp;
    }
    Json(CommandCatalogue {
        commands: vec![CatalogueEntry {
            schema: COMMAND_NAME.to_string(),
            version: COMMAND_VERSION.to_string(),
            dataschema: format!(
                "{}/commands/{COMMAND_NAME}/{COMMAND_VERSION}",
                base_url(&state.config)
            ),
            description: Some(
                "Request a lightweight health-check intent for a named target".to_string(),
            ),
        }],
    })
    .into_response()
}

async fn handle_health_check_descriptor(
    State(state): State<OapState>,
    headers: HeaderMap,
) -> Response {
    if let Err(resp) = authorize(&state, &headers) {
        return resp;
    }
    Json(json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "RunHealthCheck",
        "description": "Request a lightweight health-check intent for a named OpsClaw target.",
        "type": "object",
        "required": ["target"],
        "properties": {
            "target": {
                "type": "string",
                "minLength": 1,
                "description": "Configured OpsClaw target name or address."
            }
        },
        "additionalProperties": false,
        "produces": [EVENT_TYPE]
    }))
    .into_response()
}

async fn handle_command_post(
    State(state): State<OapState>,
    headers: HeaderMap,
    Json(req): Json<CloudEvent>,
) -> Response {
    if let Err(resp) = authorize(&state, &headers) {
        return resp;
    }
    match accept_command(&state, req) {
        Ok(accepted) => (StatusCode::CREATED, Json(accepted)).into_response(),
        Err((status, error, message)) => error_response(status, error, message),
    }
}

async fn handle_events(
    State(state): State<OapState>,
    headers: HeaderMap,
    Query(filters): Query<EventFilters>,
) -> Response {
    if let Err(resp) = authorize(&state, &headers) {
        return resp;
    }
    let events = state
        .events
        .lock()
        .iter()
        .filter(|event| {
            filters
                .event_type
                .as_ref()
                .map_or(true, |t| event.event_type == *t)
        })
        .filter(|event| {
            filters.correlation_id.as_ref().map_or(true, |id| {
                event
                    .data
                    .get("correlationId")
                    .and_then(Value::as_str)
                    .map_or(false, |event_id| event_id == id)
            })
        })
        .cloned()
        .collect();
    Json(EventList { events }).into_response()
}

fn accept_command(
    state: &OapState,
    req: CloudEvent,
) -> std::result::Result<CommandAccepted, (StatusCode, &'static str, String)> {
    validate_cloudevent_basics(state, &req)?;
    if req.event_type != COMMAND_TYPE {
        return Err((
            StatusCode::BAD_REQUEST,
            "unsupported-command",
            format!("unsupported command type '{}'", req.event_type),
        ));
    }
    let data = req.data.as_object().ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            "invalid-command",
            "data must be an object".to_string(),
        )
    })?;
    if data.keys().any(|key| key != "target") {
        return Err((
            StatusCode::BAD_REQUEST,
            "invalid-command",
            "data may only contain the 'target' field".to_string(),
        ));
    }
    let target = data
        .get("target")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|target| !target.is_empty())
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                "invalid-command",
                "data.target is required".to_string(),
            )
        })?
        .to_string();
    if let Err(e) = state.ops_config.resolve_target(&target) {
        return Err((
            StatusCode::BAD_REQUEST,
            "unknown-target",
            format!("target is not configured: {e}"),
        ));
    }

    let payload_hash = hash_command_payload(&req)?;
    let accepted_at = Utc::now();
    {
        let mut commands = state.commands.lock();
        prune_command_records(&mut commands, accepted_at);
        if let Some(existing) = commands.get(&req.id) {
            if existing.payload_hash == payload_hash {
                return Ok(CommandAccepted {
                    id: req.id,
                    correlation_id: existing.correlation_id.clone(),
                });
            }
            return Err((
                StatusCode::CONFLICT,
                "command-id-conflict",
                "command id already exists with a different payload".to_string(),
            ));
        }
        let correlation_id = Uuid::new_v4().to_string();
        commands.insert(
            req.id.clone(),
            CommandRecord {
                payload_hash,
                correlation_id: correlation_id.clone(),
                accepted_at,
            },
        );
        prune_command_records(&mut commands, accepted_at);
        drop(commands);
        append_event(
            state,
            CloudEvent {
                specversion: "1.0".to_string(),
                id: Uuid::new_v4().to_string(),
                source: format!("opsclaw:oap:{}", state.config.agent_id),
                event_type: EVENT_TYPE.to_string(),
                time: accepted_at,
                datacontenttype: "application/json".to_string(),
                dataschema: None,
                data: json!({
                    "correlationId": correlation_id.clone(),
                    "target": target,
                    "acceptedAt": accepted_at,
                }),
            },
        );
        Ok(CommandAccepted {
            id: req.id,
            correlation_id,
        })
    }
}

fn prune_command_records(
    commands: &mut HashMap<String, CommandRecord>,
    now: chrono::DateTime<Utc>,
) {
    let cutoff = now - ChronoDuration::seconds(COMMAND_IDEMPOTENCY_TTL_SECS);
    commands.retain(|_, record| record.accepted_at >= cutoff);
    while commands.len() > COMMAND_IDEMPOTENCY_LIMIT {
        let Some(oldest_id) = commands
            .iter()
            .min_by_key(|(_, record)| record.accepted_at)
            .map(|(id, _)| id.clone())
        else {
            break;
        };
        commands.remove(&oldest_id);
    }
}

fn validate_cloudevent_basics(
    state: &OapState,
    req: &CloudEvent,
) -> std::result::Result<(), (StatusCode, &'static str, String)> {
    if req.specversion != "1.0" {
        return Err((
            StatusCode::BAD_REQUEST,
            "invalid-cloudevent",
            "specversion must be 1.0".to_string(),
        ));
    }
    if !is_json_content_type(&req.datacontenttype) {
        return Err((
            StatusCode::BAD_REQUEST,
            "invalid-cloudevent",
            "datacontenttype must be application/json".to_string(),
        ));
    }
    let dataschema = req.dataschema.as_deref().unwrap_or_default().trim();
    if dataschema.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "invalid-cloudevent",
            "dataschema is required".to_string(),
        ));
    }
    let expected = command_dataschema(&state.config);
    let legacy = format!("{COMMAND_NAME}/{COMMAND_VERSION}");
    if dataschema != expected && dataschema != legacy {
        return Err((
            StatusCode::BAD_REQUEST,
            "invalid-cloudevent",
            format!("dataschema must match {expected}"),
        ));
    }
    if req.id.trim().is_empty() || req.source.trim().is_empty() || req.event_type.trim().is_empty()
    {
        return Err((
            StatusCode::BAD_REQUEST,
            "invalid-cloudevent",
            "id, source, and type are required".to_string(),
        ));
    }
    if !req.data.is_object() {
        return Err((
            StatusCode::BAD_REQUEST,
            "invalid-command",
            "data must be an object".to_string(),
        ));
    }
    Ok(())
}

fn is_json_content_type(value: &str) -> bool {
    value
        .split(';')
        .next()
        .map(str::trim)
        .is_some_and(|essence| essence.eq_ignore_ascii_case("application/json"))
}

fn command_dataschema(config: &OapServerConfig) -> String {
    format!(
        "{}/commands/{COMMAND_NAME}/{COMMAND_VERSION}",
        base_url(config)
    )
}

fn hash_command_payload(
    req: &CloudEvent,
) -> std::result::Result<Vec<u8>, (StatusCode, &'static str, String)> {
    let bytes = serde_json::to_vec(req).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            "invalid-command",
            format!("command payload is not serializable: {e}"),
        )
    })?;
    Ok(Sha256::digest(bytes).to_vec())
}

fn append_event(state: &OapState, event: CloudEvent) {
    let mut events = state.events.lock();
    if events.len() == EVENT_LOG_LIMIT {
        events.pop_front();
    }
    events.push_back(event);
}

fn authorize(state: &OapState, headers: &HeaderMap) -> std::result::Result<(), Response> {
    if state.config.token.is_empty() {
        if unauthenticated_loopback_allowed(&state.config) {
            return Ok(());
        }
        return Err(error_response(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "OAP operational endpoints require a configured bearer token",
        ));
    }
    if !public_url_allows_plaintext_bearer(&state.config) {
        return Err(error_response(
            StatusCode::FORBIDDEN,
            "insecure-transport",
            "OAP bearer authentication requires loopback HTTP or an HTTPS public_url",
        ));
    }
    let authorized = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map_or(false, |t| constant_time_eq(t, &state.config.token));
    if authorized {
        Ok(())
    } else {
        Err(error_response(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "unauthorized",
        ))
    }
}

fn validate_oap_security(config: &OapServerConfig, addr: &SocketAddr) -> Result<()> {
    anyhow::ensure!(
        !config.token.trim().is_empty()
            || (addr.ip().is_loopback() && unauthenticated_loopback_allowed(config)),
        "OAP server requires a non-empty token unless allow_unauthenticated_loopback is set on a loopback bind"
    );
    anyhow::ensure!(
        public_url_allows_plaintext_bearer(config),
        "OAP bearer authentication requires loopback HTTP or an HTTPS public_url"
    );
    Ok(())
}

fn is_loopback_bind(bind: &str) -> bool {
    bind.parse::<std::net::IpAddr>()
        .map(|ip| ip.is_loopback())
        .unwrap_or(false)
}

fn unauthenticated_loopback_allowed(config: &OapServerConfig) -> bool {
    config.allow_unauthenticated_loopback
        && is_loopback_bind(&config.bind)
        && public_url_is_empty_or_loopback_http(config)
}

fn public_url_is_empty_or_loopback_http(config: &OapServerConfig) -> bool {
    let public_url = config.public_url.trim();
    public_url.is_empty() || public_url_http_host_is_loopback(public_url)
}

fn public_url_allows_plaintext_bearer(config: &OapServerConfig) -> bool {
    let public_url = config.public_url.trim();
    if public_url.starts_with("https://") {
        return true;
    }
    if public_url.starts_with("http://") {
        return public_url_http_host_is_loopback(public_url);
    }
    is_loopback_bind(&config.bind)
}

fn public_url_http_host_is_loopback(public_url: &str) -> bool {
    public_url
        .strip_prefix("http://")
        .and_then(|rest| rest.split('/').next())
        .and_then(|host_port| host_port.split(':').next())
        .is_some_and(|host| {
            host == "localhost"
                || host
                    .parse::<std::net::IpAddr>()
                    .map(|ip| ip.is_loopback())
                    .unwrap_or(false)
        })
}

fn constant_time_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.bytes()
        .zip(b.bytes())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

fn error_response(status: StatusCode, error: &str, message: impl Into<String>) -> Response {
    (
        status,
        Json(ErrorResponse {
            error: error.to_string(),
            message: message.into(),
        }),
    )
        .into_response()
}

fn manifest(state: &OapState) -> OapManifest {
    let base = base_url(&state.config);
    let mut services = BTreeMap::new();
    services.insert(
        SERVICE_KEY.to_string(),
        OapService {
            version: env!("CARGO_PKG_VERSION").to_string(),
            description: state.config.agent_description.clone(),
            rest: OapRestTransport {
                endpoint: base.clone(),
            },
        },
    );
    OapManifest {
        oap: OapRoot {
            version: OAP_VERSION.to_string(),
            authentication: Some(
                if state.config.token.is_empty() && unauthenticated_loopback_allowed(&state.config)
                {
                    OapAuthentication {
                        auth_type: "none".to_string(),
                        scheme: None,
                        location: None,
                    }
                } else {
                    OapAuthentication {
                        auth_type: "bearer".to_string(),
                        scheme: Some("Bearer".to_string()),
                        location: None,
                    }
                },
            ),
            services,
            capabilities: vec![
                OapCapability {
                    name: "io.oap.agents.commands".to_string(),
                    version: OAP_VERSION.to_string(),
                    service: SERVICE_KEY.to_string(),
                    description: "Discover and submit OpsClaw SRE commands".to_string(),
                    status: None,
                    spec: "https://openagentprotocol.io/specs/agents/commands".to_string(),
                    schema: "https://openagentprotocol.io/v1/schemas/agents/commands.json"
                        .to_string(),
                    endpoints: vec![
                        endpoint("GET", "/commands", "Command catalogue"),
                        endpoint("POST", "/commands", "Command ingestion"),
                        endpoint("GET", "/commands/{schema}/{version}", "Get command schema"),
                    ],
                },
                OapCapability {
                    name: "io.oap.agents.queries".to_string(),
                    version: OAP_VERSION.to_string(),
                    service: SERVICE_KEY.to_string(),
                    description: "Read safe OpsClaw state".to_string(),
                    status: None,
                    spec: "https://openagentprotocol.io/specs/agents/queries".to_string(),
                    schema: "https://openagentprotocol.io/v1/schemas/agents/queries.json"
                        .to_string(),
                    endpoints: vec![
                        endpoint("GET", "/queries", "Query catalogue"),
                        endpoint("GET", "/queries/{schema}/{version}", "Get query schema"),
                        endpoint("GET", "/queries/{schema}", "Execute query"),
                    ],
                },
                OapCapability {
                    name: "io.oap.agents.events".to_string(),
                    version: OAP_VERSION.to_string(),
                    service: SERVICE_KEY.to_string(),
                    description: "List OpsClaw OAP events produced by accepted commands"
                        .to_string(),
                    status: None,
                    spec: "https://openagentprotocol.io/specs/agents/events".to_string(),
                    schema: "https://openagentprotocol.io/v1/schemas/agents/events.json"
                        .to_string(),
                    endpoints: vec![endpoint("GET", "/events", "List events")],
                },
            ],
            agents: vec![OapAgentDescriptor {
                id: state.config.agent_id.clone(),
                name: state.config.agent_name.clone(),
                description: state.config.agent_description.clone(),
                agent_type: "sre-agent".to_string(),
                accepts: vec![COMMAND_TYPE.to_string()],
                produces: vec![EVENT_TYPE.to_string()],
                status: "running".to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
                endpoint: Some(base),
            }],
        },
    }
}

fn endpoint(method: &str, path: &str, description: &str) -> OapEndpoint {
    OapEndpoint {
        method: method.to_string(),
        path: path.to_string(),
        description: Some(description.to_string()),
    }
}

fn agent_status(state: &OapState) -> AgentStatus {
    let (target_count, project_count, environment_count) = counts(&state.ops_config);
    AgentStatus {
        agent_id: state.config.agent_id.clone(),
        agent_name: state.config.agent_name.clone(),
        agent_version: env!("CARGO_PKG_VERSION").to_string(),
        oap_status: "partial".to_string(),
        target_count,
        project_count,
        environment_count,
        timestamp: Utc::now(),
    }
}

fn counts(config: &OpsConfig) -> (usize, usize, usize) {
    if config.projects.is_empty() {
        (config.targets.as_ref().map_or(0, Vec::len), 0, 0)
    } else {
        let environment_count = config
            .projects
            .iter()
            .map(|project| project.environments.len())
            .sum();
        let target_count = config
            .projects
            .iter()
            .flat_map(|project| &project.environments)
            .map(|environment| environment.targets.len())
            .sum();
        (target_count, config.projects.len(), environment_count)
    }
}

fn base_url(config: &OapServerConfig) -> String {
    if !config.public_url.is_empty() {
        config.public_url.trim_end_matches('/').to_string()
    } else {
        format!("http://{}:{}", config.bind, config.port)
    }
}

fn agent_status_schema() -> Value {
    json!({
        "type": "object",
        "required": [
            "agentId",
            "agentName",
            "agentVersion",
            "oapStatus",
            "targetCount",
            "projectCount",
            "environmentCount",
            "timestamp"
        ],
        "properties": {
            "agentId": { "type": "string" },
            "agentName": { "type": "string" },
            "agentVersion": { "type": "string" },
            "oapStatus": { "type": "string" },
            "targetCount": { "type": "integer", "minimum": 0 },
            "projectCount": { "type": "integer", "minimum": 0 },
            "environmentCount": { "type": "integer", "minimum": 0 },
            "timestamp": { "type": "string", "format": "date-time" }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ops_config::{ConnectionType, TargetConfig};
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    fn test_config() -> OapServerConfig {
        OapServerConfig {
            enabled: true,
            port: 0,
            bind: "127.0.0.1".into(),
            public_url: "https://agent.example.test/oap".into(),
            token: "test-token".into(),
            allow_unauthenticated_loopback: false,
            agent_id: "agent-1".into(),
            agent_name: "OpsClaw Test".into(),
            agent_description: "Test OAP agent".into(),
        }
    }

    fn test_ops_config() -> OpsConfig {
        OpsConfig {
            targets: Some(vec![TargetConfig {
                name: "web-1".into(),
                connection_type: ConnectionType::Local,
                host: None,
                port: None,
                user: None,
                key_secret: None,
                autonomy: Default::default(),
                context_file: None,
                probes: None,
                data_sources: None,
                escalation: None,
                kubeconfig: None,
                context: None,
                namespace: None,
            }]),
            ..Default::default()
        }
    }

    fn test_app() -> Router {
        build_router(test_config(), test_ops_config())
    }

    fn test_app_without_token() -> Router {
        let mut config = test_config();
        config.token.clear();
        build_router(config, test_ops_config())
    }

    async fn body_json(resp: axum::http::Response<Body>) -> Value {
        let body = axum::body::to_bytes(resp.into_body(), 1_048_576)
            .await
            .unwrap();
        serde_json::from_slice(&body).unwrap()
    }

    fn auth(req: axum::http::request::Builder) -> axum::http::request::Builder {
        req.header(header::AUTHORIZATION, "Bearer test-token")
    }

    #[tokio::test]
    async fn oap_manifest_is_public_and_only_advertises_mvp() {
        let resp = test_app()
            .oneshot(
                Request::builder()
                    .uri("/.well-known/oap")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        assert_eq!(body["oap"]["version"], OAP_VERSION);
        assert_eq!(
            body["oap"]["services"][SERVICE_KEY]["rest"]["endpoint"],
            "https://agent.example.test/oap"
        );
        assert_eq!(body["oap"]["agents"][0]["id"], "agent-1");
        assert!(body.get("capabilities").is_none());
        let capability_names: Vec<_> = body["oap"]["capabilities"]
            .as_array()
            .unwrap()
            .iter()
            .map(|item| item["name"].as_str().unwrap())
            .collect();
        assert_eq!(
            capability_names,
            vec![
                "io.oap.agents.commands",
                "io.oap.agents.queries",
                "io.oap.agents.events"
            ]
        );
        assert!(!body.to_string().contains("a2a"));
        assert!(!body.to_string().contains("mcp"));
    }

    #[tokio::test]
    async fn oap_operational_endpoints_require_auth_when_token_configured() {
        let unauthorized = test_app()
            .oneshot(
                Request::builder()
                    .uri("/queries")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);

        let authorized = test_app()
            .oneshot(
                auth(Request::builder().uri("/queries"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(authorized.status(), StatusCode::OK);
    }

    #[test]
    fn oap_security_rejects_empty_token_without_loopback_dev_flag() {
        let mut config = test_config();
        config.token.clear();
        let addr: SocketAddr = "127.0.0.1:42619".parse().unwrap();
        assert!(validate_oap_security(&config, &addr).is_err());

        config.allow_unauthenticated_loopback = true;
        assert!(validate_oap_security(&config, &addr).is_err());

        config.public_url = "http://127.0.0.1:42619/oap".into();
        assert!(validate_oap_security(&config, &addr).is_ok());
    }

    #[test]
    fn oap_security_rejects_plaintext_public_bearer() {
        let mut config = test_config();
        config.public_url = "http://agent.example.test/oap".into();
        let addr: SocketAddr = "0.0.0.0:42619".parse().unwrap();
        assert!(validate_oap_security(&config, &addr).is_err());

        config.public_url = "https://agent.example.test/oap".into();
        assert!(validate_oap_security(&config, &addr).is_ok());
    }

    #[tokio::test]
    async fn oap_operational_endpoints_allow_public_access_only_with_explicit_loopback_flag() {
        let app = test_app_without_token();
        let manifest = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/.well-known/oap")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(manifest.status(), StatusCode::OK);
        let body = body_json(manifest).await;
        assert_eq!(body["oap"]["authentication"]["type"], "bearer");

        let queries = app
            .oneshot(
                Request::builder()
                    .uri("/queries")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(queries.status(), StatusCode::UNAUTHORIZED);

        let mut config = test_config();
        config.token.clear();
        config.allow_unauthenticated_loopback = true;
        config.public_url = "http://127.0.0.1:42619/oap".into();
        let queries = build_router(config, test_ops_config())
            .oneshot(
                Request::builder()
                    .uri("/queries")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(queries.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn oap_query_catalogue_schema_and_execution_work() {
        let app = test_app();
        let catalogue = app
            .clone()
            .oneshot(
                auth(Request::builder().uri("/queries"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(catalogue.status(), StatusCode::OK);
        let body = body_json(catalogue).await;
        assert_eq!(body["queries"][0]["schema"], QUERY_NAME);

        let schema = app
            .clone()
            .oneshot(
                auth(Request::builder().uri("/queries/get-agent-status/1.0"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(schema.status(), StatusCode::OK);
        let body = body_json(schema).await;
        assert_eq!(
            body["response"]["properties"]["targetCount"]["type"],
            "integer"
        );

        let status = app
            .oneshot(
                auth(Request::builder().uri("/queries/get-agent-status"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(status.status(), StatusCode::OK);
        let body = body_json(status).await;
        assert_eq!(body["targetCount"], 1);
        assert_eq!(body["agentId"], "agent-1");
    }

    #[tokio::test]
    async fn oap_command_rejects_malformed_unsupported_and_unknown_target() {
        let app = test_app();
        let unsupported = test_command("cmd-1", "OtherCommand", json!({"target": "web-1"}));
        let resp = app
            .clone()
            .oneshot(
                auth(Request::builder().method("POST").uri("/commands"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_vec(&unsupported).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        let unknown = test_command("cmd-2", COMMAND_TYPE, json!({"target": "missing"}));
        let resp = app
            .oneshot(
                auth(Request::builder().method("POST").uri("/commands"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_vec(&unknown).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn oap_command_requires_server_supported_cloudevent_envelope() {
        let app = test_app();
        let mut wrong_content_type =
            test_command("cmd-content-type", COMMAND_TYPE, json!({"target": "web-1"}));
        wrong_content_type.datacontenttype = "text/plain".into();
        let resp = app
            .clone()
            .oneshot(
                auth(Request::builder().method("POST").uri("/commands"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_vec(&wrong_content_type).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = body_json(resp).await;
        assert_eq!(body["error"], "invalid-cloudevent");

        let mut missing_dataschema =
            test_command("cmd-dataschema", COMMAND_TYPE, json!({"target": "web-1"}));
        missing_dataschema.dataschema = None;
        let resp = app
            .oneshot(
                auth(Request::builder().method("POST").uri("/commands"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_vec(&missing_dataschema).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = body_json(resp).await;
        assert_eq!(body["message"], "dataschema is required");
    }

    fn test_command(id: &str, event_type: &str, data: Value) -> CloudEvent {
        CloudEvent {
            specversion: "1.0".into(),
            id: id.into(),
            source: "test".into(),
            event_type: event_type.into(),
            time: Utc::now(),
            datacontenttype: "application/json".into(),
            dataschema: Some(format!("{COMMAND_NAME}/{COMMAND_VERSION}")),
            data,
        }
    }

    #[tokio::test]
    async fn oap_command_idempotency_distinguishes_conflicts() {
        let app = test_app();
        let command = test_command("cmd-1", COMMAND_TYPE, json!({"target": "web-1"}));
        let submit = |command: &CloudEvent| {
            auth(Request::builder().method("POST").uri("/commands"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(command).unwrap()))
                .unwrap()
        };
        let first = app.clone().oneshot(submit(&command)).await.unwrap();
        assert_eq!(first.status(), StatusCode::CREATED);
        let first_body = body_json(first).await;

        let duplicate = app.clone().oneshot(submit(&command)).await.unwrap();
        assert_eq!(duplicate.status(), StatusCode::CREATED);
        let duplicate_body = body_json(duplicate).await;
        assert_eq!(first_body["correlationId"], duplicate_body["correlationId"]);

        let mut conflicting = command;
        conflicting.source = "other-source".into();
        let conflict = app.oneshot(submit(&conflicting)).await.unwrap();
        assert_eq!(conflict.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn oap_accepted_command_creates_retrievable_event() {
        let app = test_app();
        let command = test_command("cmd-events", COMMAND_TYPE, json!({"target": "web-1"}));
        let accepted = app
            .clone()
            .oneshot(
                auth(Request::builder().method("POST").uri("/commands"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_vec(&command).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(accepted.status(), StatusCode::CREATED);
        let accepted_body = body_json(accepted).await;
        let correlation_id = accepted_body["correlationId"].as_str().unwrap();

        let events = app
            .oneshot(
                auth(Request::builder().uri(format!(
                    "/events?type={EVENT_TYPE}&correlationId={correlation_id}"
                )))
                .body(Body::empty())
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(events.status(), StatusCode::OK);
        let body = body_json(events).await;
        assert_eq!(body["events"].as_array().unwrap().len(), 1);
        assert_eq!(body["events"][0]["type"], EVENT_TYPE);
        assert_eq!(body["events"][0]["data"]["target"], "web-1");
    }

    #[tokio::test]
    async fn oap_events_filter_by_type_and_correlation_id() {
        let app = test_app();
        let first = test_command("cmd-filter-1", COMMAND_TYPE, json!({"target": "web-1"}));
        let second = test_command("cmd-filter-2", COMMAND_TYPE, json!({"target": "web-1"}));

        for command in [&first, &second] {
            let resp = app
                .clone()
                .oneshot(
                    auth(Request::builder().method("POST").uri("/commands"))
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(Body::from(serde_json::to_vec(command).unwrap()))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::CREATED);
        }

        let all_events = app
            .clone()
            .oneshot(
                auth(Request::builder().uri("/events"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let all_body = body_json(all_events).await;
        assert_eq!(all_body["events"].as_array().unwrap().len(), 2);

        let no_type_match = app
            .clone()
            .oneshot(
                auth(Request::builder().uri("/events?type=OtherEvent"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let no_type_body = body_json(no_type_match).await;
        assert!(no_type_body["events"].as_array().unwrap().is_empty());

        let correlation_id = all_body["events"][0]["data"]["correlationId"]
            .as_str()
            .unwrap();
        let one_match = app
            .oneshot(
                auth(Request::builder().uri(format!(
                    "/events?type={EVENT_TYPE}&correlationId={correlation_id}"
                )))
                .body(Body::empty())
                .unwrap(),
            )
            .await
            .unwrap();
        let one_match_body = body_json(one_match).await;
        assert_eq!(one_match_body["events"].as_array().unwrap().len(), 1);
    }
}
