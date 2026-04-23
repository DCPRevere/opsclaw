//! DNS lookup tool. Ad-hoc agent-callable lookups for A, AAAA, CNAME, MX,
//! TXT, NS, PTR, SRV records, plus an optional TCP-reachability probe.

use std::fmt::Write as _;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::time::Duration;

use async_trait::async_trait;
use hickory_resolver::config::{
    ConnectionConfig, NameServerConfig, ResolverConfig, ResolverOpts,
};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::proto::rr::{RData, RecordType};
use hickory_resolver::Resolver;
use serde::{Deserialize, Serialize};
use serde_json::json;
use zeroclaw::tools::traits::{Tool, ToolResult};

const DEFAULT_TIMEOUT_SECS: u64 = 5;

type TokioResolver = Resolver<TokioRuntimeProvider>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum DnsRecord {
    A,
    Aaaa,
    Cname,
    Mx,
    Txt,
    Ns,
    Ptr,
    Srv,
}

impl FromStr for DnsRecord {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_uppercase().as_str() {
            "A" => Ok(Self::A),
            "AAAA" => Ok(Self::Aaaa),
            "CNAME" => Ok(Self::Cname),
            "MX" => Ok(Self::Mx),
            "TXT" => Ok(Self::Txt),
            "NS" => Ok(Self::Ns),
            "PTR" => Ok(Self::Ptr),
            "SRV" => Ok(Self::Srv),
            other => Err(format!(
                "unsupported record type '{other}' (supported: A, AAAA, CNAME, MX, TXT, NS, PTR, SRV)"
            )),
        }
    }
}

impl DnsRecord {
    fn as_record_type(self) -> RecordType {
        match self {
            Self::A => RecordType::A,
            Self::Aaaa => RecordType::AAAA,
            Self::Cname => RecordType::CNAME,
            Self::Mx => RecordType::MX,
            Self::Txt => RecordType::TXT,
            Self::Ns => RecordType::NS,
            Self::Ptr => RecordType::PTR,
            Self::Srv => RecordType::SRV,
        }
    }
}

pub struct DnsTool;

impl DnsTool {
    pub fn new() -> Self {
        Self
    }
}

impl Default for DnsTool {
    fn default() -> Self {
        Self::new()
    }
}

fn build_resolver(custom: Option<IpAddr>, timeout: Duration) -> anyhow::Result<TokioResolver> {
    let provider = TokioRuntimeProvider::default();
    let builder = if let Some(ip) = custom {
        let mut cfg = ResolverConfig::default();
        cfg.add_name_server(NameServerConfig::new(
            ip,
            true,
            vec![ConnectionConfig::udp(), ConnectionConfig::tcp()],
        ));
        Resolver::builder_with_config(cfg, provider)
    } else {
        Resolver::builder(provider)?
    };

    let mut opts = ResolverOpts::default();
    opts.timeout = timeout;

    Ok(builder.with_options(opts).build()?)
}

fn reverse_name(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            format!("{}.{}.{}.{}.in-addr.arpa.", o[3], o[2], o[1], o[0])
        }
        IpAddr::V6(v6) => {
            let mut parts = String::with_capacity(72);
            for byte in v6.octets().iter().rev() {
                let hi = byte >> 4;
                let lo = byte & 0x0f;
                parts.push(char::from_digit(u32::from(lo), 16).unwrap());
                parts.push('.');
                parts.push(char::from_digit(u32::from(hi), 16).unwrap());
                parts.push('.');
            }
            parts.push_str("ip6.arpa.");
            parts
        }
    }
}

async fn do_lookup(
    resolver: &TokioResolver,
    record: DnsRecord,
    name: &str,
) -> anyhow::Result<Vec<String>> {
    let query_name = if record == DnsRecord::Ptr {
        let ip: IpAddr = name
            .parse()
            .map_err(|_| anyhow::anyhow!("PTR lookup requires an IP address, got '{name}'"))?;
        reverse_name(ip)
    } else {
        name.to_string()
    };

    let answer = resolver
        .lookup(query_name.as_str(), record.as_record_type())
        .await?;

    let mut out = Vec::new();
    for r in answer.answers() {
        let ttl = r.ttl;
        let rendered = match &r.data {
            RData::A(v) => format!("A {} ttl={}", v.0, ttl),
            RData::AAAA(v) => format!("AAAA {} ttl={}", v.0, ttl),
            RData::CNAME(v) => format!("CNAME {} ttl={}", v.0, ttl),
            RData::MX(v) => format!("MX {} {} ttl={}", v.preference, v.exchange, ttl),
            RData::TXT(v) => {
                let joined = v
                    .txt_data
                    .iter()
                    .map(|b| String::from_utf8_lossy(b).into_owned())
                    .collect::<Vec<_>>()
                    .join(" ");
                format!("TXT \"{joined}\" ttl={ttl}")
            }
            RData::NS(v) => format!("NS {} ttl={}", v.0, ttl),
            RData::PTR(v) => format!("PTR {} ttl={}", v.0, ttl),
            RData::SRV(v) => format!(
                "SRV {} {} {} {} ttl={}",
                v.priority, v.weight, v.port, v.target, ttl
            ),
            other => format!("{other} ttl={ttl}"),
        };
        out.push(rendered);
    }
    Ok(out)
}

async fn do_tcp_probe(host: &str, port: u16, timeout: Duration) -> String {
    let addrs: Vec<SocketAddr> = match host.parse::<IpAddr>() {
        Ok(ip) => vec![SocketAddr::new(ip, port)],
        Err(_) => match tokio::net::lookup_host((host, port)).await {
            Ok(iter) => iter.collect(),
            Err(e) => return format!("tcp_probe: dns error: {e}"),
        },
    };
    let Some(addr) = addrs.into_iter().next() else {
        return "tcp_probe: no address resolved".into();
    };
    match tokio::time::timeout(timeout, tokio::net::TcpStream::connect(addr)).await {
        Ok(Ok(_)) => format!("tcp_probe: connected to {addr}"),
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
            format!("tcp_probe: refused by {addr}")
        }
        Ok(Err(e)) => format!("tcp_probe: error on {addr}: {e}"),
        Err(_) => format!("tcp_probe: timeout after {}s ({addr})", timeout.as_secs()),
    }
}

#[async_trait]
impl Tool for DnsTool {
    fn name(&self) -> &str {
        "dns"
    }

    fn description(&self) -> &str {
        "Resolve DNS records (A, AAAA, CNAME, MX, TXT, NS, PTR, SRV) and \
         optionally probe TCP reachability. PTR takes an IP; all others a \
         hostname. Uses the system resolver unless 'resolver' is provided."
    }

    fn parameters_schema(&self) -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "name": {
                    "type": "string",
                    "description": "Hostname to look up (or IP for PTR)"
                },
                "record": {
                    "type": "string",
                    "description": "Record type: A, AAAA, CNAME, MX, TXT, NS, PTR, SRV. Default A.",
                    "default": "A"
                },
                "resolver": {
                    "type": "string",
                    "description": "Custom resolver IP (e.g. 1.1.1.1). Default: system resolver."
                },
                "tcp_probe": {
                    "type": "boolean",
                    "description": "If true, also TCP-connect to name:port.",
                    "default": false
                },
                "port": {
                    "type": "integer",
                    "description": "Port for tcp_probe (1-65535)."
                },
                "timeout_secs": {
                    "type": "integer",
                    "description": "Per-operation timeout in seconds (default 5)."
                }
            },
            "required": ["name"]
        })
    }

    async fn execute(&self, args: serde_json::Value) -> anyhow::Result<ToolResult> {
        let name = match args.get("name").and_then(|v| v.as_str()) {
            Some(s) if !s.is_empty() => s.to_string(),
            _ => {
                return Ok(ToolResult {
                    success: false,
                    output: String::new(),
                    error: Some("missing 'name' parameter".into()),
                });
            }
        };

        let record = match args.get("record").and_then(|v| v.as_str()) {
            Some(s) => match s.parse::<DnsRecord>() {
                Ok(r) => r,
                Err(e) => {
                    return Ok(ToolResult {
                        success: false,
                        output: String::new(),
                        error: Some(e),
                    });
                }
            },
            None => DnsRecord::A,
        };

        let resolver_ip = match args.get("resolver").and_then(|v| v.as_str()) {
            Some(s) => match s.parse::<IpAddr>() {
                Ok(ip) => Some(ip),
                Err(_) => {
                    return Ok(ToolResult {
                        success: false,
                        output: String::new(),
                        error: Some(format!("invalid 'resolver' IP: {s}")),
                    });
                }
            },
            None => None,
        };

        let timeout_secs = args
            .get("timeout_secs")
            .and_then(|v| v.as_u64())
            .unwrap_or(DEFAULT_TIMEOUT_SECS);
        let timeout = Duration::from_secs(timeout_secs);

        let tcp_probe = args
            .get("tcp_probe")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let port = args.get("port").and_then(|v| v.as_u64()).and_then(|p| {
            if (1..=65535).contains(&p) {
                Some(p as u16)
            } else {
                None
            }
        });
        if tcp_probe && port.is_none() {
            return Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some("tcp_probe=true requires a valid 'port' (1-65535)".into()),
            });
        }

        let resolver = match build_resolver(resolver_ip, timeout) {
            Ok(r) => r,
            Err(e) => {
                return Ok(ToolResult {
                    success: false,
                    output: String::new(),
                    error: Some(format!("resolver init failed: {e}")),
                });
            }
        };

        let resolver_label = resolver_ip
            .map(|ip| ip.to_string())
            .unwrap_or_else(|| "system".into());

        let mut out = String::new();
        writeln!(
            out,
            "resolver: {resolver_label}  record: {:?}  name: {name}",
            record
        )
        .ok();

        let lookup_res =
            tokio::time::timeout(timeout, do_lookup(&resolver, record, &name)).await;
        match lookup_res {
            Ok(Ok(records)) if records.is_empty() => {
                writeln!(out, "(no records)").ok();
            }
            Ok(Ok(records)) => {
                for r in records {
                    writeln!(out, "  {r}").ok();
                }
            }
            Ok(Err(e)) => {
                let msg = e.to_string();
                let tag = if msg.contains("no record found") || msg.contains("NXDomain") {
                    "NXDOMAIN"
                } else if msg.contains("SERVFAIL") || msg.contains("server failure") {
                    "SERVFAIL"
                } else if msg.contains("timed out") {
                    "TIMEOUT"
                } else {
                    "ERROR"
                };
                return Ok(ToolResult {
                    success: false,
                    output: out,
                    error: Some(format!("{tag}: {msg}")),
                });
            }
            Err(_) => {
                return Ok(ToolResult {
                    success: false,
                    output: out,
                    error: Some(format!("TIMEOUT: lookup exceeded {timeout_secs}s")),
                });
            }
        };

        if tcp_probe {
            if let Some(p) = port {
                let probe_result = do_tcp_probe(&name, p, timeout).await;
                writeln!(out, "{probe_result}").ok();
            }
        }

        Ok(ToolResult {
            success: true,
            output: out,
            error: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn record_parsing_accepts_all_known() {
        for (s, expected) in [
            ("a", DnsRecord::A),
            ("A", DnsRecord::A),
            ("aaaa", DnsRecord::Aaaa),
            ("CNAME", DnsRecord::Cname),
            ("mx", DnsRecord::Mx),
            ("txt", DnsRecord::Txt),
            ("NS", DnsRecord::Ns),
            ("ptr", DnsRecord::Ptr),
            ("SRV", DnsRecord::Srv),
        ] {
            assert_eq!(s.parse::<DnsRecord>().unwrap(), expected, "input={s}");
        }
    }

    #[test]
    fn record_parsing_rejects_unknown() {
        assert!("SOA".parse::<DnsRecord>().is_err());
        assert!("".parse::<DnsRecord>().is_err());
        assert!("txtx".parse::<DnsRecord>().is_err());
    }

    #[test]
    fn reverse_name_ipv4() {
        let n = reverse_name(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)));
        assert_eq!(n, "4.3.2.1.in-addr.arpa.");
    }

    #[test]
    fn reverse_name_ipv6() {
        let ip: IpAddr = "2001:db8::1".parse().unwrap();
        let n = reverse_name(ip);
        assert!(n.ends_with(".ip6.arpa."));
        // 32 nibble labels (32 dots) + "ip6" + "arpa" + trailing dot = 34.
        assert_eq!(n.matches('.').count(), 34);
    }

    #[test]
    fn tool_metadata() {
        let t = DnsTool::new();
        assert_eq!(t.name(), "dns");
        assert!(!t.description().is_empty());
        let schema = t.parameters_schema();
        assert!(schema["properties"]["name"].is_object());
        assert!(schema["required"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v == "name"));
    }

    #[tokio::test]
    async fn missing_name_is_rejected() {
        let t = DnsTool::new();
        let r = t.execute(json!({})).await.unwrap();
        assert!(!r.success);
        assert!(r.error.unwrap().contains("name"));
    }

    #[tokio::test]
    async fn unknown_record_type_is_rejected() {
        let t = DnsTool::new();
        let r = t
            .execute(json!({"name": "example.com", "record": "BOGUS"}))
            .await
            .unwrap();
        assert!(!r.success);
        assert!(r.error.unwrap().contains("unsupported record type"));
    }

    #[tokio::test]
    async fn bad_resolver_ip_is_rejected() {
        let t = DnsTool::new();
        let r = t
            .execute(json!({"name": "example.com", "resolver": "not-an-ip"}))
            .await
            .unwrap();
        assert!(!r.success);
        assert!(r.error.unwrap().contains("invalid 'resolver'"));
    }

    #[tokio::test]
    async fn tcp_probe_without_port_is_rejected() {
        let t = DnsTool::new();
        let r = t
            .execute(json!({"name": "example.com", "tcp_probe": true}))
            .await
            .unwrap();
        assert!(!r.success);
        assert!(r.error.unwrap().contains("port"));
    }

    // Network tests — require real DNS, keep ignored so `cargo test` stays hermetic.
    #[tokio::test]
    #[ignore]
    async fn real_lookup_a() {
        let t = DnsTool::new();
        let r = t
            .execute(json!({"name": "one.one.one.one", "record": "A"}))
            .await
            .unwrap();
        assert!(r.success, "error: {:?}", r.error);
        assert!(r.output.contains("A 1.1.1.1") || r.output.contains("A 1.0.0.1"));
    }
}
