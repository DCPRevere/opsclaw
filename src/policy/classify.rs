//! Risk classification of concrete commands — in code, never by the LLM
//! (brief §5). This file is safety-critical: policy gating derives from the
//! classes assigned here, and the `hard_blocked` list is the always-on block
//! that no autonomy level can override.
//!
//! Model: a command line is split into pipeline/sequence segments (respecting
//! quotes), wrapper prefixes are stripped (sudo, env, timeout, …), and each
//! segment is matched against ordered rules. The whole line classifies as the
//! MAXIMUM of its segments. Command-composing tools (ssh, shell) rely on this
//! as the authority; structured tools' self-declared risk acts as a floor —
//! the final class is `max(classified, tool_floor)`, so classification can
//! raise but a tool can never talk its way below its declaration.
//!
//! Unknown commands classify as `Medium`, not `Read` — failing closed: an
//! unrecognized binary auto-executes nowhere below `auto`.

use regex::Regex;
use std::sync::LazyLock;

use crate::domain::RiskClass;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Classification {
    pub risk: RiskClass,
    /// Matched the always-on block list: refused at EVERY autonomy level.
    pub hard_blocked: bool,
    /// The rule that fired (for the audit record and approval context).
    pub rule: &'static str,
}

/// The line the classifier should see for a given TOOL's command. The
/// kubernetes tool/executor contract strips the leading binary (`get pods
/// -n x`; `KubernetesExecutor` prepends `kubectl` itself), but every
/// kubectl rule below matches `^kubectl\s+…` — so classify what will
/// actually run, not the tool-internal spelling. Without this, every k8s
/// READ fail-closed to Medium (observe mode blocked the entire kubernetes
/// tool, seen live), and — worse, the other direction — a bare
/// `delete namespaces --all` line dodged the kubectl hard-block patterns,
/// leaving only the tool's self-declared risk between it and execution.
/// Every other tool (docker, systemd, argocd, ssh, shell) composes the
/// full binary-prefixed line already and passes through untouched.
pub fn line_for_classification<'c>(tool: &str, command: &'c str) -> std::borrow::Cow<'c, str> {
    let trimmed = command.trim_start();
    if tool == "kubernetes" && !trimmed.starts_with("kubectl") {
        std::borrow::Cow::Owned(format!("kubectl {trimmed}"))
    } else {
        std::borrow::Cow::Borrowed(command)
    }
}

/// Classify a full command line (the max over its segments).
pub fn classify_command(line: &str) -> Classification {
    // Endpoint READ lines (`tools::endpoint::{get_json, query_json}` compose
    // them; `targets::endpoint::EndpointExecutor` performs them) are a URL
    // path plus, for `endpoint-query`, a JSON body — NOT shell. Segment
    // splitting a JSON body on `;`/`&` would classify its fragments as
    // unknown commands (fail-closed Medium) and block legitimate log
    // searches under `observe`; shell hard-block patterns are equally
    // meaningless against JSON. Read-safety for these lines is enforced
    // where it belongs: the executor's per-kind path allowlists (a
    // non-read path is refused BEFORE any request), so classifying the
    // verb alone is sound, not lenient.
    if line.starts_with("endpoint-get ") || line.starts_with("endpoint-query ") {
        return Classification {
            risk: RiskClass::Read,
            hard_blocked: false,
            rule: "endpoint-read",
        };
    }
    // Hard-block patterns that SPAN shell operators (the fork bomb is `:|:&`)
    // must see the whole raw line — segment splitting would dismember them.
    if HB_FORKBOMB.is_match(line) {
        return Classification {
            risk: RiskClass::Destructive,
            hard_blocked: true,
            rule: "hard:forkbomb",
        };
    }
    let mut result = Classification { risk: RiskClass::Read, hard_blocked: false, rule: "empty" };
    for segment in split_segments(line) {
        let seg = strip_wrappers(segment.trim());
        if seg.is_empty() {
            continue;
        }
        let c = classify_segment(seg);
        if c.hard_blocked || c.risk > result.risk {
            result = c;
            if result.hard_blocked {
                return result; // nothing outranks the block list
            }
        }
    }
    result
}

/// Split on unquoted `|`, `;`, `&&`, `||`, `&`, and newlines. Quote-aware so
/// `grep "rm -rf /" log` stays ONE segment led by `grep`.
fn split_segments(line: &str) -> Vec<&str> {
    let mut segments = Vec::new();
    let (mut start, mut in_single, mut in_double, mut escaped) = (0usize, false, false, false);
    let bytes = line.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i] as char;
        if escaped {
            escaped = false;
        } else {
            match c {
                '\\' if !in_single => escaped = true,
                '\'' if !in_double => in_single = !in_single,
                '"' if !in_single => in_double = !in_double,
                '|' | ';' | '&' | '\n' if !in_single && !in_double => {
                    segments.push(&line[start..i]);
                    // Treat doubled operators (&&, ||) as one separator.
                    if i + 1 < bytes.len() && (bytes[i + 1] as char == c) {
                        i += 1;
                    }
                    start = i + 1;
                }
                _ => {}
            }
        }
        i += 1;
    }
    segments.push(&line[start..]);
    segments
}

/// Strip command wrappers so `sudo systemctl stop x` classifies as the
/// systemctl call, and env-var prefixes (`FOO=1 cmd`) don't hide the command.
fn strip_wrappers(mut seg: &str) -> &str {
    loop {
        let mut words = seg.splitn(2, char::is_whitespace);
        let Some(first) = words.next() else { return seg };
        let rest = words.next().unwrap_or("").trim_start();
        let is_env_assign = first.contains('=') && !first.starts_with('=');
        let is_wrapper = matches!(first, "sudo" | "env" | "nohup" | "nice" | "ionice" | "time")
            // `timeout 30 cmd` / `doas cmd`
            || first == "timeout" || first == "doas";
        // `xargs`/`watch` execute the command that follows their flags —
        // classify that command, not the wrapper.
        if matches!(first, "xargs" | "watch") {
            let mut r = rest;
            loop {
                let mut it = r.splitn(2, char::is_whitespace);
                match it.next() {
                    Some(w) if w.starts_with('-') => r = it.next().unwrap_or("").trim_start(),
                    _ => break,
                }
            }
            if r.is_empty() {
                return seg;
            }
            seg = r;
            continue;
        }
        if is_env_assign || is_wrapper {
            // For `timeout`, also drop its numeric argument.
            if first == "timeout" {
                let mut r = rest.splitn(2, char::is_whitespace);
                let maybe_n = r.next().unwrap_or("");
                if maybe_n.chars().all(|c| c.is_ascii_digit() || c == 's' || c == 'm') {
                    seg = r.next().unwrap_or("").trim_start();
                    continue;
                }
            }
            if rest.is_empty() {
                return seg;
            }
            seg = rest;
        } else {
            return seg;
        }
    }
}

struct Rule {
    re: &'static LazyLock<Regex>,
    risk: RiskClass,
    hard: bool,
    name: &'static str,
}

// Rules are built explicitly (no clever macro) so each regex is individually
// reviewable. Keep patterns ANCHORED at segment start (`^`) — arguments and
// quoted strings must not fire leading-word rules.

macro_rules! rule_re {
    ($name:ident, $pat:literal) => {
        static $name: LazyLock<Regex> = LazyLock::new(|| Regex::new($pat).expect("static regex"));
    };
}

// ---- Always-on block list (hard_blocked): no autonomy level may run these.
rule_re!(HB_RM_ROOT, r"^rm\s+(-[a-zA-Z]+\s+)*(-[a-zA-Z]*[rf][a-zA-Z]*\s+)*(/|/\*)(\s|$)");
rule_re!(HB_DD_BLOCKDEV, r"^dd\s+.*\bof=/dev/(sd|nvme|vd|xvd|hd|mmcblk|dm-)");
rule_re!(HB_MKFS, r"^mkfs(\.[a-z0-9]+)?\s");
rule_re!(HB_WIPEFS, r"^wipefs\s");
rule_re!(HB_SHRED_DEV, r"^shred\s+.*/dev/");
rule_re!(HB_FORKBOMB, r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}");
rule_re!(HB_CHMOD_ROOT, r"^ch(mod|own)\s+(-[a-zA-Z]+\s+)*.*\s+/(\s|$)");
rule_re!(HB_REDIR_BLOCKDEV, r">\s*/dev/(sd|nvme|vd|xvd|hd|mmcblk)");
rule_re!(HB_DROP_DATABASE, r"(?i)^\s*drop\s+database\b");
rule_re!(HB_KUBE_DELETE_ALL_NS, r"^kubectl\s+delete\s+(ns|namespace)s?\s+--all\b");

// ---- Destructive (gated hardest; runbook pre-approval does NOT unlock these
//      at act_on_known — they always ask below `auto`, and `auto` still asks).
rule_re!(D_RM_RF, r"^rm\s+(-[a-zA-Z]+\s+)*-[a-zA-Z]*[rf]");
rule_re!(D_KUBE_DELETE_HEAVY, r"^kubectl\s+delete\s+(ns|namespace|pv|persistentvolume|crd|node)\b");
rule_re!(D_KUBE_DELETE_FLAG_ALL, r"^kubectl\s+delete\s+.*--all\b");
rule_re!(D_TERRAFORM_DESTROY, r"^terraform\s+destroy\b");
rule_re!(D_AZ_DELETE, r"^az\s+.*\bdelete\b");
rule_re!(D_DOCKER_PRUNE, r"^docker\s+(system|volume|image|container)\s+prune\b");
rule_re!(D_DROP_TABLE, r"(?i)^\s*drop\s+(table|index|schema|user|role)\b");
rule_re!(D_TRUNCATE, r"(?i)^\s*truncate\s+table\b");
rule_re!(D_DELETE_NO_WHERE, r"(?i)^\s*delete\s+from\s+\S+\s*;?\s*$");
rule_re!(D_GIT_FORCE_PUSH, r"^git\s+push\s+.*(--force|-f)\b");
rule_re!(D_USERDEL, r"^userdel\s");

// ---- High: service-affecting, recoverable.
rule_re!(H_SYSTEMCTL, r"^systemctl\s+(stop|restart|kill|mask|isolate)\b");
rule_re!(H_REBOOT, r"^(reboot|shutdown|halt|poweroff)\b");
rule_re!(H_KILL, r"^(kill|pkill|killall)\b");
rule_re!(H_DOCKER_LIFECYCLE, r"^docker\s+(stop|restart|kill|rm|rmi)\b");
rule_re!(H_KUBE_DISRUPT, r"^kubectl\s+(delete|drain|cordon|taint|rollout\s+(restart|undo))\b");
rule_re!(H_IPTABLES_MUT, r"^(iptables|nft|ufw|firewall-cmd)\s+.*(-F|-X|-D|delete|flush|disable)");
rule_re!(H_SQL_DELETE, r"(?i)^\s*delete\s+from\b");
rule_re!(H_SQL_UPDATE, r"(?i)^\s*update\s+\S+\s+set\b");
rule_re!(H_UMOUNT, r"^u?mount\s");
rule_re!(H_SWAPOFF, r"^swapoff\b");
rule_re!(H_ARGO_ROLLBACK, r"^argocd\s+app\s+(rollback|delete|terminate-op)\b");

// ---- Medium: mutating but contained.
rule_re!(M_SYSTEMCTL, r"^systemctl\s+(start|reload|enable|disable|daemon-reload|unmask)\b");
rule_re!(
    M_KUBE_MUT,
    r"^kubectl\s+(apply|scale|patch|label|annotate|set|create|edit|uncordon|exec|cp|port-forward)\b"
);
rule_re!(
    M_DOCKER_MUT,
    r"^docker\s+(run|start|create|exec|pull|build|tag|push|update|pause|unpause)\b"
);
rule_re!(M_ARGO_MUT, r"^argocd\s+app\s+(sync|set|patch|create)\b");
rule_re!(
    M_FILE_MUT,
    r"^(mv|cp|mkdir|rmdir|touch|ln|sed\s+(-[a-zA-Z]+\s+)*-i|tee|truncate|chmod|chown|chgrp)\b"
);
rule_re!(
    M_PKG,
    r"^(apt|apt-get|yum|dnf|pacman|apk|pip|pip3|npm|cargo)\s+(install|remove|update|upgrade|uninstall|add|del)\b"
);
rule_re!(M_NET_CLIENT, r"^(curl|wget|nc|ncat|ssh|scp|rsync)\b");
rule_re!(M_GIT_MUT, r"^git\s+(push|commit|merge|rebase|reset|checkout|revert|cherry-pick|clean)\b");
rule_re!(
    M_SQL_INSERT,
    r"(?i)^\s*(insert\s+into|create\s+(table|index|user|role)|alter|grant|revoke|reindex|vacuum)\b"
);
rule_re!(M_WRITE_REDIR, r"(^|\s)>{1,2}\s*\S");
rule_re!(M_SWAPON, r"^swapon\b");

// ---- Read: recognized read-only leading words.
rule_re!(
    R_READ,
    r"^(ls|ll|cat|head|tail|less|more|grep|egrep|fgrep|rg|find|stat|file|wc|du|df|free|ps|top|htop|uptime|w|who|id|whoami|hostname|hostnamectl|uname|date|env|printenv|echo|printf|pwd|which|type|dig|nslookup|host|ping|traceroute|tracepath|mtr|ss|netstat|ip|ifconfig|arp|lsof|lsblk|blkid|fdisk\s+-l|mount\s*$|vmstat|iostat|mpstat|sar|dmesg|journalctl|last|lastlog|numactl|nproc|lscpu|lsmem|lspci|lsusb|sysctl\s+[^-w]|ulimit|getent|md5sum|sha\d*sum|b2sum|openssl\s+(x509|s_client|verify)|git\s+(status|log|diff|show|branch|remote|describe)|systemctl\s+(status|show|list-units|list-timers|is-active|is-enabled|cat)|docker\s+(ps|images|inspect|logs|stats|version|info|top|diff|port)|kubectl\s+(get|describe|logs|top|explain|version|api-resources|cluster-info|config\s+(view|get-contexts|current-context)|auth\s+can-i)|argocd\s+app\s+(list|get|history|diff)|az\s+.*\b(show|list|list-usage|get-access-token)\b|helm\s+(list|status|get|history|show)|crictl\s+(ps|pods|logs|inspect)|select\b|SELECT\b|explain\b|show\b|describe\b)"
);

static RULES: LazyLock<Vec<Rule>> = LazyLock::new(|| {
    vec![
        // Block list first — nothing may shadow it.
        Rule { re: &HB_RM_ROOT, risk: RiskClass::Destructive, hard: true, name: "hard:rm-root" },
        Rule {
            re: &HB_DD_BLOCKDEV,
            risk: RiskClass::Destructive,
            hard: true,
            name: "hard:dd-blockdev",
        },
        Rule { re: &HB_MKFS, risk: RiskClass::Destructive, hard: true, name: "hard:mkfs" },
        Rule { re: &HB_WIPEFS, risk: RiskClass::Destructive, hard: true, name: "hard:wipefs" },
        Rule {
            re: &HB_SHRED_DEV,
            risk: RiskClass::Destructive,
            hard: true,
            name: "hard:shred-dev",
        },
        Rule { re: &HB_FORKBOMB, risk: RiskClass::Destructive, hard: true, name: "hard:forkbomb" },
        Rule {
            re: &HB_CHMOD_ROOT,
            risk: RiskClass::Destructive,
            hard: true,
            name: "hard:chmod-root",
        },
        Rule {
            re: &HB_REDIR_BLOCKDEV,
            risk: RiskClass::Destructive,
            hard: true,
            name: "hard:redir-blockdev",
        },
        Rule {
            re: &HB_DROP_DATABASE,
            risk: RiskClass::Destructive,
            hard: true,
            name: "hard:drop-database",
        },
        Rule {
            re: &HB_KUBE_DELETE_ALL_NS,
            risk: RiskClass::Destructive,
            hard: true,
            name: "hard:kubectl-delete-all-ns",
        },
        // Destructive.
        Rule { re: &D_RM_RF, risk: RiskClass::Destructive, hard: false, name: "rm-rf" },
        Rule {
            re: &D_KUBE_DELETE_HEAVY,
            risk: RiskClass::Destructive,
            hard: false,
            name: "kubectl-delete-heavy",
        },
        Rule {
            re: &D_KUBE_DELETE_FLAG_ALL,
            risk: RiskClass::Destructive,
            hard: false,
            name: "kubectl-delete-all",
        },
        Rule {
            re: &D_TERRAFORM_DESTROY,
            risk: RiskClass::Destructive,
            hard: false,
            name: "terraform-destroy",
        },
        Rule { re: &D_AZ_DELETE, risk: RiskClass::Destructive, hard: false, name: "az-delete" },
        Rule {
            re: &D_DOCKER_PRUNE,
            risk: RiskClass::Destructive,
            hard: false,
            name: "docker-prune",
        },
        Rule { re: &D_DROP_TABLE, risk: RiskClass::Destructive, hard: false, name: "sql-drop" },
        Rule { re: &D_TRUNCATE, risk: RiskClass::Destructive, hard: false, name: "sql-truncate" },
        Rule {
            re: &D_DELETE_NO_WHERE,
            risk: RiskClass::Destructive,
            hard: false,
            name: "sql-delete-no-where",
        },
        Rule {
            re: &D_GIT_FORCE_PUSH,
            risk: RiskClass::Destructive,
            hard: false,
            name: "git-force-push",
        },
        Rule { re: &D_USERDEL, risk: RiskClass::Destructive, hard: false, name: "userdel" },
        // High.
        Rule { re: &H_SYSTEMCTL, risk: RiskClass::High, hard: false, name: "systemctl-disrupt" },
        Rule { re: &H_REBOOT, risk: RiskClass::High, hard: false, name: "reboot" },
        Rule { re: &H_KILL, risk: RiskClass::High, hard: false, name: "kill" },
        Rule {
            re: &H_DOCKER_LIFECYCLE,
            risk: RiskClass::High,
            hard: false,
            name: "docker-lifecycle",
        },
        Rule { re: &H_KUBE_DISRUPT, risk: RiskClass::High, hard: false, name: "kubectl-disrupt" },
        Rule { re: &H_IPTABLES_MUT, risk: RiskClass::High, hard: false, name: "firewall-mutate" },
        Rule { re: &H_SQL_DELETE, risk: RiskClass::High, hard: false, name: "sql-delete" },
        Rule { re: &H_SQL_UPDATE, risk: RiskClass::High, hard: false, name: "sql-update" },
        Rule { re: &H_UMOUNT, risk: RiskClass::High, hard: false, name: "mount" },
        Rule { re: &H_SWAPOFF, risk: RiskClass::High, hard: false, name: "swapoff" },
        Rule { re: &H_ARGO_ROLLBACK, risk: RiskClass::High, hard: false, name: "argocd-rollback" },
        // Medium.
        Rule { re: &M_SYSTEMCTL, risk: RiskClass::Medium, hard: false, name: "systemctl-mutate" },
        Rule { re: &M_KUBE_MUT, risk: RiskClass::Medium, hard: false, name: "kubectl-mutate" },
        Rule { re: &M_DOCKER_MUT, risk: RiskClass::Medium, hard: false, name: "docker-mutate" },
        Rule { re: &M_ARGO_MUT, risk: RiskClass::Medium, hard: false, name: "argocd-mutate" },
        Rule { re: &M_FILE_MUT, risk: RiskClass::Medium, hard: false, name: "file-mutate" },
        Rule { re: &M_PKG, risk: RiskClass::Medium, hard: false, name: "package-mutate" },
        Rule { re: &M_NET_CLIENT, risk: RiskClass::Medium, hard: false, name: "net-client" },
        Rule { re: &M_GIT_MUT, risk: RiskClass::Medium, hard: false, name: "git-mutate" },
        Rule { re: &M_SQL_INSERT, risk: RiskClass::Medium, hard: false, name: "sql-mutate" },
        Rule { re: &M_SWAPON, risk: RiskClass::Medium, hard: false, name: "swapon" },
        // Read.
        Rule { re: &R_READ, risk: RiskClass::Read, hard: false, name: "read" },
        // Write-redirection check runs AFTER read so `ps aux > /tmp/x` still
        // classifies Medium via the max() in classify_segment.
        Rule { re: &M_WRITE_REDIR, risk: RiskClass::Medium, hard: false, name: "write-redirect" },
    ]
});

fn classify_segment(seg: &str) -> Classification {
    let mut best: Option<Classification> = None;
    for rule in RULES.iter() {
        if rule.re.is_match(seg) {
            let c = Classification { risk: rule.risk, hard_blocked: rule.hard, rule: rule.name };
            if c.hard_blocked {
                return c;
            }
            match &best {
                Some(b) if b.risk >= c.risk => {}
                _ => best = Some(c),
            }
        }
    }
    // Unknown commands fail closed to Medium.
    best.unwrap_or(Classification {
        risk: RiskClass::Medium,
        hard_blocked: false,
        rule: "unknown-command",
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use RiskClass::*;

    fn risk(line: &str) -> RiskClass {
        classify_command(line).risk
    }

    fn hard(line: &str) -> bool {
        classify_command(line).hard_blocked
    }

    #[test]
    fn reads_classify_read() {
        for cmd in [
            "df -h",
            "free -m",
            "ps aux",
            "uptime",
            "cat /var/log/syslog",
            "journalctl -u nginx --since '1 hour ago'",
            "systemctl status nginx",
            "kubectl get pods -A",
            "kubectl describe pod web-1 -n prod",
            "kubectl logs deploy/api --tail 100",
            "docker ps -a",
            "docker logs api --tail 50",
            "dig +short example.com",
            "ss -tlnp",
            "argocd app list",
            "az aks show -g rg-prod -n cluster",
            "az vm list-usage --location uksouth",
            "helm list -A",
            "SELECT count(*) FROM jobs;",
            "git status",
        ] {
            assert_eq!(risk(cmd), Read, "{cmd}");
            assert!(!hard(cmd), "{cmd}");
        }
    }

    #[test]
    fn mediums() {
        for cmd in [
            "kubectl scale deploy/api --replicas=3 -n prod",
            "kubectl apply -f manifest.yaml",
            "systemctl reload nginx",
            "docker run -d nginx",
            "sed -i 's/a/b/' /etc/app.conf",
            "curl -X POST http://internal/api",
            "argocd app sync api",
            "apt-get install -y jq",
            "some-unknown-binary --flag",
            "echo hello > /tmp/out.txt", // read cmd + write redirect
        ] {
            assert_eq!(risk(cmd), Medium, "{cmd}");
            assert!(!hard(cmd), "{cmd}");
        }
    }

    #[test]
    fn highs() {
        for cmd in [
            "systemctl restart nginx",
            "systemctl stop postgresql",
            "kill -9 1234",
            "pkill -f java",
            "docker restart api",
            "docker rm old-container",
            "kubectl delete pod web-1 -n prod",
            "kubectl drain node-3 --ignore-daemonsets",
            "kubectl rollout restart deploy/api",
            "kubectl rollout undo deploy/api",
            "reboot",
            "iptables -F",
            "DELETE FROM sessions WHERE expired = true;",
            "UPDATE jobs SET enabled = false WHERE id = 'x';",
            "argocd app rollback api 42",
        ] {
            assert_eq!(risk(cmd), High, "{cmd}");
            assert!(!hard(cmd), "{cmd}");
        }
    }

    #[test]
    fn destructives_gated_not_blocked() {
        for cmd in [
            "rm -rf /var/log/app",
            "rm -fr ./build",
            "kubectl delete namespace staging",
            "kubectl delete pods --all -n dev",
            "terraform destroy -auto-approve",
            "az group delete -n rg-old --yes",
            "docker system prune -a --volumes",
            "DROP TABLE users;",
            "TRUNCATE TABLE events;",
            "DELETE FROM audit;",
            "git push --force origin main",
        ] {
            assert_eq!(risk(cmd), Destructive, "{cmd}");
            assert!(!hard(cmd), "{cmd} must be gated, not hard-blocked");
        }
    }

    #[test]
    fn hard_block_list() {
        for cmd in [
            "rm -rf /",
            "rm -rf / --no-preserve-root",
            "sudo rm -rf /",
            "dd if=/dev/zero of=/dev/sda",
            "mkfs.ext4 /dev/sdb1",
            "wipefs -a /dev/sda",
            ":(){ :|:& };:",
            "chmod -R 777 /",
            "echo x > /dev/sda",
            "DROP DATABASE prod;",
            "kubectl delete namespaces --all",
        ] {
            assert!(hard(cmd), "{cmd} must be hard-blocked");
            assert_eq!(risk(cmd), Destructive, "{cmd}");
        }
    }

    #[test]
    fn benign_lookalikes_do_not_misfire() {
        // Dangerous strings as ARGUMENTS to read commands must not fire.
        assert_eq!(risk(r#"grep "rm -rf /" /var/log/audit.log"#), Read);
        assert_eq!(risk(r#"journalctl | grep "DROP TABLE""#), Read);
        assert_eq!(risk("cat /etc/mkfs.conf"), Read);
        // `--force` inside a quoted arg, not a git push.
        assert_eq!(risk(r#"grep -- "--force" deploy.log"#), Read);
    }

    #[test]
    fn pipelines_classify_as_max_segment() {
        assert_eq!(risk("ps aux | grep java"), Read);
        assert_eq!(risk("cat ids.txt | xargs kill -9"), High);
        assert_eq!(risk("df -h && systemctl restart nginx"), High);
        assert_eq!(risk("uptime; rm -rf /tmp/x"), Destructive);
        assert!(hard("uptime && rm -rf /"));
    }

    #[test]
    fn wrappers_are_stripped() {
        assert_eq!(risk("sudo systemctl restart nginx"), High);
        assert_eq!(risk("sudo -u postgres psql"), Medium); // unknown after strip → medium floor via psql? psql unknown → medium
        assert_eq!(risk("env FOO=1 kubectl get pods"), Read);
        assert_eq!(risk("RUST_LOG=debug ./app --check"), Medium); // unknown binary
        assert_eq!(risk("timeout 30 df -h"), Read);
        assert!(hard("sudo dd if=/dev/zero of=/dev/nvme0n1"));
    }

    #[test]
    fn unknown_fails_closed_to_medium() {
        assert_eq!(risk("frobnicate --all"), Medium);
        assert_eq!(classify_command("frobnicate").rule, "unknown-command");
    }
}
