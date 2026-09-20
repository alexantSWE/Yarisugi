use anyhow::{bail, Context, Result};
use std::net::Ipv4Addr;
use std::process::{Command, Stdio};

use crate::RoutingConfig;

/// Settings the routing backends operate on. Carries renderable strings so the
/// module stays free of parser coupling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TProxySettings {
    pub tproxy_port: u16,
    pub proxy_fwmark: u32,
    pub table_id: u32,
    pub dns_ipv4: Option<Ipv4Addr>,
    pub bypass_subnets: Vec<String>,
    pub bypass_subnets_v6: Vec<String>,
    pub core_uid: Option<u32>,
}

impl From<&RoutingConfig> for TProxySettings {
    fn from(config: &RoutingConfig) -> Self {
        Self {
            tproxy_port: config.tproxy_port,
            proxy_fwmark: config.proxy_fwmark,
            table_id: config.table_id,
            dns_ipv4: config.dns_ipv4,
            bypass_subnets: config.bypass_subnets.iter().map(ToString::to_string).collect(),
            bypass_subnets_v6: config.bypass_subnets_v6.iter().map(ToString::to_string).collect(),
            core_uid: config.core_uid,
        }
    }
}

const LOCAL_BYPASS_V4: &[&str] = &["127.0.0.0/8", "169.254.0.0/16"];
const LOCAL_BYPASS_V6: &[&str] = &["::1/128", "fe80::/10", "fc00::/7"];

pub trait RoutingBackend: Send + Sync {
    fn enable(&self, settings: &TProxySettings) -> Result<()>;
    fn disable(&self, settings: Option<&TProxySettings>) -> Result<()>;
}

/// Real TPROXY/nftables backend. Requires root, the `nft` and `ip` binaries.
/// Rulesets are applied atomically as a single `nft -f -` transaction; policy
/// routing is installed/removed around it and rolled back on failure.
pub struct NftablesBackend;

impl RoutingBackend for NftablesBackend {
    fn enable(&self, settings: &TProxySettings) -> Result<()> {
        ensure_prerequisites()?;
        install_policy_routing(settings)?;
        if let Err(error) = apply_ruleset(&render_ruleset(settings)) {
            remove_policy_routing(settings)?;
            return Err(error.context("nftables ruleset failed; policy routing was rolled back"));
        }
        Ok(())
    }

    fn disable(&self, settings: Option<&TProxySettings>) -> Result<()> {
        let _ = apply_ruleset("delete table inet myproxy");
        if let Some(settings) = settings {
            remove_policy_routing(settings)?;
        }
        Ok(())
    }
}

fn ensure_prerequisites() -> Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        bail!("nftables backend requires root privileges");
    }
    for binary in ["nft", "ip"] {
        if Command::new(binary).arg("--version").output().is_err() {
            bail!("required binary `{binary}` is not available");
        }
    }
    Ok(())
}

fn apply_ruleset(ruleset: &str) -> Result<()> {
    let mut child = Command::new("nft")
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("failed to run `nft -f -`")?;
    use std::io::Write;
    child
        .stdin
        .as_mut()
        .context("nft stdin is unavailable")?
        .write_all(ruleset.as_bytes())
        .context("failed to write ruleset to nft")?;
    let status = child.wait_with_output()?;
    if !status.status.success() {
        bail!(
            "nft rejected the ruleset: {}",
            String::from_utf8_lossy(&status.stderr).trim()
        );
    }
    Ok(())
}

fn install_policy_routing(settings: &TProxySettings) -> Result<()> {
    run_ip(&rule_args(true, Op::Add, settings))?;
    run_ip(&route_args(true, Op::Add, settings))?;
    run_ip(&rule_args(false, Op::Add, settings))?;
    run_ip(&route_args(false, Op::Add, settings))?;
    Ok(())
}

fn remove_policy_routing(settings: &TProxySettings) -> Result<()> {
    for args in [
        rule_args(true, Op::Del, settings),
        route_args(true, Op::Del, settings),
        rule_args(false, Op::Del, settings),
        route_args(false, Op::Del, settings),
    ] {
        let _ = run_ip(&args);
    }
    Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Op {
    Add,
    Del,
}

/// `ip [-6] rule add|del fwmark 0x{N} lookup {table}`
fn rule_args(v4: bool, op: Op, settings: &TProxySettings) -> Vec<String> {
    let mut args = vec!["ip".into()];
    if !v4 {
        args.push("-6".into());
    }
    args.push("rule".into());
    args.push(match op {
        Op::Add => "add".into(),
        Op::Del => "del".into(),
    });
    args.push("fwmark".into());
    args.push(format!("{:#x}", settings.proxy_fwmark));
    args.push("lookup".into());
    args.push(settings.table_id.to_string());
    args
}

/// `ip [-6] route add local 0.0.0.0/0|::/0 dev lo table {table}` (flush on del)
fn route_args(v4: bool, op: Op, settings: &TProxySettings) -> Vec<String> {
    let mut args = vec!["ip".into()];
    if !v4 {
        args.push("-6".into());
    }
    args.push("route".into());
    args.push(match op {
        Op::Add => "add".into(),
        Op::Del => "flush".into(),
    });
    if op == Op::Add {
        args.push("local".into());
        args.push(if v4 { "0.0.0.0/0" } else { "::/0" }.into());
        args.push("dev".into());
        args.push("lo".into());
    }
    args.push("table".into());
    args.push(settings.table_id.to_string());
    args
}

fn run_ip(args: &[String]) -> Result<()> {
    let output = Command::new(&args[0])
        .args(&args[1..])
        .output()
        .with_context(|| format!("failed to run `{}`", args.join(" ")))?;
    if !output.status.success() {
        bail!(
            "`ip` rejected arguments `{}`: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}
/// Renders an atomic nftables ruleset for local TPROXY interception.
///
/// Mark scheme (single value, per the upstream sing-box convention):
///   - packets leaving locally are stamped with `proxy_fwmark` in the output
///     `type route` hook so the policy rule (`fwmark lookup table`) routes them
///     into TPROXY;
///   - `meta mark {mark} return` in output keeps already-marked sockets (the
///     proxy core's own connections, which bind SO_MARK) from being re-marked,
///     which is what breaks the intercept loop;
///   - prerouting stamps intercepted sockets with the same mark value.
pub fn render_ruleset(settings: &TProxySettings) -> String {
    let mark = format!("{:#x}", settings.proxy_fwmark);
    let bypass_v4 = cidr_set(&settings.bypass_subnets, LOCAL_BYPASS_V4);
    let bypass_v6 = cidr_set(&settings.bypass_subnets_v6, LOCAL_BYPASS_V6);
    let uid_bypass = settings
        .core_uid
        .map(|uid| format!("\t\tmeta skuid {} return\n", uid))
        .unwrap_or_default();

    format!(
        "table inet myproxy {{
\tset bypass_v4 {{
\t\ttype ipv4_addr
\t\tflags interval
\t\telements = {{ {bypass_v4} }}
\t}}
\tset bypass_v6 {{
\t\ttype ipv6_addr
\t\tflags interval
\t\telements = {{ {bypass_v6} }}
\t}}
\tchain prerouting {{
\t\ttype filter hook prerouting priority mangle; policy accept;
\t\tip daddr @bypass_v4 return
\t\tip6 daddr @bypass_v6 return
\t\tmeta mark {mark} return
\t\tmeta l4proto {{ tcp, udp }} tproxy to :{port} meta mark set {mark} accept
\t}}
\tchain output {{
\t\ttype route hook output priority mangle; policy accept;
\t\tip daddr @bypass_v4 return
\t\tip6 daddr @bypass_v6 return
\t\tmeta mark {mark} return
{uid_bypass}\t\tmeta l4proto {{ tcp, udp }} meta mark set {mark} accept
\t}}
}}\n",
        port = settings.tproxy_port,
        mark = mark,
        bypass_v4 = bypass_v4,
        bypass_v6 = bypass_v6,
        uid_bypass = uid_bypass,
    )
}

fn cidr_set(configured: &[String], defaults: &[&str]) -> String {
    let mut cidrs: Vec<String> = defaults.iter().map(|value| (*value).to_owned()).collect();
    for cidr in configured {
        if !cidrs.contains(cidr) {
            cidrs.push(cidr.clone());
        }
    }
    cidrs.join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings(tproxy_port: u16, fwmark: u32, table: u32) -> TProxySettings {
        TProxySettings {
            tproxy_port,
            proxy_fwmark: fwmark,
            table_id: table,
            dns_ipv4: None,
            bypass_subnets: vec!["192.168.0.0/16".into()],
            bypass_subnets_v6: vec!["2001:db8::/32".into()],
            core_uid: Some(1000),
        }
    }

    #[test]
    fn ruleset_contains_dual_stack_tproxy_pipeline() {
        let rendered = render_ruleset(&settings(12345, 0x1, 100));
        assert!(rendered.contains("tproxy to :12345"));
        assert_eq!(rendered.matches("meta mark set 0x1").count(), 2);
        assert_eq!(rendered.matches("meta mark 0x1 return").count(), 2);
        assert!(rendered.contains("meta skuid 1000 return"));
        assert!(rendered.contains("ip daddr @bypass_v4 return"));
        assert!(rendered.contains("ip6 daddr @bypass_v6 return"));
        assert!(rendered.contains("::1/128"));
        assert!(rendered.contains("fc00::/7"));
        assert!(rendered.contains("192.168.0.0/16"));
        assert!(rendered.contains("2001:db8::/32"));
    }

    #[test]
    fn ruleset_omits_uid_bypass_when_unset() {
        let mut empty = settings(12345, 0x1, 100);
        empty.core_uid = None;
        assert!(!render_ruleset(&empty).contains("skuid"));
    }

    #[test]
    fn mark_is_formatted_as_hex() {
        assert!(render_ruleset(&settings(12345, 0xff, 100)).contains("meta mark 0xff"));
    }

    #[test]
    fn policy_rules_use_fwmark_table_and_family() {
        let cfg = settings(12345, 0x1, 100);
        assert_eq!(
            rule_args(true, Op::Add, &cfg).join(" "),
            "ip rule add fwmark 0x1 lookup 100"
        );
        assert_eq!(
            rule_args(false, Op::Add, &cfg).join(" "),
            "ip -6 rule add fwmark 0x1 lookup 100"
        );
        assert_eq!(
            route_args(false, Op::Del, &cfg).join(" "),
            "ip -6 route flush table 100"
        );
        assert_eq!(
            route_args(true, Op::Add, &cfg).join(" "),
            "ip route add local 0.0.0.0/0 dev lo table 100"
        );
    }

    #[test]
    fn configured_bypass_matches_local_defaults_without_duplication() {
        let mut cfg = settings(12345, 0x1, 100);
        cfg.bypass_subnets = vec!["127.0.0.0/8".into(), "10.0.0.0/8".into()];
        let cidrs = cidr_set(&cfg.bypass_subnets, LOCAL_BYPASS_V4);
        assert_eq!(cidrs.matches("127.0.0.0/8").count(), 1);
        assert!(cidrs.contains("10.0.0.0/8"));
    }
}
