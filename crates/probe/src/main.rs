use anyhow::{bail, Context, Result};
use myproxy_parser::ingest_subscription;
use myproxy_probe::{probe_batch, ProbeConfig, ProbeDepth, ProbeEngine, ProbeFailure};
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut path = None;
    let mut concurrency = ProbeConfig::default().concurrency_limit;
    let mut timeout_ms = ProbeConfig::default().connect_timeout.as_millis() as u64;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--concurrency" => {
                index += 1;
                concurrency = args
                    .get(index)
                    .with_context(|| "--concurrency needs a value")?
                    .parse()
                    .context("--concurrency must be a number")?;
            }
            "--timeout-ms" => {
                index += 1;
                timeout_ms = args
                    .get(index)
                    .with_context(|| "--timeout-ms needs a value")?
                    .parse()
                    .context("--timeout-ms must be a number")?;
            }
            flag if flag.starts_with("--") => bail!("unknown flag {flag}"),
            value => {
                if path.is_some() {
                    bail!("expected a single subscription file");
                }
                path = Some(value.to_owned());
            }
        }
        index += 1;
    }
    let path = path.context("usage: myproxy-probe <subscription> [--concurrency N] [--timeout-ms T]")?;

    let raw = std::fs::read(&path)
        .with_context(|| format!("failed to read {}", path))?;
    let report = ingest_subscription(&raw, 1);

    let config = ProbeConfig {
        concurrency_limit: concurrency,
        connect_timeout: Duration::from_millis(timeout_ms),
        ..ProbeConfig::default()
    };
    let engine = ProbeEngine::new(config);

    let mut outcomes = probe_batch(&engine, &report.successful_nodes, ProbeDepth::L4Ping).await;
    outcomes.sort_by(|a, b| a.label.cmp(&b.label));

    let alive = outcomes.iter().filter(|outcome| outcome.alive).count();
    for outcome in &outcomes {
        let status = if outcome.alive { "ALIVE" } else { "DEAD " };
        let latency = outcome
            .latency_ms
            .map(|rtt| format!("{}ms", rtt))
            .unwrap_or_else(|| "--".into());
        let reason = outcome
            .failure
            .map(describe_failure)
            .unwrap_or_else(|| "ok");
        let country = String::from_utf8_lossy(&outcome.country_code);
        println!(
            "[{status}] {:>8}  {:9}@{}  {}  {}",
            latency, outcome.protocol, country, outcome.label, reason
        );
    }

    let skipped = report.failed_entries.len();
    println!(
        "\n{} of {} nodes alive ({} skipped, {} duplicates)",
        alive,
        report.successful_nodes.len(),
        skipped,
        report.duplicates_omitted
    );
    Ok(())
}

fn describe_failure(failure: ProbeFailure) -> &'static str {
    match failure {
        ProbeFailure::Refused => "connection refused",
        ProbeFailure::TimedOut => "timed out",
        ProbeFailure::Unresolvable => "unresolvable",
        ProbeFailure::NoReply => "no reply",
        ProbeFailure::Io => "io error",
    }
}