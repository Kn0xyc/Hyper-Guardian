use std::{collections::HashSet, net::IpAddr, str::FromStr, time::Duration};

use anyhow::Context;
use ipnet::IpNet;
use tokio::{process::Command, time::timeout};
use tracing::info;

pub fn in_scope(target: &str, allowlist: &[String]) -> bool {
    if allowlist
        .iter()
        .any(|item| item.eq_ignore_ascii_case(target))
    {
        return true;
    }

    if let Ok(ip) = IpAddr::from_str(target) {
        return allowlist.iter().any(|entry| {
            IpNet::from_str(entry)
                .map(|net| net.contains(&ip))
                .unwrap_or(false)
        });
    }

    false
}

pub async fn run_command_allowlisted(
    cmd: &str,
    args: &[String],
    allowed: &[&str],
    timeout_secs: u64,
) -> anyhow::Result<String> {
    let allowed_set: HashSet<&str> = allowed.iter().copied().collect();
    if !allowed_set.contains(cmd) {
        anyhow::bail!("command not allowed: {cmd}");
    }

    info!(command = cmd, ?args, "audit: launching external tool");
    let mut child = Command::new(cmd)
        .args(args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .context("failed to spawn command")?;

    let out = timeout(Duration::from_secs(timeout_secs), child.wait_with_output()).await??;

    if !out.status.success() {
        anyhow::bail!("command failed: {}", String::from_utf8_lossy(&out.stderr));
    }

    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}
