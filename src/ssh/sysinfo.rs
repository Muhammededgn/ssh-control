use std::time::Duration;

use russh::ChannelMsg;
use russh::client;

use super::client::Handler;
use crate::config::SystemInfo;
use crate::error::{AppError, Result};

const EXEC_TIMEOUT: Duration = Duration::from_secs(10);

/// Marker prefixes for each probed value, so the combined shell command's
/// output can be parsed by line regardless of ordering/interleaving quirks.
const CPU_MODEL: &str = "SSHCTL_CPU_MODEL:";
const CPU_CORES: &str = "SSHCTL_CPU_CORES:";
const MEM_TOTAL: &str = "SSHCTL_MEM_TOTAL:";
const MEM_USED: &str = "SSHCTL_MEM_USED:";
const DISK_TOTAL: &str = "SSHCTL_DISK_TOTAL:";
const DISK_USED: &str = "SSHCTL_DISK_USED:";
const GPU_MODEL: &str = "SSHCTL_GPU_MODEL:";

/// One `sh -c` invocation combining every probe, each result on its own
/// prefixed line. Every probe degrades to an empty value (never fails the
/// whole command) so a restricted shell/missing tool just yields blanks
/// rather than aborting the others — `2>/dev/null` and `|| true` throughout.
fn probe_command() -> String {
    format!(
        "echo '{CPU_MODEL}'$(grep -m1 'model name' /proc/cpuinfo 2>/dev/null | cut -d: -f2 | sed 's/^ *//'); \
         echo '{CPU_CORES}'$(nproc 2>/dev/null); \
         echo '{MEM_TOTAL}'$(free -b 2>/dev/null | awk '/^Mem:/{{print $2}}'); \
         echo '{MEM_USED}'$(free -b 2>/dev/null | awk '/^Mem:/{{print $3}}'); \
         echo '{DISK_TOTAL}'$(df -B1 --total 2>/dev/null | awk '/^total/{{print $2}}'); \
         echo '{DISK_USED}'$(df -B1 --total 2>/dev/null | awk '/^total/{{print $3}}'); \
         echo '{GPU_MODEL}'$(lspci 2>/dev/null | grep -Ei 'vga|3d controller|display controller' | head -1 | cut -d: -f3- | sed 's/^ *//')"
    )
}

/// Runs a one-shot probe command over a fresh exec channel on `handle` and
/// parses CPU/RAM/disk/GPU info out of it. Best-effort: any missing/blank
/// field is left `None` rather than failing the whole fetch, since not every
/// remote shell has every tool (`lspci`, `free`, ...) installed.
pub async fn fetch(handle: &mut client::Handle<Handler>) -> Result<SystemInfo> {
    let mut channel = handle.channel_open_session().await?;
    channel.exec(true, probe_command()).await?;

    let mut output = Vec::new();
    let result = tokio::time::timeout(EXEC_TIMEOUT, async {
        loop {
            match channel.wait().await {
                Some(ChannelMsg::Data { data }) => output.extend_from_slice(&data),
                Some(ChannelMsg::ExtendedData { data, .. }) => output.extend_from_slice(&data),
                Some(ChannelMsg::ExitStatus { .. }) | Some(ChannelMsg::Eof) | Some(ChannelMsg::Close) | None => {
                    break;
                }
                _ => {}
            }
        }
    })
    .await;

    if result.is_err() {
        return Err(AppError::SshConnect("timed out fetching system info".into()));
    }

    let text = String::from_utf8_lossy(&output);
    Ok(parse(&text))
}

fn field<'a>(text: &'a str, prefix: &str) -> Option<&'a str> {
    text.lines().find_map(|line| line.strip_prefix(prefix)).map(str::trim).filter(|s| !s.is_empty())
}

fn parse(text: &str) -> SystemInfo {
    SystemInfo {
        cpu_model: field(text, CPU_MODEL).map(str::to_string),
        cpu_cores: field(text, CPU_CORES).and_then(|s| s.parse().ok()),
        mem_total_bytes: field(text, MEM_TOTAL).and_then(|s| s.parse().ok()),
        mem_used_bytes: field(text, MEM_USED).and_then(|s| s.parse().ok()),
        disk_total_bytes: field(text, DISK_TOTAL).and_then(|s| s.parse().ok()),
        disk_used_bytes: field(text, DISK_USED).and_then(|s| s.parse().ok()),
        gpu_model: field(text, GPU_MODEL).map(str::to_string),
        fetched_at_unix: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_well_formed_output() {
        let text = format!(
            "{CPU_MODEL}Intel(R) Core(TM) i7\n{CPU_CORES}8\n{MEM_TOTAL}16000000000\n{MEM_USED}4000000000\n\
             {DISK_TOTAL}500000000000\n{DISK_USED}100000000000\n{GPU_MODEL}NVIDIA GeForce RTX 3080\n"
        );
        let info = parse(&text);
        assert_eq!(info.cpu_model.as_deref(), Some("Intel(R) Core(TM) i7"));
        assert_eq!(info.cpu_cores, Some(8));
        assert_eq!(info.mem_total_bytes, Some(16_000_000_000));
        assert_eq!(info.mem_used_bytes, Some(4_000_000_000));
        assert_eq!(info.disk_total_bytes, Some(500_000_000_000));
        assert_eq!(info.disk_used_bytes, Some(100_000_000_000));
        assert_eq!(info.gpu_model.as_deref(), Some("NVIDIA GeForce RTX 3080"));
    }

    #[test]
    fn missing_fields_become_none() {
        let text = format!("{CPU_MODEL}\n{CPU_CORES}4\n");
        let info = parse(&text);
        assert_eq!(info.cpu_model, None);
        assert_eq!(info.cpu_cores, Some(4));
        assert_eq!(info.mem_total_bytes, None);
        assert_eq!(info.gpu_model, None);
    }
}
