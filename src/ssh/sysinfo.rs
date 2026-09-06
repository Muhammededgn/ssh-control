use std::time::Duration;

use russh::ChannelMsg;
use russh::client;

use super::client::Handler;
use crate::config::SystemInfo;
use crate::error::{AppError, Result};

const EXEC_TIMEOUT: Duration = Duration::from_secs(10);

/// The live poll's own budget, shorter than `EXEC_TIMEOUT` on purpose: this
/// one runs again in a few seconds either way, and a reading that has not
/// arrived by then is one the next poll will bring. `fetch` has no next time.
const USAGE_TIMEOUT: Duration = Duration::from_secs(3);

/// Marker prefixes for each probed value, so the combined shell command's
/// output can be parsed by line regardless of ordering/interleaving quirks.
const CPU_MODEL: &str = "SSHCTL_CPU_MODEL:";
const CPU_CORES: &str = "SSHCTL_CPU_CORES:";
const MEM_TOTAL: &str = "SSHCTL_MEM_TOTAL:";
const MEM_USED: &str = "SSHCTL_MEM_USED:";
const DISK_TOTAL: &str = "SSHCTL_DISK_TOTAL:";
const DISK_USED: &str = "SSHCTL_DISK_USED:";
const GPU_MODEL: &str = "SSHCTL_GPU_MODEL:";

/// The two figures that are worth re-reading while a session is open.
///
/// Deliberately not a `SystemInfo`: the other five fields — CPU model, core
/// count, GPU model, and both totals — cannot change between polls, so a poll
/// that carried them would be re-running `lspci` and grepping `/proc/cpuinfo`
/// every few seconds to learn nothing. It is also not persisted: the vault's
/// snapshot is still written once per connect (`crate::session`), and a save
/// rewrites the whole encrypted envelope.
///
/// Each field is separately optional so a half-answer is still worth keeping —
/// a shell with `free` but no `df` reports memory and leaves disk alone.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Usage {
    pub mem_used_bytes: Option<u64>,
    pub disk_used_bytes: Option<u64>,
}

impl Usage {
    /// Folds a fresh reading in, field by field, keeping the last good value
    /// for anything the new one did not answer.
    ///
    /// Per field rather than wholesale because the failures are per field: a
    /// `df` that hangs on one stale mount leaves that line blank while `free`
    /// still reports, and blanking half the display for it would be losing
    /// information the session already gave us.
    pub fn merge(&mut self, fresh: Usage) {
        if fresh.mem_used_bytes.is_some() {
            self.mem_used_bytes = fresh.mem_used_bytes;
        }
        if fresh.disk_used_bytes.is_some() {
            self.disk_used_bytes = fresh.disk_used_bytes;
        }
    }
}

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

/// The dynamic half of `probe_command`, and only that half. The two share
/// their marker prefixes and their parser, so a line that moves moves in both.
fn usage_command() -> String {
    format!(
        "echo '{MEM_USED}'$(free -b 2>/dev/null | awk '/^Mem:/{{print $3}}'); \
         echo '{DISK_USED}'$(df -B1 --total 2>/dev/null | awk '/^total/{{print $3}}')"
    )
}

/// Runs `command` over a fresh exec channel and returns whatever it wrote.
///
/// A fresh channel per call, which is what makes polling free of the session
/// it rides on: russh carries many channels on one connection, so nothing has
/// to be torn down or reopened to ask a question.
async fn exec_capture(handle: &client::Handle<Handler>, command: String, budget: Duration) -> Result<String> {
    let mut channel = handle.channel_open_session().await?;
    channel.exec(true, command).await?;

    let mut output = Vec::new();
    let result = tokio::time::timeout(budget, async {
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

    Ok(String::from_utf8_lossy(&output).into_owned())
}

/// One live reading of the two figures that move.
///
/// Best-effort in the same way `fetch` is, and the caller keeps its last good
/// reading rather than blanking on an error — a poll that failed says nothing
/// about the machine, only about this one exec channel.
pub async fn poll_usage(handle: &client::Handle<Handler>) -> Result<Usage> {
    let text = exec_capture(handle, usage_command(), USAGE_TIMEOUT).await?;
    Ok(parse_usage(&text))
}

/// Runs a one-shot probe command over a fresh exec channel on `handle` and
/// parses CPU/RAM/disk/GPU info out of it. Best-effort: any missing/blank
/// field is left `None` rather than failing the whole fetch, since not every
/// remote shell has every tool (`lspci`, `free`, ...) installed.
///
/// `&Handle`, for the same reason `pty_bridge::run_interactive` takes one: the
/// TUI joins the two on one connection.
pub async fn fetch(handle: &client::Handle<Handler>) -> Result<SystemInfo> {
    let text = exec_capture(handle, probe_command(), EXEC_TIMEOUT).await?;
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

fn parse_usage(text: &str) -> Usage {
    Usage {
        mem_used_bytes: field(text, MEM_USED).and_then(|s| s.parse().ok()),
        disk_used_bytes: field(text, DISK_USED).and_then(|s| s.parse().ok()),
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
    fn a_usage_poll_reads_only_the_two_figures_that_move() {
        let text = format!("{MEM_USED}4000000000\n{DISK_USED}100000000000\n");
        let usage = parse_usage(&text);
        assert_eq!(usage.mem_used_bytes, Some(4_000_000_000));
        assert_eq!(usage.disk_used_bytes, Some(100_000_000_000));
        // The static half is not in the command, so it cannot be in the reply.
        assert!(!usage_command().contains(CPU_MODEL));
        assert!(!usage_command().contains(MEM_TOTAL));
        assert!(!usage_command().contains(GPU_MODEL));
    }

    #[test]
    fn a_blank_field_keeps_the_last_good_reading() {
        let mut usage = Usage { mem_used_bytes: Some(1), disk_used_bytes: Some(2) };
        // `free` answered, `df` did not.
        usage.merge(parse_usage(&format!("{MEM_USED}9\n{DISK_USED}\n")));
        assert_eq!(usage.mem_used_bytes, Some(9));
        assert_eq!(usage.disk_used_bytes, Some(2));
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
