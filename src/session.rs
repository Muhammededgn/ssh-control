//! What one SSH session teaches the vault, and how it lands on the entry.
//!
//! Both ways into a server — the TUI's `App::connect_flow` and
//! `cli::connect` — have to record the same three things: the host key
//! accepted on a first connect, when the connection happened, and whatever the
//! sysinfo probe managed to read. A CLI connect that skipped them would leave
//! the server list's "last connected" column lying and re-run TOFU on the next
//! launch, so the policy lives here rather than twice.
//!
//! It sits above `ssh/`, not inside it: `ssh::connect` takes a `Target` and
//! knows nothing about `ServerEntry` or the vault, and that separation is
//! deliberate (see `ssh::Target`'s own note).
//!
//! A jump host is the one thing recorded through a second path, `observe_jumps`
//! / `JumpRecord`, and it is not an oversight that it does not go through
//! `SessionRecord`: **a bastion records a fingerprint and never a timestamp.**
//! Passing through a machine is not connecting to it, and stamping
//! `last_connected_unix` there would reorder the server list under
//! `ServerSort::LastConnected` for a host nobody logged into.

use std::io::Write;

use crate::config::ServerEntry;
use crate::config::device;
use crate::config::SystemInfo;
use crate::i18n::Strings;
use crate::ssh::{self, HostKeyOutcome};
use uuid::Uuid;
use crate::ssh::script_runner::RunEvent;

/// Everything one connection teaches the vault about a server.
pub struct SessionRecord {
    /// `Some` only on a first connect — the fingerprint to remember from now
    /// on. A `Trusted` outcome has nothing to write, and a `Mismatch` never
    /// gets this far: `ssh::connect` fails with `HostKeyChanged` instead.
    pub fingerprint: Option<String>,
    pub connected_at: u64,
    /// `None` when the probe failed. Best-effort by design: a restricted
    /// shell or a host with no `lscpu` is still a host the user connected to.
    pub system_info: Option<SystemInfo>,
}

/// What the handshake alone teaches the vault: the fingerprint to remember on
/// a first connect, and the moment it happened.
///
/// No await — all of it is already known when `ssh::connect` returns. That is
/// what lets `App::connect_flow` write this half *before* the interactive
/// shell starts and run the probe alongside the shell rather than in front of
/// it.
pub fn observe_handshake(connected: &ssh::Connected) -> SessionRecord {
    let fingerprint = match &connected.host_key_outcome {
        HostKeyOutcome::FirstConnect { fingerprint } => Some(fingerprint.clone()),
        HostKeyOutcome::Trusted | HostKeyOutcome::Mismatch { .. } => None,
    };
    SessionRecord { fingerprint, connected_at: device::now_unix(), system_info: None }
}

/// The handshake plus the probe, for a caller with nothing else to do while it
/// runs — which is the CLI, where the probe sits in front of nothing.
///
/// Awaits, and borrows nothing but the connection — deliberately. Both callers
/// need to write the result into a `Config` they only borrow *between* awaits
/// (the `NextStep` rule in `app.rs`), so this returns a plain owned value and
/// leaves the storing to them.
pub async fn observe(connected: &ssh::Connected) -> SessionRecord {
    let mut record = observe_handshake(connected);
    record.system_info = ssh::sysinfo::fetch(&connected.handle).await.ok();
    record
}

/// What a bastion on the way taught the vault: a first-connect fingerprint,
/// and nothing else.
///
/// Deliberately not a `SessionRecord`. That one also stamps
/// `last_connected_unix`, and a host merely tunnelled through is not a
/// connection the user made — stamping it would reorder the list under
/// `ServerSort::LastConnected` and show "last connected: 2 minutes ago" on a
/// machine nobody logged into. There is no sysinfo probe on a hop either, for
/// the same reason: nothing asked about it.
pub struct JumpRecord {
    pub server_id: Uuid,
    pub fingerprint: String,
}

/// Pairs the outcomes `connect` recorded for the chain with the entries they
/// came from.
///
/// `jump_ids` is built in the same borrow that built the `Target`, in the same
/// order, so index `i` is `Target::jumps[i]`. That correlation lives here
/// rather than in `ssh/` because it is the one step that needs to know about
/// `ServerEntry` and `Uuid`, which `ssh::connect` deliberately does not.
///
/// Only first connects produce a record. A hop already trusted has nothing to
/// write, and a mismatch never gets this far — `connect` fails.
pub fn observe_jumps(connected: &ssh::Connected, jump_ids: &[Uuid]) -> Vec<JumpRecord> {
    connected
        .jump_outcomes
        .iter()
        .zip(jump_ids)
        .filter_map(|(outcome, &server_id)| match outcome {
            HostKeyOutcome::FirstConnect { fingerprint } => Some(JumpRecord { server_id, fingerprint: fingerprint.clone() }),
            HostKeyOutcome::Trusted | HostKeyOutcome::Mismatch { .. } => None,
        })
        .collect()
}

impl JumpRecord {
    /// Writes the fingerprint and nothing else. See the type's own note for
    /// why that is the whole of it.
    pub fn apply_to(&self, entry: &mut ServerEntry) {
        entry.host_key_fingerprint = Some(self.fingerprint.clone());
    }
}

impl SessionRecord {
    /// Folds the session back into the entry it belongs to.
    ///
    /// The timestamp is stamped whether or not the probe worked, and that is
    /// the point: `last_connected_unix` is separate from
    /// `system_info.fetched_at_unix` precisely so a host with a restricted
    /// shell still registers as one the user reaches.
    pub fn apply_to(&self, entry: &mut ServerEntry) {
        if let Some(fingerprint) = &self.fingerprint {
            entry.host_key_fingerprint = Some(fingerprint.clone());
        }
        entry.last_connected_unix = Some(self.connected_at);
        if self.system_info.is_some() {
            entry.system_info = self.system_info.clone();
        }
    }
}

/// Prints a script event straight to the primary screen buffer.
///
/// Used by both connect paths for the `run_on_connect` scripts: the TUI has
/// already suspended the alternate screen by this point and the CLI never
/// entered one, so in both cases this is writing to the user's own terminal.
/// `\r\n` rather than `\n` because raw mode is on and a bare newline would
/// stair-step.
pub fn print_script_event_plain(event: RunEvent, strings: &Strings, partial: &mut String) {
    let mut out = std::io::stdout();

    match event {
        RunEvent::StepStarted { command, .. } => {
            let _ = write!(out, "$ {command}\r\n");
        }
        RunEvent::Output { chunk, .. } => {
            partial.push_str(&String::from_utf8_lossy(chunk));
            while let Some(pos) = partial.find('\n') {
                let line: String = partial.drain(..=pos).collect();
                let _ = write!(out, "{}\r\n", line.trim_end_matches(['\r', '\n']));
            }
        }
        RunEvent::StepFinished { exit_code, .. } => {
            if !partial.is_empty() {
                let line = std::mem::take(partial);
                let _ = write!(out, "{line}\r\n");
            }
            let _ = write!(out, "[{}{exit_code}]\r\n", strings.log_exit_prefix);
        }
        RunEvent::StepSkipped { .. } => {
            let _ = write!(out, "{}\r\n", strings.log_skipped);
        }
        RunEvent::StepError { message, .. } => {
            if !partial.is_empty() {
                let line = std::mem::take(partial);
                let _ = write!(out, "{line}\r\n");
            }
            let _ = write!(out, "{}{message}\r\n", strings.log_error_prefix);
        }
        RunEvent::StepTimedOut { seconds, .. } => {
            if !partial.is_empty() {
                let line = std::mem::take(partial);
                let _ = write!(out, "{line}\r\n");
            }
            let _ = write!(out, "{}{seconds}{}\r\n", strings.log_timed_out_prefix, strings.log_timed_out_suffix);
        }
    }
    let _ = out.flush();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AuthMethod;

    fn entry() -> ServerEntry {
        ServerEntry::new("web-1".into(), "web-1.example.com".into(), 22, "root".into(), AuthMethod::password("x"))
    }

    /// A first connect is the only time the fingerprint is written, and it has
    /// to stick — otherwise every launch re-runs TOFU and the check protects
    /// nothing.
    #[test]
    fn a_first_connect_records_the_host_key() {
        let mut e = entry();
        SessionRecord { fingerprint: Some("SHA256:abc".into()), connected_at: 100, system_info: None }.apply_to(&mut e);

        assert_eq!(e.host_key_fingerprint.as_deref(), Some("SHA256:abc"));
        assert_eq!(e.last_connected_unix, Some(100));
    }

    /// The two timestamps move independently on purpose: a host with a
    /// restricted shell never yields sysinfo, and must still show as reached.
    #[test]
    fn a_failed_probe_still_counts_as_a_connection() {
        let mut e = entry();
        e.system_info = Some(SystemInfo { cpu_cores: Some(8), ..SystemInfo::default() });

        SessionRecord { fingerprint: None, connected_at: 200, system_info: None }.apply_to(&mut e);

        assert_eq!(e.last_connected_unix, Some(200));
        assert_eq!(e.system_info.as_ref().and_then(|i| i.cpu_cores), Some(8), "the last good snapshot is kept, not blanked");
        assert!(e.host_key_fingerprint.is_none(), "a trusted key writes nothing");
    }
}
