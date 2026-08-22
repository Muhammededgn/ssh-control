use std::time::Duration;

use russh::ChannelMsg;
use russh::client;

use super::client::Handler;
use crate::config::{Script, ScriptStep, ServerEntry, StepCondition};
use crate::error::Result;

/// What a step gets when `ScriptStep::timeout_secs` is unset — which is every
/// step written before that field existed.
pub const STEP_TIMEOUT: Duration = Duration::from_secs(120);

/// The `{{host}}`-style placeholders a step command may use, resolved from
/// the `ServerEntry` the script belongs to.
///
/// Built where the entry is still borrowed and carried across the `.await`
/// like `ssh::Target`, for the same reason: the connect flows may not hold a
/// borrow of `App::state` while they run (see the `NextStep` pattern).
/// Deliberately *not* part of `Target` — expansion happens before a
/// connection exists, and `Target` is what `connect` needs, nothing more.
pub struct ScriptVars {
    pub name: String,
    pub host: String,
    pub port: u16,
    pub username: String,
}

impl ScriptVars {
    pub fn from_entry(entry: &ServerEntry) -> Self {
        Self { name: entry.name.clone(), host: entry.host.clone(), port: entry.port, username: entry.username.clone() }
    }

    fn value(&self, key: &str) -> Option<String> {
        match key {
            "name" => Some(self.name.clone()),
            "host" => Some(self.host.clone()),
            "port" => Some(self.port.to_string()),
            "username" => Some(self.username.clone()),
            _ => None,
        }
    }

    /// Substitutes every known `{{key}}` in `command`, **literally and without
    /// quoting**.
    ///
    /// That is the deliberate half of this. The whole point of the feature is
    /// commands like `ssh {{username}}@{{host}}` and
    /// `curl http://{{host}}:{{port}}/health` — auto-quoting would turn those
    /// into a single quoted word and break every one of them. The values come
    /// from the vault entry the user typed themselves, so quoting is the
    /// user's job, exactly as it is in a shell alias.
    ///
    /// An unknown placeholder is left standing rather than replaced with an
    /// empty string: `awk '{{print $1}}'` is a real command, and silently
    /// eating it would turn a working script into a subtly wrong one.
    pub fn expand(&self, command: &str) -> String {
        let mut out = String::with_capacity(command.len());
        let mut rest = command;
        while let Some(open) = rest.find("{{") {
            out.push_str(&rest[..open]);
            let after = &rest[open + 2..];
            match after.find("}}") {
                Some(close) => match self.value(after[..close].trim()) {
                    Some(value) => {
                        out.push_str(&value);
                        rest = &after[close + 2..];
                    }
                    // Unknown key: emit the opener and resume *inside* it, so
                    // a `}}` that closes nothing cannot swallow a later
                    // placeholder.
                    None => {
                        out.push_str("{{");
                        rest = after;
                    }
                },
                // No closing delimiter at all — the rest is literal text.
                None => {
                    out.push_str("{{");
                    rest = after;
                }
            }
        }
        out.push_str(rest);
        out
    }

    /// A copy of `script` with every step's command expanded. Only the command
    /// is substituted — a `StepCondition::OutputContains` needle is matched
    /// against output, not sent to the shell, and expanding it would make the
    /// same script behave differently on two servers for no stated reason.
    pub fn expand_script(&self, script: &Script) -> Script {
        Script {
            steps: script
                .steps
                .iter()
                .map(|step| ScriptStep { command: self.expand(&step.command), ..step.clone() })
                .collect(),
            ..script.clone()
        }
    }
}

/// Emitted synchronously as a script runs, so callers can drive either a live
/// TUI redraw or a plain stdout print from the very same execution loop.
pub enum RunEvent<'a> {
    StepStarted { index: usize, command: &'a str },
    Output { index: usize, chunk: &'a [u8] },
    StepFinished { index: usize, exit_code: i32 },
    StepSkipped { index: usize },
    /// The exec channel itself failed to open/run (connection dropped
    /// mid-script, etc.) — distinct from a step merely exiting non-zero.
    StepError { index: usize, message: &'a str },
    /// The step outlived its timeout. Its own event rather than a `StepError`
    /// so the message can be localized against the number of seconds; the
    /// number is the timeout that was actually applied, not the constant.
    StepTimedOut { index: usize, seconds: u64 },
}

/// Exit code a timed-out step is recorded with, so the next step's
/// `OnFailure` / `OutputContains` sees a failure rather than a skip. 124 is
/// what coreutils `timeout(1)` reports, for the same reason.
pub const TIMEOUT_EXIT_CODE: i32 = 124;

/// What `run_step` came back with. A timeout is not an error: the step ran, it
/// just did not finish, and the output it managed to produce is still worth
/// showing and still worth matching `OutputContains` against.
enum StepOutcome {
    Finished { exit_code: i32, output: String },
    TimedOut { output: String },
}

/// Outcome of one step, used only to evaluate the *next* step's condition —
/// never persisted (see `Script` doc comment).
#[derive(Clone)]
pub enum StepStatus {
    Ran { exit_code: i32, output: String },
    Skipped,
}

/// Whether a step should run, based on the immediately preceding step's
/// `StepStatus` (`None` only for the very first step, which callers must
/// always run regardless of its stored condition — see `Script` doc comment).
/// A `Skipped` previous step fails every condition except `Always`, which is
/// how a skip cascades down a chain of `OnSuccess`/`OnFailure`/`OutputContains`
/// steps until one of them is unconditional again.
fn should_run(condition: &StepCondition, prev: Option<&StepStatus>) -> bool {
    match condition {
        StepCondition::Always => true,
        StepCondition::OnSuccess => matches!(prev, Some(StepStatus::Ran { exit_code: 0, .. })),
        StepCondition::OnFailure => matches!(prev, Some(StepStatus::Ran { exit_code, .. }) if *exit_code != 0),
        StepCondition::OutputContains(needle) => {
            matches!(prev, Some(StepStatus::Ran { output, .. }) if output.contains(needle.as_str()))
        }
    }
}

/// Runs every step of `script` in order over fresh exec channels on `handle`,
/// calling `on_event` synchronously as each step starts, streams output, and
/// finishes. Mirrors `ssh::sysinfo::fetch`'s exec-channel-per-command pattern,
/// generalized to a whole ordered chain with per-step conditions.
pub async fn run_script(
    handle: &mut client::Handle<Handler>,
    script: &Script,
    mut on_event: impl FnMut(RunEvent),
) -> Vec<StepStatus> {
    let mut results: Vec<StepStatus> = Vec::with_capacity(script.steps.len());

    for (index, step) in script.steps.iter().enumerate() {
        let prev = results.last();
        if index != 0 && !should_run(&step.condition, prev) {
            on_event(RunEvent::StepSkipped { index });
            results.push(StepStatus::Skipped);
            continue;
        }

        on_event(RunEvent::StepStarted { index, command: &step.command });

        let timeout = step.timeout_secs.map(Duration::from_secs).unwrap_or(STEP_TIMEOUT);
        match run_step(handle, &step.command, timeout, |chunk| on_event(RunEvent::Output { index, chunk })).await {
            Ok(StepOutcome::Finished { exit_code, output }) => {
                on_event(RunEvent::StepFinished { index, exit_code });
                results.push(StepStatus::Ran { exit_code, output });
            }
            Ok(StepOutcome::TimedOut { output }) => {
                on_event(RunEvent::StepTimedOut { index, seconds: timeout.as_secs() });
                results.push(StepStatus::Ran { exit_code: TIMEOUT_EXIT_CODE, output });
            }
            Err(e) => {
                on_event(RunEvent::StepError { index, message: &e.to_string() });
                results.push(StepStatus::Skipped);
            }
        }
    }

    results
}

async fn run_step(
    handle: &mut client::Handle<Handler>,
    command: &str,
    timeout: Duration,
    mut on_output: impl FnMut(&[u8]),
) -> Result<StepOutcome> {
    let mut channel = handle.channel_open_session().await?;
    channel.exec(true, command).await?;

    let mut output = Vec::new();
    let mut exit_code = 0i32;

    let result = tokio::time::timeout(timeout, async {
        loop {
            match channel.wait().await {
                Some(ChannelMsg::Data { data }) => {
                    on_output(&data);
                    output.extend_from_slice(&data);
                }
                Some(ChannelMsg::ExtendedData { data, .. }) => {
                    on_output(&data);
                    output.extend_from_slice(&data);
                }
                Some(ChannelMsg::ExitStatus { exit_status }) => {
                    exit_code = exit_status as i32;
                }
                // Servers commonly send channel EOF *before* the exit-status
                // request, so EOF must not end the loop early — only Close
                // (which always comes last) does.
                Some(ChannelMsg::Close) | None => break,
                _ => {}
            }
        }
    })
    .await;

    let output = String::from_utf8_lossy(&output).into_owned();
    if result.is_err() {
        return Ok(StepOutcome::TimedOut { output });
    }

    Ok(StepOutcome::Finished { exit_code, output })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vars() -> ScriptVars {
        ScriptVars { name: "prod-web".into(), host: "example.com".into(), port: 2222, username: "deploy".into() }
    }

    #[test]
    fn every_placeholder_resolves_from_the_entry() {
        assert_eq!(vars().expand("ssh {{username}}@{{host}} -p {{port}}"), "ssh deploy@example.com -p 2222");
        assert_eq!(vars().expand("echo {{name}}"), "echo prod-web");
    }

    /// Substitution is literal on purpose. A value with a space must land in
    /// the command exactly as typed — quoting is the user's job, the same way
    /// it is in a shell alias, because auto-quoting would break the
    /// `{{username}}@{{host}}` form the feature exists for.
    #[test]
    fn values_are_substituted_literally_and_never_quoted() {
        let v = ScriptVars { name: "two words".into(), host: "h".into(), port: 22, username: "u".into() };
        assert_eq!(v.expand("echo {{name}}"), "echo two words");
    }

    /// `awk '{{print $1}}'` is a real command. Replacing an unknown key with
    /// nothing would turn a working script into a subtly wrong one, so it is
    /// left standing instead.
    #[test]
    fn an_unknown_placeholder_is_left_alone() {
        assert_eq!(vars().expand("awk '{{print $1}}'"), "awk '{{print $1}}'");
        assert_eq!(vars().expand("{{nope}} {{host}}"), "{{nope}} example.com");
        assert_eq!(vars().expand("echo {{unclosed"), "echo {{unclosed");
    }

    /// The needle is matched against output, never sent to a shell — expanding
    /// it would make one stored script behave differently per server.
    #[test]
    fn expand_script_touches_commands_only() {
        let script = Script {
            id: uuid::Uuid::nil(),
            name: "s".into(),
            run_on_connect: false,
            steps: vec![ScriptStep {
                command: "ping {{host}}".into(),
                condition: StepCondition::OutputContains("{{host}}".into()),
                timeout_secs: Some(5),
            }],
        };
        let expanded = vars().expand_script(&script);
        assert_eq!(expanded.steps[0].command, "ping example.com");
        assert_eq!(expanded.steps[0].condition, StepCondition::OutputContains("{{host}}".into()));
        assert_eq!(expanded.steps[0].timeout_secs, Some(5), "the rest of the step is carried through unchanged");
    }

    fn ran(exit_code: i32) -> StepStatus {
        StepStatus::Ran { exit_code, output: String::new() }
    }

    fn ran_with_output(output: &str) -> StepStatus {
        StepStatus::Ran { exit_code: 0, output: output.to_string() }
    }

    #[test]
    fn always_runs_regardless_of_previous() {
        assert!(should_run(&StepCondition::Always, None));
        assert!(should_run(&StepCondition::Always, Some(&ran(0))));
        assert!(should_run(&StepCondition::Always, Some(&ran(1))));
        assert!(should_run(&StepCondition::Always, Some(&StepStatus::Skipped)));
    }

    #[test]
    fn on_success_only_runs_after_zero_exit() {
        assert!(should_run(&StepCondition::OnSuccess, Some(&ran(0))));
        assert!(!should_run(&StepCondition::OnSuccess, Some(&ran(1))));
        assert!(!should_run(&StepCondition::OnSuccess, Some(&StepStatus::Skipped)));
        assert!(!should_run(&StepCondition::OnSuccess, None));
    }

    #[test]
    fn on_failure_only_runs_after_nonzero_exit() {
        assert!(should_run(&StepCondition::OnFailure, Some(&ran(1))));
        assert!(!should_run(&StepCondition::OnFailure, Some(&ran(0))));
        assert!(!should_run(&StepCondition::OnFailure, Some(&StepStatus::Skipped)));
        assert!(!should_run(&StepCondition::OnFailure, None));
    }

    #[test]
    fn output_contains_matches_previous_output() {
        let cond = StepCondition::OutputContains("ready".to_string());
        assert!(should_run(&cond, Some(&ran_with_output("server is ready now"))));
        assert!(!should_run(&cond, Some(&ran_with_output("still booting"))));
        assert!(!should_run(&cond, Some(&StepStatus::Skipped)));
    }

    /// The issue's second acceptance criterion: a step killed by its timeout
    /// has to look like a failure to the next step, not like a skip — a skip
    /// would cascade and silence the `OnFailure` cleanup that exists precisely
    /// for this case.
    #[test]
    fn a_timed_out_step_reads_as_a_failure_to_the_next_one() {
        let timed_out = ran(TIMEOUT_EXIT_CODE);
        assert!(should_run(&StepCondition::OnFailure, Some(&timed_out)));
        assert!(!should_run(&StepCondition::OnSuccess, Some(&timed_out)));
    }

    #[test]
    fn skip_cascades_through_conditional_steps_but_not_always() {
        // step0 fails -> step1 (OnSuccess) skipped -> step2 (OnFailure) must
        // also skip, since its "previous" (step1) never actually ran -> step3
        // (Always) still runs despite the whole chain above it being skipped.
        let step0 = ran(1);
        assert!(!should_run(&StepCondition::OnSuccess, Some(&step0)));
        let step1 = StepStatus::Skipped;
        assert!(!should_run(&StepCondition::OnFailure, Some(&step1)));
        let step2 = StepStatus::Skipped;
        assert!(should_run(&StepCondition::Always, Some(&step2)));
    }
}
