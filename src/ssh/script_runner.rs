use std::time::Duration;

use russh::ChannelMsg;
use russh::client;

use super::client::Handler;
use crate::config::{Script, StepCondition};
use crate::error::{AppError, Result};

const STEP_TIMEOUT: Duration = Duration::from_secs(120);

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

        match run_step(handle, &step.command, |chunk| on_event(RunEvent::Output { index, chunk })).await {
            Ok((exit_code, output)) => {
                on_event(RunEvent::StepFinished { index, exit_code });
                results.push(StepStatus::Ran { exit_code, output });
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
    mut on_output: impl FnMut(&[u8]),
) -> Result<(i32, String)> {
    let mut channel = handle.channel_open_session().await?;
    channel.exec(true, command).await?;

    let mut output = Vec::new();
    let mut exit_code = 0i32;

    let result = tokio::time::timeout(STEP_TIMEOUT, async {
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

    if result.is_err() {
        return Err(AppError::SshConnect("step timed out".into()));
    }

    Ok((exit_code, String::from_utf8_lossy(&output).into_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

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
