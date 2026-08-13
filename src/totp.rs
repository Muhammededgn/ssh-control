use std::time::{SystemTime, UNIX_EPOCH};

use totp_rs::{Algorithm, Secret, TOTP};

/// The four mutually-exclusive vault security modes, in increasing order of
/// what they ask of the user. See the README's security model for the threat
/// each one actually addresses.
///
/// The one thing true of all of them: TOTP never adds *offline* cryptographic
/// strength, because verifying a code requires holding the shared secret.
/// It raises the bar for someone at the keyboard, not for someone holding the
/// file.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AuthMode {
    /// No prompt at all. The vault is still encrypted — under a device key held
    /// by the OS credential store — so a copied file opens nowhere else.
    None,
    /// Password on every launch.
    Password,
    /// Password on every launch, then a TOTP code.
    PasswordTotp,
    /// TOTP day to day, with the password kept as the escalation path: a copied
    /// vault, too many failures, a replayed code or a long gap all fall back to
    /// it.
    TotpDaily,
}

const ISSUER: &str = "ssh-control";
const ACCOUNT: &str = "vault";
const DIGITS: usize = 6;
/// Per RFC 6238 §5.2, 1 step of tolerance on either side of the current step
/// to absorb clock drift between this machine and the authenticator device.
const SKEW: u8 = 1;
const STEP_SECONDS: u64 = 30;

/// Generates a fresh random 160-bit TOTP secret, base32-encoded for display
/// and for pasting/scanning into an authenticator app.
pub fn generate_secret_base32() -> String {
    Secret::generate_secret().to_encoded().to_string()
}

fn build(secret_base32: &str) -> Option<TOTP> {
    let bytes = Secret::Encoded(secret_base32.to_string()).to_bytes().ok()?;
    TOTP::new(Algorithm::SHA1, DIGITS, SKEW, STEP_SECONDS, bytes, Some(ISSUER.to_string()), ACCOUNT.to_string()).ok()
}

/// `otpauth://` URI for the given secret — encodes into a QR code so an
/// authenticator app can scan it directly instead of the user retyping the
/// base32 secret by hand.
pub fn otpauth_url(secret_base32: &str) -> Option<String> {
    build(secret_base32).map(|t| t.get_url())
}

/// The outcome of the one code check in the app. Every caller goes through
/// `check_code` so the replay counter can never be advanced from somewhere that
/// forgot about it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CodeCheck {
    /// Valid, and newer than anything accepted before. The step is what the
    /// caller must persist — and only on this outcome.
    Accepted(u64),
    /// Valid for the secret, but at a step already used. A code stays valid for
    /// the whole ~90 s skew window, so without this someone who watched the
    /// user type one could walk up and reuse it.
    Replayed,
    /// Wrong, or the secret is malformed. Callers show one generic message
    /// either way and never distinguish the reason.
    Invalid,
}

/// Verifies a user-entered code and classifies it against `last_step`.
///
/// **A rejected code must never advance the stored step.** Otherwise anyone at
/// the prompt could burn the user's current code by typing it wrong, or replay
/// detection could be reset by a stranger. The signature enforces that by
/// handing back the step only on `Accepted`.
pub fn check_code(secret_base32: &str, code: &str, last_step: u64) -> CodeCheck {
    let Some(totp) = build(secret_base32) else {
        return CodeCheck::Invalid;
    };
    let Ok(now) = SystemTime::now().duration_since(UNIX_EPOCH) else {
        return CodeCheck::Invalid;
    };

    let current = now.as_secs() / STEP_SECONDS;
    let skew = u64::from(SKEW);
    // Newest step first: a code can be valid at more than one step only in
    // pathological cases, and taking the highest advances the counter as far as
    // it legitimately can.
    for step in (current.saturating_sub(skew)..=current + skew).rev() {
        if codes_match(&totp.generate(step * STEP_SECONDS), code) {
            return if step > last_step { CodeCheck::Accepted(step) } else { CodeCheck::Replayed };
        }
    }
    CodeCheck::Invalid
}

/// Verifies a code where there is no replay history to check against — the
/// enrolment form, which is only confirming the user's authenticator is set up
/// correctly before anything is stored.
pub fn verify_enrollment(secret_base32: &str, code: &str) -> bool {
    matches!(check_code(secret_base32, code, 0), CodeCheck::Accepted(_))
}

/// Compares two codes without an early exit on the first differing digit.
/// The window is small and this is a local prompt, but leaking a prefix match
/// through timing would hand an attacker the code one digit at a time.
fn codes_match(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn current_code(secret: &str) -> String {
        build(secret).expect("valid secret should build a TOTP instance").generate_current().expect("system clock should be readable")
    }

    #[test]
    fn generated_secret_round_trips_through_verify() {
        let secret = generate_secret_base32();
        assert!(matches!(check_code(&secret, &current_code(&secret), 0), CodeCheck::Accepted(_)));
    }

    #[test]
    fn wrong_code_is_rejected() {
        let secret = generate_secret_base32();
        // Flip the first digit to guarantee a different, still 6-digit code.
        let mut bytes = current_code(&secret).into_bytes();
        bytes[0] = if bytes[0] == b'0' { b'1' } else { b'0' };
        let wrong = String::from_utf8(bytes).unwrap();

        assert_eq!(check_code(&secret, &wrong, 0), CodeCheck::Invalid);
    }

    #[test]
    fn malformed_secret_is_rejected_not_panicking() {
        assert_eq!(check_code("not valid base32!!", "123456", 0), CodeCheck::Invalid);
    }

    /// The point of the guard: a code stays valid for the whole skew window, so
    /// accepting it once has to lock it out for the rest of that window.
    #[test]
    fn a_code_cannot_be_used_twice() {
        let secret = generate_secret_base32();
        let code = current_code(&secret);

        let CodeCheck::Accepted(step) = check_code(&secret, &code, 0) else {
            panic!("a fresh code should be accepted");
        };
        assert_eq!(check_code(&secret, &code, step), CodeCheck::Replayed);
    }

    /// A wrong guess must not move the counter, or anyone at the prompt could
    /// burn the code the user is about to type.
    #[test]
    fn a_rejected_code_yields_no_step_to_store() {
        let secret = generate_secret_base32();
        assert!(matches!(check_code(&secret, "000000", 0), CodeCheck::Invalid | CodeCheck::Replayed));
        // The only variant carrying a step is `Accepted`, so there is nothing a
        // caller could persist from a rejection even by mistake.
        assert!(matches!(check_code(&secret, &current_code(&secret), 0), CodeCheck::Accepted(_)));
    }

    #[test]
    fn an_older_step_is_treated_as_a_replay_not_a_fresh_code() {
        let secret = generate_secret_base32();
        let code = current_code(&secret);
        // Pretend a far newer step was already accepted, as it would be after a
        // clock jump backwards.
        assert_eq!(check_code(&secret, &code, u64::MAX), CodeCheck::Replayed);
    }

    #[test]
    fn enrollment_accepts_a_live_code_without_replay_history() {
        let secret = generate_secret_base32();
        assert!(verify_enrollment(&secret, &current_code(&secret)));
        assert!(!verify_enrollment(&secret, "000000"));
    }

    #[test]
    fn otpauth_url_contains_issuer_and_secret() {
        let secret = generate_secret_base32();
        let url = otpauth_url(&secret).expect("valid secret should produce a URL");
        assert!(url.starts_with("otpauth://totp/"));
        assert!(url.contains("ssh-control"));
    }
}
