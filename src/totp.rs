use totp_rs::{Algorithm, Secret, TOTP};

/// The three mutually-exclusive vault unlock modes. See the plan/docs for the
/// exact threat model of each — `TotpOnly` in particular provides no
/// protection against local disk access, only against someone using an
/// already-open session without the paired authenticator device.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AuthMode {
    Password,
    TwoFactor,
    TotpOnly,
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

/// Verifies a user-entered code against the secret at the current time
/// (within the configured skew window). Returns `false` (not an error) for
/// any malformed secret or code — callers show a single generic "invalid
/// code" message either way, never distinguishing the failure reason.
pub fn verify_code(secret_base32: &str, code: &str) -> bool {
    let Some(totp) = build(secret_base32) else {
        return false;
    };
    totp.check_current(code).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_secret_round_trips_through_verify() {
        let secret = generate_secret_base32();
        let totp = build(&secret).expect("valid secret should build a TOTP instance");
        let code = totp.generate_current().expect("system clock should be readable");
        assert!(verify_code(&secret, &code));
    }

    #[test]
    fn wrong_code_is_rejected() {
        let secret = generate_secret_base32();
        let totp = build(&secret).unwrap();
        let real_code = totp.generate_current().unwrap();
        // Flip the first digit to guarantee a different, still 6-digit code.
        let mut bytes = real_code.into_bytes();
        bytes[0] = if bytes[0] == b'0' { b'1' } else { b'0' };
        let wrong = String::from_utf8(bytes).unwrap();

        assert!(!verify_code(&secret, &wrong));
    }

    #[test]
    fn malformed_secret_is_rejected_not_panicking() {
        assert!(!verify_code("not valid base32!!", "123456"));
    }

    #[test]
    fn otpauth_url_contains_issuer_and_secret() {
        let secret = generate_secret_base32();
        let url = otpauth_url(&secret).expect("valid secret should produce a URL");
        assert!(url.starts_with("otpauth://totp/"));
        assert!(url.contains("ssh-control"));
    }
}
