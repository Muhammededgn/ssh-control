//! Test helper only: prints the current 6-digit TOTP code for a given base32
//! secret, simulating what an authenticator app would show. Not part of the
//! shipped binary.
fn main() {
    let secret = std::env::args().nth(1).expect("usage: gen_totp_code <base32-secret>");
    let url = ssh_control::totp::otpauth_url(&secret).unwrap_or_default();
    eprintln!("otpauth url: {url}");
    // Reuse the library's own verify_code isn't enough to print a code, so
    // borrow totp-rs directly with the same parameters as src/totp.rs.
    use totp_rs::{Algorithm, Secret, TOTP};
    let bytes = Secret::Encoded(secret).to_bytes().unwrap();
    let totp = TOTP::new(Algorithm::SHA1, 6, 1, 30, bytes, Some("ssh-control".to_string()), "vault".to_string()).unwrap();
    println!("{}", totp.generate_current().unwrap());
}
