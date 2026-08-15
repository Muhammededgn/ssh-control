//! Test helper only: lists a remote directory over the hand-written SFTP
//! client, without the TUI. Not part of the shipped binary.
//!
//! The protocol layer is unit-tested against a fake server, which cannot catch
//! the things only a real implementation does — how OpenSSH batches READDIR,
//! which attributes it omits, what its status messages say. This is how that
//! gets checked by hand.
//!
//! ```sh
//! cargo run --example sftp_ls -- <host> <port> <user> <key-path> [remote-dir]
//! ```
use ssh_control::config::AuthMethod;
use ssh_control::ssh::{self, sftp};

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 5 {
        eprintln!("usage: sftp_ls <host> <port> <user> <key-path> [remote-dir]");
        std::process::exit(2);
    }

    let target = ssh::Target {
        host: args[1].clone(),
        port: args[2].parse().expect("port"),
        username: args[3].clone(),
        auth: AuthMethod::SshKey { key_path: args[4].clone(), passphrase: None },
        // No pinned fingerprint: this helper trusts whatever answers, which is
        // fine for a local test server and is why it is not the app's path.
        host_key_fingerprint: None,
    };

    let mut connected = ssh::connect(&target).await.expect("connect");
    let mut client = sftp::open_session(&mut connected.handle).await.expect("sftp subsystem");

    let dir = match args.get(5) {
        Some(dir) => dir.clone(),
        None => client.realpath(".").await.expect("realpath"),
    };
    println!("{dir}");

    for entry in client.list_dir(&dir).await.expect("listing") {
        println!("{:?}\t{:>12}\t{}", entry.kind, entry.size, entry.name);
    }
}
