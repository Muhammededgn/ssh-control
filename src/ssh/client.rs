use std::sync::{Arc, Mutex};

use russh::keys::{HashAlg, PublicKey};
use russh::{Channel, client};

use crate::error::AppError;

/// Result of the TOFU (trust-on-first-connect) host-key check, recorded by
/// `Handler::check_server_key` so `ssh::session::connect` can inspect it after
/// the handshake completes (or fails).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HostKeyOutcome {
    /// Fingerprint matched the one already stored for this server.
    Trusted,
    /// No fingerprint was stored yet; this one was accepted and should now be
    /// persisted onto the `ServerEntry`.
    FirstConnect { fingerprint: String },
    /// Fingerprint did not match the stored one — connection is rejected.
    Mismatch { expected: String, actual: String },
}

/// Where one `-R` rule's incoming connections should be delivered.
///
/// The server end is what the rule asked `tcpip_forward` to listen on; the
/// destination is dialled here, on this machine.
#[derive(Clone, Debug)]
pub struct RemoteRoute {
    pub bind_addr: String,
    pub bind_port: u16,
    pub dest_host: String,
    pub dest_port: u16,
}

/// russh client handler. Two jobs: the TOFU host-key check, and answering the
/// channels a `-R` forward pushes back at us. Everything else uses default
/// (no-op) trait method implementations.
///
/// The `-R` half is here and nowhere else because it has to be: a remote
/// forward's connections arrive as a *callback*, not on the handle, and the
/// handler is moved into russh at connect time. So the routes are handed to it
/// before the move, and there is no later opportunity.
pub struct Handler {
    expected_fingerprint: Option<String>,
    pub outcome: Arc<Mutex<Option<HostKeyOutcome>>>,
    /// Empty for a bastion hop and for a session with no `-R` rules. An empty
    /// table rejects everything, which is what a server that opens an
    /// unrequested forwarded channel should get.
    remote_routes: Vec<RemoteRoute>,
}

impl Handler {
    pub fn new(expected_fingerprint: Option<String>, remote_routes: Vec<RemoteRoute>) -> Self {
        Self {
            expected_fingerprint,
            outcome: Arc::new(Mutex::new(None)),
            remote_routes,
        }
    }
}

impl client::Handler for Handler {
    type Error = AppError;

    async fn check_server_key(&mut self, server_public_key: &PublicKey) -> Result<bool, Self::Error> {
        let actual = server_public_key.fingerprint(HashAlg::Sha256).to_string();

        let (accept, result) = match &self.expected_fingerprint {
            None => (true, HostKeyOutcome::FirstConnect { fingerprint: actual }),
            Some(expected) if *expected == actual => (true, HostKeyOutcome::Trusted),
            Some(expected) => (
                false,
                HostKeyOutcome::Mismatch {
                    expected: expected.clone(),
                    actual,
                },
            ),
        };

        *self.outcome.lock().expect("outcome mutex poisoned") = Some(result);
        Ok(accept)
    }

    /// A connection arriving on a `-R` forward.
    ///
    /// **Matched against the route table before it is accepted.** russh's
    /// default implementation accepts every such channel and then drops it,
    /// which is a black hole; rejecting an address nothing asked for is the
    /// difference between a forward and letting the server open sockets on
    /// this machine at will.
    ///
    /// The pump is spawned rather than joined into anything, because there is
    /// nothing here to join it into — this is a callback inside russh's own
    /// session task. It ends on its own when the channel closes, which is what
    /// dropping the session does to every channel it owns.
    async fn server_channel_open_forwarded_tcpip(
        &mut self,
        channel: Channel<client::Msg>,
        connected_address: &str,
        connected_port: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: client::ChannelOpenHandle,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        let route = self.remote_routes.iter().find(|r| {
            r.bind_port == connected_port as u16
                // The server reports back what it actually bound, which for an
                // empty or wildcard bind address is its own choice of
                // "everything" — so the port is what identifies the rule and
                // the address only has to not contradict it.
                && (r.bind_addr.is_empty() || r.bind_addr == connected_address || connected_address.is_empty())
        });

        let Some(route) = route.cloned() else {
            // Dropping `reply` would also refuse, but saying so explicitly is
            // what makes this a decision rather than an omission.
            reply.reject(russh::ChannelOpenFailure::AdministrativelyProhibited).await;
            return Ok(());
        };

        reply.accept().await;
        tokio::spawn(async move {
            let Ok(mut socket) = tokio::net::TcpStream::connect((route.dest_host.as_str(), route.dest_port)).await else {
                return;
            };
            let mut stream = channel.into_stream();
            let _ = tokio::io::copy_bidirectional(&mut socket, &mut stream).await;
        });
        Ok(())
    }
}
