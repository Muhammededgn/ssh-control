//! Port forwarding: `-L`, `-R` and `-D`, started with a session and gone with
//! it.
//!
//! **`Drop` is the whole lifetime story.** A `Forwards` owns every accept task
//! and aborts them all when it goes out of scope, so the flow that started them
//! never has to remember to stop them and no exit path — an early `?`, an Esc,
//! a panic unwind — can leave a listener bound after the session it belonged to
//! is gone. A leaked listener is this feature's characteristic failure: the
//! next connect would find the port taken by a tunnel to a session that no
//! longer exists. Same argument CLAUDE.md makes for `App::connecting` being
//! cleared in exactly one place.
//!
//! The accept loops are `tokio::spawn`ed and own an `Arc` clone of the session
//! handle, because a forward has to keep serving while `App::run` is blocked
//! inside `connect_flow`'s PTY await — there is nothing polling a future joined
//! into that flow once it returns.
//!
//! `-R` works differently and is not here: the server does the listening, and
//! connections arrive as callbacks on the `Handler` (see `ssh::client`). All
//! this module does for it is ask, with `tcpip_forward`, and report the answer.

pub mod socks;

use std::sync::Arc;

use russh::client;
use tokio::io::copy_bidirectional;
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use uuid::Uuid;

use super::client::Handler;
use crate::config::{ForwardKind, ForwardRule};

/// A rule that came up, and the address it actually bound.
///
/// The address is reported rather than echoed back from the rule because port
/// `0` is a legitimate way to ask the OS for a free one, and the number the
/// user needs is the one that got picked.
pub struct Started {
    pub id: Uuid,
    pub label: String,
}

/// A rule that did not come up, and why.
pub struct Failed {
    pub id: Uuid,
    pub label: String,
    pub error: String,
}

/// Every listener a session brought up, and the tasks feeding them.
pub struct Forwards {
    tasks: Vec<JoinHandle<()>>,
    pub started: Vec<Started>,
    pub failed: Vec<Failed>,
}

impl Drop for Forwards {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

/// Brings up every enabled rule.
///
/// Awaits only the binds — one round trip for a `-R`, none at all for the
/// others — and returns as soon as they are up, so the shell is not held
/// behind them.
///
/// **A rule that will not come up is reported, never fatal.** `EADDRINUSE`
/// from a session that is still closing is by far the likeliest failure here,
/// and letting a convenience tunnel hold the user's shell hostage is the wrong
/// trade — the same call `record_session` makes when the config directory is
/// read-only, and `run_script_flow` makes when one host of a fleet will not
/// answer.
pub async fn start(handle: Arc<client::Handle<Handler>>, rules: &[ForwardRule]) -> Forwards {
    let mut forwards = Forwards { tasks: Vec::new(), started: Vec::new(), failed: Vec::new() };

    for rule in rules.iter().filter(|r| r.enabled) {
        let label = rule.label();
        let outcome = match &rule.kind {
            ForwardKind::Local { bind_addr, bind_port, dest_host, dest_port } => {
                bind_local(Arc::clone(&handle), bind_addr, *bind_port, dest_host.clone(), *dest_port).await
            }
            ForwardKind::Dynamic { bind_addr, bind_port } => bind_dynamic(Arc::clone(&handle), bind_addr, *bind_port).await,
            ForwardKind::Remote { bind_addr, bind_port, .. } => request_remote(&handle, bind_addr, *bind_port).await,
        };

        match outcome {
            Ok(task) => {
                forwards.started.push(Started { id: rule.id, label });
                if let Some(task) = task {
                    forwards.tasks.push(task);
                }
            }
            Err(error) => forwards.failed.push(Failed { id: rule.id, label, error }),
        }
    }

    forwards
}

/// `-L`: accept locally, open a `direct-tcpip` channel per connection.
async fn bind_local(
    handle: Arc<client::Handle<Handler>>,
    bind_addr: &str,
    bind_port: u16,
    dest_host: String,
    dest_port: u16,
) -> Result<Option<JoinHandle<()>>, String> {
    let listener = TcpListener::bind((bind_addr, bind_port)).await.map_err(|e| e.to_string())?;
    Ok(Some(tokio::spawn(async move {
        while let Ok((socket, peer)) = listener.accept().await {
            let handle = Arc::clone(&handle);
            let (host, port) = (dest_host.clone(), dest_port);
            tokio::spawn(async move {
                let _ = tunnel(&handle, socket, peer, &host, port).await;
            });
        }
    })))
}

/// `-D`: the same listener with a SOCKS5 handshake in front, so the
/// destination comes from each client instead of from the rule.
async fn bind_dynamic(handle: Arc<client::Handle<Handler>>, bind_addr: &str, bind_port: u16) -> Result<Option<JoinHandle<()>>, String> {
    let listener = TcpListener::bind((bind_addr, bind_port)).await.map_err(|e| e.to_string())?;
    Ok(Some(tokio::spawn(async move {
        while let Ok((mut socket, peer)) = listener.accept().await {
            let handle = Arc::clone(&handle);
            tokio::spawn(async move {
                let request = match socks::handshake(&mut socket).await {
                    Ok(request) => request,
                    // A refusal still gets an answer, so the client can say
                    // why it failed rather than reporting a dropped socket.
                    Err(socks::SocksError::Refused(code)) => {
                        let _ = socks::reply(&mut socket, code).await;
                        return;
                    }
                    Err(_) => return,
                };
                // Answered *before* the copy starts, and only once the channel
                // is open: a client that gets `Succeeded` and then nothing has
                // no way to tell the far end refused.
                let opened = handle
                    .channel_open_direct_tcpip(request.host.as_str(), u32::from(request.port), peer.ip().to_string(), u32::from(peer.port()))
                    .await;
                let Ok(channel) = opened else {
                    let _ = socks::reply(&mut socket, socks::Reply::HostUnreachable).await;
                    return;
                };
                if socks::reply(&mut socket, socks::Reply::Succeeded).await.is_err() {
                    return;
                }
                let mut stream = channel.into_stream();
                let _ = copy_bidirectional(&mut socket, &mut stream).await;
            });
        }
    })))
}

/// `-R`: ask the server to listen. Nothing is spawned here — the connections
/// arrive as `Handler` callbacks, which is why the routes were handed to the
/// handler before the handshake.
async fn request_remote(handle: &client::Handle<Handler>, bind_addr: &str, bind_port: u16) -> Result<Option<JoinHandle<()>>, String> {
    // `RequestDenied` is a normal answer here — `GatewayPorts no`, or a
    // privileged port — and reads as a failed bind rather than a broken
    // session.
    handle
        .tcpip_forward(bind_addr, u32::from(bind_port))
        .await
        .map(|_| None)
        .map_err(|e| e.to_string())
}

/// One local socket joined to one `direct-tcpip` channel.
async fn tunnel(
    handle: &client::Handle<Handler>,
    mut socket: TcpStream,
    peer: std::net::SocketAddr,
    dest_host: &str,
    dest_port: u16,
) -> std::io::Result<()> {
    // `channel_open_direct_tcpip` awaits its own open confirmation (russh's
    // `wait_channel_confirmation`), unlike `request_subsystem` — so unlike
    // `sftp::open_session` there is no want-reply message left for
    // `into_stream()` to swallow, and no `wait()` loop belongs here.
    let channel = handle
        .channel_open_direct_tcpip(dest_host, u32::from(dest_port), peer.ip().to_string(), u32::from(peer.port()))
        .await
        .map_err(std::io::Error::other)?;
    let mut stream = channel.into_stream();
    copy_bidirectional(&mut socket, &mut stream).await?;
    Ok(())
}
