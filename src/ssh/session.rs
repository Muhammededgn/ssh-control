use std::sync::Arc;
use std::time::Duration;

use russh::client;
use russh::keys::agent::AgentIdentity;
use russh::keys::agent::client::AgentClient;
use russh::keys::{PrivateKeyWithHashAlg, load_secret_key};
use uuid::Uuid;

use super::client::{Handler, HostKeyOutcome, RemoteRoute};
use crate::config::{AuthMethod, ForwardKind, ServerEntry};
use crate::error::{AppError, Result};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// How many bastions a chain may name before it is refused.
///
/// A belt-and-braces companion to the cycle check rather than a limit anyone
/// should reach: a chain this long is a mistake either way, and a stated error
/// beats discovering it as a stack of ten timeouts.
const MAX_JUMPS: usize = 8;

pub struct Connected {
    /// The destination session. Declared **first** so it drops before the
    /// bastions it is tunnelled through — see the note on `jumps`.
    ///
    /// `Arc` because a port forward's accept loop has to keep opening channels
    /// on it while `App::run` is blocked inside the PTY await, and
    /// `client::Handle` is not `Clone` — it owns an `UnboundedReceiver`. Every
    /// channel-opening method takes `&self`, so one shared handle serves the
    /// session, the probe and every forward at once.
    pub handle: Arc<client::Handle<Handler>>,
    pub host_key_outcome: HostKeyOutcome,
    /// One per `Target::jumps`, in the same order, so the caller can pair them
    /// back up with the entries it resolved the chain from. Empty for a direct
    /// connect.
    pub jump_outcomes: Vec<HostKeyOutcome>,
    /// The bastion sessions this connection rides on, outermost first.
    ///
    /// Never read. Owned only so they outlive `handle`: dropping a `Handle`
    /// drops the last `Sender` into its session task, the task ends, and its
    /// `direct-tcpip` channel closes — which would pull the transport out from
    /// under the destination session. **Do not reorder these two fields**;
    /// declaration order is the whole of the guarantee.
    #[allow(dead_code, reason = "owned to keep the tunnel alive for the lifetime of `handle`")]
    jumps: Vec<client::Handle<Handler>>,
}

/// Everything needed to authenticate **one** SSH hop.
///
/// The connect flows in `app.rs` have to own their input across an `.await`
/// (no borrow of `App::state` may be held that long — see the `NextStep`
/// pattern), so they build these instead of cloning whole entries with their
/// names, `system_info` and every `Script`. Each credential copy that remains
/// is a `Secret`, so it is wiped when the `Endpoint` drops — a chain simply
/// holds one per hop rather than one in total.
pub struct Endpoint {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub auth: AuthMethod,
    pub host_key_fingerprint: Option<String>,
}

/// One destination, plus the bastions to reach it through.
pub struct Target {
    pub endpoint: Endpoint,
    /// Bastions to traverse, **outermost first**. Empty is a direct connect —
    /// the only shape that existed before jump hosts.
    ///
    /// Flat, and resolved at build time on purpose. Flat, because `connect` is
    /// then a loop rather than a recursion, and because a nested `Target` would
    /// let a *hop* carry hops of its own — a shape `from_entry` never builds
    /// but `connect` would have to handle anyway. Resolved at build time,
    /// because a `Uuid` can only be looked up while `Config` is borrowed, and
    /// `connect` runs long past that point.
    pub jumps: Vec<Endpoint>,
    /// The vault ids of `jumps`, in the same order.
    ///
    /// Carried here rather than walked a second time by the caller: two walks
    /// over the same chain are two chances to disagree about its order, and the
    /// order is the only thing that pairs a hop's host-key outcome back to the
    /// entry it belongs to. `Connected` stays free of them — it reports
    /// outcomes positionally and knows nothing about the vault.
    pub jump_ids: Vec<Uuid>,
    /// The `-R` rules, in the shape the `Handler` needs them.
    ///
    /// On the target rather than reached for later because there is no later:
    /// the handler is constructed before `connect_stream` moves it into russh,
    /// and a remote forward's connections come back through it.
    pub remote_routes: Vec<RemoteRoute>,
}

impl Endpoint {
    fn from_entry(entry: &ServerEntry) -> Self {
        Self {
            host: entry.host.clone(),
            port: entry.port,
            username: entry.username.clone(),
            auth: entry.auth.clone(),
            host_key_fingerprint: entry.host_key_fingerprint.clone(),
        }
    }
}

impl Target {
    /// Resolves `entry`'s bastion chain out of `servers`.
    ///
    /// Fallible, and takes the whole list, because a jump reference can dangle
    /// — an entry deleted while this one still points at it — or loop, and both
    /// have to be caught **here**, inside the caller's borrow. By the time
    /// `connect` runs there is nothing left to look anything up in.
    ///
    /// The signature changed rather than a second constructor being added
    /// beside the old one: a call site that forgot to switch would silently
    /// ignore a configured bastion and connect straight to a host that is not
    /// reachable that way. A compile error is the only reliable reminder.
    pub fn from_entry(entry: &ServerEntry, servers: &[ServerEntry]) -> Result<Self> {
        let mut jumps = Vec::new();
        let mut jump_ids = Vec::new();
        let mut seen = vec![entry.id];
        let mut at = entry;

        while let Some(next_id) = at.jump_host {
            if seen.contains(&next_id) {
                return Err(AppError::Validation(format!("'{}' is reached through a jump chain that loops back on itself", entry.name)));
            }
            let Some(next) = servers.iter().find(|s| s.id == next_id) else {
                return Err(AppError::Validation(format!("'{}' is set to connect through a server that no longer exists", at.name)));
            };
            if jumps.len() == MAX_JUMPS {
                return Err(AppError::Validation(format!("'{}' is behind more than {MAX_JUMPS} jump hosts", entry.name)));
            }
            seen.push(next_id);
            jumps.push(Endpoint::from_entry(next));
            jump_ids.push(next_id);
            at = next;
        }

        // Built innermost-first by walking outwards; `connect` wants to dial
        // the outermost bastion first. Both vectors turn together — they are
        // one list in two halves.
        jumps.reverse();
        jump_ids.reverse();

        let remote_routes = entry
            .forwards
            .iter()
            .filter(|f| f.enabled)
            .filter_map(|f| match &f.kind {
                ForwardKind::Remote { bind_addr, bind_port, dest_host, dest_port } => Some(RemoteRoute {
                    bind_addr: bind_addr.clone(),
                    bind_port: *bind_port,
                    dest_host: dest_host.clone(),
                    dest_port: *dest_port,
                }),
                ForwardKind::Local { .. } | ForwardKind::Dynamic { .. } => None,
            })
            .collect();

        Ok(Self { endpoint: Endpoint::from_entry(entry), jumps, jump_ids, remote_routes })
    }
}

/// Establishes and authenticates an SSH connection to `server`, traversing its
/// bastion chain on the way. This is the shared core behind the interactive
/// PTY passthrough, the script runner and the file browser — only what happens
/// with the resulting `Handle` differs.
///
/// A loop rather than a recursion, which is what the flat `Target::jumps`
/// buys: the first hop is a TCP connect and every later one rides a
/// `direct-tcpip` channel on the hop before it, so the only difference between
/// them is where the byte stream comes from.
///
/// **Each hop gets its own TOFU check** against its own stored fingerprint.
/// The alternative — trusting a bastion because it is only being passed
/// through — would put the one machine that sees every session outside the
/// check that exists to notice exactly that.
pub async fn connect(server: &Target) -> Result<Connected> {
    let mut jumps: Vec<client::Handle<Handler>> = Vec::new();
    let mut jump_outcomes = Vec::new();

    for hop in &server.jumps {
        let carrier = jumps.last();
        // A bastion gets no routes: a `-R` rule belongs to the destination,
        // and a hop that could open sockets on this machine would be a hop
        // doing something nobody asked it to.
        let (handle, outcome) = match open_hop(carrier, hop, Vec::new()).await {
            Ok(opened) => opened,
            // Say which machine refused, so "authentication failed" does not
            // read as the destination rejecting the user's credentials.
            Err(e) => return Err(AppError::JumpFailed { host: hop.host.clone(), source: Box::new(e) }),
        };
        jumps.push(handle);
        jump_outcomes.push(outcome);
    }

    // Handed over before the handshake, because that is the only chance: the
    // handler is moved into russh and a `-R` connection arrives as a callback
    // on it, never on the handle.
    let (handle, host_key_outcome) = open_hop(jumps.last(), &server.endpoint, server.remote_routes.clone()).await?;
    Ok(Connected { handle: Arc::new(handle), host_key_outcome, jump_outcomes, jumps })
}

/// Opens and authenticates one hop, over `carrier` if there is one and over a
/// fresh TCP connection if there is not.
async fn open_hop(
    carrier: Option<&client::Handle<Handler>>,
    endpoint: &Endpoint,
    remote_routes: Vec<RemoteRoute>,
) -> Result<(client::Handle<Handler>, HostKeyOutcome)> {
    let config = Arc::new(client::Config::default());
    let handler = Handler::new(endpoint.host_key_fingerprint.clone(), remote_routes);
    let outcome_ref = handler.outcome.clone();

    // Per hop, not a budget shared across the chain: a two-hop connect
    // legitimately takes twice as long as a one-hop one, and a total budget
    // would make the last hop fail for reasons the first one caused. The user
    // still has one escape hatch either way — `connect_flow` runs this inside
    // `await_on_screen`, where Esc cancels.
    let connect_result = tokio::time::timeout(CONNECT_TIMEOUT, async {
        match carrier {
            None => client::connect(config, (endpoint.host.as_str(), endpoint.port), handler).await,
            Some(carrier) => {
                // `channel_open_direct_tcpip` awaits its own open confirmation
                // (russh's `wait_channel_confirmation`), unlike
                // `request_subsystem` — so unlike `sftp::open_session` there is
                // no want-reply message left for `into_stream()` to swallow,
                // and no `wait()` loop is needed here. The originator address
                // is ours to state and no server acts on it.
                let channel = carrier
                    .channel_open_direct_tcpip(endpoint.host.as_str(), u32::from(endpoint.port), "127.0.0.1", 0)
                    .await?;
                client::connect_stream(config, channel.into_stream(), handler).await
            }
        }
    })
    .await
    .map_err(|_| AppError::SshConnect("connection timed out".into()))?;

    let mut handle = match connect_result {
        Ok(handle) => handle,
        Err(e) => {
            let outcome = outcome_ref.lock().expect("outcome mutex poisoned").clone();
            if let Some(HostKeyOutcome::Mismatch { actual, .. }) = outcome {
                return Err(AppError::HostKeyChanged { fingerprint: actual });
            }
            return Err(e);
        }
    };

    authenticate(&mut handle, endpoint).await?;

    let outcome = outcome_ref
        .lock()
        .expect("outcome mutex poisoned")
        .clone()
        .unwrap_or(HostKeyOutcome::Trusted);

    Ok((handle, outcome))
}

async fn authenticate(handle: &mut client::Handle<Handler>, server: &Endpoint) -> Result<()> {
    let auth_result = match &server.auth {
        // russh takes the password by value and we cannot reach inside it to
        // wipe it afterwards — this hand-off is the end of the line for what
        // `Secret` can protect, not an oversight.
        AuthMethod::Password { password } => {
            handle
                .authenticate_password(server.username.clone(), password.as_str().to_string())
                .await?
        }
        AuthMethod::SshKey { key_path, passphrase } => {
            let key = load_secret_key(key_path, passphrase.as_ref().map(|p| p.as_str()))
                .map_err(|e| AppError::SshAuthFailed(format!("failed to load key '{key_path}': {e}")))?;
            let hash_alg = handle.best_supported_rsa_hash().await?.flatten();
            let key_with_hash = PrivateKeyWithHashAlg::new(Arc::new(key), hash_alg);
            handle
                .authenticate_publickey(server.username.clone(), key_with_hash)
                .await?
        }
        AuthMethod::Agent => return authenticate_via_agent(handle, &server.username).await,
    };

    match auth_result {
        client::AuthResult::Success => Ok(()),
        client::AuthResult::Failure { .. } => {
            Err(AppError::SshAuthFailed("credentials rejected by server".into()))
        }
    }
}

/// Public-key authentication where the key never leaves the agent.
///
/// **Every identity is tried, not just the first.** An agent commonly holds
/// several keys and only one of them is in this host's `authorized_keys`;
/// offering one and giving up is the difference between "works" and a bare
/// "credentials rejected by server", which would send the user to look at the
/// wrong machine.
///
/// The three ways this can fail before a server ever sees a signature — no
/// agent configured, a socket that is gone, an agent holding nothing — are all
/// `AppError::SshAgent` rather than `SshAuthFailed`, because in none of them is
/// there anything wrong with the user's account on the remote host.
async fn authenticate_via_agent(handle: &mut client::Handle<Handler>, username: &str) -> Result<()> {
    let mut agent = AgentClient::connect_env().await.map_err(|e| {
        AppError::SshAgent(match e {
            russh::keys::Error::EnvVar(_) => "SSH_AUTH_SOCK is not set — no agent is running".to_string(),
            russh::keys::Error::BadAuthSock => "SSH_AUTH_SOCK points at a socket that is not there — the agent has gone away".to_string(),
            other => format!("could not reach the agent: {other}"),
        })
    })?;

    let identities = agent
        .request_identities()
        .await
        .map_err(|e| AppError::SshAgent(format!("could not list the agent's keys: {e}")))?;

    // Certificates need `authenticate_certificate_with` and a different reply
    // shape; skipping them here loses nothing an agent-only user has today.
    let keys: Vec<_> = identities
        .into_iter()
        .filter_map(|id| match id {
            AgentIdentity::PublicKey { key, .. } => Some(key),
            AgentIdentity::Certificate { .. } => None,
        })
        .collect();

    if keys.is_empty() {
        return Err(AppError::SshAgent("the agent is running but holds no usable keys — try `ssh-add`".into()));
    }

    let hash_alg = handle.best_supported_rsa_hash().await?.flatten();

    for key in keys {
        let attempt = handle
            .authenticate_publickey_with(username.to_string(), key, hash_alg, &mut agent)
            .await
            // `S::Error` here is russh's `AgentAuthError`, not `russh::Error`,
            // so there is no `From` to lean on.
            .map_err(|e| AppError::SshAgent(format!("the agent refused to sign: {e}")))?;
        if let client::AuthResult::Success = attempt {
            return Ok(());
        }
    }

    Err(AppError::SshAuthFailed("the server accepted none of the agent's keys".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AuthMethod;

    fn entry(name: &str) -> ServerEntry {
        ServerEntry::new(name.into(), format!("{name}.example.com"), 22, "root".into(), AuthMethod::Agent)
    }

    /// `a -> b -> c`, where `a` is the destination and `c` the outermost
    /// bastion.
    fn chain(len: usize) -> Vec<ServerEntry> {
        let mut servers: Vec<_> = (0..len).map(|i| entry(&format!("hop-{i}"))).collect();
        for i in 0..len.saturating_sub(1) {
            servers[i].jump_host = Some(servers[i + 1].id);
        }
        servers
    }

    fn hosts(target: &Target) -> Vec<&str> {
        target.jumps.iter().map(|e| e.host.as_str()).collect()
    }

    #[test]
    fn a_server_with_no_jump_host_is_a_direct_connect() {
        let servers = chain(1);
        let target = Target::from_entry(&servers[0], &servers).unwrap();
        assert!(target.jumps.is_empty());
        assert!(target.jump_ids.is_empty());
        assert_eq!(target.endpoint.host, "hop-0.example.com");
    }

    /// Outermost first, because that is the one `connect` dials over TCP —
    /// every later hop rides the one before it. Getting this backwards would
    /// tunnel out through the destination.
    #[test]
    fn a_chain_is_resolved_outermost_first() {
        let servers = chain(3);
        let target = Target::from_entry(&servers[0], &servers).unwrap();
        assert_eq!(hosts(&target), ["hop-2.example.com", "hop-1.example.com"]);
        assert_eq!(target.endpoint.host, "hop-0.example.com");
    }

    /// `jump_ids` is what pairs a hop's host-key outcome back to its entry, so
    /// it has to turn with `jumps` and not against it.
    #[test]
    fn the_ids_are_in_the_same_order_as_the_hops() {
        let servers = chain(3);
        let target = Target::from_entry(&servers[0], &servers).unwrap();
        assert_eq!(target.jump_ids, vec![servers[2].id, servers[1].id]);
    }

    #[test]
    fn a_server_pointing_at_itself_is_refused() {
        let mut servers = chain(1);
        servers[0].jump_host = Some(servers[0].id);
        assert!(Target::from_entry(&servers[0], &servers).is_err());
    }

    #[test]
    fn a_chain_that_loops_back_is_refused_rather_than_walked_forever() {
        let mut servers = chain(3);
        // hop-2 points back at hop-0, closing the ring.
        let first = servers[0].id;
        servers[2].jump_host = Some(first);
        assert!(Target::from_entry(&servers[0], &servers).is_err());
    }

    /// A loop that does not include the destination still has to stop — the
    /// walk would otherwise circle it without ever revisiting `entry.id`.
    #[test]
    fn a_loop_further_down_the_chain_is_refused_too() {
        let mut servers = chain(3);
        let second = servers[1].id;
        servers[2].jump_host = Some(second);
        assert!(Target::from_entry(&servers[0], &servers).is_err());
    }

    /// The entry a chain points at can be deleted by another window, and this
    /// has to be caught here — `connect` has nothing left to look it up in.
    #[test]
    fn a_jump_host_that_no_longer_exists_is_refused() {
        let mut servers = chain(2);
        servers[0].jump_host = Some(uuid::Uuid::new_v4());
        servers.truncate(1);
        assert!(Target::from_entry(&servers[0], &servers).is_err());
    }

    #[test]
    fn a_chain_longer_than_the_cap_is_refused() {
        let servers = chain(MAX_JUMPS + 3);
        assert!(Target::from_entry(&servers[0], &servers).is_err());
        // And one that fits is still fine.
        let ok = chain(MAX_JUMPS);
        assert!(Target::from_entry(&ok[0], &ok).is_ok());
    }

    /// Every hop carries its own pinned fingerprint, or TOFU on a bastion
    /// would be decided by the destination's.
    #[test]
    fn each_hop_carries_its_own_stored_fingerprint() {
        let mut servers = chain(2);
        servers[1].host_key_fingerprint = Some("SHA256:bastion".into());
        servers[0].host_key_fingerprint = Some("SHA256:target".into());
        let target = Target::from_entry(&servers[0], &servers).unwrap();
        assert_eq!(target.jumps[0].host_key_fingerprint.as_deref(), Some("SHA256:bastion"));
        assert_eq!(target.endpoint.host_key_fingerprint.as_deref(), Some("SHA256:target"));
    }
}
