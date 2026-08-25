//! Just enough SOCKS5 to be the front half of a `-D` forward.
//!
//! Generic over the stream and free of russh, for the reason
//! `ssh::sftp::client` is: the protocol is then testable over
//! `tokio::io::duplex` against a handful of bytes, with no server anywhere.
//!
//! **`CONNECT` only.** That is what a browser, `curl --socks5` and every
//! `ProxyCommand` wrapper use. `BIND` and `UDP ASSOCIATE` are answered with
//! "command not supported" rather than ignored, so a client that wants them
//! fails immediately and legibly instead of hanging on a handshake that will
//! never finish.
//!
//! Every read goes through a length check before it slices. The bytes come
//! from whatever connected to the port; a truncated greeting is an error, never
//! a panic — the same discipline `sftp::wire`'s `Cursor` enforces.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const VERSION: u8 = 5;
const AUTH_NONE: u8 = 0;
const AUTH_UNACCEPTABLE: u8 = 0xff;

const CMD_CONNECT: u8 = 1;

const ADDR_IPV4: u8 = 1;
const ADDR_DOMAIN: u8 = 3;
const ADDR_IPV6: u8 = 4;

/// SOCKS5 reply codes, as far as this proxy uses them.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Reply {
    Succeeded = 0,
    GeneralFailure = 1,
    HostUnreachable = 4,
    CommandNotSupported = 7,
    AddressTypeNotSupported = 8,
}

/// Where a client asked to be connected. The host is left as written — a
/// domain is resolved by the *far* end, which is the point of `-D`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Request {
    pub host: String,
    pub port: u16,
}

#[derive(Debug)]
pub enum SocksError {
    /// The stream ended, or was never SOCKS5 to begin with.
    Protocol(&'static str),
    Io(std::io::Error),
    /// Well-formed, but asking for something this proxy does not do. Carries
    /// the code to answer with, so the caller can reply before hanging up —
    /// a client that gets a reply can say why it failed.
    Refused(Reply),
}

impl std::fmt::Display for SocksError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SocksError::Protocol(m) => write!(f, "{m}"),
            SocksError::Io(e) => write!(f, "{e}"),
            SocksError::Refused(r) => write!(f, "refused: {r:?}"),
        }
    }
}

impl From<std::io::Error> for SocksError {
    fn from(e: std::io::Error) -> Self {
        SocksError::Io(e)
    }
}

type Result<T> = std::result::Result<T, SocksError>;

/// Greeting, method selection, and the `CONNECT` request.
///
/// Returns once the client has said where it wants to go and *before* anything
/// is opened — the caller answers with `reply` when it knows whether it worked,
/// which is what lets a failed connect come back as `HostUnreachable` rather
/// than a dropped socket.
pub async fn handshake<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S) -> Result<Request> {
    greet(stream).await?;
    request(stream).await
}

async fn greet<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S) -> Result<()> {
    let mut head = [0u8; 2];
    stream.read_exact(&mut head).await?;
    if head[0] != VERSION {
        return Err(SocksError::Protocol("not a SOCKS5 client"));
    }
    let mut methods = vec![0u8; usize::from(head[1])];
    stream.read_exact(&mut methods).await?;

    // No authentication: the listener is on loopback by default and the SSH
    // session behind it is already authenticated. A username/password layer
    // here would be a second credential to store for no gain.
    if !methods.contains(&AUTH_NONE) {
        stream.write_all(&[VERSION, AUTH_UNACCEPTABLE]).await?;
        return Err(SocksError::Protocol("the client offered no usable auth method"));
    }
    stream.write_all(&[VERSION, AUTH_NONE]).await?;
    Ok(())
}

async fn request<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S) -> Result<Request> {
    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await?;
    if head[0] != VERSION {
        return Err(SocksError::Protocol("not a SOCKS5 request"));
    }
    if head[1] != CMD_CONNECT {
        return Err(SocksError::Refused(Reply::CommandNotSupported));
    }

    let host = match head[3] {
        ADDR_IPV4 => {
            let mut octets = [0u8; 4];
            stream.read_exact(&mut octets).await?;
            std::net::Ipv4Addr::from(octets).to_string()
        }
        ADDR_IPV6 => {
            let mut octets = [0u8; 16];
            stream.read_exact(&mut octets).await?;
            std::net::Ipv6Addr::from(octets).to_string()
        }
        ADDR_DOMAIN => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut name = vec![0u8; usize::from(len[0])];
            stream.read_exact(&mut name).await?;
            // Left as written and never resolved here: `-D`'s whole purpose is
            // that the *far* end does the lookup, on the network it can see.
            String::from_utf8(name).map_err(|_| SocksError::Protocol("the destination name is not utf-8"))?
        }
        _ => return Err(SocksError::Refused(Reply::AddressTypeNotSupported)),
    };

    let mut port = [0u8; 2];
    stream.read_exact(&mut port).await?;
    Ok(Request { host, port: u16::from_be_bytes(port) })
}

/// Answers a request.
///
/// The bound address is always reported as `0.0.0.0:0`. Clients that use
/// `CONNECT` ignore it — it exists for `BIND`, which this proxy refuses — and
/// the honest answer is that there is no local socket to name: the far end
/// made the connection.
pub async fn reply<S: AsyncWrite + Unpin>(stream: &mut S, reply: Reply) -> Result<()> {
    stream.write_all(&[VERSION, reply as u8, 0, ADDR_IPV4, 0, 0, 0, 0, 0, 0]).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    /// Drives `handshake` against a scripted client over a duplex pipe, and
    /// hands back whatever the proxy wrote.
    ///
    /// The client's write half is **shut down before the handshake runs**, so
    /// a script that stops mid-packet reaches the proxy as EOF. Without that,
    /// every truncation test would block forever waiting for bytes the script
    /// was never going to send — which is exactly the failure the truncation
    /// tests exist to rule out in production code.
    async fn run(client_bytes: &[u8]) -> (Result<Request>, Vec<u8>) {
        let (mut client, mut proxy) = tokio::io::duplex(1024);
        client.write_all(client_bytes).await.unwrap();
        client.shutdown().await.unwrap();

        let outcome = handshake(&mut proxy).await;
        drop(proxy);

        let mut written = Vec::new();
        let _ = tokio::io::AsyncReadExt::read_to_end(&mut client, &mut written).await;
        (outcome, written)
    }

    fn connect_to(addr_type: u8, addr: &[u8], port: u16) -> Vec<u8> {
        let mut bytes = vec![VERSION, 1, AUTH_NONE, VERSION, CMD_CONNECT, 0, addr_type];
        bytes.extend_from_slice(addr);
        bytes.extend_from_slice(&port.to_be_bytes());
        bytes
    }

    #[tokio::test]
    async fn an_ipv4_connect_round_trips() {
        let (request, written) = run(&connect_to(ADDR_IPV4, &[10, 0, 0, 4], 5432)).await;
        assert_eq!(request.unwrap(), Request { host: "10.0.0.4".into(), port: 5432 });
        assert_eq!(&written[..2], &[VERSION, AUTH_NONE], "no-auth is selected first");
    }

    #[tokio::test]
    async fn an_ipv6_connect_round_trips() {
        let addr = [0x20, 0x01, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let (request, _) = run(&connect_to(ADDR_IPV6, &addr, 443)).await;
        assert_eq!(request.unwrap().host, "2001:db8::1");
    }

    /// The name is passed through untouched. Resolving it here would defeat
    /// the whole point of a dynamic forward — the far end is the side that can
    /// see the network the name belongs to.
    #[tokio::test]
    async fn a_domain_name_is_passed_through_unresolved() {
        let name = b"db.internal";
        let mut addr = vec![name.len() as u8];
        addr.extend_from_slice(name);
        let (request, _) = run(&connect_to(ADDR_DOMAIN, &addr, 5432)).await;
        assert_eq!(request.unwrap(), Request { host: "db.internal".into(), port: 5432 });
    }

    /// A client asking for BIND must be told so, not left hanging on a
    /// handshake that will never complete.
    #[tokio::test]
    async fn an_unsupported_command_is_refused_with_a_code_to_answer_with() {
        let bytes = vec![VERSION, 1, AUTH_NONE, VERSION, 2 /* BIND */, 0, ADDR_IPV4, 1, 2, 3, 4, 0, 80];
        let (outcome, _) = run(&bytes).await;
        assert!(matches!(outcome, Err(SocksError::Refused(Reply::CommandNotSupported))));
    }

    #[tokio::test]
    async fn an_unknown_address_type_is_refused_rather_than_guessed_at() {
        let bytes = vec![VERSION, 1, AUTH_NONE, VERSION, CMD_CONNECT, 0, 9, 0, 80];
        let (outcome, _) = run(&bytes).await;
        assert!(matches!(outcome, Err(SocksError::Refused(Reply::AddressTypeNotSupported))));
    }

    #[tokio::test]
    async fn a_client_that_cannot_do_no_auth_is_told_so() {
        let (outcome, written) = run(&[VERSION, 1, 2 /* user/pass only */]).await;
        assert!(matches!(outcome, Err(SocksError::Protocol(_))));
        assert_eq!(written, vec![VERSION, AUTH_UNACCEPTABLE]);
    }

    #[tokio::test]
    async fn something_that_is_not_socks5_is_an_error_not_a_hang() {
        let (outcome, _) = run(b"GET / HTTP/1.1\r\n").await;
        assert!(matches!(outcome, Err(SocksError::Protocol(_))));
    }

    /// The bytes arrive from whatever connected to the port. Every one of
    /// these truncations has to be an error rather than a panic.
    #[tokio::test]
    async fn every_truncation_is_an_error_rather_than_a_panic() {
        for prefix in [
            vec![VERSION],
            vec![VERSION, 3, AUTH_NONE],
            vec![VERSION, 1, AUTH_NONE, VERSION, CMD_CONNECT],
            vec![VERSION, 1, AUTH_NONE, VERSION, CMD_CONNECT, 0, ADDR_IPV4, 10, 0],
            vec![VERSION, 1, AUTH_NONE, VERSION, CMD_CONNECT, 0, ADDR_DOMAIN, 40, b'a'],
        ] {
            let (outcome, _) = run(&prefix).await;
            assert!(outcome.is_err(), "{prefix:?} must not parse");
        }
    }

    #[tokio::test]
    async fn a_reply_is_ten_bytes_and_names_its_code() {
        let (mut client, mut proxy) = tokio::io::duplex(64);
        reply(&mut proxy, Reply::HostUnreachable).await.unwrap();
        drop(proxy);
        let mut written = Vec::new();
        let _ = tokio::io::AsyncReadExt::read_to_end(&mut client, &mut written).await;
        assert_eq!(written, vec![VERSION, 4, 0, ADDR_IPV4, 0, 0, 0, 0, 0, 0]);
    }
}
