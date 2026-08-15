//! The SFTP request/reply layer.
//!
//! Generic over the stream on purpose. In the app `S` is russh's
//! `ChannelStream`, but the tests below drive the very same code over
//! `tokio::io::duplex` against a hand-written fake server — so the protocol is
//! covered without an SSH connection, a server process, or a network.

use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::wire::{self, Attrs, Encoder, FileKind, Reply};
use crate::error::{AppError, Result};

/// How long any single request may take. A timeout leaves the stream
/// desynced — the reply may still arrive later and would then be read as the
/// answer to a different request — so it drops the session rather than
/// retrying. Generous, because a `READDIR` on a huge directory is legitimately
/// slow.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// A `READDIR` loop has to stop somewhere. A directory needing more than this
/// many round trips (100-ish names each, so millions of entries) is a server
/// that is not sending EOF, not a directory anyone is browsing.
const MAX_READDIR_BATCHES: usize = 20_000;

/// One entry of a remote directory listing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RemoteEntry {
    pub name: String,
    pub kind: FileKind,
    pub size: u64,
    pub mtime: Option<u32>,
}

impl RemoteEntry {
    pub fn is_dir(&self) -> bool {
        self.kind == FileKind::Dir
    }
}

/// An open file on the server. Opaque bytes chosen by the server; it is only
/// ever handed back verbatim.
#[derive(Clone, Debug)]
pub struct FileHandle(Vec<u8>);

pub struct SftpClient<S> {
    stream: S,
    next_id: u32,
}

impl<S: AsyncRead + AsyncWrite + Unpin> SftpClient<S> {
    /// Sends `INIT` and checks the version the server answers with.
    pub async fn init(stream: S) -> Result<Self> {
        let mut client = Self { stream, next_id: 1 };
        client.write_packet(&Encoder::init().finish()).await?;

        match client.read_reply().await? {
            (_, Reply::Version(v)) if v >= wire::VERSION => Ok(client),
            (_, Reply::Version(v)) => Err(AppError::Sftp(format!("server speaks sftp version {v}, need {}", wire::VERSION))),
            _ => Err(AppError::Sftp("server did not answer the sftp handshake".into())),
        }
    }

    /// Canonicalizes a path — also how the starting directory is resolved,
    /// since `realpath(".")` is the server's idea of the login directory.
    pub async fn realpath(&mut self, path: &str) -> Result<String> {
        let id = self.next_id();
        let packet = Encoder::request(wire::FXP_REALPATH, id).str(path).finish();
        match self.request(id, &packet).await? {
            // v3 answers REALPATH with a NAME reply of exactly one entry.
            Reply::Name(entries) => entries
                .into_iter()
                .next()
                .map(|e| e.filename)
                .ok_or_else(|| AppError::Sftp("server returned no path for realpath".into())),
            Reply::Status { code, message } => Err(wire::status_error(path, code, message)),
            _ => Err(unexpected("realpath")),
        }
    }

    /// The whole listing of one directory.
    ///
    /// `READDIR` is a loop, not a call: each reply carries only some of the
    /// names, and the end is signalled by a `STATUS` of `EOF` — which is
    /// termination, not failure. The handle is closed on the error path too, so
    /// a listing that fails half way does not leak a handle on the server.
    pub async fn list_dir(&mut self, path: &str) -> Result<Vec<RemoteEntry>> {
        let handle = self.opendir(path).await?;
        let result = self.read_all_names(path, &handle).await;
        let _ = self.close(handle).await;
        result
    }

    async fn read_all_names(&mut self, path: &str, handle: &FileHandle) -> Result<Vec<RemoteEntry>> {
        let mut entries = Vec::new();

        for _ in 0..MAX_READDIR_BATCHES {
            let id = self.next_id();
            let packet = Encoder::request(wire::FXP_READDIR, id).bytes(&handle.0).finish();
            match self.request(id, &packet).await? {
                Reply::Name(names) => {
                    for entry in names {
                        // The browser navigates with Backspace, so these two are
                        // never rows — and "." as a row would make `cd` into it
                        // a no-op that looks broken.
                        if entry.filename == "." || entry.filename == ".." {
                            continue;
                        }
                        entries.push(RemoteEntry {
                            kind: entry.kind(),
                            size: entry.attrs.size.unwrap_or(0),
                            mtime: entry.attrs.mtime,
                            name: entry.filename,
                        });
                    }
                }
                Reply::Status { code: wire::FX_EOF, .. } => return Ok(entries),
                Reply::Status { code, message } => return Err(wire::status_error(path, code, message)),
                _ => return Err(unexpected("readdir")),
            }
        }
        Err(AppError::Sftp("server never finished the directory listing".into()))
    }

    pub async fn stat(&mut self, path: &str) -> Result<Attrs> {
        self.stat_with(wire::FXP_STAT, path).await
    }

    /// `LSTAT` — does not follow symlinks, which is how the walk tells a
    /// symlinked directory from a real one.
    pub async fn lstat(&mut self, path: &str) -> Result<Attrs> {
        self.stat_with(wire::FXP_LSTAT, path).await
    }

    async fn stat_with(&mut self, kind: u8, path: &str) -> Result<Attrs> {
        let id = self.next_id();
        let packet = Encoder::request(kind, id).str(path).finish();
        match self.request(id, &packet).await? {
            Reply::Attrs(attrs) => Ok(attrs),
            Reply::Status { code, message } => Err(wire::status_error(path, code, message)),
            _ => Err(unexpected("stat")),
        }
    }

    /// "Is there anything at this path?" — a missing file is an answer, not an
    /// error, which is what the overwrite check needs. A denial stays an error:
    /// not being allowed to look is not the same as nothing being there.
    pub async fn try_stat(&mut self, path: &str) -> Result<Option<Attrs>> {
        match self.stat(path).await {
            Ok(attrs) => Ok(Some(attrs)),
            Err(AppError::SftpStatus { code: wire::FX_NO_SUCH_FILE, .. }) => Ok(None),
            Err(e) => Err(e),
        }
    }

    pub async fn mkdir(&mut self, path: &str) -> Result<()> {
        let id = self.next_id();
        let packet = Encoder::request(wire::FXP_MKDIR, id).str(path).empty_attrs().finish();
        self.expect_ok(id, &packet, path).await
    }

    pub async fn remove(&mut self, path: &str) -> Result<()> {
        let id = self.next_id();
        let packet = Encoder::request(wire::FXP_REMOVE, id).str(path).finish();
        self.expect_ok(id, &packet, path).await
    }

    pub async fn rename(&mut self, from: &str, to: &str) -> Result<()> {
        let id = self.next_id();
        let packet = Encoder::request(wire::FXP_RENAME, id).str(from).str(to).finish();
        self.expect_ok(id, &packet, to).await
    }

    pub async fn open_read(&mut self, path: &str) -> Result<FileHandle> {
        self.open(path, wire::FXF_READ).await
    }

    /// Create-or-truncate, the semantics an upload wants.
    pub async fn open_write(&mut self, path: &str) -> Result<FileHandle> {
        self.open(path, wire::FXF_WRITE | wire::FXF_CREAT | wire::FXF_TRUNC).await
    }

    async fn open(&mut self, path: &str, pflags: u32) -> Result<FileHandle> {
        let id = self.next_id();
        let packet = Encoder::request(wire::FXP_OPEN, id).str(path).u32(pflags).empty_attrs().finish();
        match self.request(id, &packet).await? {
            Reply::Handle(h) => Ok(FileHandle(h)),
            Reply::Status { code, message } => Err(wire::status_error(path, code, message)),
            _ => Err(unexpected("open")),
        }
    }

    async fn opendir(&mut self, path: &str) -> Result<FileHandle> {
        let id = self.next_id();
        let packet = Encoder::request(wire::FXP_OPENDIR, id).str(path).finish();
        match self.request(id, &packet).await? {
            Reply::Handle(h) => Ok(FileHandle(h)),
            Reply::Status { code, message } => Err(wire::status_error(path, code, message)),
            _ => Err(unexpected("opendir")),
        }
    }

    /// Reads one chunk at `offset`, appending to `out`, and returns how many
    /// bytes arrived. `Ok(0)` means end of file.
    ///
    /// A short reply is **not** end of file — servers are free to return less
    /// than was asked for. Only a `STATUS` of `EOF` ends the file, which is why
    /// the caller advances by the returned count instead of assuming `CHUNK`.
    pub async fn read_chunk(&mut self, handle: &FileHandle, offset: u64, out: &mut Vec<u8>) -> Result<usize> {
        let id = self.next_id();
        let packet = Encoder::request(wire::FXP_READ, id)
            .bytes(&handle.0)
            .u64(offset)
            .u32(wire::CHUNK as u32)
            .finish();
        match self.request(id, &packet).await? {
            Reply::Data(data) => {
                out.extend_from_slice(&data);
                Ok(data.len())
            }
            Reply::Status { code: wire::FX_EOF, .. } => Ok(0),
            Reply::Status { code, message } => Err(wire::status_error("", code, message)),
            _ => Err(unexpected("read")),
        }
    }

    /// One `WRITE` is all-or-nothing in v3: the reply is a single status, so
    /// there is no partial-write case to unwind.
    pub async fn write_chunk(&mut self, handle: &FileHandle, offset: u64, data: &[u8]) -> Result<()> {
        let id = self.next_id();
        let packet = Encoder::request(wire::FXP_WRITE, id).bytes(&handle.0).u64(offset).bytes(data).finish();
        self.expect_ok(id, &packet, "").await
    }

    pub async fn close(&mut self, handle: FileHandle) -> Result<()> {
        let id = self.next_id();
        let packet = Encoder::request(wire::FXP_CLOSE, id).bytes(&handle.0).finish();
        self.expect_ok(id, &packet, "").await
    }

    async fn expect_ok(&mut self, id: u32, packet: &[u8], path: &str) -> Result<()> {
        match self.request(id, packet).await? {
            Reply::Status { code: wire::FX_OK, .. } => Ok(()),
            Reply::Status { code, message } => Err(wire::status_error(path, code, message)),
            _ => Err(unexpected("status")),
        }
    }

    fn next_id(&mut self) -> u32 {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1).max(1);
        id
    }

    /// One request, one reply.
    ///
    /// Exactly one request is ever in flight, which is what makes matching an
    /// assertion rather than a table of waiting callers: there is no reader
    /// task and no id-to-waker map. The cost is that throughput is bounded by
    /// one 32 KiB chunk per round trip — pipelining a window of reads is the
    /// documented next step, and the explicit `offset` arguments above are the
    /// seam for it.
    ///
    /// A reply bearing the wrong id means the stream is desynced. There is no
    /// recovering from that by reading further, so it is a hard error and the
    /// caller drops the session.
    async fn request(&mut self, id: u32, packet: &[u8]) -> Result<Reply> {
        self.write_packet(packet).await?;
        let (reply_id, reply) = self.read_reply().await?;
        match reply_id {
            Some(got) if got == id => Ok(reply),
            Some(got) => Err(AppError::Sftp(format!("reply for request {got} arrived for request {id}"))),
            None => Err(AppError::Sftp("unexpected handshake reply mid-session".into())),
        }
    }

    async fn write_packet(&mut self, packet: &[u8]) -> Result<()> {
        timeout(self.stream.write_all(packet)).await?.map_err(AppError::Io)?;
        timeout(self.stream.flush()).await?.map_err(AppError::Io)
    }

    async fn read_reply(&mut self) -> Result<(Option<u32>, Reply)> {
        let mut len_buf = [0u8; 4];
        timeout(self.stream.read_exact(&mut len_buf)).await?.map_err(read_error)?;

        // Checked before allocating: the length is whatever the far end sent,
        // and a desynced stream can make it enormous.
        let len = u32::from_be_bytes(len_buf) as usize;
        if len == 0 || len > wire::MAX_PACKET {
            return Err(AppError::Sftp(format!("server announced an impossible packet of {len} bytes")));
        }

        let mut body = vec![0u8; len];
        timeout(self.stream.read_exact(&mut body)).await?.map_err(read_error)?;
        Reply::decode(&body)
    }
}

/// A closed stream mid-reply is a dropped connection, not a malformed packet —
/// the screen reacts differently to the two, so the distinction is made here
/// rather than left to a generic I/O error.
fn read_error(e: std::io::Error) -> AppError {
    if e.kind() == std::io::ErrorKind::UnexpectedEof {
        AppError::Sftp("the connection closed mid-reply".into())
    } else {
        AppError::Io(e)
    }
}

fn unexpected(op: &str) -> AppError {
    AppError::Sftp(format!("server sent the wrong kind of reply to {op}"))
}

async fn timeout<T>(fut: impl std::future::Future<Output = T>) -> Result<T> {
    tokio::time::timeout(REQUEST_TIMEOUT, fut)
        .await
        .map_err(|_| AppError::Sftp("the server stopped answering".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ssh::sftp::wire::{ATTR_PERMISSIONS, ATTR_SIZE};
    use tokio::io::DuplexStream;

    /// A scripted server: it reads whole frames and replies with whatever the
    /// test queued, so a client op can be exercised end to end without SSH.
    struct FakeServer {
        stream: DuplexStream,
    }

    impl FakeServer {
        /// Reads one request frame and returns `(type, request-id, body)`.
        async fn read_request(&mut self) -> (u8, u32, Vec<u8>) {
            let mut len_buf = [0u8; 4];
            self.stream.read_exact(&mut len_buf).await.expect("length");
            let len = u32::from_be_bytes(len_buf) as usize;
            let mut body = vec![0u8; len];
            self.stream.read_exact(&mut body).await.expect("body");

            let kind = body[0];
            // INIT is the one request with no id.
            let id = if kind == wire::FXP_INIT { 0 } else { u32::from_be_bytes([body[1], body[2], body[3], body[4]]) };
            (kind, id, body)
        }

        async fn send(&mut self, packet: &[u8]) {
            self.stream.write_all(packet).await.expect("write");
            self.stream.flush().await.expect("flush");
        }

        async fn send_version(&mut self) {
            let (kind, _, _) = self.read_request().await;
            assert_eq!(kind, wire::FXP_INIT);
            let mut e = Encoder::raw(wire::FXP_VERSION);
            e.u32(3);
            self.send(&e.finish()).await;
        }

        async fn send_status(&mut self, id: u32, code: u32, message: &str) {
            let mut e = Encoder::request(wire::FXP_STATUS, id);
            e.u32(code);
            e.str(message);
            self.send(&e.finish()).await;
        }

        async fn send_handle(&mut self, id: u32, handle: &[u8]) {
            let mut e = Encoder::request(wire::FXP_HANDLE, id);
            e.bytes(handle);
            self.send(&e.finish()).await;
        }

        async fn send_names(&mut self, id: u32, names: &[(&str, u32, u64)]) {
            let mut e = Encoder::request(wire::FXP_NAME, id);
            e.u32(names.len() as u32);
            for (name, perms, size) in names {
                e.str(name);
                e.str("-rw-r--r-- 1 root root");
                e.u32(ATTR_SIZE | ATTR_PERMISSIONS);
                e.u64(*size);
                e.u32(*perms);
            }
            self.send(&e.finish()).await;
        }

        async fn send_data(&mut self, id: u32, data: &[u8]) {
            let mut e = Encoder::request(wire::FXP_DATA, id);
            e.bytes(data);
            self.send(&e.finish()).await;
        }
    }

    fn pair() -> (DuplexStream, FakeServer) {
        let (client, server) = tokio::io::duplex(64 * 1024);
        (client, FakeServer { stream: server })
    }

    #[tokio::test]
    async fn the_handshake_refuses_an_older_server() {
        let (client, mut server) = pair();
        tokio::spawn(async move {
            let (kind, _, _) = server.read_request().await;
            assert_eq!(kind, wire::FXP_INIT);
            let mut e = Encoder::raw(wire::FXP_VERSION);
            e.u32(2);
            server.send(&e.finish()).await;
        });

        let result = SftpClient::init(client).await;
        assert!(matches!(result.err(), Some(AppError::Sftp(_))), "version 2 is not enough");
    }

    /// The listing loop: two batches of names, then EOF. A client that treated
    /// the first reply as the whole listing would silently show half a
    /// directory.
    #[tokio::test]
    async fn a_listing_concatenates_every_batch_until_eof() {
        let (client, mut server) = pair();
        tokio::spawn(async move {
            server.send_version().await;

            let (kind, id, _) = server.read_request().await;
            assert_eq!(kind, wire::FXP_OPENDIR);
            server.send_handle(id, b"h").await;

            let (_, id, _) = server.read_request().await;
            server.send_names(id, &[("a", 0o100644, 10), ("b", 0o040755, 0)]).await;

            let (_, id, _) = server.read_request().await;
            server.send_names(id, &[("c", 0o100644, 30), (".", 0o040755, 0), ("..", 0o040755, 0)]).await;

            let (_, id, _) = server.read_request().await;
            server.send_status(id, wire::FX_EOF, "").await;

            let (kind, id, _) = server.read_request().await;
            assert_eq!(kind, wire::FXP_CLOSE);
            server.send_status(id, wire::FX_OK, "").await;
        });

        let mut sftp = SftpClient::init(client).await.expect("handshake");
        let entries = sftp.list_dir("/tmp").await.expect("listing");

        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, ["a", "b", "c"], "both batches, and no . or ..");
        assert!(entries[1].is_dir());
        assert_eq!(entries[2].size, 30);
    }

    /// A denied listing is the server answering, not the stream breaking — it
    /// has to come back as a status the screen can show on one pane.
    #[tokio::test]
    async fn a_denied_listing_reports_the_servers_own_message() {
        let (client, mut server) = pair();
        tokio::spawn(async move {
            server.send_version().await;
            let (_, id, _) = server.read_request().await;
            server.send_status(id, wire::FX_PERMISSION_DENIED, "permission denied").await;
        });

        let mut sftp = SftpClient::init(client).await.expect("handshake");
        let err = sftp.list_dir("/root").await.expect_err("denied");
        let AppError::SftpStatus { code, path, message } = err else { panic!("expected a status error") };
        assert_eq!(code, wire::FX_PERMISSION_DENIED);
        assert_eq!(path, "/root");
        assert_eq!(message, "permission denied");
    }

    /// A short DATA reply is normal. Reading it as end-of-file would truncate
    /// downloads at the first chunk a server chose to shorten.
    #[tokio::test]
    async fn a_short_read_is_not_the_end_of_the_file() {
        let (client, mut server) = pair();
        tokio::spawn(async move {
            server.send_version().await;

            let (_, id, _) = server.read_request().await;
            server.send_data(id, b"hello ").await;
            let (_, id, _) = server.read_request().await;
            server.send_data(id, b"world").await;
            let (_, id, _) = server.read_request().await;
            server.send_status(id, wire::FX_EOF, "").await;
        });

        let mut sftp = SftpClient::init(client).await.expect("handshake");
        let handle = FileHandle(b"h".to_vec());
        let mut out = Vec::new();
        let mut offset = 0u64;
        loop {
            let n = sftp.read_chunk(&handle, offset, &mut out).await.expect("read");
            if n == 0 {
                break;
            }
            offset += n as u64;
        }
        assert_eq!(out, b"hello world");
    }

    /// "Nothing there" is an answer the overwrite check needs; "not allowed to
    /// look" is not the same answer and must stay an error.
    #[tokio::test]
    async fn try_stat_separates_a_missing_file_from_a_denied_one() {
        let (client, mut server) = pair();
        tokio::spawn(async move {
            server.send_version().await;
            let (_, id, _) = server.read_request().await;
            server.send_status(id, wire::FX_NO_SUCH_FILE, "").await;
            let (_, id, _) = server.read_request().await;
            server.send_status(id, wire::FX_PERMISSION_DENIED, "").await;
        });

        let mut sftp = SftpClient::init(client).await.expect("handshake");
        assert_eq!(sftp.try_stat("/nope").await.expect("missing is not an error"), None);
        assert!(sftp.try_stat("/root/secret").await.is_err(), "a denial is still an error");
    }

    /// A reply carrying someone else's id means the stream is desynced. Reading
    /// on would answer every later request with the wrong data, so it is fatal.
    #[tokio::test]
    async fn a_reply_with_the_wrong_id_is_fatal() {
        let (client, mut server) = pair();
        tokio::spawn(async move {
            server.send_version().await;
            let (_, id, _) = server.read_request().await;
            server.send_status(id.wrapping_add(9), wire::FX_OK, "").await;
        });

        let mut sftp = SftpClient::init(client).await.expect("handshake");
        let err = sftp.mkdir("/tmp/x").await.expect_err("desync");
        assert!(matches!(err, AppError::Sftp(_)));
    }

    /// A server that hangs up must produce an error, not a hang.
    #[tokio::test]
    async fn a_connection_dropped_mid_reply_errors_rather_than_hangs() {
        let (client, mut server) = pair();
        tokio::spawn(async move {
            server.send_version().await;
            let (_, _, _) = server.read_request().await;
            drop(server);
        });

        let mut sftp = SftpClient::init(client).await.expect("handshake");
        let err = sftp.realpath(".").await.expect_err("closed stream");
        assert!(matches!(err, AppError::Sftp(_)));
    }

    /// The frame length is attacker-controlled in the sense that matters: it
    /// arrives from the far end and is used to size an allocation.
    #[tokio::test]
    async fn an_absurd_packet_length_is_refused_before_allocating() {
        let (client, mut server) = pair();
        tokio::spawn(async move {
            server.send_version().await;
            let (_, _, _) = server.read_request().await;
            server.send(&(u32::MAX).to_be_bytes()).await;
        });

        let mut sftp = SftpClient::init(client).await.expect("handshake");
        let err = sftp.realpath(".").await.expect_err("impossible length");
        assert!(matches!(err, AppError::Sftp(_)));
    }

    #[tokio::test]
    async fn realpath_returns_the_servers_canonical_path() {
        let (client, mut server) = pair();
        tokio::spawn(async move {
            server.send_version().await;
            let (kind, id, _) = server.read_request().await;
            assert_eq!(kind, wire::FXP_REALPATH);
            server.send_names(id, &[("/home/emin", 0o040755, 0)]).await;
        });

        let mut sftp = SftpClient::init(client).await.expect("handshake");
        assert_eq!(sftp.realpath(".").await.expect("realpath"), "/home/emin");
    }
}
