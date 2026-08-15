//! SFTP protocol version 3 packet encoding and decoding.
//!
//! Pure data: no I/O, no async, nothing from russh. Everything that can be
//! got wrong about the wire format is decided here and unit-tested here, which
//! is why `client.rs` above it reads as plain request/reply.
//!
//! Two rules hold throughout:
//!
//! - **The decoder never slices directly.** Every read goes through `Cursor`,
//!   which returns `Err` on a short buffer. A truncated or hostile packet has
//!   to be an error, never a panic — this runs against whatever the server
//!   sends.
//! - **Unknown trailing data is consumed, not ignored.** An `ATTRS` extended
//!   block sits in the middle of a `NAME` entry, so skipping it desyncs every
//!   following entry rather than merely losing a field.

use crate::error::{AppError, Result};

// Requests.
pub const FXP_INIT: u8 = 1;
pub const FXP_OPEN: u8 = 3;
pub const FXP_CLOSE: u8 = 4;
pub const FXP_READ: u8 = 5;
pub const FXP_WRITE: u8 = 6;
pub const FXP_LSTAT: u8 = 7;
pub const FXP_OPENDIR: u8 = 11;
pub const FXP_READDIR: u8 = 12;
pub const FXP_REMOVE: u8 = 13;
pub const FXP_MKDIR: u8 = 14;
pub const FXP_REALPATH: u8 = 16;
pub const FXP_STAT: u8 = 17;
pub const FXP_RENAME: u8 = 18;

// Replies.
pub const FXP_VERSION: u8 = 2;
pub const FXP_STATUS: u8 = 101;
pub const FXP_HANDLE: u8 = 102;
pub const FXP_DATA: u8 = 103;
pub const FXP_NAME: u8 = 104;
pub const FXP_ATTRS: u8 = 105;

// Status codes.
pub const FX_OK: u32 = 0;
pub const FX_EOF: u32 = 1;
pub const FX_NO_SUCH_FILE: u32 = 2;
pub const FX_PERMISSION_DENIED: u32 = 3;
pub const FX_NO_CONNECTION: u32 = 6;
pub const FX_CONNECTION_LOST: u32 = 7;

// OPEN pflags.
pub const FXF_READ: u32 = 0x0000_0001;
pub const FXF_WRITE: u32 = 0x0000_0002;
pub const FXF_CREAT: u32 = 0x0000_0008;
pub const FXF_TRUNC: u32 = 0x0000_0010;

// ATTRS flags.
pub const ATTR_SIZE: u32 = 0x0000_0001;
pub const ATTR_UIDGID: u32 = 0x0000_0002;
pub const ATTR_PERMISSIONS: u32 = 0x0000_0004;
pub const ATTR_ACMODTIME: u32 = 0x0000_0008;
pub const ATTR_EXTENDED: u32 = 0x8000_0000;

/// The protocol version this client speaks. Version 3 is the one every server
/// in practice implements; a server offering less is refused rather than
/// worked around.
pub const VERSION: u32 = 3;

/// Payload bytes per READ/WRITE. 32 KiB is what fits inside the 34000-byte
/// packet limit every server accepts — larger reads are silently clamped by
/// some servers and rejected outright by others.
pub const CHUNK: usize = 32 * 1024;

/// Hard ceiling on a declared frame length, checked *before* allocating.
///
/// The length arrives from the network. Without this, a desynced stream or a
/// hostile server could make us reserve a gigabyte off one bad u32 — the same
/// reasoning as `config::format::check_kdf_params`, which bounds costs before
/// deriving rather than after.
pub const MAX_PACKET: usize = 256 * 1024;

fn corrupt(what: &str) -> AppError {
    AppError::Sftp(format!("malformed {what} from server"))
}

/// A bounds-checked reader over one packet's payload.
pub struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.pos.checked_add(n).ok_or_else(|| corrupt("packet"))?;
        let slice = self.buf.get(self.pos..end).ok_or_else(|| corrupt("packet"))?;
        self.pos = end;
        Ok(slice)
    }

    pub fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    pub fn u32(&mut self) -> Result<u32> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub fn u64(&mut self) -> Result<u64> {
        let b = self.take(8)?;
        Ok(u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
    }

    /// An SSH string: `u32 len` then that many raw bytes. Deliberately bytes,
    /// not `String` — filenames on a unix server are not required to be UTF-8,
    /// and pretending otherwise here would corrupt them before anything higher
    /// up got the chance to decide what to do about it.
    pub fn bytes(&mut self) -> Result<&'a [u8]> {
        let len = self.u32()? as usize;
        self.take(len)
    }

    /// A string that is meant to be text (a path the server echoed back, an
    /// error message). Lossy on purpose: an unprintable byte in an error
    /// message must not turn the error into a different error.
    pub fn string(&mut self) -> Result<String> {
        Ok(String::from_utf8_lossy(self.bytes()?).into_owned())
    }
}

/// Builds a packet body. The frame header (length and type) is added by
/// `finish`, so no caller has to remember that the length covers the type byte.
pub struct Encoder {
    buf: Vec<u8>,
}

impl Encoder {
    /// A request: type byte, then the request id every reply echoes.
    pub fn request(kind: u8, id: u32) -> Self {
        let mut e = Self { buf: vec![kind] };
        e.u32(id);
        e
    }

    /// A packet with neither an id nor a version — only `VERSION`, which the
    /// fake server in `client.rs`'s tests has to be able to send.
    #[cfg(test)]
    pub fn raw(kind: u8) -> Self {
        Self { buf: vec![kind] }
    }

    /// `INIT` has no request id — it is the one packet sent before ids exist.
    /// The same is true of the `VERSION` reply, and mixing them up shifts every
    /// later field by four bytes, which is the classic first bug here.
    pub fn init() -> Self {
        let mut e = Self { buf: vec![FXP_INIT] };
        e.u32(VERSION);
        e
    }

    pub fn u32(&mut self, v: u32) -> &mut Self {
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }

    pub fn u64(&mut self, v: u64) -> &mut Self {
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }

    pub fn bytes(&mut self, v: &[u8]) -> &mut Self {
        self.u32(v.len() as u32);
        self.buf.extend_from_slice(v);
        self
    }

    pub fn str(&mut self, v: &str) -> &mut Self {
        self.bytes(v.as_bytes())
    }

    /// An empty attribute set — "I am not asking you to change anything".
    pub fn empty_attrs(&mut self) -> &mut Self {
        self.u32(0)
    }

    pub fn finish(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.buf.len() + 4);
        out.extend_from_slice(&(self.buf.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.buf);
        out
    }
}

/// The attributes a v3 server may send. Every field is optional because the
/// flags word says which were included, and servers differ on what they bother
/// to send — notably in `READDIR` replies.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Attrs {
    pub size: Option<u64>,
    pub permissions: Option<u32>,
    pub mtime: Option<u32>,
}

impl Attrs {
    pub fn decode(c: &mut Cursor) -> Result<Self> {
        let flags = c.u32()?;
        let mut attrs = Attrs::default();

        if flags & ATTR_SIZE != 0 {
            attrs.size = Some(c.u64()?);
        }
        if flags & ATTR_UIDGID != 0 {
            let _uid = c.u32()?;
            let _gid = c.u32()?;
        }
        if flags & ATTR_PERMISSIONS != 0 {
            attrs.permissions = Some(c.u32()?);
        }
        if flags & ATTR_ACMODTIME != 0 {
            let _atime = c.u32()?;
            attrs.mtime = Some(c.u32()?);
        }
        // Consumed, not skipped: in a NAME reply the next entry starts right
        // after this block, so leaving it in the buffer misreads every
        // remaining name rather than merely dropping an extension.
        if flags & ATTR_EXTENDED != 0 {
            let count = c.u32()?;
            for _ in 0..count {
                let _type = c.bytes()?;
                let _data = c.bytes()?;
            }
        }
        Ok(attrs)
    }

    /// The file type bits of a unix mode, when the server sent permissions.
    pub fn file_kind(&self) -> Option<FileKind> {
        self.permissions.map(|p| match p & 0o170000 {
            0o040000 => FileKind::Dir,
            0o120000 => FileKind::Symlink,
            0o100000 => FileKind::File,
            _ => FileKind::Other,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileKind {
    Dir,
    File,
    Symlink,
    Other,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NameEntry {
    pub filename: String,
    /// The `ls -l`-style line v3 requires. Kept because it is the only way to
    /// tell a directory from a file when the server omits permissions, which
    /// several non-OpenSSH servers do in `READDIR`.
    pub longname: String,
    pub attrs: Attrs,
}

impl NameEntry {
    pub fn kind(&self) -> FileKind {
        if let Some(kind) = self.attrs.file_kind() {
            return kind;
        }
        match self.longname.as_bytes().first() {
            Some(b'd') => FileKind::Dir,
            Some(b'l') => FileKind::Symlink,
            Some(b'-') => FileKind::File,
            _ => FileKind::Other,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reply {
    Version(u32),
    Status { code: u32, message: String },
    Handle(Vec<u8>),
    Data(Vec<u8>),
    Name(Vec<NameEntry>),
    Attrs(Attrs),
}

impl Reply {
    /// Decodes one packet body (everything after the length prefix).
    ///
    /// Returns the request id alongside, or `None` for `VERSION`, which is the
    /// only reply that carries no id.
    pub fn decode(body: &[u8]) -> Result<(Option<u32>, Reply)> {
        let mut c = Cursor::new(body);
        let kind = c.u8()?;

        if kind == FXP_VERSION {
            // Extension pairs may follow to the end of the packet; nothing here
            // needs them, and unlike an ATTRS block they are trailing, so
            // leaving them unread cannot desync anything.
            return Ok((None, Reply::Version(c.u32()?)));
        }

        let id = c.u32()?;
        let reply = match kind {
            FXP_STATUS => {
                let code = c.u32()?;
                // v3 always sends message and language, but a short packet from
                // a sloppy server should degrade to an empty message rather
                // than to "malformed".
                let message = if c.remaining() > 0 { c.string()? } else { String::new() };
                Reply::Status { code, message }
            }
            FXP_HANDLE => Reply::Handle(c.bytes()?.to_vec()),
            FXP_DATA => Reply::Data(c.bytes()?.to_vec()),
            FXP_NAME => {
                let count = c.u32()? as usize;
                let mut entries = Vec::with_capacity(count.min(1024));
                for _ in 0..count {
                    let filename = c.string()?;
                    let longname = c.string()?;
                    let attrs = Attrs::decode(&mut c)?;
                    entries.push(NameEntry { filename, longname, attrs });
                }
                Reply::Name(entries)
            }
            FXP_ATTRS => Reply::Attrs(Attrs::decode(&mut c)?),
            other => return Err(AppError::Sftp(format!("unexpected packet type {other} from server"))),
        };
        Ok((Some(id), reply))
    }
}

/// Turns a non-OK status into the error the screens react to.
pub fn status_error(path: &str, code: u32, message: String) -> AppError {
    let message = if message.is_empty() { default_status_message(code) } else { message };
    AppError::SftpStatus { code, path: path.to_string(), message }
}

fn default_status_message(code: u32) -> String {
    match code {
        FX_NO_SUCH_FILE => "no such file or directory".to_string(),
        FX_PERMISSION_DENIED => "permission denied".to_string(),
        FX_NO_CONNECTION | FX_CONNECTION_LOST => "connection lost".to_string(),
        other => format!("server error {other}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Frames the way `client.rs` does, so the tests exercise the same bytes
    /// that go on the wire.
    fn body_of(packet: &[u8]) -> &[u8] {
        let len = u32::from_be_bytes([packet[0], packet[1], packet[2], packet[3]]) as usize;
        assert_eq!(len, packet.len() - 4, "the length prefix covers everything after itself");
        &packet[4..]
    }

    /// The length counts the type byte and the id, but not itself. An
    /// off-by-four here breaks every packet.
    #[test]
    fn the_length_prefix_covers_the_type_byte() {
        let packet = Encoder::request(FXP_STAT, 7).str("/tmp").finish();
        // 1 type + 4 id + 4 length-of-string + 4 bytes.
        assert_eq!(packet.len(), 4 + 13);
        assert_eq!(body_of(&packet).len(), 13);
    }

    /// INIT carries a version and nothing else — no request id. Encoding one
    /// shifts every field of the reply by four bytes.
    #[test]
    fn init_has_no_request_id() {
        let packet = Encoder::init().finish();
        let body = body_of(&packet);
        assert_eq!(body[0], FXP_INIT);
        assert_eq!(u32::from_be_bytes([body[1], body[2], body[3], body[4]]), VERSION);
        assert_eq!(body.len(), 5);
    }

    /// And the VERSION reply likewise, which is why `decode` returns an
    /// `Option<u32>` id rather than a `u32`.
    #[test]
    fn version_decodes_without_an_id_and_ignores_extensions() {
        let mut e = Encoder { buf: vec![FXP_VERSION] };
        e.u32(3);
        e.str("posix-rename@openssh.com");
        e.str("1");
        let packet = e.finish();

        let (id, reply) = Reply::decode(body_of(&packet)).expect("decodes");
        assert_eq!(id, None);
        assert_eq!(reply, Reply::Version(3));
    }

    fn encode_name(entries: &[(&str, &str, Attrs)]) -> Vec<u8> {
        let mut e = Encoder::request(FXP_NAME, 42);
        e.u32(entries.len() as u32);
        for (filename, longname, attrs) in entries {
            e.str(filename);
            e.str(longname);
            let mut flags = 0;
            if attrs.size.is_some() {
                flags |= ATTR_SIZE;
            }
            if attrs.permissions.is_some() {
                flags |= ATTR_PERMISSIONS;
            }
            if attrs.mtime.is_some() {
                flags |= ATTR_ACMODTIME;
            }
            e.u32(flags);
            if let Some(size) = attrs.size {
                e.u64(size);
            }
            if let Some(perms) = attrs.permissions {
                e.u32(perms);
            }
            if let Some(mtime) = attrs.mtime {
                e.u32(0);
                e.u32(mtime);
            }
        }
        e.finish()
    }

    #[test]
    fn a_name_reply_round_trips_every_entry() {
        let dir = Attrs { size: None, permissions: Some(0o040755), mtime: Some(100) };
        let file = Attrs { size: Some(4096), permissions: Some(0o100644), mtime: None };
        let packet = encode_name(&[("etc", "drwxr-xr-x 1 root root", dir), ("hosts", "-rw-r--r-- 1 root root", file)]);

        let (id, reply) = Reply::decode(body_of(&packet)).expect("decodes");
        assert_eq!(id, Some(42));
        let Reply::Name(entries) = reply else { panic!("expected NAME") };
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].filename, "etc");
        assert_eq!(entries[0].kind(), FileKind::Dir);
        assert_eq!(entries[1].attrs.size, Some(4096));
        assert_eq!(entries[1].kind(), FileKind::File);
    }

    /// The extended block sits *between* two entries. Failing to consume it
    /// does not lose a field, it misreads every name after it.
    #[test]
    fn an_extended_attribute_block_is_consumed_so_the_next_entry_still_parses() {
        let mut e = Encoder::request(FXP_NAME, 1);
        e.u32(2);
        e.str("first");
        e.str("-rw-r--r--");
        e.u32(ATTR_SIZE | ATTR_EXTENDED);
        e.u64(10);
        e.u32(1);
        e.str("acl@example.com");
        e.str("whatever");
        e.str("second");
        e.str("-rw-r--r--");
        e.u32(ATTR_SIZE);
        e.u64(20);
        let packet = e.finish();

        let (_, reply) = Reply::decode(body_of(&packet)).expect("decodes");
        let Reply::Name(entries) = reply else { panic!("expected NAME") };
        assert_eq!(entries[1].filename, "second", "the second entry must survive the extended block");
        assert_eq!(entries[1].attrs.size, Some(20));
    }

    /// A server that sends no permissions in READDIR still has to be told apart
    /// from a file, and the longname is the only thing left to go on.
    #[test]
    fn a_directory_is_recognised_from_the_longname_when_permissions_are_missing() {
        let entry = NameEntry {
            filename: "logs".to_string(),
            longname: "drwxr-xr-x 2 root root 4096 Jan 1 00:00 logs".to_string(),
            attrs: Attrs::default(),
        };
        assert_eq!(entry.kind(), FileKind::Dir);

        let link = NameEntry { longname: "lrwxrwxrwx 1 root root".to_string(), ..entry.clone() };
        assert_eq!(link.kind(), FileKind::Symlink);

        let unknown = NameEntry { longname: String::new(), ..entry };
        assert_eq!(unknown.kind(), FileKind::Other);
    }

    /// Permissions win when both are available — the longname is the fallback,
    /// not the source of truth.
    #[test]
    fn permissions_take_precedence_over_the_longname() {
        let entry = NameEntry {
            filename: "x".to_string(),
            longname: "-rw-r--r-- 1 root root".to_string(),
            attrs: Attrs { permissions: Some(0o040755), ..Attrs::default() },
        };
        assert_eq!(entry.kind(), FileKind::Dir);
    }

    /// Every short read has to come back as an error. A panic here is a panic
    /// on whatever the network sent.
    #[test]
    fn a_truncated_packet_is_an_error_not_a_panic() {
        let packet = encode_name(&[("etc", "drwxr-xr-x", Attrs { size: Some(1), ..Attrs::default() })]);
        let body = body_of(&packet);

        for cut in 1..body.len() {
            // Every prefix either decodes (if it happens to be complete) or
            // errors — never panics.
            let _ = Reply::decode(&body[..cut]);
        }
        assert!(Reply::decode(&body[..body.len() - 1]).is_err(), "a packet missing its tail is malformed");
        assert!(Reply::decode(&[]).is_err(), "an empty packet has not even a type byte");
    }

    #[test]
    fn a_status_without_a_message_still_decodes() {
        let mut e = Encoder::request(FXP_STATUS, 9);
        e.u32(FX_EOF);
        let packet = e.finish();

        let (id, reply) = Reply::decode(body_of(&packet)).expect("decodes");
        assert_eq!(id, Some(9));
        assert_eq!(reply, Reply::Status { code: FX_EOF, message: String::new() });
    }

    #[test]
    fn an_unknown_packet_type_is_refused() {
        let mut e = Encoder { buf: vec![200] };
        e.u32(1);
        assert!(Reply::decode(body_of(&e.finish())).is_err());
    }

    /// Filenames are bytes on the wire. Decoding is lossy for display, but it
    /// must not fail — a file with an odd name still has to appear in the list.
    #[test]
    fn a_non_utf8_filename_decodes_lossily_rather_than_failing() {
        let mut e = Encoder::request(FXP_NAME, 3);
        e.u32(1);
        e.bytes(&[0xff, 0xfe, b'a']);
        e.str("-rw-r--r--");
        e.u32(0);
        let packet = e.finish();

        let (_, reply) = Reply::decode(body_of(&packet)).expect("decodes");
        let Reply::Name(entries) = reply else { panic!("expected NAME") };
        assert!(entries[0].filename.contains('\u{fffd}'), "invalid bytes become replacement characters");
    }

    /// An empty message is filled in, a server-supplied one is kept — the
    /// screen shows whichever is more useful.
    #[test]
    fn a_status_error_always_carries_something_readable() {
        let AppError::SftpStatus { message, .. } = status_error("/x", FX_PERMISSION_DENIED, String::new()) else {
            panic!("expected SftpStatus");
        };
        assert_eq!(message, "permission denied");

        let AppError::SftpStatus { message, .. } = status_error("/x", FX_PERMISSION_DENIED, "nope".to_string()) else {
            panic!("expected SftpStatus");
        };
        assert_eq!(message, "nope");
    }
}
