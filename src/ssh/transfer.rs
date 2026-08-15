//! Planning and running file transfers in both directions.
//!
//! Knows `std::fs` and `SftpClient`; knows nothing about ratatui. The UI drives
//! it through one callback and can stop it by returning `ControlFlow::Break`.
//!
//! The work is split in two on purpose: **plan first, copy second**. Walking
//! the tree up front is what makes a real "12 of 47 files, 61%" possible, and
//! it is also where destination collisions are found — so by the time bytes
//! start moving, every question has already been asked. A prompt in the middle
//! of the copy loop would have to run while a `&mut SftpClient` is held over a
//! half-written file, which is where this feature goes wrong.

use std::io::{Read, Write};
use std::ops::ControlFlow;
use std::path::{Path, PathBuf};

use tokio::io::{AsyncRead, AsyncWrite};

use super::sftp::{FileKind, SftpClient};
use crate::error::{AppError, Result};

/// Bytes per read/write. The same 32 KiB the protocol layer uses, so a chunk
/// is exactly one round trip.
const CHUNK: usize = super::sftp::wire::CHUNK;

/// Suffix a transfer writes under before the final rename.
///
/// Nothing partial is ever left at the destination path: a truncated file that
/// looks complete is worse than no file at all, and a resumed-looking name is
/// the only honest way to say "this is not finished yet".
const PART_SUFFIX: &str = ".part";

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Direction {
    Upload,
    Download,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SkipReason {
    /// The user chose to keep the file that is already there.
    Exists,
    /// Symlinks are listed but never followed: a directory symlink can point
    /// back up its own tree, and detecting that needs identity information
    /// SFTP v3 does not provide.
    Symlink,
}

#[derive(Clone, Debug)]
pub struct TransferItem {
    pub src: String,
    pub dst: String,
    pub is_dir: bool,
    pub size: u64,
    /// Something already sits at `dst`. Answered before the copy starts.
    pub exists: bool,
    pub skip: Option<SkipReason>,
}

impl TransferItem {
    /// The name shown while this item is being copied — the destination's last
    /// component, which is what the user is watching appear.
    pub fn display_name(&self) -> &str {
        self.dst.rsplit('/').next().unwrap_or(&self.dst)
    }
}

#[derive(Clone, Debug, Default)]
pub struct TransferPlan {
    pub items: Vec<TransferItem>,
    pub total_bytes: u64,
}

impl TransferPlan {
    /// Indices of the files that would overwrite something. Directories are not
    /// conflicts: merging into an existing directory is the normal case.
    pub fn conflicts(&self) -> Vec<usize> {
        self.items
            .iter()
            .enumerate()
            .filter(|(_, item)| item.exists && !item.is_dir && item.skip.is_none())
            .map(|(i, _)| i)
            .collect()
    }

    /// Bytes that will actually move, once skips are decided.
    pub fn planned_bytes(&self) -> u64 {
        self.items.iter().filter(|i| i.skip.is_none() && !i.is_dir).map(|i| i.size).sum()
    }

    pub fn file_count(&self) -> usize {
        self.items.iter().filter(|i| i.skip.is_none() && !i.is_dir).count()
    }
}

#[derive(Clone, Debug)]
pub enum TransferEvent<'a> {
    /// Emitted while walking, before any byte moves.
    Scanning { files: usize, bytes: u64 },
    ItemStarted { index: usize, name: &'a str, size: u64 },
    Progress { done_bytes: u64 },
    ItemFinished { index: usize },
    ItemSkipped { index: usize, reason: SkipReason },
    ItemFailed { index: usize, name: &'a str, message: String },
}

#[derive(Clone, Debug, Default)]
pub struct TransferSummary {
    pub files: usize,
    pub bytes: u64,
    pub skipped: usize,
    pub failures: Vec<String>,
    pub cancelled: bool,
}

/// Walks what the user selected into a plan.
///
/// Directories are emitted before their contents, so creating them in order is
/// enough — nothing has to sort or look ahead.
pub async fn plan<S>(
    sftp: &mut SftpClient<S>,
    direction: Direction,
    sources: &[(String, bool)],
    dest_dir: &str,
    mut on_event: impl FnMut(TransferEvent) -> ControlFlow<()>,
) -> Result<TransferPlan>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut plan = TransferPlan::default();

    for (src, is_dir) in sources {
        let name = last_component(src);
        let dst = join(direction, dest_dir, name);
        if *is_dir {
            match direction {
                Direction::Upload => walk_local(sftp, src, &dst, &mut plan, &mut on_event).await?,
                Direction::Download => Box::pin(walk_remote(sftp, src, &dst, &mut plan, &mut on_event)).await?,
            }
        } else {
            let size = match direction {
                Direction::Upload => std::fs::metadata(src).map(|m| m.len()).unwrap_or(0),
                Direction::Download => sftp.stat(src).await.ok().and_then(|a| a.size).unwrap_or(0),
            };
            push_file(sftp, direction, src.clone(), dst, size, &mut plan, &mut on_event).await?;
        }
    }
    Ok(plan)
}

/// A local directory, and everything under it, as upload work.
async fn walk_local<S>(
    sftp: &mut SftpClient<S>,
    src: &str,
    dst: &str,
    plan: &mut TransferPlan,
    on_event: &mut impl FnMut(TransferEvent) -> ControlFlow<()>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // Iterative rather than recursive: an async recursive walk needs boxing at
    // every level, and the queue is clearer about the "directory before its
    // contents" ordering anyway.
    let mut queue = vec![(PathBuf::from(src), dst.to_string())];

    while let Some((dir, dst_dir)) = queue.pop() {
        plan.items.push(TransferItem {
            src: dir.to_string_lossy().into_owned(),
            dst: dst_dir.clone(),
            is_dir: true,
            size: 0,
            exists: false,
            skip: None,
        });

        let entries = match std::fs::read_dir(&dir) {
            Ok(entries) => entries,
            // A directory that cannot be read is reported as a failed item at
            // copy time rather than aborting the whole plan.
            Err(_) => continue,
        };

        for entry in entries.flatten() {
            let Some(name) = entry.file_name().to_str().map(|s| s.to_string()) else {
                // A name that cannot round-trip through UTF-8 would be
                // corrupted on the way out, so it is left alone entirely.
                continue;
            };
            let child_dst = format!("{dst_dir}/{name}");
            let meta = match entry.path().symlink_metadata() {
                Ok(meta) => meta,
                Err(_) => continue,
            };

            if meta.is_symlink() {
                plan.items.push(TransferItem {
                    src: entry.path().to_string_lossy().into_owned(),
                    dst: child_dst,
                    is_dir: false,
                    size: 0,
                    exists: false,
                    skip: Some(SkipReason::Symlink),
                });
            } else if meta.is_dir() {
                queue.push((entry.path(), child_dst));
            } else {
                push_file(
                    sftp,
                    Direction::Upload,
                    entry.path().to_string_lossy().into_owned(),
                    child_dst,
                    meta.len(),
                    plan,
                    on_event,
                )
                .await?;
            }
        }
    }
    Ok(())
}

/// A remote directory, and everything under it, as download work.
async fn walk_remote<S>(
    sftp: &mut SftpClient<S>,
    src: &str,
    dst: &str,
    plan: &mut TransferPlan,
    on_event: &mut impl FnMut(TransferEvent) -> ControlFlow<()>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut queue = vec![(src.to_string(), dst.to_string())];

    while let Some((dir, dst_dir)) = queue.pop() {
        plan.items.push(TransferItem {
            src: dir.clone(),
            dst: dst_dir.clone(),
            is_dir: true,
            size: 0,
            exists: false,
            skip: None,
        });

        let entries = match sftp.list_dir(&dir).await {
            Ok(entries) => entries,
            Err(_) => continue,
        };

        for entry in entries {
            let child_src = if dir.ends_with('/') { format!("{dir}{}", entry.name) } else { format!("{dir}/{}", entry.name) };
            let child_dst = format!("{dst_dir}/{}", entry.name);
            match entry.kind {
                FileKind::Dir => queue.push((child_src, child_dst)),
                FileKind::Symlink => plan.items.push(TransferItem {
                    src: child_src,
                    dst: child_dst,
                    is_dir: false,
                    size: 0,
                    exists: false,
                    skip: Some(SkipReason::Symlink),
                }),
                FileKind::File | FileKind::Other => {
                    push_file(sftp, Direction::Download, child_src, child_dst, entry.size, plan, on_event).await?;
                }
            }
        }
    }
    Ok(())
}

/// Adds one file to the plan, answering "is something already there?" while the
/// walk is the thing keeping the user waiting anyway.
async fn push_file<S>(
    sftp: &mut SftpClient<S>,
    direction: Direction,
    src: String,
    dst: String,
    size: u64,
    plan: &mut TransferPlan,
    on_event: &mut impl FnMut(TransferEvent) -> ControlFlow<()>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let exists = match direction {
        Direction::Upload => sftp.try_stat(&dst).await.unwrap_or(None).is_some(),
        Direction::Download => Path::new(&dst).exists(),
    };

    plan.total_bytes += size;
    plan.items.push(TransferItem { src, dst, is_dir: false, size, exists, skip: None });

    let files = plan.items.iter().filter(|i| !i.is_dir).count();
    if on_event(TransferEvent::Scanning { files, bytes: plan.total_bytes }).is_break() {
        return Err(AppError::Sftp("cancelled".into()));
    }
    Ok(())
}

/// Moves the bytes.
///
/// `on_event` returning `ControlFlow::Break` stops the run — that is how the UI
/// cancels, and it is checked after every chunk so a cancel lands within one
/// round trip rather than at the next file. A deliberate divergence from
/// `script_runner::run_script`, whose callback returns `()` and which therefore
/// cannot be interrupted at all.
pub async fn run<S>(
    sftp: &mut SftpClient<S>,
    direction: Direction,
    plan: &TransferPlan,
    mut on_event: impl FnMut(TransferEvent) -> ControlFlow<()>,
) -> TransferSummary
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut summary = TransferSummary::default();
    let mut done_bytes = 0u64;

    for (index, item) in plan.items.iter().enumerate() {
        if let Some(reason) = item.skip {
            summary.skipped += 1;
            if on_event(TransferEvent::ItemSkipped { index, reason }).is_break() {
                summary.cancelled = true;
                return summary;
            }
            continue;
        }

        if item.is_dir {
            if let Err(e) = ensure_dir(sftp, direction, &item.dst).await {
                summary.failures.push(format!("{}: {e}", item.display_name()));
                let name = item.display_name();
                if on_event(TransferEvent::ItemFailed { index, name, message: e.to_string() }).is_break() {
                    summary.cancelled = true;
                    return summary;
                }
            }
            continue;
        }

        if on_event(TransferEvent::ItemStarted { index, name: item.display_name(), size: item.size }).is_break() {
            summary.cancelled = true;
            return summary;
        }

        let outcome = copy_file(sftp, direction, item, &mut done_bytes, &mut on_event).await;
        match outcome {
            Ok(true) => {
                summary.files += 1;
                summary.bytes += item.size;
                if on_event(TransferEvent::ItemFinished { index }).is_break() {
                    summary.cancelled = true;
                    return summary;
                }
            }
            // Cancelled mid-file: the partial destination has already been
            // cleaned up by `copy_file`.
            Ok(false) => {
                summary.cancelled = true;
                return summary;
            }
            Err(e) => {
                // One unreadable file does not end the run — the rest of the
                // selection is still worth moving, and the summary says what
                // did not make it.
                summary.failures.push(format!("{}: {e}", item.display_name()));
                let name = item.display_name();
                if on_event(TransferEvent::ItemFailed { index, name, message: e.to_string() }).is_break() {
                    summary.cancelled = true;
                    return summary;
                }
            }
        }
    }
    summary
}

/// `Ok(false)` means the user cancelled; the partial file is gone by then.
async fn copy_file<S>(
    sftp: &mut SftpClient<S>,
    direction: Direction,
    item: &TransferItem,
    done_bytes: &mut u64,
    on_event: &mut impl FnMut(TransferEvent) -> ControlFlow<()>,
) -> Result<bool>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let part = format!("{}{PART_SUFFIX}", item.dst);

    let result = match direction {
        Direction::Upload => upload(sftp, &item.src, &part, done_bytes, on_event).await,
        Direction::Download => download(sftp, &item.src, &part, done_bytes, on_event).await,
    };

    match result {
        Ok(true) => {
            // v3 RENAME fails when the target exists, so an overwrite has to
            // remove first — done only now, with the replacement complete and
            // closed, so the window where neither file exists is microseconds.
            match direction {
                Direction::Upload => {
                    if item.exists {
                        let _ = sftp.remove(&item.dst).await;
                    }
                    sftp.rename(&part, &item.dst).await?;
                }
                Direction::Download => std::fs::rename(&part, &item.dst)?,
            }
            Ok(true)
        }
        Ok(false) => {
            cleanup(sftp, direction, &part).await;
            Ok(false)
        }
        Err(e) => {
            cleanup(sftp, direction, &part).await;
            Err(e)
        }
    }
}

async fn upload<S>(
    sftp: &mut SftpClient<S>,
    src: &str,
    part: &str,
    done_bytes: &mut u64,
    on_event: &mut impl FnMut(TransferEvent) -> ControlFlow<()>,
) -> Result<bool>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut file = std::fs::File::open(src)?;
    let handle = sftp.open_write(part).await?;
    let mut buf = vec![0u8; CHUNK];
    let mut offset = 0u64;

    loop {
        let read = file.read(&mut buf)?;
        if read == 0 {
            break;
        }
        sftp.write_chunk(&handle, offset, &buf[..read]).await?;
        offset += read as u64;
        *done_bytes += read as u64;
        if on_event(TransferEvent::Progress { done_bytes: *done_bytes }).is_break() {
            let _ = sftp.close(handle).await;
            return Ok(false);
        }
    }

    sftp.close(handle).await?;
    Ok(true)
}

async fn download<S>(
    sftp: &mut SftpClient<S>,
    src: &str,
    part: &str,
    done_bytes: &mut u64,
    on_event: &mut impl FnMut(TransferEvent) -> ControlFlow<()>,
) -> Result<bool>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let handle = sftp.open_read(src).await?;
    let mut file = std::fs::File::create(part)?;
    let mut buf = Vec::with_capacity(CHUNK);
    let mut offset = 0u64;

    loop {
        buf.clear();
        let read = sftp.read_chunk(&handle, offset, &mut buf).await?;
        if read == 0 {
            break;
        }
        file.write_all(&buf)?;
        offset += read as u64;
        *done_bytes += read as u64;
        if on_event(TransferEvent::Progress { done_bytes: *done_bytes }).is_break() {
            let _ = sftp.close(handle).await;
            return Ok(false);
        }
    }

    file.flush()?;
    sftp.close(handle).await?;
    Ok(true)
}

async fn cleanup<S>(sftp: &mut SftpClient<S>, direction: Direction, part: &str)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    match direction {
        Direction::Upload => {
            let _ = sftp.remove(part).await;
        }
        Direction::Download => {
            let _ = std::fs::remove_file(part);
        }
    }
}

/// Creates a destination directory, tolerating one that is already there.
///
/// v3 has no "already exists" status — an existing directory comes back as a
/// generic `FAILURE` — so the check is a stat first. "Create and ignore the
/// error" would swallow a permission denial here and surface it as a confusing
/// failure on the first child file instead.
async fn ensure_dir<S>(sftp: &mut SftpClient<S>, direction: Direction, dst: &str) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    match direction {
        Direction::Upload => match sftp.try_stat(dst).await? {
            Some(attrs) if attrs.file_kind() == Some(FileKind::Dir) => Ok(()),
            Some(_) => Err(AppError::Sftp(format!("{dst} exists and is not a directory"))),
            None => sftp.mkdir(dst).await,
        },
        Direction::Download => {
            let path = Path::new(dst);
            if path.is_dir() {
                return Ok(());
            }
            std::fs::create_dir_all(path).map_err(AppError::Io)
        }
    }
}

/// Joins a destination path. Remote paths are always `/`-separated; local ones
/// go through `Path` so the platform decides.
fn join(direction: Direction, dir: &str, name: &str) -> String {
    match direction {
        Direction::Upload => {
            if dir.ends_with('/') {
                format!("{dir}{name}")
            } else {
                format!("{dir}/{name}")
            }
        }
        Direction::Download => Path::new(dir).join(name).to_string_lossy().into_owned(),
    }
}

fn last_component(path: &str) -> &str {
    path.trim_end_matches('/').rsplit('/').next().unwrap_or(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_destination_name_comes_from_the_source() {
        assert_eq!(last_component("/srv/www/index.html"), "index.html");
        assert_eq!(last_component("/srv/www/"), "www");
        assert_eq!(last_component("plain"), "plain");
    }

    #[test]
    fn remote_destinations_never_double_their_separator() {
        assert_eq!(join(Direction::Upload, "/srv", "a"), "/srv/a");
        assert_eq!(join(Direction::Upload, "/", "a"), "/a");
    }

    fn item(dst: &str, is_dir: bool, size: u64, exists: bool) -> TransferItem {
        TransferItem { src: format!("/src/{dst}"), dst: dst.to_string(), is_dir, size, exists, skip: None }
    }

    /// Only files that would replace something are questions. Merging into an
    /// existing directory is the normal case and must not prompt.
    #[test]
    fn only_existing_files_count_as_conflicts() {
        let plan = TransferPlan {
            items: vec![
                item("dir", true, 0, true),
                item("a", false, 10, true),
                item("b", false, 20, false),
                TransferItem { skip: Some(SkipReason::Symlink), ..item("link", false, 0, true) },
            ],
            total_bytes: 30,
        };
        assert_eq!(plan.conflicts(), vec![1]);
    }

    /// The progress denominator has to be what will actually move, or a run
    /// with skips would stop at 60% and look stuck.
    #[test]
    fn planned_bytes_exclude_skipped_files_and_directories() {
        let mut plan = TransferPlan {
            items: vec![item("dir", true, 0, false), item("a", false, 10, false), item("b", false, 20, false)],
            total_bytes: 30,
        };
        assert_eq!(plan.planned_bytes(), 30);
        assert_eq!(plan.file_count(), 2);

        plan.items[1].skip = Some(SkipReason::Exists);
        assert_eq!(plan.planned_bytes(), 20);
        assert_eq!(plan.file_count(), 1);
    }

    #[test]
    fn the_displayed_name_is_the_destinations_last_component() {
        assert_eq!(item("/srv/www/index.html", false, 0, false).display_name(), "index.html");
    }

    /// A scripted sftp server backed by an in-memory file table, enough to run
    /// a real upload and a real download end to end — the byte loop, the
    /// `.part` rename and the overwrite removal included — with no ssh, no
    /// server process and no network.
    mod fake {
        use super::super::super::sftp::wire::{self, Cursor, Encoder};
        use std::collections::HashMap;
        use std::sync::{Arc, Mutex};
        use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

        pub type Files = Arc<Mutex<HashMap<String, Vec<u8>>>>;

        pub fn spawn(files: Files) -> DuplexStream {
            let (client, mut server) = tokio::io::duplex(1024 * 1024);
            tokio::spawn(async move {
                let mut handles: HashMap<Vec<u8>, String> = HashMap::new();
                let mut next_handle = 0u32;

                loop {
                    let mut len_buf = [0u8; 4];
                    if server.read_exact(&mut len_buf).await.is_err() {
                        return;
                    }
                    let len = u32::from_be_bytes(len_buf) as usize;
                    let mut body = vec![0u8; len];
                    if server.read_exact(&mut body).await.is_err() {
                        return;
                    }

                    let mut c = Cursor::new(&body);
                    let kind = c.u8().expect("type");
                    if kind == wire::FXP_INIT {
                        let mut e = Encoder::raw(wire::FXP_VERSION);
                        e.u32(3);
                        let _ = server.write_all(&e.finish()).await;
                        continue;
                    }
                    let id = c.u32().expect("id");

                    let reply = match kind {
                        wire::FXP_STAT | wire::FXP_LSTAT => {
                            let path = c.string().expect("path");
                            match files.lock().expect("lock").get(&path) {
                                Some(data) => {
                                    let mut e = Encoder::request(wire::FXP_ATTRS, id);
                                    e.u32(wire::ATTR_SIZE | wire::ATTR_PERMISSIONS);
                                    e.u64(data.len() as u64);
                                    e.u32(0o100644);
                                    e.finish()
                                }
                                None => status(id, wire::FX_NO_SUCH_FILE),
                            }
                        }
                        wire::FXP_OPEN => {
                            let path = c.string().expect("path");
                            let pflags = c.u32().expect("pflags");
                            next_handle += 1;
                            let handle = next_handle.to_be_bytes().to_vec();
                            handles.insert(handle.clone(), path.clone());
                            // Only a write truncates — opening the source of a
                            // download must leave its contents alone.
                            if pflags & wire::FXF_WRITE != 0 {
                                files.lock().expect("lock").entry(path).or_default().clear();
                            }
                            let mut e = Encoder::request(wire::FXP_HANDLE, id);
                            e.bytes(&handle);
                            e.finish()
                        }
                        wire::FXP_WRITE => {
                            let handle = c.bytes().expect("handle").to_vec();
                            let _offset = c.u64().expect("offset");
                            let data = c.bytes().expect("data").to_vec();
                            let path = handles.get(&handle).cloned().unwrap_or_default();
                            files.lock().expect("lock").entry(path).or_default().extend_from_slice(&data);
                            status(id, wire::FX_OK)
                        }
                        wire::FXP_READ => {
                            let handle = c.bytes().expect("handle").to_vec();
                            let offset = c.u64().expect("offset") as usize;
                            let len = c.u32().expect("len") as usize;
                            let path = handles.get(&handle).cloned().unwrap_or_default();
                            let files = files.lock().expect("lock");
                            let data = files.get(&path).cloned().unwrap_or_default();
                            if offset >= data.len() {
                                status(id, wire::FX_EOF)
                            } else {
                                let end = (offset + len).min(data.len());
                                let mut e = Encoder::request(wire::FXP_DATA, id);
                                e.bytes(&data[offset..end]);
                                e.finish()
                            }
                        }
                        wire::FXP_RENAME => {
                            let from = c.string().expect("from");
                            let to = c.string().expect("to");
                            let mut files = files.lock().expect("lock");
                            match files.remove(&from) {
                                // v3 RENAME refuses an existing target, which is
                                // why the client removes first.
                                Some(_) if files.contains_key(&to) => status(id, wire::FX_FAILURE),
                                Some(data) => {
                                    files.insert(to, data);
                                    status(id, wire::FX_OK)
                                }
                                None => status(id, wire::FX_NO_SUCH_FILE),
                            }
                        }
                        wire::FXP_REMOVE => {
                            let path = c.string().expect("path");
                            files.lock().expect("lock").remove(&path);
                            status(id, wire::FX_OK)
                        }
                        // OPENDIR is answered with a handle whose "path" is the
                        // directory; READDIR then reports EOF, since these
                        // tests never walk a remote tree.
                        wire::FXP_OPENDIR => {
                            let path = c.string().expect("path");
                            next_handle += 1;
                            let handle = next_handle.to_be_bytes().to_vec();
                            handles.insert(handle.clone(), path);
                            let mut e = Encoder::request(wire::FXP_HANDLE, id);
                            e.bytes(&handle);
                            e.finish()
                        }
                        wire::FXP_READDIR => status(id, wire::FX_EOF),
                        _ => status(id, wire::FX_OK),
                    };
                    let _ = server.write_all(&reply).await;
                }
            });
            client
        }

        fn status(id: u32, code: u32) -> Vec<u8> {
            let mut e = Encoder::request(wire::FXP_STATUS, id);
            e.u32(code);
            e.str("");
            e.finish()
        }
    }

    use crate::ssh::sftp::SftpClient;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    async fn client(files: fake::Files) -> SftpClient<tokio::io::DuplexStream> {
        SftpClient::init(fake::spawn(files)).await.expect("handshake")
    }

    fn no_cancel(_: TransferEvent) -> ControlFlow<()> {
        ControlFlow::Continue(())
    }

    /// The upload path end to end: the bytes arrive, and they arrive at the
    /// final name — never at the `.part` the transfer wrote under.
    #[tokio::test]
    async fn an_upload_lands_under_its_final_name() {
        let dir = tempfile::tempdir().expect("tempdir");
        let src = dir.path().join("hello.txt");
        // Larger than one chunk, so the loop is exercised rather than a single
        // write that would hide an offset bug.
        let content = vec![b'x'; CHUNK + 1234];
        std::fs::write(&src, &content).expect("write");

        let files: fake::Files = Arc::new(Mutex::new(HashMap::new()));
        let mut sftp = client(files.clone()).await;

        let sources = vec![(src.to_string_lossy().into_owned(), false)];
        let plan = plan(&mut sftp, Direction::Upload, &sources, "/srv", no_cancel).await.expect("plan");
        assert_eq!(plan.total_bytes, content.len() as u64);
        assert!(plan.conflicts().is_empty(), "nothing is there yet");

        let summary = run(&mut sftp, Direction::Upload, &plan, no_cancel).await;
        assert_eq!(summary.files, 1);
        assert!(summary.failures.is_empty());

        let files = files.lock().expect("lock");
        assert_eq!(files.get("/srv/hello.txt"), Some(&content));
        assert!(!files.contains_key("/srv/hello.txt.part"), "the partial name must not survive");
    }

    /// Download is the mirror image, and it must not leave a `.part` behind
    /// either.
    #[tokio::test]
    async fn a_download_writes_the_file_and_removes_the_partial() {
        let dir = tempfile::tempdir().expect("tempdir");
        let content = vec![b'y'; CHUNK * 2];

        let files: fake::Files = Arc::new(Mutex::new(HashMap::new()));
        files.lock().expect("lock").insert("/srv/data.bin".to_string(), content.clone());
        let mut sftp = client(files.clone()).await;

        let sources = vec![("/srv/data.bin".to_string(), false)];
        let dest = dir.path().to_string_lossy().into_owned();
        let plan = plan(&mut sftp, Direction::Download, &sources, &dest, no_cancel).await.expect("plan");

        let summary = run(&mut sftp, Direction::Download, &plan, no_cancel).await;
        assert_eq!(summary.files, 1);
        assert_eq!(std::fs::read(dir.path().join("data.bin")).expect("read"), content);
        assert!(!dir.path().join("data.bin.part").exists(), "the partial file is renamed, not left");
    }

    /// The point of the `.part` policy: a cancelled transfer leaves nothing at
    /// the destination that could be mistaken for a complete file.
    #[tokio::test]
    async fn a_cancelled_download_leaves_no_partial_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let files: fake::Files = Arc::new(Mutex::new(HashMap::new()));
        files.lock().expect("lock").insert("/srv/big.bin".to_string(), vec![b'z'; CHUNK * 8]);
        let mut sftp = client(files).await;

        let sources = vec![("/srv/big.bin".to_string(), false)];
        let dest = dir.path().to_string_lossy().into_owned();
        let plan = plan(&mut sftp, Direction::Download, &sources, &dest, no_cancel).await.expect("plan");

        // Break on the first chunk of progress, the way Esc would.
        let summary = run(&mut sftp, Direction::Download, &plan, |event| match event {
            TransferEvent::Progress { .. } => ControlFlow::Break(()),
            _ => ControlFlow::Continue(()),
        })
        .await;

        assert!(summary.cancelled);
        assert_eq!(summary.files, 0);
        assert!(!dir.path().join("big.bin").exists());
        assert!(!dir.path().join("big.bin.part").exists(), "the partial write is cleaned up");
    }

    /// An existing destination is found during the walk, so the prompt happens
    /// before any byte moves.
    #[tokio::test]
    async fn an_existing_destination_is_reported_as_a_conflict() {
        let dir = tempfile::tempdir().expect("tempdir");
        let src = dir.path().join("conf.yml");
        std::fs::write(&src, b"new").expect("write");

        let files: fake::Files = Arc::new(Mutex::new(HashMap::new()));
        files.lock().expect("lock").insert("/srv/conf.yml".to_string(), b"old".to_vec());
        let mut sftp = client(files.clone()).await;

        let sources = vec![(src.to_string_lossy().into_owned(), false)];
        let mut plan = plan(&mut sftp, Direction::Upload, &sources, "/srv", no_cancel).await.expect("plan");
        assert_eq!(plan.conflicts(), vec![0]);

        // Choosing "skip" leaves what was already there untouched.
        plan.items[0].skip = Some(SkipReason::Exists);
        let summary = run(&mut sftp, Direction::Upload, &plan, no_cancel).await;
        assert_eq!(summary.skipped, 1);
        assert_eq!(files.lock().expect("lock").get("/srv/conf.yml"), Some(&b"old".to_vec()));
    }

    /// And choosing to overwrite really does replace it — v3 RENAME refuses an
    /// existing target, so this is the path that needs the remove first.
    #[tokio::test]
    async fn overwriting_replaces_the_file_that_was_there() {
        let dir = tempfile::tempdir().expect("tempdir");
        let src = dir.path().join("conf.yml");
        std::fs::write(&src, b"new").expect("write");

        let files: fake::Files = Arc::new(Mutex::new(HashMap::new()));
        files.lock().expect("lock").insert("/srv/conf.yml".to_string(), b"old".to_vec());
        let mut sftp = client(files.clone()).await;

        let sources = vec![(src.to_string_lossy().into_owned(), false)];
        let plan = plan(&mut sftp, Direction::Upload, &sources, "/srv", no_cancel).await.expect("plan");
        let summary = run(&mut sftp, Direction::Upload, &plan, no_cancel).await;

        assert_eq!(summary.files, 1);
        assert_eq!(files.lock().expect("lock").get("/srv/conf.yml"), Some(&b"new".to_vec()));
    }

    /// A whole directory, with a nested one inside it: directories are emitted
    /// before their contents so creating them in order is enough, and symlinks
    /// are listed as skips rather than followed.
    #[tokio::test]
    async fn a_directory_upload_walks_its_whole_tree() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("site");
        std::fs::create_dir_all(root.join("assets")).expect("mkdir");
        std::fs::write(root.join("index.html"), b"<html>").expect("write");
        std::fs::write(root.join("assets/app.js"), b"console.log(1)").expect("write");
        #[cfg(unix)]
        std::os::unix::fs::symlink(root.join("index.html"), root.join("link.html")).expect("symlink");

        let files: fake::Files = Arc::new(Mutex::new(HashMap::new()));
        let mut sftp = client(files.clone()).await;

        let sources = vec![(root.to_string_lossy().into_owned(), true)];
        let plan = plan(&mut sftp, Direction::Upload, &sources, "/srv", no_cancel).await.expect("plan");

        let dirs: Vec<&str> = plan.items.iter().filter(|i| i.is_dir).map(|i| i.dst.as_str()).collect();
        assert!(dirs.contains(&"/srv/site"));
        assert!(dirs.contains(&"/srv/site/assets"));
        let first_file = plan.items.iter().position(|i| !i.is_dir).expect("a file");
        assert!(plan.items[..first_file].iter().any(|i| i.is_dir), "directories come before their contents");
        assert!(plan.items.iter().any(|i| i.skip == Some(SkipReason::Symlink)), "the symlink is a skip");

        let summary = run(&mut sftp, Direction::Upload, &plan, no_cancel).await;
        assert_eq!(summary.files, 2);
        let files = files.lock().expect("lock");
        assert_eq!(files.get("/srv/site/index.html"), Some(&b"<html>".to_vec()));
        assert_eq!(files.get("/srv/site/assets/app.js"), Some(&b"console.log(1)".to_vec()));
    }
}
