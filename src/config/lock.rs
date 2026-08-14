//! A whole-vault advisory lock, so two running instances cannot clobber each
//! other.
//!
//! Every save rewrites the entire envelope from the `Config` that instance
//! holds in memory (`ConfigStore::save`), which makes concurrent instances
//! last-writer-wins: add a server in one, save in the other, and the first edit
//! is gone with nothing to show for it. The lock makes that impossible by
//! letting only one instance hold an open vault at a time.
//!
//! **It is an advisory lock on a sibling file, not on the vault itself.** Both
//! halves of that matter. `flock` is released by the kernel when the process
//! dies, so a crash or a `kill -9` cannot strand the lock the way a marker file
//! would. And it has to be a *sibling*: the vault is replaced by a rename on
//! every save, so a descriptor held on `config.enc` would end up pinning an
//! unlinked inode that no later instance could ever contend with.

use std::fs::{File, OpenOptions};
use std::path::Path;

use crate::error::{AppError, Result};

/// Holds the vault lock for as long as it lives.
///
/// Acquired the first time a vault is actually opened rather than at startup:
/// an instance sitting on the password screen holds no decrypted config and so
/// can clobber nothing. Once taken it is kept until the process exits — in
/// particular the idle auto-lock does *not* release it, because handing the
/// vault to another instance while the user is still sitting in front of this
/// one would only move the surprise somewhere else.
#[derive(Default)]
pub struct VaultLock {
    /// `None` until the first successful acquisition. Dropping the `File`
    /// closes the descriptor, which is what releases the lock.
    held: std::cell::RefCell<Option<File>>,
}

impl VaultLock {
    pub fn new() -> Self {
        Self::default()
    }

    /// Takes the lock, or reports that another instance already has it.
    ///
    /// Idempotent: calling it again once held is a no-op, so every path that
    /// opens a vault can call it without tracking whether some earlier path
    /// already did.
    pub fn acquire(&self, lock_path: &Path) -> Result<()> {
        if self.held.borrow().is_some() {
            return Ok(());
        }

        if let Some(parent) = lock_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        // Never truncates: the file's contents are irrelevant — only the
        // descriptor carries the lock — and truncating would be a pointless
        // write to a file another instance may hold.
        let file = OpenOptions::new().read(true).write(true).create(true).truncate(false).open(lock_path)?;

        take_exclusive(&file)?;
        *self.held.borrow_mut() = Some(file);
        Ok(())
    }

    #[cfg(test)]
    fn is_held(&self) -> bool {
        self.held.borrow().is_some()
    }

    /// Releases the lock. Only used by the tests — the real lifecycle is "held
    /// until the process exits", which the `File`'s own drop takes care of.
    #[cfg(test)]
    fn release(&self) {
        *self.held.borrow_mut() = None;
    }
}

fn take_exclusive(file: &File) -> Result<()> {
    use rustix::fs::{FlockOperation, flock};

    match flock(file, FlockOperation::NonBlockingLockExclusive) {
        Ok(()) => Ok(()),
        // The one error that is not a failure: somebody else is running.
        Err(e) if e == rustix::io::Errno::WOULDBLOCK => Err(AppError::VaultInUse),
        Err(e) => Err(AppError::Io(std::io::Error::from(e))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lock_path(dir: &tempfile::TempDir) -> std::path::PathBuf {
        dir.path().join("config.enc.lock")
    }

    #[test]
    fn a_second_instance_cannot_take_a_held_lock() {
        let dir = tempfile::tempdir().unwrap();
        let path = lock_path(&dir);

        let first = VaultLock::new();
        first.acquire(&path).expect("an uncontended lock should be granted");

        let second = VaultLock::new();
        assert!(matches!(second.acquire(&path), Err(AppError::VaultInUse)));
    }

    #[test]
    fn releasing_hands_the_lock_to_the_next_instance() {
        let dir = tempfile::tempdir().unwrap();
        let path = lock_path(&dir);

        let first = VaultLock::new();
        first.acquire(&path).unwrap();
        first.release();

        let second = VaultLock::new();
        second.acquire(&path).expect("a released lock should be available again");
    }

    /// Every path that opens a vault calls `acquire`, so it has to be safe to
    /// call on an instance that already holds it.
    #[test]
    fn acquiring_twice_from_the_same_instance_is_a_no_op() {
        let dir = tempfile::tempdir().unwrap();
        let path = lock_path(&dir);

        let lock = VaultLock::new();
        lock.acquire(&path).unwrap();
        lock.acquire(&path).expect("re-acquiring what we already hold must succeed");
        assert!(lock.is_held());
    }

    /// The lock file is created on demand — on a first run the config directory
    /// does not exist yet when the setup screen writes the first vault.
    #[test]
    fn the_lock_file_is_created_along_with_its_directory() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("not-yet").join("config.enc.lock");

        VaultLock::new().acquire(&path).expect("acquire should create what it needs");
        assert!(path.exists());
    }
}
