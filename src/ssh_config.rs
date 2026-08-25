//! Reading OpenSSH's own `~/.ssh/config`, so a populated one does not have to
//! be retyped into the server form a host at a time.
//!
//! This is a *reader*. Nothing here ever writes to `~/.ssh/config`, and nothing
//! here ever opens an `IdentityFile` — an imported entry points at the key path
//! the user already had, and the key stays where OpenSSH keeps it.
//!
//! It sits at the crate root rather than under `ssh/` for the same reason
//! `session.rs` does: `ssh/` is russh wrappers, and this module knows nothing
//! about a connection. It parses a text file.
//!
//! **The parser is hand-written on purpose.** The subset that matters is five
//! keywords, and this is a tool whose dependency list is deliberately short —
//! a crate parsing a file that names the user's private keys is not a small
//! thing to add.

use std::path::PathBuf;

/// One `Host` block, already resolved against the wildcard defaults.
///
/// Deliberately not a `ServerEntry`: this is what the file said, and the
/// import screen is what decides which of them become vault entries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SshConfigHost {
    /// The `Host` pattern. Becomes the server's name — it is what the user
    /// types after `ssh`, so it is the name they already know the host by.
    pub alias: String,
    /// `HostName`, falling back to the alias. That fallback is OpenSSH's own:
    /// a block with no `HostName` connects to its alias.
    pub hostname: String,
    pub user: Option<String>,
    pub port: Option<u16>,
    /// `IdentityFile`, with a leading `~` expanded. Never opened.
    pub identity_file: Option<String>,
}

impl SshConfigHost {
    /// The username to connect as.
    ///
    /// A block with no `User` connects as whoever is running `ssh`, so that is
    /// the fallback here too. It lives on the type rather than at the import
    /// call site so the row the user reads and the entry that gets written
    /// cannot disagree about who they are about to log in as.
    pub fn username(&self) -> String {
        self.user.clone().unwrap_or_else(local_user)
    }
}

/// The account `ssh` would use with no `User` line. `"root"` is a last resort
/// for an environment with no `USER` at all — the form's own default, and
/// visible on the row before anything is imported.
fn local_user() -> String {
    std::env::var("USER").ok().filter(|u| !u.is_empty()).unwrap_or_else(|| "root".to_string())
}

/// `$HOME/.ssh/config`, or `None` when there is no home directory to look in.
pub fn default_path() -> Option<PathBuf> {
    home_dir().map(|home| home.join(".ssh").join("config"))
}

fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME").filter(|h| !h.is_empty()).map(PathBuf::from)
}

/// Settings that apply to every block, gathered from `Host *`.
#[derive(Default)]
struct Defaults {
    user: Option<String>,
    port: Option<u16>,
    identity_file: Option<String>,
}

/// Which kind of block the parser is currently inside.
enum Block {
    /// Before the first `Host` line. OpenSSH allows settings here; they apply
    /// to everything, so they are treated exactly like `Host *`.
    Preamble,
    /// A real host, being accumulated.
    Host(SshConfigHost),
    /// `Host *` — its settings become defaults rather than a server.
    Wildcard,
    /// A narrower wildcard (`Host *.internal`) or a `Match` block. Its
    /// settings belong to hosts this file never names, so they are dropped
    /// rather than guessed at.
    Skipped,
}

/// Parses the text of an ssh config into the hosts worth importing.
///
/// **Never fails.** A real `~/.ssh/config` is full of keywords this app has no
/// opinion on, and one unreadable line must not cost the user the other forty
/// hosts — so anything unrecognised is skipped in silence.
///
/// Takes the text rather than a path so it can be tested without a fixture on
/// disk, the same shape `ssh::sftp::wire` is in.
///
/// Two simplifications, both deliberate:
///
/// - **`Host *` is folded in as a default, not applied first-wins.** OpenSSH
///   takes the *first* value it sees for an option, so a `Host *` block at the
///   top of a file wins over the specific blocks below it. Reproducing that
///   would mean an import that behaves differently depending on where the user
///   put a block, for a feature whose whole job is to guess sensibly. A
///   specific block always wins here.
/// - **`Include` is ignored.** Following it means globbing, recursion and a
///   depth limit. If it matters it is a follow-up, not a silent half-job.
pub fn parse(text: &str) -> Vec<SshConfigHost> {
    let mut defaults = Defaults::default();
    let mut hosts: Vec<SshConfigHost> = Vec::new();
    let mut block = Block::Preamble;

    for line in text.lines() {
        let Some((keyword, value)) = split_line(line) else { continue };

        // A `Host` or `Match` line closes whatever came before it.
        if keyword == "host" || keyword == "match" {
            if let Block::Host(entry) = std::mem::replace(&mut block, Block::Skipped) {
                hosts.push(entry);
            }
            block = if keyword == "match" { Block::Skipped } else { open_host(value) };
            continue;
        }

        match &mut block {
            Block::Skipped => {}
            Block::Preamble | Block::Wildcard => match keyword.as_str() {
                "user" => defaults.user = Some(value.to_string()),
                "port" => defaults.port = value.parse().ok(),
                "identityfile" => defaults.identity_file = Some(expand_tilde(value)),
                _ => {}
            },
            Block::Host(entry) => match keyword.as_str() {
                "hostname" => entry.hostname = value.to_string(),
                "user" => entry.user = Some(value.to_string()),
                // An unparseable port leaves the field alone rather than
                // dropping the host: the rest of the block is still useful,
                // and the form's own default is a better answer than nothing.
                "port" => entry.port = value.parse().ok().or(entry.port),
                // Only the first `IdentityFile` in a block. OpenSSH allows
                // several and tries each; the vault holds one path, and the
                // first is the one the user meant.
                "identityfile" if entry.identity_file.is_none() => {
                    entry.identity_file = Some(expand_tilde(value));
                }
                _ => {}
            },
        }
    }

    if let Block::Host(entry) = block {
        hosts.push(entry);
    }

    for host in &mut hosts {
        // `hostname` was seeded with the alias, so it is never empty and never
        // needs a default.
        if host.user.is_none() {
            host.user.clone_from(&defaults.user);
        }
        if host.port.is_none() {
            host.port = defaults.port;
        }
        if host.identity_file.is_none() {
            host.identity_file.clone_from(&defaults.identity_file);
        }
    }

    hosts
}

/// Starts a block for a `Host` line.
///
/// A pattern list is only importable when it names exactly one literal host.
/// `Host web-1 web1.example.com` is two names for one machine and there is no
/// answer to which the entry should be called, so it is skipped rather than
/// guessed at — the same reasoning as a wildcard.
fn open_host(value: &str) -> Block {
    let mut patterns = value.split_whitespace();
    let (Some(first), None) = (patterns.next(), patterns.next()) else {
        return Block::Skipped;
    };
    if first == "*" {
        return Block::Wildcard;
    }
    if first.contains(['*', '?', '!']) {
        return Block::Skipped;
    }
    Block::Host(SshConfigHost {
        alias: first.to_string(),
        hostname: first.to_string(),
        user: None,
        port: None,
        identity_file: None,
    })
}

/// Splits one line into a lowercased keyword and its value, or `None` for a
/// blank or comment line.
///
/// Keywords are case-insensitive in OpenSSH and values are not, which is why
/// only the left half is folded. The separator may be whitespace or `=`, with
/// optional spaces around it.
fn split_line(line: &str) -> Option<(String, &str)> {
    let line = line.split('#').next().unwrap_or("").trim();
    if line.is_empty() {
        return None;
    }
    let at = line.find([' ', '\t', '='])?;
    let (keyword, rest) = line.split_at(at);
    let value = rest.trim_start_matches([' ', '\t', '=']).trim();
    if value.is_empty() {
        return None;
    }
    Some((keyword.to_ascii_lowercase(), value))
}

/// Expands a leading `~`. Anything else is left exactly as written — a path is
/// the user's to spell, and rewriting one we did not have to would be a way to
/// point at the wrong key.
fn expand_tilde(path: &str) -> String {
    let Some(rest) = path.strip_prefix("~/") else {
        return path.to_string();
    };
    match home_dir() {
        Some(home) => home.join(rest).to_string_lossy().into_owned(),
        None => path.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deliberately awkward: mixed-case keywords, an `=` separator, a comment
    /// on a live line, a `Match` block, a multi-pattern `Host`, and the
    /// `Host *` block at the bottom where people actually put it.
    const CONFIG: &str = r#"
# work
Host bastion
    HostName bastion.example.com
    User ops
    Port 2222
    IdentityFile ~/.ssh/id_bastion

host db          # the alias is all we get
    hostname=db.internal
    IdentityFile ~/.ssh/id_db
    IdentityFile ~/.ssh/id_db_backup

Host laptop-only
    HostName 10.0.0.4

Host *.internal
    User nobody

Host web-1 web1.example.com
    HostName web1.example.com

Match host *.corp
    User matched

Include ~/.ssh/config.d/*

Host *
    User default-user
    Port 22
"#;

    fn parsed() -> Vec<SshConfigHost> {
        parse(CONFIG)
    }

    fn get(name: &str) -> SshConfigHost {
        parsed().into_iter().find(|h| h.alias == name).unwrap_or_else(|| panic!("{name} was not imported"))
    }

    #[test]
    fn a_block_keeps_what_it_states_whatever_the_spelling_or_separator() {
        let bastion = get("bastion");
        assert_eq!(bastion.hostname, "bastion.example.com");
        assert_eq!(bastion.user.as_deref(), Some("ops"));
        assert_eq!(bastion.port, Some(2222));

        // Lowercase keywords, an `=`, and a trailing comment on the Host line.
        let db = get("db");
        assert_eq!(db.hostname, "db.internal");
    }

    /// `Host *` is the one wildcard that means something here, and it fills in
    /// only what a block did not say for itself.
    #[test]
    fn the_wildcard_block_fills_gaps_and_never_overrides() {
        assert_eq!(get("bastion").user.as_deref(), Some("ops"), "a stated user wins over the default");
        assert_eq!(get("laptop-only").user.as_deref(), Some("default-user"), "a silent block takes the default");
        assert_eq!(get("laptop-only").port, Some(22));
    }

    /// A narrower wildcard names hosts the file never lists, so there is
    /// nothing to import and nothing to guess at. Same for `Match`, and for a
    /// `Host` line naming several patterns — which of them would be the name?
    #[test]
    fn wildcards_matches_and_multi_pattern_blocks_are_not_servers() {
        let aliases: Vec<_> = parsed().into_iter().map(|h| h.alias).collect();
        assert_eq!(aliases, ["bastion", "db", "laptop-only"]);
    }

    /// The settings under a skipped block must not leak onto the block before
    /// it — that is the failure a naive parser has, and it is silent.
    #[test]
    fn a_skipped_block_does_not_pour_its_settings_into_its_neighbour() {
        assert_ne!(get("laptop-only").user.as_deref(), Some("nobody"), "the *.internal block must not reach laptop-only");
        assert!(!parsed().iter().any(|h| h.user.as_deref() == Some("matched")), "a Match block belongs to nobody here");
    }

    /// One vault entry holds one key path, so the first `IdentityFile` in a
    /// block is the one that survives. OpenSSH tries each in turn; picking the
    /// last would silently import the fallback key.
    #[test]
    fn the_first_identity_file_in_a_block_is_the_one_kept() {
        let db = get("db");
        assert!(db.identity_file.as_deref().unwrap().ends_with("/.ssh/id_db"), "got {:?}", db.identity_file);
    }

    /// A block naming no key is the one that becomes agent auth downstream, so
    /// "no key" has to survive the parse as `None` and not as a guess.
    #[test]
    fn a_block_with_no_identity_file_of_its_own_reports_none_unless_the_wildcard_had_one() {
        assert_eq!(get("laptop-only").identity_file, None);
    }

    #[test]
    fn a_block_with_no_hostname_connects_to_its_alias() {
        let hosts = parse("Host shortcut\n    User me\n");
        assert_eq!(hosts[0].hostname, "shortcut");
    }

    /// An unparseable port must not cost the user the whole host — the rest of
    /// the block still says something useful.
    #[test]
    fn a_bad_port_is_dropped_and_the_host_survives() {
        let hosts = parse("Host odd\n    HostName odd.example.com\n    Port not-a-number\n");
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].port, None);
        assert_eq!(hosts[0].hostname, "odd.example.com");
    }

    /// Settings before the first `Host` line apply to everything in OpenSSH,
    /// so they are treated exactly as `Host *` — not attributed to whichever
    /// block happens to come first.
    #[test]
    fn a_preamble_behaves_like_the_wildcard_block() {
        let hosts = parse("Port 2200\n\nHost a\nHost b\n    Port 22\n");
        assert_eq!(hosts[0].port, Some(2200));
        assert_eq!(hosts[1].port, Some(22));
    }

    #[test]
    fn an_empty_or_comment_only_file_is_no_hosts_rather_than_an_error() {
        assert!(parse("").is_empty());
        assert!(parse("# nothing here\n\n   \n").is_empty());
    }
}
