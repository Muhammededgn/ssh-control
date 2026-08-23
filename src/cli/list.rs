//! `ssh-control list`.
//!
//! Two forms, chosen by whether stdout is a terminal: aligned columns for a
//! person, a single tab between fields for `cut -f2`. The acceptance criterion
//! on the issue is "works in a pipe", and a pipe is exactly where the padding
//! stops being help and starts being something to strip.

use crate::config::{ServerEntry, ServerSort};

/// The three columns. Deliberately not the credential, and not the host-key
/// fingerprint either — `list` is the one output likely to end up in a log or
/// a paste.
fn row(entry: &ServerEntry) -> [String; 3] {
    [
        entry.name.clone(),
        format!("{}@{}:{}", entry.username, entry.host, entry.port),
        entry.tags.join(","),
    ]
}

/// Servers in display order, by the vault's own stored preference.
///
/// `ServerSort::LastConnected` puts the never-connected last, matching the
/// list screen; ties fall back to the name so the output is stable between
/// runs rather than shuffling.
fn ordered(servers: &[ServerEntry], sort: ServerSort) -> Vec<&ServerEntry> {
    let mut out: Vec<&ServerEntry> = servers.iter().collect();
    match sort {
        ServerSort::Name => out.sort_by_key(|a| a.name.to_lowercase()),
        ServerSort::Tag => out.sort_by(|a, b| {
            let key = |e: &ServerEntry| e.tags.first().map(|t| t.to_lowercase());
            // `None` last: an untagged entry belongs after the groups, not
            // before them.
            key(a).is_none().cmp(&key(b).is_none()).then_with(|| key(a).cmp(&key(b))).then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
        }),
        ServerSort::LastConnected => out.sort_by(|a, b| {
            b.last_connected_unix.cmp(&a.last_connected_unix).then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
        }),
    }
    out
}

/// The whole output, ready to print. Returned rather than printed so the tests
/// can read it.
pub fn render(servers: &[ServerEntry], sort: ServerSort, aligned: bool) -> String {
    let rows: Vec<[String; 3]> = ordered(servers, sort).into_iter().map(row).collect();
    if rows.is_empty() {
        return String::new();
    }

    let mut out = String::new();
    if !aligned {
        for r in &rows {
            out.push_str(&r.join("\t"));
            out.push('\n');
        }
        return out;
    }

    // Widths from the data, in characters rather than bytes — a server named
    // in Turkish or Russian would otherwise pad short by the number of
    // multi-byte characters in it.
    let width = |i: usize| rows.iter().map(|r| r[i].chars().count()).max().unwrap_or(0);
    let (w0, w1) = (width(0), width(1));
    for r in &rows {
        let pad = |i: usize, w: usize| " ".repeat(w.saturating_sub(r[i].chars().count()));
        // The last column is never padded: trailing spaces on every line are
        // invisible until something diffs them.
        out.push_str(format!("{}{}  {}{}  {}", r[0], pad(0, w0), r[1], pad(1, w1), r[2]).trim_end());
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AuthMethod;

    fn entry(name: &str, user: &str, port: u16, tags: &[&str]) -> ServerEntry {
        let mut e = ServerEntry::new(name.into(), format!("{name}.example.com"), port, user.into(), AuthMethod::password("hunter2"));
        e.tags = tags.iter().map(|t| (*t).to_string()).collect();
        e
    }

    fn servers() -> Vec<ServerEntry> {
        vec![entry("web-1", "root", 22, &["prod"]), entry("db-1", "postgres", 5432, &["prod", "db"])]
    }

    #[test]
    fn the_piped_form_is_three_tab_separated_fields() {
        let out = render(&servers(), ServerSort::Name, false);
        let lines: Vec<&str> = out.lines().collect();

        assert_eq!(lines[0], "db-1\tpostgres@db-1.example.com:5432\tprod,db");
        assert_eq!(lines[1], "web-1\troot@web-1.example.com:22\tprod");
        // The whole point: `cut -f2` has to give the connection string.
        assert!(lines.iter().all(|l| l.split('\t').count() == 3));
    }

    #[test]
    fn the_terminal_form_lines_the_columns_up() {
        let out = render(&servers(), ServerSort::Name, true);
        let starts: Vec<usize> = out.lines().map(|l| l.find('@').expect("a user@host") ).collect();

        assert!(!out.contains('\t'), "padding replaces tabs, it does not join them");
        assert_eq!(starts[0] - "postgres".len(), starts[1] - "root".len(), "the second column starts at one place");
        assert!(out.lines().all(|l| l == l.trim_end()), "no trailing padding");
    }

    /// `list` is the output most likely to be pasted into an issue or caught by
    /// a log. Same spirit as `model::tests::debug_never_prints_a_credential`.
    #[test]
    fn a_credential_never_reaches_the_output() {
        let mut with_key = servers();
        with_key.push({
            let mut e = entry("key-box", "deploy", 22, &[]);
            e.auth = AuthMethod::SshKey { key_path: "/home/me/.ssh/id_ed25519".into(), passphrase: Some(crate::config::Secret::from("pp".to_string())) };
            e.host_key_fingerprint = Some("SHA256:secretish".into());
            e
        });

        for aligned in [true, false] {
            let out = render(&with_key, ServerSort::Name, aligned);
            assert!(!out.contains("hunter2"));
            assert!(!out.contains("pp"));
            assert!(!out.contains("id_ed25519"));
            assert!(!out.contains("SHA256"));
        }
    }

    #[test]
    fn an_empty_vault_prints_nothing_at_all() {
        assert_eq!(render(&[], ServerSort::Name, true), "");
        assert_eq!(render(&[], ServerSort::Name, false), "");
    }

    /// Ties fall back to the name, so two runs of the same vault give the same
    /// bytes — a listing that reshuffles is useless in a diff.
    #[test]
    fn the_order_is_stable_when_nothing_distinguishes_two_entries() {
        let untouched = vec![entry("b", "root", 22, &[]), entry("a", "root", 22, &[])];
        for sort in [ServerSort::Name, ServerSort::Tag, ServerSort::LastConnected] {
            let out = render(&untouched, sort, false);
            assert!(out.starts_with("a\t"), "{sort:?} should fall back to the name");
        }
    }
}
