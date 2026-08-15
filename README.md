# ssh-control

[![CI](https://github.com/Muhammededgn/ssh-control/actions/workflows/ci.yml/badge.svg)](https://github.com/Muhammededgn/ssh-control/actions/workflows/ci.yml)

A local, encrypted SSH connection manager with an interactive terminal UI.

Servers, credentials and per-server automation scripts live in a single
AES-256-GCM encrypted file on your own machine. Nothing is synced, uploaded, or
shared with a third party. Connecting hands the terminal to a real PTY session,
so `vim`, `htop`, `tmux` and Ctrl+C behave exactly as they would under plain
`ssh`.

## Features

- **Encrypted vault** — Argon2id-derived key, AES-256-GCM, authenticated header
- **Four security modes** — from no prompt at all to a code-only daily unlock with the password as fallback
- **Full PTY passthrough** — byte-for-byte, with window-resize forwarding
- **TOFU host keys** — fingerprints are pinned on first connect and a mismatch
  refuses the connection
- **System info** — CPU / RAM / disk / GPU snapshot fetched on connect and shown
  in the server list
- **Per-server scripts** — ordered command chains with per-step conditions
  (always, on success, on failure, output contains) and per-step timeouts,
  optionally auto-run on connect
- **Search** — `/` filters the server list by name, host or username
- **Keybinding overlay** — `F2` (or `?` on the lists) shows what the current
  screen can do
- **Four UI languages** — English, Turkish, Spanish, Russian

## Platform

Unix only — Linux, macOS and the BSDs. The PTY bridge is built on unix signals
and non-blocking file descriptors, so the crate does not compile on Windows and
says so rather than failing somewhere confusing. Packaging is deb, rpm, Arch and
a portable tarball.

## Install

### Prebuilt packages

Every tagged release publishes `.deb`, `.rpm`, Arch `.pkg.tar.zst` and a plain
tarball on the [releases page](https://github.com/Muhammededgn/ssh-control/releases),
alongside a `SHA256SUMS` file. The binaries are built against glibc 2.36, so
they run on Debian 12+, Ubuntu 22.04+ and Fedora 37+.

```sh
# Debian / Ubuntu
sudo dpkg -i ssh-control_0.2.0-1_amd64.deb

# Fedora / RHEL
sudo rpm -i ssh-control-0.2.0-1.x86_64.rpm

# Arch
sudo pacman -U ssh-control-0.2.0-1-x86_64.pkg.tar.zst

# Anything else
tar xzf ssh-control-0.2.0-x86_64-linux.tar.gz
sudo install -Dm755 ssh-control-0.2.0-x86_64-linux/ssh-control /usr/local/bin/ssh-control
```

### Arch, from source

```sh
cd packaging/arch && makepkg -si
```

### From source

```sh
cargo build --release
./target/release/ssh-control
```

Requires a Rust toolchain (edition 2024), CMake, a C compiler, and a unix-like
OS. CMake and the C compiler are for `aws-lc-sys`, which `russh` depends on.

## Usage

Run `ssh-control`. On first launch you set a master password (minimum 8
characters); afterwards it asks for that password to unlock.

`--version` and `--help` are the only flags; everything else is configured from
inside the app. It is an interactive TUI and needs a terminal, so it says so
rather than failing obscurely when piped or run from a service manager.

| Screen | Keys |
|---|---|
| Server list | `Enter` connect · `/` search · `a` add · `e` edit · `d` delete · `s` scripts · `l` lock · `F1` settings · `q` quit |
| Forms | `Tab` next field · `Ctrl+Enter` save · `Esc` cancel |
| Script list | `Enter` run · `a` add · `e` edit · `d` delete · `Esc` back |
| Step editor | `←`/`→` change condition · `Ctrl+↑`/`Ctrl+↓` reorder · `Esc` cancel |
| Run log | `↑`/`↓` `PgUp`/`PgDn` `Home` scroll · `End` follow the tail |
| Settings | `←`/`→` switch tab · `Esc` back |
| Anywhere | `F2` keybindings, and `?` on the lists and the run log |

While `/` is open every key is filter text, so the single-letter shortcuts are
unavailable until `Enter` (connect, keeping the filter) or `Esc` (clear it).

Settings (`F1`) covers the UI language, changing the master password, and the
two-factor / TOTP modes.

## Files

Everything lives in your platform config directory (`~/.config/ssh-control` on
Linux), created `0700` with `0600` files:

| File | Contents |
|---|---|
| `config.enc` | The encrypted vault: servers, credentials, scripts, TOTP secret |
| `prefs.lang` | UI language code — plain text, read before unlocking |
| `vault-id` | An identifier naming this vault's OS credential-store entry — plain text, not a secret |
| `config.enc.lock` | Always empty. Only one running instance may hold the vault open, and this is what they contend on |

The vault is rewritten atomically (staged in a sibling `.tmp` file, fsynced,
then renamed), so an interrupted save can never truncate or corrupt it.

**Only one instance at a time.** Every save rewrites the whole vault from the
copy that instance holds in memory, so two running at once would be
last-writer-wins — add a server in one, save in the other, and the first edit
would be gone with nothing to show for it. The second instance is refused with
an explicit message instead. The lock is taken the first time a vault is
actually opened, so a window sitting on the password screen blocks nothing, and
it is an advisory `flock`, so a crash releases it rather than stranding it.

## Security model

### The four modes

Chosen on first run, changeable under `F1` → Security. The vault is always
encrypted; the modes differ in what is asked of you and in what an attacker
needs.

| Mode | Asked at startup | Someone who copies `config.enc` needs |
|---|---|---|
| 1. No prompt | nothing | this machine's credential-store entry — which does not travel with the file |
| 2. Password | password | your password |
| 3. Password + code | password, then a code | your password |
| 4. Code only | a code | your password |

Under the hood every mode is the same shape: a random 32-byte master key
encrypts the vault, and each unlock method holds that key wrapped under its own
key-encryption key. Changing your password rewraps 32 bytes; it does not
re-encrypt the vault.

**What it protects against.** Someone who gets a copy of `config.enc` — a stolen
laptop, a leaked backup, a synced dotfile repo — cannot read your servers or
credentials. Password slots are derived with Argon2id and every slot descriptor
is bound as AEAD additional data, so rolling the stored KDF parameters back to
something cheap fails the authentication tag rather than silently weakening the
derivation.

**Modes 1 and 4 bind the vault to this machine.** Their key material lives in
the OS credential store (Secret Service on Linux, Keychain on macOS), *outside*
the config directory. Copy the vault elsewhere and that key does not come with
it, so the copy falls back to the password — which is exactly why mode 4 keeps
one. These two modes are offered only when a credential store is actually
reachable; on a headless server there usually is none, and the setup screen says
so rather than quietly downgrading you.

**Mode 1 has no fallback unless you set one.** Setup offers an optional recovery
password. Skip it and losing the credential-store entry — an OS reinstall, a
cleared keyring — loses the vault permanently.

**When mode 4 asks for the password.** When this machine has no credential-store
entry for the vault, after five wrong codes in a row, when a code is reused, and
once every 30 days so the password does not quietly rot in your memory.

**TOTP is not cryptographic strength.** Verifying a code means holding the
shared secret, so anyone who holds the file holds the secret too. A code stops
someone at your keyboard; it does nothing against someone with a copy of the
vault. That is why every mode with a code also has a password behind it, and why
mode 4's real security is the password, not the code. A code is accepted once —
reusing one inside its ~90-second validity window is refused and escalates to
the password.

**Idle auto-lock.** After 15 minutes without a keypress the vault re-locks and
the master key is wiped from memory. Change the timeout — Off, 1, 5, 15, 30 or
60 minutes — under `F1` → Auto-lock. The timer never interrupts a live SSH
session or a running script, and `l` still locks immediately.

**What it does not protect against.** While the vault is unlocked, the key and
the decrypted credentials are in process memory. Credentials are held in buffers
that are wiped when dropped, but this is not a defense against malware or
another process running as your user — which can also simply ask the credential
store for the device key.

**Credentials are stored, not referenced.** Passwords and key passphrases are
kept inside the encrypted vault so connecting requires no further prompting.
They are redacted from all debug output, but they are on disk. In any mode with
a password slot, the vault at rest is exactly as strong as that password.
Choose a strong one.

### Upgrading from the old TOTP-only mode

Earlier versions had a TOTP-only mode that kept its secret in plain text in
`totp-only.secret`, because the app had to read it before you typed anything.
Anyone who could read that file could open the vault without ever producing a
code.

That mode is gone. The first launch after upgrading asks you to set a password,
then converts the vault to mode 4: the secret moves into the OS credential
store, the password becomes the fallback, and the plaintext file is deleted —
only after the replacement has been written and proved to open.

## Development

```sh
cargo test --locked
cargo clippy --all-targets --locked -- -D warnings
```

These are exactly what CI runs on every push. Note the source is *not*
rustfmt-formatted — it uses a deliberately compact hand style, so there is no
`cargo fmt` gate.

Releases are cut by pushing a version tag. The tag, `Cargo.toml` and
`packaging/arch/PKGBUILD` must all carry the same version or the release
workflow fails before building anything:

```sh
git tag v0.2.0 && git push origin v0.2.0
```

`examples/gen_totp_code.rs` prints the current code for a base32 secret, which
is handy for exercising the 2FA flows without an authenticator app:

```sh
cargo run --example gen_totp_code -- JBSWY3DPEHPK3PXP
```

## License

MIT — see [LICENSE](LICENSE).
