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
- **Three unlock modes** — master password, password + TOTP (2FA), or TOTP-only
- **Full PTY passthrough** — byte-for-byte, with window-resize forwarding
- **TOFU host keys** — fingerprints are pinned on first connect and a mismatch
  refuses the connection
- **System info** — CPU / RAM / disk / GPU snapshot fetched on connect and shown
  in the server list
- **Per-server scripts** — ordered command chains with per-step conditions
  (always, on success, on failure, output contains), optionally auto-run on
  connect
- **Four UI languages** — English, Turkish, Spanish, Russian

## Install

### Prebuilt packages

Every tagged release publishes `.deb`, `.rpm`, Arch `.pkg.tar.zst` and a plain
tarball on the [releases page](https://github.com/Muhammededgn/ssh-control/releases),
alongside a `SHA256SUMS` file. The binaries are built against glibc 2.36, so
they run on Debian 12+, Ubuntu 22.04+ and Fedora 37+.

```sh
# Debian / Ubuntu
sudo dpkg -i ssh-control_0.1.0-1_amd64.deb

# Fedora / RHEL
sudo rpm -i ssh-control-0.1.0-1.x86_64.rpm

# Arch
sudo pacman -U ssh-control-0.1.0-1-x86_64.pkg.tar.zst

# Anything else
tar xzf ssh-control-0.1.0-x86_64-linux.tar.gz
sudo install -Dm755 ssh-control-0.1.0-x86_64-linux/ssh-control /usr/local/bin/ssh-control
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

| Screen | Keys |
|---|---|
| Server list | `Enter` connect · `a` add · `e` edit · `d` delete · `s` scripts · `l` lock · `F1` settings · `q` quit |
| Forms | `Tab` next field · `Ctrl+Enter` save · `Esc` cancel |
| Script list | `Enter` run · `a` add · `e` edit · `d` delete · `Esc` back |
| Step editor | `←`/`→` change condition · `Ctrl+↑`/`Ctrl+↓` reorder · `Esc` cancel |
| Settings | `←`/`→` switch tab · `Esc` back |

Settings (`F1`) covers the UI language, changing the master password, and the
two-factor / TOTP modes.

## Files

Everything lives in your platform config directory (`~/.config/ssh-control` on
Linux), created `0700` with `0600` files:

| File | Contents |
|---|---|
| `config.enc` | The encrypted vault: servers, credentials, scripts, 2FA secret |
| `prefs.lang` | UI language code — plain text, read before unlocking |
| `totp-only.secret` | TOTP-only mode secret — **plain text**, see below |

The vault is rewritten atomically (staged in a sibling `.tmp` file, fsynced,
then renamed), so an interrupted save can never truncate or corrupt it.

## Security model

**What it protects against.** Someone who gets a copy of `config.enc` — a stolen
laptop, a leaked backup, a shared filesystem — cannot read your servers or
credentials without the master password. The key is derived with Argon2id
(19 MiB, 2 passes) and the file header is bound as AEAD additional data, so
tampering with the stored KDF parameters fails the authentication tag rather
than silently weakening the derivation.

**Idle auto-lock.** After 15 minutes without a keypress the vault re-locks
itself and the master key is wiped from memory; you are back at the unlock
screen. Change the timeout — Off, 1, 5, 15, 30 or 60 minutes — under
`F1` → Auto-lock. The timer never interrupts a live SSH session or a running
script, and `l` still locks immediately.

**What it does not protect against.** While the vault is unlocked, the key and
the decrypted credentials are in process memory. Credentials are held in
buffers that are wiped when dropped, but this is not a defense against malware
or another process running as your user.

**TOTP-only mode is weaker, by design.** In this mode there is no password at
all, so the vault key is derived from the TOTP secret — which must be stored in
the clear in `totp-only.secret` for the app to read it before you type
anything. Anyone with read access to that file can decrypt the vault. It
protects against someone using an already-open machine without your
authenticator device; it does *not* protect the file at rest. Use the master
password or 2FA mode if disk access is part of your threat model.

**Credentials are stored, not referenced.** Passwords and key passphrases are
kept inside the encrypted vault so connecting requires no further prompting.
They are redacted from all debug output, but they are on disk, encrypted only
by your master password. Choose a strong one.

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
git tag v0.1.0 && git push origin v0.1.0
```

`examples/gen_totp_code.rs` prints the current code for a base32 secret, which
is handy for exercising the 2FA flows without an authenticator app:

```sh
cargo run --example gen_totp_code -- JBSWY3DPEHPK3PXP
```

## License

MIT — see [LICENSE](LICENSE).
