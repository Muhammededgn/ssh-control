//! Crossterm key events, encoded back into the bytes a terminal would have
//! sent.
//!
//! Pure data: no I/O, no async, nothing from russh or ratatui. The session
//! pane reads keys through crossterm — which has already parsed the terminal's
//! escape sequences into `KeyEvent`s — and the remote PTY expects those bytes
//! back. Everything that can be got wrong about that round trip is decided
//! here and unit-tested here, the same argument `ssh::sftp::wire` makes.
//!
//! `ssh::pty_bridge` needs none of this: it copies stdin through byte for
//! byte and never parses anything. That is the difference between the two
//! connect modes, and it is why only one of them can promise fidelity.
//!
//! **What a legacy terminal cannot tell apart, this cannot either.**
//! `ratatui::try_init` enables raw mode and the alternate screen and nothing
//! else — no keyboard enhancement flags — so `Ctrl+I` arrives as `Tab`,
//! `Ctrl+M` as `Enter` and `Ctrl+[` as `Esc`. Those collisions are what the
//! wire itself carries without the kitty protocol, so the remote sees exactly
//! what it would see under plain `ssh` from the same terminal. Pushing the
//! flags to resolve them would change how the *whole app* reads keys (every
//! `event::read` call site would start seeing releases and repeats), which is
//! issue #38's problem and not this one's.
//!
//! There is no mouse reporting and no bracketed paste for the same reason:
//! neither is enabled, so neither can be forwarded. A paste arrives as a burst
//! of `Char` events, which the pane's drain coalesces into one write — fast,
//! but the remote is not told it was a paste.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

/// The bytes `key` would have arrived as, or `None` when it has no encoding —
/// a bare modifier press, `KeyCode::Null`, a media or menu key. `None` is
/// dropped rather than sent as an empty write.
///
/// `app_cursor` is DECCKM: with it set the cursor keys are `ESC O A` rather
/// than `ESC [ A`, which is what a full-screen program that enabled it expects
/// back. It is a parameter and not a global for the reason `ServerSort` is
/// threaded per call — the caller reads it off the live `vt100::Screen`, so
/// there is nothing here to drift out of step with the remote, and the table
/// tests can drive both halves.
pub fn encode(key: KeyEvent, app_cursor: bool) -> Option<Vec<u8>> {
    let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
    let alt = key.modifiers.contains(KeyModifiers::ALT);
    let shift = key.modifiers.contains(KeyModifiers::SHIFT);

    let mut out = match key.code {
        KeyCode::Char(c) => {
            let mut bytes = Vec::new();
            if ctrl {
                match control_byte(c) {
                    // An unmapped combination (`Ctrl+1`, say) has no control
                    // byte; a real terminal sends the plain character, so so
                    // do we rather than swallowing the keystroke.
                    Some(b) => bytes.push(b),
                    None => bytes.extend_from_slice(c.encode_utf8(&mut [0u8; 4]).as_bytes()),
                }
            } else {
                bytes.extend_from_slice(c.encode_utf8(&mut [0u8; 4]).as_bytes());
            }
            bytes
        }
        // `\r`, never `\n`. The PTY's ICRNL is what turns this into a newline
        // for the remote line discipline; sending `\n` at a shell prompt is a
        // line feed and not a submit.
        KeyCode::Enter => vec![b'\r'],
        // DEL, not BS. Every modern termios has `erase = ^?`, and `\x08` is
        // what `Ctrl+Backspace` means — the deliberate word-erase in bash.
        KeyCode::Backspace if ctrl => vec![0x08],
        KeyCode::Backspace => vec![0x7f],
        KeyCode::Tab => vec![b'\t'],
        KeyCode::BackTab => b"\x1b[Z".to_vec(),
        KeyCode::Esc => vec![0x1b],
        KeyCode::Delete if ctrl => b"\x1b[3;5~".to_vec(),
        KeyCode::Up | KeyCode::Down | KeyCode::Right | KeyCode::Left | KeyCode::Home | KeyCode::End => {
            cursor_key(key.code, app_cursor, shift, alt, ctrl)?
        }
        KeyCode::Insert => b"\x1b[2~".to_vec(),
        KeyCode::Delete => b"\x1b[3~".to_vec(),
        KeyCode::PageUp => b"\x1b[5~".to_vec(),
        KeyCode::PageDown => b"\x1b[6~".to_vec(),
        KeyCode::F(n) => function_key(n)?,
        _ => return None,
    };

    // Alt is the ESC prefix, and it goes in front of whatever the key already
    // encoded to — including a control byte, so `Ctrl+Alt+c` is `ESC 0x03`.
    // The cursor keys already carry their modifiers in the `1;m` parameter and
    // must not be prefixed twice.
    if alt && !is_csi(&out) {
        out.insert(0, 0x1b);
    }
    Some(out)
}

/// The C0 control byte for `Ctrl+<c>`, or `None` when the combination has
/// none. Letters fold to `& 0x1f`; the rest of the set is the handful of
/// punctuation ASCII assigns a control code to.
fn control_byte(c: char) -> Option<u8> {
    match c {
        'a'..='z' => Some(c as u8 & 0x1f),
        'A'..='Z' => Some(c.to_ascii_lowercase() as u8 & 0x1f),
        ' ' | '@' => Some(0x00),
        '[' => Some(0x1b),
        '\\' => Some(0x1c),
        ']' => Some(0x1d),
        '^' => Some(0x1e),
        '_' => Some(0x1f),
        '?' => Some(0x7f),
        _ => None,
    }
}

/// Whether these bytes are already a CSI sequence carrying their own modifier
/// parameter — an `ESC` prefix on top of one would be read as two keys.
fn is_csi(bytes: &[u8]) -> bool {
    bytes.starts_with(b"\x1b[") || bytes.starts_with(b"\x1bO")
}

/// The arrows plus Home/End, which are the only keys whose *introducer*
/// changes with DECCKM. An unmodified key is `ESC[A` or, under `app_cursor`,
/// `ESC O A`; a modified one is always the CSI form with an `1;m` parameter,
/// because `ESC O` has nowhere to put parameters.
fn cursor_key(code: KeyCode, app_cursor: bool, shift: bool, alt: bool, ctrl: bool) -> Option<Vec<u8>> {
    let final_byte = match code {
        KeyCode::Up => b'A',
        KeyCode::Down => b'B',
        KeyCode::Right => b'C',
        KeyCode::Left => b'D',
        KeyCode::End => b'F',
        KeyCode::Home => b'H',
        _ => return None,
    };

    let modifier = 1 + u8::from(shift) + 2 * u8::from(alt) + 4 * u8::from(ctrl);
    if modifier > 1 {
        return Some(format!("\x1b[1;{modifier}{}", final_byte as char).into_bytes());
    }
    if app_cursor {
        return Some(vec![0x1b, b'O', final_byte]);
    }
    Some(vec![0x1b, b'[', final_byte])
}

/// F1–F12. The first four are the VT100 `ESC O` forms every terminfo entry
/// agrees on; the rest are the xterm `~` forms, whose numbering skips 16, 22
/// and 25 for historical reasons and is copied here rather than computed.
fn function_key(n: u8) -> Option<Vec<u8>> {
    let seq: &[u8] = match n {
        1 => b"\x1bOP",
        2 => b"\x1bOQ",
        3 => b"\x1bOR",
        4 => b"\x1bOS",
        5 => b"\x1b[15~",
        6 => b"\x1b[17~",
        7 => b"\x1b[18~",
        8 => b"\x1b[19~",
        9 => b"\x1b[20~",
        10 => b"\x1b[21~",
        11 => b"\x1b[23~",
        12 => b"\x1b[24~",
        _ => return None,
    };
    Some(seq.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plain(code: KeyCode) -> Option<Vec<u8>> {
        encode(KeyEvent::new(code, KeyModifiers::NONE), false)
    }

    fn with(code: KeyCode, modifiers: KeyModifiers) -> Option<Vec<u8>> {
        encode(KeyEvent::new(code, modifiers), false)
    }

    #[test]
    fn a_printable_character_is_its_utf8() {
        assert_eq!(plain(KeyCode::Char('a')), Some(b"a".to_vec()));
        assert_eq!(plain(KeyCode::Char('Z')), Some(b"Z".to_vec()));
        // Shift is already folded into the character crossterm reports, so it
        // must not add anything of its own.
        assert_eq!(with(KeyCode::Char('Z'), KeyModifiers::SHIFT), Some(b"Z".to_vec()));
    }

    /// A name typed in Turkish or Russian goes to the remote shell as the
    /// bytes it is, not as a `?`.
    #[test]
    fn a_multibyte_character_keeps_all_of_its_bytes() {
        assert_eq!(plain(KeyCode::Char('ğ')), Some("ğ".as_bytes().to_vec()));
        assert_eq!(plain(KeyCode::Char('д')), Some("д".as_bytes().to_vec()));
        assert_eq!(plain(KeyCode::Char('€')), Some("€".as_bytes().to_vec()));
    }

    #[test]
    fn control_letters_fold_to_the_c0_set() {
        for (i, c) in ('a'..='z').enumerate() {
            let expected = (i + 1) as u8;
            assert_eq!(with(KeyCode::Char(c), KeyModifiers::CONTROL), Some(vec![expected]), "Ctrl+{c}");
            // Crossterm reports the uppercase form on some terminals; both
            // have to land on the same byte.
            assert_eq!(with(KeyCode::Char(c.to_ascii_uppercase()), KeyModifiers::CONTROL), Some(vec![expected]));
        }
    }

    /// The one that matters most: an interrupt has to reach the remote as
    /// `0x03` or the pane cannot stop a runaway command.
    #[test]
    fn ctrl_c_is_the_interrupt_byte() {
        assert_eq!(with(KeyCode::Char('c'), KeyModifiers::CONTROL), Some(vec![0x03]));
    }

    #[test]
    fn the_punctuation_control_codes_are_carried() {
        assert_eq!(with(KeyCode::Char('@'), KeyModifiers::CONTROL), Some(vec![0x00]));
        assert_eq!(with(KeyCode::Char(' '), KeyModifiers::CONTROL), Some(vec![0x00]));
        assert_eq!(with(KeyCode::Char('['), KeyModifiers::CONTROL), Some(vec![0x1b]));
        assert_eq!(with(KeyCode::Char('\\'), KeyModifiers::CONTROL), Some(vec![0x1c]));
        assert_eq!(with(KeyCode::Char(']'), KeyModifiers::CONTROL), Some(vec![0x1d]));
        assert_eq!(with(KeyCode::Char('^'), KeyModifiers::CONTROL), Some(vec![0x1e]));
        assert_eq!(with(KeyCode::Char('_'), KeyModifiers::CONTROL), Some(vec![0x1f]));
        assert_eq!(with(KeyCode::Char('?'), KeyModifiers::CONTROL), Some(vec![0x7f]));
    }

    /// A combination with no control code sends the plain character, which is
    /// what a real terminal does — swallowing the keystroke would be worse.
    #[test]
    fn an_unmapped_control_combination_sends_the_character() {
        assert_eq!(with(KeyCode::Char('1'), KeyModifiers::CONTROL), Some(b"1".to_vec()));
    }

    #[test]
    fn alt_is_the_escape_prefix() {
        assert_eq!(with(KeyCode::Char('x'), KeyModifiers::ALT), Some(vec![0x1b, b'x']));
        assert_eq!(with(KeyCode::Char('c'), KeyModifiers::ALT | KeyModifiers::CONTROL), Some(vec![0x1b, 0x03]));
    }

    /// `\n` at a shell prompt is a line feed, not a submit. This is the one
    /// mapping a reader is most likely to "correct" into a bug.
    #[test]
    fn enter_is_carriage_return_and_never_line_feed() {
        assert_eq!(plain(KeyCode::Enter), Some(vec![b'\r']));
    }

    #[test]
    fn backspace_is_del_and_ctrl_backspace_is_bs() {
        assert_eq!(plain(KeyCode::Backspace), Some(vec![0x7f]));
        assert_eq!(with(KeyCode::Backspace, KeyModifiers::CONTROL), Some(vec![0x08]));
    }

    #[test]
    fn the_simple_keys_are_themselves() {
        assert_eq!(plain(KeyCode::Esc), Some(vec![0x1b]));
        assert_eq!(plain(KeyCode::Tab), Some(vec![b'\t']));
        assert_eq!(plain(KeyCode::BackTab), Some(b"\x1b[Z".to_vec()));
    }

    /// The whole reason `app_cursor` is a parameter: a program that enabled
    /// DECCKM expects `ESC O A` back and does not recognise `ESC [ A`.
    #[test]
    fn the_cursor_keys_follow_deckm() {
        for (code, letter) in [(KeyCode::Up, 'A'), (KeyCode::Down, 'B'), (KeyCode::Right, 'C'), (KeyCode::Left, 'D'), (KeyCode::End, 'F'), (KeyCode::Home, 'H')] {
            let normal = encode(KeyEvent::new(code, KeyModifiers::NONE), false);
            let application = encode(KeyEvent::new(code, KeyModifiers::NONE), true);
            assert_eq!(normal, Some(format!("\x1b[{letter}").into_bytes()));
            assert_eq!(application, Some(format!("\x1bO{letter}").into_bytes()));
        }
    }

    /// A modified cursor key is always the CSI form: `ESC O` has nowhere to
    /// put the parameter, so DECCKM does not apply to it.
    #[test]
    fn a_modified_cursor_key_carries_its_modifier_in_the_csi_form() {
        assert_eq!(encode(KeyEvent::new(KeyCode::Left, KeyModifiers::CONTROL), true), Some(b"\x1b[1;5D".to_vec()));
        assert_eq!(with(KeyCode::Right, KeyModifiers::SHIFT), Some(b"\x1b[1;2C".to_vec()));
        assert_eq!(with(KeyCode::Up, KeyModifiers::ALT), Some(b"\x1b[1;3A".to_vec()));
        assert_eq!(with(KeyCode::Down, KeyModifiers::CONTROL | KeyModifiers::SHIFT), Some(b"\x1b[1;6B".to_vec()));
    }

    #[test]
    fn the_editing_keys_are_the_tilde_forms() {
        assert_eq!(plain(KeyCode::Insert), Some(b"\x1b[2~".to_vec()));
        assert_eq!(plain(KeyCode::Delete), Some(b"\x1b[3~".to_vec()));
        assert_eq!(plain(KeyCode::PageUp), Some(b"\x1b[5~".to_vec()));
        assert_eq!(plain(KeyCode::PageDown), Some(b"\x1b[6~".to_vec()));
    }

    #[test]
    fn the_function_keys_split_at_four() {
        assert_eq!(plain(KeyCode::F(1)), Some(b"\x1bOP".to_vec()));
        assert_eq!(plain(KeyCode::F(4)), Some(b"\x1bOS".to_vec()));
        assert_eq!(plain(KeyCode::F(5)), Some(b"\x1b[15~".to_vec()));
        assert_eq!(plain(KeyCode::F(12)), Some(b"\x1b[24~".to_vec()));
        // The numbering skips 16, 22 and 25 — nothing computes them.
        assert_eq!(plain(KeyCode::F(10)), Some(b"\x1b[21~".to_vec()));
        assert_eq!(plain(KeyCode::F(11)), Some(b"\x1b[23~".to_vec()));
    }

    /// Dropped rather than sent as an empty write: a modifier on its own is
    /// not a keystroke the remote has any use for.
    #[test]
    fn a_key_with_no_encoding_is_none() {
        assert_eq!(plain(KeyCode::F(13)), None);
        assert_eq!(plain(KeyCode::Null), None);
        assert_eq!(plain(KeyCode::CapsLock), None);
    }
}
