use qrcode::QrCode;
use qrcode::render::unicode;
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::text::Line;
use ratatui::widgets::{Scrollbar, ScrollbarOrientation, ScrollbarState};

/// Returns a rect of `width`x`height` centered within `area`, clamped so it
/// never exceeds `area`'s bounds. Used for popups/overlays (unlock screen,
/// confirm dialogs).
pub fn centered_rect(width: u16, height: u16, area: Rect) -> Rect {
    let width = width.min(area.width);
    let height = height.min(area.height);

    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length((area.height.saturating_sub(height)) / 2),
            Constraint::Length(height),
            Constraint::Min(0),
        ])
        .split(area);

    let horizontal = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Length((area.width.saturating_sub(width)) / 2),
            Constraint::Length(width),
            Constraint::Min(0),
        ])
        .split(vertical[1]);

    horizontal[1]
}

/// Renders a text buffer as a run of `*` of the same length, for masked
/// password/passphrase input fields.
pub fn mask(s: &str) -> String {
    "*".repeat(s.chars().count())
}

/// Appends a `(3/17)` position counter to a list's block title.
///
/// Counts *items*, not rows, and that is the point: a server row is one or two
/// lines depending on whether system info was ever fetched, so a row-based
/// figure would not match anything the user can count on screen. An empty list
/// gets no counter rather than `(0/0)`.
pub fn list_title_with_position(title: &str, selected: usize, total: usize) -> String {
    if total == 0 {
        return title.to_string();
    }
    format!("{title}({}/{total}) ", selected + 1)
}

/// The scrollbar drawn down the right edge of a list, positioned by item.
///
/// Split out because both list screens need the identical five lines, and
/// because the `Rect` it takes has to be the *same* one the list was rendered
/// into — ratatui insets it past the border itself.
pub fn render_list_scrollbar(frame: &mut Frame, area: Rect, selected: usize, total: usize) {
    // One item cannot scroll, and a scrollbar with nothing to say is just
    // noise on the border.
    if total <= 1 {
        return;
    }

    let mut state = ScrollbarState::new(total).position(selected);
    frame.render_stateful_widget(
        Scrollbar::new(ScrollbarOrientation::VerticalRight).begin_symbol(None).end_symbol(None),
        area,
        &mut state,
    );
}

/// Renders `data` as a QR code in half-block characters, for scanning an
/// `otpauth://` URI with a phone. An unencodable string yields one blank line
/// rather than an error: the secret is always shown as text beside the code, so
/// a missing QR degrades to retyping rather than to a dead end.
pub fn qr_lines(data: &str) -> Vec<Line<'static>> {
    if data.is_empty() {
        return vec![Line::from("")];
    }
    let Ok(code) = QrCode::new(data.as_bytes()) else {
        return vec![Line::from("")];
    };
    let rendered = code.render::<unicode::Dense1x2>().quiet_zone(false).build();
    rendered.lines().map(|l| Line::from(l.to_string())).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_counter_is_one_based_for_the_reader() {
        assert_eq!(list_title_with_position(" Servers ", 0, 17), " Servers (1/17) ");
        assert_eq!(list_title_with_position(" Servers ", 16, 17), " Servers (17/17) ");
    }

    /// "(0/0)" under an empty list is noise, and the list already says it is
    /// empty in words.
    #[test]
    fn an_empty_list_gets_no_counter() {
        assert_eq!(list_title_with_position(" Servers ", 0, 0), " Servers ");
    }
}
