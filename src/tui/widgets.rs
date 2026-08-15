use qrcode::QrCode;
use qrcode::render::unicode;
use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Style};
use ratatui::text::Line;
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Scrollbar, ScrollbarOrientation, ScrollbarState, Wrap};

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

/// Below this a bordered form has nothing left to show: two rows go to the
/// border, so the height buys one field and the hint line, and a width under
/// thirty columns cuts labels off mid-word.
pub const MIN_FORM_WIDTH: u16 = 30;
pub const MIN_FORM_HEIGHT: u16 = 7;

/// Draws `message` in place of a screen that cannot be rendered usefully, and
/// says so. Returns `true` when it did, so callers `return` on it.
///
/// An explicit message beats a squashed frame: the previous behaviour silently
/// clipped the bottom fields, so focus could sit on a field that was not on
/// screen and the user typed into nothing.
pub fn render_if_too_small(
    frame: &mut Frame,
    area: Rect,
    min_width: u16,
    min_height: u16,
    message: &str,
) -> bool {
    if area.width >= min_width && area.height >= min_height {
        return false;
    }
    let paragraph = Paragraph::new(message)
        .wrap(Wrap { trim: true })
        .alignment(Alignment::Center)
        .style(Style::default().fg(Color::Yellow));
    frame.render_widget(Clear, area);
    frame.render_widget(paragraph, area);
    true
}

/// The smallest scroll that keeps `focus_row` on screen, clamped so the last
/// line never floats above the bottom edge.
///
/// Stateless on purpose: the focused row is the only thing that has to be
/// visible, so there is no scroll position to carry between frames and nothing
/// that can drift out of step with the focus.
pub fn form_scroll_offset(focus_row: usize, total_lines: usize, visible: usize) -> usize {
    if visible == 0 || total_lines <= visible {
        return 0;
    }
    let max = total_lines - visible;
    focus_row.saturating_sub(visible - 1).min(max)
}

/// A form's lines in a bordered block, scrolled to keep the focused row
/// visible, or the "terminal too small" message if it cannot be drawn at all.
///
/// `focus_row` indexes `lines`, so callers must build the two in the same
/// order — a form whose line list does not match its focus order would scroll
/// to the wrong place.
pub fn render_form(
    frame: &mut Frame,
    area: Rect,
    title: &str,
    lines: Vec<Line<'static>>,
    focus_row: usize,
    too_small_message: &str,
) {
    if render_if_too_small(frame, area, MIN_FORM_WIDTH, MIN_FORM_HEIGHT, too_small_message) {
        return;
    }

    let visible = area.height.saturating_sub(2) as usize;
    let offset = form_scroll_offset(focus_row, lines.len(), visible);

    // Arrows on the border are the only signal that fields exist off screen;
    // without them a clamped form looks like the whole form.
    let more_above = offset > 0;
    let more_below = offset + visible < lines.len();
    let title = match (more_above, more_below) {
        (true, true) => format!("{title}↑↓ "),
        (true, false) => format!("{title}↑ "),
        (false, true) => format!("{title}↓ "),
        (false, false) => title.to_string(),
    };

    let block = Block::default().borders(Borders::ALL).title(title);
    frame.render_widget(Paragraph::new(lines).scroll((offset as u16, 0)).block(block), area);
}

/// A byte count at whichever unit keeps it readable — "4.0 KiB", "1.2 GiB".
///
/// Distinct from `main_menu`'s fixed-GiB helper on purpose: that one compares
/// two figures of the same magnitude (RAM used against RAM total), where a
/// shifting unit would make the pair harder to read. Here the numbers range
/// from a few bytes to several gigabytes and a fixed unit would print
/// "0.0 GiB" for most files.
pub fn format_size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    // Whole bytes never need a decimal point; anything scaled does.
    if unit == 0 { format!("{bytes} B") } else { format!("{value:.1} {}", UNITS[unit]) }
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

    #[test]
    fn sizes_scale_to_a_readable_unit() {
        assert_eq!(format_size(0), "0 B");
        assert_eq!(format_size(512), "512 B");
        assert_eq!(format_size(1024), "1.0 KiB");
        assert_eq!(format_size(1536), "1.5 KiB");
        assert_eq!(format_size(3 * 1024 * 1024 * 1024), "3.0 GiB");
    }

    #[test]
    fn a_form_that_fits_never_scrolls() {
        assert_eq!(form_scroll_offset(0, 6, 10), 0);
        assert_eq!(form_scroll_offset(5, 6, 10), 0);
    }

    /// The focused row has to be on screen, and the scroll has to be the
    /// smallest one that gets it there — jumping the focused field to the top
    /// would throw away the context above it.
    #[test]
    fn the_focused_row_is_pulled_just_into_view() {
        // Nine lines, four visible: rows 0..=3 need no scroll.
        assert_eq!(form_scroll_offset(3, 9, 4), 0);
        assert_eq!(form_scroll_offset(4, 9, 4), 1);
        assert_eq!(form_scroll_offset(8, 9, 4), 5);
    }

    /// Past the end the last line still sits on the bottom edge rather than
    /// scrolling off the top of a half-empty frame.
    #[test]
    fn the_offset_never_scrolls_past_the_last_line() {
        assert_eq!(form_scroll_offset(100, 9, 4), 5);
        assert_eq!(form_scroll_offset(0, 9, 0), 0);
    }
}
