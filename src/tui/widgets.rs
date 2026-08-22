use qrcode::QrCode;
use qrcode::render::unicode;
use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders, Clear, List, ListItem, ListState, Padding, Paragraph, Scrollbar, ScrollbarOrientation, ScrollbarState, Wrap};

use crate::tui::theme;

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

/// Clears `area` and puts the theme's own surface back underneath.
///
/// `Clear` resets every cell to the terminal's own default, which under a
/// preset with a background of its own is a hole punched through the middle of
/// the frame.
/// Every overlay wants the surface back, not the terminal — so no screen may
/// render a bare `Clear` any more.
pub fn clear_surface(frame: &mut Frame, area: Rect) {
    frame.render_widget(Clear, area);
    frame.render_widget(Block::default().style(theme::band()), area);
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

/// Rows one logical line occupies once `Wrap { trim: false }` has had it.
///
/// Greedy word wrapping, matching what ratatui does closely enough that the
/// scrollbar and the `End` clamp land on the same row the user sees. A word
/// longer than the width is broken rather than allowed to overflow.
///
/// Here rather than on the one screen that started with it, because a panel
/// sized as if each line were one row loses its hint the moment a server name
/// is long enough to wrap.
pub fn wrapped_rows(text: &str, width: u16) -> usize {
    let width = width.max(1) as usize;
    let mut rows = 1;
    let mut col = 0;

    for word in text.split_inclusive(' ') {
        let len = word.chars().count();
        if col + len > width && col > 0 {
            rows += 1;
            col = 0;
        }
        // A single word wider than the viewport wraps within itself.
        if len > width {
            rows += (len - 1) / width;
            col = len % width;
        } else {
            col += len;
        }
    }
    rows
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
        .style(Style::default().fg(theme::warning()));
    clear_surface(frame, area);
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

/// The standard bordered panel: rounded, one column of breathing room either
/// side, a bold title in the accent, and a border in `theme::hint()` so the
/// frame stays quieter than what is inside it.
///
/// Every screen goes through this rather than building its own `Block`, and
/// `no_screen_hand_rolls_its_own_block` pins that — a screen that builds its
/// own is a screen the next border change cannot reach, which is the same
/// failure mode as a screen that names its own colour and just as invisible
/// without a test.
pub fn panel(title: &str) -> Block<'static> {
    Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(theme::hint()))
        .padding(Padding::horizontal(1))
        .title(Span::styled(title.to_string(), Style::default().fg(theme::accent()).add_modifier(Modifier::BOLD)))
}

/// `panel`, with the border in the accent while focused — the convention
/// `file_browser::render_pane` already established for its two panes.
pub fn focus_panel(title: &str, focused: bool) -> Block<'static> {
    let border = if focused { theme::accent() } else { theme::hint() };
    panel(title).border_style(Style::default().fg(border))
}

/// A dialog: `panel` plus a row of vertical padding and the surface fill, so
/// it reads as sitting on top of the frame rather than cut out of it.
///
/// Vertical padding is deliberately *not* on `panel`: a list spends those rows
/// on entries, and rows are the thing this overhaul is trying to recover.
pub fn modal(title: &str) -> Block<'static> {
    panel(title).padding(Padding::new(2, 2, 1, 0)).style(theme::band())
}

/// The shared body of `render_form` and `render_panel`: `lines` in `block`,
/// scrolled by the smallest amount that keeps `focus_row` on screen, with the
/// border saying so.
fn render_lines_scrolled(frame: &mut Frame, rect: Rect, title: &str, lines: Vec<Line<'static>>, focus_row: usize, block: Block<'static>) {
    let inner = block.inner(rect);
    let visible = inner.height as usize;
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

    let block = block.title(Span::styled(title, Style::default().fg(theme::accent()).add_modifier(Modifier::BOLD)));
    frame.render_widget(Paragraph::new(lines).scroll((offset as u16, 0)).block(block), rect);
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
    render_lines_scrolled(frame, area, title, lines, focus_row, panel(""));
}

/// Below this a dialog has nothing left to say: the border and its padding
/// take four columns and two rows before a single character of content.
pub const MIN_PANEL_WIDTH: u16 = 44;
pub const MIN_PANEL_HEIGHT: u16 = 9;

/// The same thing as `render_form`, in a centred panel sized to its content
/// but clamped to the frame — and scrolled rather than truncated when the
/// clamp bites.
///
/// This is the fix for a whole class of bug, not one screen's layout.
/// `centered_rect(w, lines.len() + 2, area)` clamps the *rect* and then the
/// paragraph silently loses whatever did not fit, so a security mode could be
/// selectable and invisible at the same time. Here the clamp becomes a scroll
/// and the ↑/↓ markers say so.
///
/// The height counts *wrapped* rows: a panel sized as if every line were one
/// row loses its hint the moment a message is long enough to wrap, which is
/// how a long server name used to push the y/n prompt off a confirm dialog.
pub fn render_panel(
    frame: &mut Frame,
    area: Rect,
    width: u16,
    title: &str,
    lines: Vec<Line<'static>>,
    focus_row: usize,
    too_small_message: &str,
) {
    if render_if_too_small(frame, area, MIN_PANEL_WIDTH, MIN_PANEL_HEIGHT, too_small_message) {
        return;
    }

    let block = modal(title);
    // Derived from the frame rather than trusted from the caller: the same
    // screen runs full-width at first run and 24 columns narrower inside the
    // Settings tab that embeds it.
    let width = width.min(area.width.saturating_sub(4)).max(MIN_PANEL_WIDTH);
    // Two for the border, four for the horizontal padding.
    let content_width = width.saturating_sub(6);
    let height = (wrapped_height(&lines, content_width) as u16 + 3).min(area.height);
    let rect = centered_rect(width, height, area);

    clear_surface(frame, rect);
    render_lines_scrolled(frame, rect, title, lines, focus_row, block);
}

/// The marker beside a selected row. Paired with `theme::selection()`, and the
/// half of the pair that still works with no colour at all.
pub const SELECT_MARKER: &str = "\u{258c} ";

/// A list in a panel, with an empty state that is a message rather than a row.
///
/// The empty state is the reason this exists. Handing `List` a single
/// `ListItem` saying "no scripts yet" made the placeholder pick up the
/// selection style and the marker, so a sentence the user cannot act on was
/// drawn as the highlighted, selectable row. Here it is centred, dimmed, and
/// outside the list entirely; `state` is not even consulted.
pub fn render_list(
    frame: &mut Frame,
    area: Rect,
    title: &str,
    items: Vec<ListItem<'static>>,
    state: &mut ListState,
    empty_message: Option<&str>,
    focused: bool,
) {
    let block = focus_panel(title, focused);
    if let Some(message) = empty_message.filter(|_| items.is_empty()) {
        let inner = block.inner(area);
        frame.render_widget(block, area);
        // Vertically centred as well as horizontally: an empty list is mostly
        // frame, and a message pinned to the top edge of it reads as a row.
        let row = Rect { y: inner.y + inner.height / 2, height: 1, ..inner };
        frame.render_widget(
            Paragraph::new(message.to_string()).alignment(Alignment::Center).style(Style::default().fg(theme::hint())),
            row,
        );
        return;
    }

    let list = List::new(items).block(block).highlight_style(theme::selection()).highlight_symbol(SELECT_MARKER);
    frame.render_stateful_widget(list, area, state);
}

/// Rows a whole line list occupies once `Wrap` has had it.
pub fn wrapped_height(lines: &[Line], width: u16) -> usize {
    lines.iter().map(|l| wrapped_rows(&l.to_string(), width)).sum()
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

    /// A screen that builds its own block is a screen the next border change
    /// cannot reach — the same failure mode as a screen that names its own
    /// colour, and just as invisible without a test. This check *is* the
    /// feature, exactly as with the missing `Default` on `Strings`.
    #[test]
    fn no_screen_hand_rolls_its_own_block() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/tui");
        let mut offenders = Vec::new();
        for entry in std::fs::read_dir(&dir).expect("src/tui is readable") {
            let path = entry.expect("dir entry").path();
            if path.extension().is_some_and(|e| e == "rs") && path.file_name().is_some_and(|n| n != "widgets.rs") {
                let text = std::fs::read_to_string(&path).expect("source is utf-8");
                if text.contains("Borders::") || text.contains("BorderType::") {
                    offenders.push(path.display().to_string());
                }
            }
        }
        assert!(offenders.is_empty(), "these build their own block instead of using widgets::panel: {offenders:?}");
    }

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
