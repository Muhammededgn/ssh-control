use qrcode::QrCode;
use qrcode::render::unicode;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::text::Line;

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
