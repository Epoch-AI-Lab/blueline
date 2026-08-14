use comfy_table::modifiers::UTF8_ROUND_CORNERS;
use comfy_table::presets::UTF8_FULL;
use comfy_table::{Cell, Color, ContentArrangement, Table};

use crate::diff::Delta;
use crate::verdict::{Verdict, VerdictBand};

pub fn sanitize_for_terminal(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            if let Some(&next) = chars.peek() {
                if next == '[' {
                    // CSI sequence: consume until 0x40..=0x7E
                    chars.next();
                    for csi in chars.by_ref() {
                        if (0x40..=0x7E).contains(&(csi as u32)) {
                            break;
                        }
                    }
                    continue;
                } else if next == ']' || next == 'P' || next == '_' || next == '^' || next == 'X' {
                    // OSC / DCS / APC / PM / SOS: consume until \x07 (BEL) or \x1b\ (ST)
                    chars.next();
                    let mut prev = '\0';
                    for osc in chars.by_ref() {
                        if osc == '\x07' || (prev == '\x1b' && osc == '\\') {
                            break;
                        }
                        prev = osc;
                    }
                    continue;
                } else {
                    // 2-byte escape sequence (e.g. \x1bN, \x1bO)
                    chars.next();
                    continue;
                }
            }
            continue;
        }
        // Control chars (< 0x20, \r, DEL 0x7F, C1 controls 0x80..=0x9F)
        let code = c as u32;
        if c == '\n' || c == '\t' {
            out.push(c);
        } else if code < 0x20 || code == 0x7f || (0x80..=0x9f).contains(&code) {
            // Strip control characters
            continue;
        } else {
            out.push(c);
        }
    }
    out
}

pub fn sanitize_terminal(input: &str) -> String {
    sanitize_for_terminal(input)
}

pub fn render_text(verdict: &Verdict, delta: &Delta) {
    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .apply_modifier(UTF8_ROUND_CORNERS)
        .set_content_arrangement(ContentArrangement::Dynamic);

    // Title / Header
    let base_display = match &verdict.baseline_version {
        Some(b) => format!("baseline {b}"),
        None => "no baseline (first sighting)".to_string(),
    };

    let title = sanitize_for_terminal(&format!(
        "BLUELINE REVIEW: {}@{}",
        verdict.name, verdict.target_version
    ));
    let base_header = sanitize_for_terminal(&base_display);

    table.set_header(vec![
        Cell::new(title).fg(Color::Cyan),
        Cell::new(base_header).fg(Color::DarkGrey),
    ]);

    // Integrity row
    table.add_row(vec![
        Cell::new("Integrity").fg(Color::White),
        Cell::new(sanitize_for_terminal(&verdict.integrity)).fg(Color::Green),
    ]);

    // Verdict row
    let (band_color, band_label) = match verdict.band {
        VerdictBand::Low => (Color::Green, "[ LOW RISK ]"),
        VerdictBand::Medium => (Color::Yellow, "[ MEDIUM RISK ]"),
        VerdictBand::High => (Color::Red, "[ HIGH RISK ]"),
        VerdictBand::Block => (Color::DarkRed, "[ BLOCK ]"),
    };

    let verdict_str =
        sanitize_for_terminal(&format!("{band_label} (Score: {}/100)", verdict.risk_score));
    table.add_row(vec![
        Cell::new("Verdict").fg(Color::White),
        Cell::new(verdict_str).fg(band_color),
    ]);

    // Delta summary row
    let delta_str = sanitize_for_terminal(&format!(
        "Files: +{} / -{} / ~{}  |  Lines: +{} / -{}",
        verdict.diff_summary.files_added,
        verdict.diff_summary.files_removed,
        verdict.diff_summary.files_modified,
        verdict.diff_summary.lines_added,
        verdict.diff_summary.lines_deleted,
    ));
    table.add_row(vec![
        Cell::new("Delta").fg(Color::White),
        Cell::new(delta_str),
    ]);

    // Lifecycle scripts
    let scripts_str =
        if delta.new_lifecycle_scripts.is_empty() && delta.modified_lifecycle_scripts.is_empty() {
            "none".to_string()
        } else {
            let mut parts = Vec::new();
            for s in &delta.new_lifecycle_scripts {
                parts.push(format!("+{}", sanitize_for_terminal(s)));
            }
            for s in &delta.modified_lifecycle_scripts {
                parts.push(format!("~{}", sanitize_for_terminal(s)));
            }
            parts.join(", ")
        };
    let script_color = if scripts_str == "none" {
        Color::Green
    } else {
        Color::Red
    };
    table.add_row(vec![
        Cell::new("Install Scripts").fg(Color::White),
        Cell::new(sanitize_for_terminal(&scripts_str)).fg(script_color),
    ]);

    println!("{table}");

    // Findings breakdown
    if !verdict.findings.is_empty() {
        println!("\nSecurity Findings ({}):", verdict.findings.len());
        for f in &verdict.findings {
            let tag = match f.severity {
                VerdictBand::Block => "  [BLOCK]  ",
                VerdictBand::High => "  [HIGH]   ",
                VerdictBand::Medium => "  [MEDIUM] ",
                VerdictBand::Low => "  [INFO]   ",
            };
            println!(
                "{} {}: {}",
                tag,
                sanitize_for_terminal(&f.title),
                sanitize_for_terminal(&f.description)
            );
        }
    }
}

pub fn render_json(verdict: &Verdict) -> anyhow::Result<()> {
    let out = serde_json::to_string(verdict)?;
    println!("{out}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitizes_escape_sequences_and_control_chars() {
        let malicious = "\x1b[2J\x1b[31;1mInjected Title\x1b[0m\r\n\x08Evil\x1b]0;Hack\x07";
        let clean = sanitize_for_terminal(malicious);
        assert!(!clean.contains('\x1b'));
        assert!(!clean.contains('\r'));
        assert!(!clean.contains('\x08'));
        assert!(!clean.contains('\x07'));
        assert!(clean.contains("Injected Title"));
        assert!(clean.contains("Evil"));
    }

    #[test]
    fn preserves_newlines_tabs_and_normal_text() {
        let normal = "Normal Title: 1.0.0\nLine 2\tTabbed";
        let clean = sanitize_for_terminal(normal);
        assert_eq!(clean, normal);
    }
}
