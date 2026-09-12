use comfy_table::modifiers::UTF8_ROUND_CORNERS;
use comfy_table::presets::UTF8_FULL;
use comfy_table::{Cell, Color, ContentArrangement, Table};

use crate::diff::Delta;
use crate::verdict::{Verdict, VerdictBand};

fn is_dangerous_unicode(c: char) -> bool {
    matches!(
        c,
        '\u{061C}' // Arabic letter mark
            | '\u{200B}'..='\u{200F}' // Zero-width spaces & directional marks
            | '\u{202A}'..='\u{202E}' // BiDi embedding / override
            | '\u{2066}'..='\u{2069}' // BiDi isolate
            | '\u{FEFF}' // Byte order mark / zero-width no-break space
    )
}

pub fn sanitize_for_terminal(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            if let Some(&next) = chars.peek() {
                if next == '[' {
                    // CSI sequence: consume until 0x40..=0x7E (final byte)
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

        if is_dangerous_unicode(c) {
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

pub fn sanitize_single_line(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            if let Some(&next) = chars.peek() {
                if next == '[' {
                    // CSI sequence: consume until 0x40..=0x7E (final byte)
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

        if is_dangerous_unicode(c) {
            continue;
        }

        match c {
            '\n' | '\r' | '\t' | '\u{000B}' | '\u{000C}' | '\u{0085}' | '\u{2028}' | '\u{2029}' => {
                out.push(' ');
            }
            _ => {
                let code = c as u32;
                if code >= 0x20 && code != 0x7f && !(0x80..=0x9f).contains(&code) {
                    out.push(c);
                }
            }
        }
    }
    out
}

pub fn sanitize_terminal(input: &str) -> String {
    sanitize_for_terminal(input)
}

pub fn render_text(verdict: &Verdict, delta: &Delta) {
    print!("{}", render_text_to_string(verdict, delta));
}

/// Cap on child reviews displayed on the card: the engine's fan-out is
/// bounded by the recursion policy, but memo reuse can attach more; the
/// rest is counted, never silently dropped.
const MAX_RENDERED_CHILDREN: usize = 8;

/// Cap on child findings rendered per child review.
const MAX_RENDERED_CHILD_FINDINGS: usize = 3;

pub fn render_text_to_string(verdict: &Verdict, delta: &Delta) -> String {
    let mut out = String::new();
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

    let title = sanitize_single_line(&format!(
        "BLUELINE REVIEW: {}@{}",
        verdict.name, verdict.target_version
    ));
    let base_header = sanitize_single_line(&base_display);

    table.set_header(vec![
        Cell::new(title).fg(Color::Cyan),
        Cell::new(base_header).fg(Color::DarkGrey),
    ]);

    // Integrity row
    table.add_row(vec![
        Cell::new("Integrity").fg(Color::White),
        Cell::new(sanitize_single_line(&verdict.integrity)).fg(Color::Green),
    ]);

    // Ecosystem row
    table.add_row(vec![
        Cell::new("Ecosystem").fg(Color::White),
        Cell::new(verdict.ecosystem.key()).fg(Color::Cyan),
    ]);

    // Verdict row
    let (band_color, band_label) = match verdict.band {
        VerdictBand::Low => (Color::Green, "[ LOW RISK ]"),
        VerdictBand::Medium => (Color::Yellow, "[ MEDIUM RISK ]"),
        VerdictBand::High => (Color::Red, "[ HIGH RISK ]"),
        VerdictBand::Block => (Color::DarkRed, "[ BLOCK ]"),
    };

    let verdict_str =
        sanitize_single_line(&format!("{band_label} (Score: {}/100)", verdict.risk_score));
    table.add_row(vec![
        Cell::new("Verdict").fg(Color::White),
        Cell::new(verdict_str).fg(band_color),
    ]);

    // Delta summary row
    let delta_str = sanitize_single_line(&format!(
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
    let mut scripts_str = String::new();
    for s in &delta.new_lifecycle_scripts {
        if !scripts_str.is_empty() {
            scripts_str.push_str(", ");
        }
        scripts_str.push('+');
        scripts_str.push_str(&sanitize_single_line(s));
    }
    for s in &delta.modified_lifecycle_scripts {
        if !scripts_str.is_empty() {
            scripts_str.push_str(", ");
        }
        scripts_str.push('~');
        scripts_str.push_str(&sanitize_single_line(s));
    }
    if scripts_str.is_empty() {
        scripts_str = "none".to_string();
    }
    let script_color = if scripts_str == "none" {
        Color::Green
    } else {
        Color::Red
    };
    table.add_row(vec![
        Cell::new("Install Scripts").fg(Color::White),
        Cell::new(sanitize_single_line(&scripts_str)).fg(script_color),
    ]);

    // Trust Sources (Phase 2)
    if let Some(ref ts) = verdict.trust_sources {
        if let Some(ref adv) = ts.advisories {
            let (adv_label, adv_color) = match adv.status {
                crate::advisory::AdvisoryStatus::Clean => (
                    "[ CLEAN ] 0 known OSV/GHSA advisories".to_string(),
                    Color::Green,
                ),
                crate::advisory::AdvisoryStatus::Vulnerable => (
                    format!("[ VULNERABLE ] {} advisory hit(s)", adv.hits.len()),
                    Color::Red,
                ),
                crate::advisory::AdvisoryStatus::StaleCache => (
                    "[ STALE CACHE ] offline fallback".to_string(),
                    Color::Yellow,
                ),
                crate::advisory::AdvisoryStatus::Unverified => (
                    "[ UNVERIFIED ] unreachable (offline)".to_string(),
                    Color::Yellow,
                ),
            };
            table.add_row(vec![
                Cell::new("Advisories (OSV)").fg(Color::White),
                Cell::new(sanitize_single_line(&adv_label)).fg(adv_color),
            ]);
        }

        if let Some(ref prov) = ts.provenance {
            let (prov_label, prov_color) = match prov.status {
                crate::provenance::ProvenanceStatus::Verified => (
                    format!("[ SLSA Level {} ] Verified Builder", prov.slsa_level),
                    Color::Green,
                ),
                crate::provenance::ProvenanceStatus::FailedMismatch => {
                    ("[ DIGEST MISMATCH ]".to_string(), Color::DarkRed)
                }
                crate::provenance::ProvenanceStatus::Missing => {
                    ("none (unattested)".to_string(), Color::DarkGrey)
                }
                crate::provenance::ProvenanceStatus::Unverified => {
                    ("unverified".to_string(), Color::Yellow)
                }
            };
            table.add_row(vec![
                Cell::new("Provenance").fg(Color::White),
                Cell::new(sanitize_single_line(&prov_label)).fg(prov_color),
            ]);

            if let Some(ref repo) = prov.source_repo {
                table.add_row(vec![
                    Cell::new("Source Repo").fg(Color::White),
                    Cell::new(sanitize_single_line(repo)).fg(Color::Cyan),
                ]);
            }

            if prov.registry_signature_present {
                table.add_row(vec![
                    Cell::new("Registry Signature").fg(Color::White),
                    Cell::new("[ VALID ] Signed by npm Registry").fg(Color::Green),
                ]);
            }
        }
    }

    out.push_str(&format!("{table}\n"));

    // Second-order reviews: the delivery chain and each referenced
    // package's verdict, so the parent card tells the whole story.
    if !verdict.recursive.is_empty() {
        out.push_str(&format!(
            "\nRecursive Reviews ({}):\n",
            verdict.recursive.len()
        ));
        for child in verdict.recursive.iter().take(MAX_RENDERED_CHILDREN) {
            out.push_str(&format!(
                "  delivered via: {} — {}:{}@{} [{}] (score {}), {} finding(s)\n",
                sanitize_single_line(&child.chain.join(" → ")),
                child.ecosystem.key(),
                sanitize_single_line(&child.name),
                sanitize_single_line(&child.version),
                child.band,
                child.risk_score,
                child.findings.len(),
            ));
            for f in child.findings.iter().take(MAX_RENDERED_CHILD_FINDINGS) {
                out.push_str(&format!(
                    "    [{}] {}: {}\n",
                    f.severity,
                    sanitize_single_line(&f.rule_id),
                    sanitize_single_line(&f.title),
                ));
            }
            if child.findings.len() > MAX_RENDERED_CHILD_FINDINGS {
                out.push_str(&format!(
                    "    … and {} more finding(s)\n",
                    child.findings.len() - MAX_RENDERED_CHILD_FINDINGS
                ));
            }
        }
        if verdict.recursive.len() > MAX_RENDERED_CHILDREN {
            out.push_str(&format!(
                "  … and {} more recursive review(s) (see JSON verdict)\n",
                verdict.recursive.len() - MAX_RENDERED_CHILDREN
            ));
        }
    }

    // Findings breakdown
    if !verdict.findings.is_empty() {
        out.push_str(&format!(
            "\nSecurity Findings ({}):\n",
            verdict.findings.len()
        ));
        for f in &verdict.findings {
            let tag = match f.severity {
                VerdictBand::Block => "  [BLOCK]  ",
                VerdictBand::High => "  [HIGH]   ",
                VerdictBand::Medium => "  [MEDIUM] ",
                VerdictBand::Low => "  [INFO]   ",
            };
            out.push_str(&format!(
                "{} {}: {}\n",
                tag,
                sanitize_single_line(&f.title),
                sanitize_single_line(&f.description)
            ));
        }
    }
    out
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
    fn sanitizes_long_osc_hyperlinks_and_payloads() {
        let long_osc = "\x1b]8;;https://attacker.com/very/long/malicious/url/that/exceeds/sixty/four/characters/payload\x07Click Me\x1b]8;;\x07";
        let clean = sanitize_for_terminal(long_osc);
        assert_eq!(clean, "Click Me");

        let single = sanitize_single_line(long_osc);
        assert_eq!(single, "Click Me");
    }

    #[test]
    fn sanitizes_dcs_apc_pm_sos_and_st_terminators() {
        // DCS with ST
        let dcs = "\x1bPpayload\x1b\\Normal";
        assert_eq!(sanitize_for_terminal(dcs), "Normal");
        assert_eq!(sanitize_single_line(dcs), "Normal");

        // DCS with backslashes in payload before ST terminator
        let dcs_with_slashes = "\x1bPdata\\with\\backslashes\x1b\\Normal";
        assert_eq!(sanitize_for_terminal(dcs_with_slashes), "Normal");
        assert_eq!(sanitize_single_line(dcs_with_slashes), "Normal");

        // APC with BEL
        let apc = "\x1b_apc_data\x07Normal";
        assert_eq!(sanitize_for_terminal(apc), "Normal");
        assert_eq!(sanitize_single_line(apc), "Normal");

        // PM with ST
        let pm = "\x1b^pm_data\x1b\\Normal";
        assert_eq!(sanitize_for_terminal(pm), "Normal");
        assert_eq!(sanitize_single_line(pm), "Normal");

        // SOS with BEL
        let sos = "\x1bXsos_data\x07Normal";
        assert_eq!(sanitize_for_terminal(sos), "Normal");
        assert_eq!(sanitize_single_line(sos), "Normal");

        // 2-byte escapes (e.g. \x1bN, \x1bO)
        let two_byte = "\x1bN\x1bONormal";
        assert_eq!(sanitize_for_terminal(two_byte), "Normal");
        assert_eq!(sanitize_single_line(two_byte), "Normal");
    }

    #[test]
    fn preserves_newlines_tabs_and_normal_text() {
        let normal = "Normal Title: 1.0.0\nLine 2\tTabbed";
        let clean = sanitize_for_terminal(normal);
        assert_eq!(clean, normal);

        // Only newline
        assert_eq!(sanitize_for_terminal("Line 1\nLine 2"), "Line 1\nLine 2");
        // Only tab
        assert_eq!(sanitize_for_terminal("Col 1\tCol 2"), "Col 1\tCol 2");
    }

    #[test]
    fn filters_bidi_and_trojan_source_characters() {
        let bidi = "legit\u{202E}txt.exe\u{202D}end";
        let clean = sanitize_for_terminal(bidi);
        assert!(!clean.contains('\u{202E}'));
        assert!(!clean.contains('\u{202D}'));
        assert_eq!(clean, "legittxt.exeend");
    }

    #[test]
    fn sanitize_single_line_removes_newlines_and_tabs() {
        let multi = "Header\n[ BLOCK ] fake\tline\u{2028}line2\u{2029}line3";
        let single = sanitize_single_line(multi);
        assert!(!single.contains('\n'));
        assert!(!single.contains('\t'));
        assert!(!single.contains('\u{2028}'));
        assert!(!single.contains('\u{2029}'));
        assert_eq!(single, "Header [ BLOCK ] fake line line2 line3");
    }

    #[test]
    fn render_text_and_json_with_lifecycle_scripts_and_findings() {
        let delta = crate::diff::Delta {
            baseline_version: Some("1.0.0".into()),
            target_version: "1.1.0".into(),
            files_added: vec![],
            files_removed: vec![],
            files_modified: vec![],
            total_lines_added: 10,
            total_lines_deleted: 2,
            new_executables: vec![],
            new_binaries: vec![],
            modified_binaries: vec![],
            new_lifecycle_scripts: vec!["postinstall".into()],
            modified_lifecycle_scripts: vec!["preinstall".into()],
            new_dependencies: vec![],
            modified_dependencies: vec![],
            removed_dependencies: vec![],
            binding_gyp_added: false,
        };
        let verdict = crate::verdict::Verdict {
            name: "my-pkg".into(),
            target_version: "1.1.0".into(),
            baseline_version: Some("1.0.0".into()),
            integrity: "sha512-test".into(),
            ecosystem: crate::registry::Ecosystem::Npm,
            band: crate::verdict::VerdictBand::Block,
            risk_score: 75,
            findings: vec![crate::verdict::Finding {
                rule_id: "R02_NEW_INSTALL_SCRIPT".into(),
                severity: crate::verdict::VerdictBand::Block,
                title: "New install-time lifecycle script: `postinstall`".into(),
                description: "Package added a postinstall script".into(),
            }],
            diff_summary: crate::verdict::DiffSummary {
                files_added: 1,
                files_removed: 0,
                files_modified: 0,
                lines_added: 10,
                lines_deleted: 2,
            },
            trust_sources: None,
            recursive: Vec::new(),
        };

        render_text(&verdict, &delta);
        assert!(render_json(&verdict).is_ok());
    }

    #[test]
    fn card_renders_recursive_delivery_chains() {
        let delta = crate::diff::Delta::default();
        let child = crate::verdict::ChildReview {
            chain: vec!["my-pkg@1.1.0".into(), "npm:evil-pkg@2.0.0".into()],
            name: "evil-pkg".into(),
            version: "2.0.0".into(),
            ecosystem: crate::registry::Ecosystem::Npm,
            band: crate::verdict::VerdictBand::High,
            risk_score: 30,
            findings: vec![crate::verdict::Finding {
                rule_id: "R01_LIFECYCLE_SCRIPT_ADDED".into(),
                severity: crate::verdict::VerdictBand::High,
                title: "New install-time lifecycle script: `preinstall`".into(),
                description: "backdoored script".into(),
            }],
        };
        let verdict = crate::verdict::Verdict {
            name: "my-pkg".into(),
            target_version: "1.1.0".into(),
            baseline_version: Some("1.0.0".into()),
            integrity: "sha512-test".into(),
            ecosystem: crate::registry::Ecosystem::Npm,
            band: crate::verdict::VerdictBand::Block,
            risk_score: 75,
            findings: Vec::new(),
            diff_summary: crate::verdict::DiffSummary::default(),
            trust_sources: None,
            recursive: vec![child],
        };
        let card = render_text_to_string(&verdict, &delta);
        assert!(
            card.contains("delivered via: my-pkg@1.1.0 → npm:evil-pkg@2.0.0"),
            "{card}"
        );
        assert!(
            card.contains("npm:evil-pkg@2.0.0 [HIGH] (score 30), 1 finding(s)"),
            "{card}"
        );
        assert!(card.contains("[HIGH] R01_LIFECYCLE_SCRIPT_ADDED"), "{card}");
    }

    #[test]
    fn card_truncates_long_recursive_lists_without_silence() {
        let delta = crate::diff::Delta::default();
        let child = |name: String| crate::verdict::ChildReview {
            chain: vec!["root@1.0.0".into(), format!("npm:{name}@1.0.0")],
            name,
            version: "1.0.0".into(),
            ecosystem: crate::registry::Ecosystem::Npm,
            band: crate::verdict::VerdictBand::Low,
            risk_score: 0,
            findings: Vec::new(),
        };
        let verdict = crate::verdict::Verdict {
            name: "root".into(),
            target_version: "1.0.0".into(),
            baseline_version: None,
            integrity: "sha512-test".into(),
            ecosystem: crate::registry::Ecosystem::Npm,
            band: crate::verdict::VerdictBand::Low,
            risk_score: 0,
            findings: Vec::new(),
            diff_summary: crate::verdict::DiffSummary::default(),
            trust_sources: None,
            recursive: (0..10).map(|i| child(format!("pkg{i}"))).collect(),
        };
        let card = render_text_to_string(&verdict, &delta);
        assert!(card.contains("Recursive Reviews (10):"), "{card}");
        assert!(card.contains("pkg7"), "{card}");
        assert!(!card.contains("pkg8 ["), "{card}");
        assert!(card.contains("… and 2 more recursive review(s)"), "{card}");
    }

    mod proptest_invariants {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            #![proptest_config(ProptestConfig {
                failure_persistence: None,
                cases: 128,
                ..ProptestConfig::default()
            })]

            #[test]
            fn output_never_contains_bidi_characters(s in "\\PC*") {
                let clean = sanitize_for_terminal(&s);
                for c in clean.chars() {
                    prop_assert!(!is_dangerous_unicode(c));
                }
            }

            #[test]
            fn single_line_never_contains_linebreaks_or_tabs(s in "\\PC*") {
                let single = sanitize_single_line(&s);
                prop_assert!(!single.contains('\n'));
                prop_assert!(!single.contains('\r'));
                prop_assert!(!single.contains('\t'));
            }
        }
    }
}
