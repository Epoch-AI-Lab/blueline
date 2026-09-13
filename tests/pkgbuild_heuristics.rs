use std::fs;
use std::path::PathBuf;

use blueline::pkgbuild::review_text;
use blueline::verdict::VerdictBand;

fn benign_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("pkgbuild_benign")
}

fn above_info(band: &VerdictBand) -> bool {
    !matches!(band, VerdictBand::Low)
}

/// R23 graduated from INFO once recursive review resolved what the
/// delivery line points at. These corpus fixtures genuinely run
/// `npm install` in their build (electron-class source builds), so their
/// R23 hits are true positives, not false ones — the gate stays strict
/// for every other rule and every other fixture.
const R23_TRUE_POSITIVE_FIXTURES: [&str; 3] =
    ["016-insomnia", "018-bitwarden-cli", "078-joplin-desktop"];

#[test]
fn benign_corpus_scores_zero_above_info() {
    let dir = benign_dir();
    let mut files: Vec<PathBuf> = fs::read_dir(&dir)
        .unwrap()
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| path.is_dir())
        .map(|path| path.join("PKGBUILD"))
        .filter(|path| path.is_file())
        .collect();
    files.sort();
    assert!(
        files.len() >= 100,
        "benign corpus needs 100+ PKGBUILDs, found {}",
        files.len()
    );
    let mut loud = Vec::new();
    for file in &files {
        let content = fs::read_to_string(file).unwrap();
        let findings = review_text(&content).unwrap();
        let fixture = file
            .parent()
            .and_then(|parent| parent.file_name())
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        for finding in findings {
            if finding.rule_id == "R23_NPM_DELIVERY"
                && R23_TRUE_POSITIVE_FIXTURES.contains(&fixture.as_str())
            {
                continue;
            }
            if above_info(&finding.severity) {
                loud.push(format!(
                    "{} {} [{}] {}",
                    fixture, finding.rule_id, finding.severity, finding.evidence
                ));
            }
        }
    }
    assert!(
        loud.is_empty(),
        "benign corpus fired {} rules above INFO:\n{}",
        loud.len(),
        loud.join("\n")
    );
}

#[test]
fn r23_is_medium_and_fires_on_all_three_true_positive_fixtures() {
    for fixture in R23_TRUE_POSITIVE_FIXTURES {
        let path = benign_dir().join(fixture).join("PKGBUILD");
        let content = fs::read_to_string(&path).unwrap();
        let findings = review_text(&content).unwrap();
        let hits: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "R23_NPM_DELIVERY")
            .collect();
        assert!(
            !hits.is_empty(),
            "{fixture}: expected R23 to fire, got none"
        );
        for hit in hits {
            assert_eq!(
                hit.severity,
                VerdictBand::Medium,
                "{fixture}: R23 must stay MEDIUM"
            );
        }
    }
}
