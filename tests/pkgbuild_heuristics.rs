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
        for finding in findings {
            if above_info(&finding.severity) {
                let fixture = file
                    .parent()
                    .and_then(|parent| parent.file_name())
                    .map(|name| name.to_string_lossy().into_owned())
                    .unwrap_or_default();
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
