# Benign PKGBUILD corpus

137 real-world PKGBUILDs, one per directory, collected 2026-09-05 from the
AUR at the commits pinned in `manifest.tsv` (`pkgbase`, short commit, date).
Upstream headers are kept intact; each file stays under its own license
(mostly GPL/MIT), vendored here as static-analysis test fixtures.

The `benign_corpus_scores_zero_above_info` gate in
`tests/pkgbuild_heuristics.rs` runs every R-rule over this corpus and fails
on any finding above INFO. A firing rule ships demoted to INFO until tuned;
fixtures are never edited to make a rule pass.
