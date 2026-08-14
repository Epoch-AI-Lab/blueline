# Adversarial verification of research-phase1 (run 2026-08-13)

Method: every claim below was checked against a fetched primary source — registry
endpoints (`registry.npmjs.org` full + corgi + per-version, `crates.io` API),
npm RFCs and CLI release notes, official docs (npm, Node, GitHub, git source),
incident postmortems and advisory/OSV entries (npm, ESLint, Mandiant,
BleepingComputer, GHSA/OSV). Anything the session could not trace to a fetched
source is marked **UNVERIFIABLE** and never assumed true.

Verdicts: **REFUTED** (wrong or fabricated), **UNVERIFIABLE** (couldn't confirm;
several are already correctly hedged in the source reports), **VERIFIED** (primary
source matches).

---

## REFUTED

| # | Claim (file:line) | Evidence | Impact |
|---|---|---|---|
| 1 | comfy-table "Current version **7.2.2**" + card-and-prompt.md:546 "all cited versions are current as of 2026-08-13" | crates.io: **8.0.0** published **2026-08-05** (8 days before the stated snapshot). 7.2.2 (2026-01-13) is a real version but is *not* current. | High. 8.0.0 is API-breaking: it removed `TableComponent`, `modifiers`, `apply_modifier`, and `presets` in favor of `TableStyle`/`custom_styling` (8.0.0 feature set: `_debug`, `_integration_test`, `custom_styling`, `default`, `reexport_crossterm`, `tty`). The report's recommended pin + its `UTF8_FULL`-preset/`apply_modifier` code snippets target the pre-8.0 API and will not compile against current comfy-table. |
| 2 | card-and-prompt.md:21 comfy-table "**88.3M** total downloads" | crates.io API `total_downloads` = **91,238,758** (~91.2M) on 2026-08-13. | Low (numeric drift, same order). |
| 3 | card-and-prompt.md:22 comfy-table "**1001** reverse dependents" | crates.io `reverse_dependencies` `meta.total` = **1147**. The report says it "couldn't confirm" — it is confirmable via the API. | Low. |
| 4 | card-and-prompt.md:52 tabled "**34.2M** total downloads" | crates.io = **35,375,720** (~35.4M). Version 0.21.0 + date 2026-05-31 are correct. | Low (numeric drift). |
| 5 | diff-engine.md:63 & :170 walkdir "2.5.0, published **2026-06-07**" | crates.io: 2.5.0 published **2024-03-01**; no release since. The "maintained as of 2026-06-07" framing is unsupported by any release. | Medium. The *feature* claims (symlink-following default off, Unlicense/MIT) are correct, but the currency/activity framing is wrong. |
| 6 | verdict-heuristics.md:181 event-stream exfil "when balances exceeded **100 BTC** / 1000 BCH" | npm postmortem (fetched via archive): exfiltration triggered only "if the wallet contained more than **1000 BTC or 1000 BCH**". The 1000 BCH half is right; the BTC threshold is wrong by 10x. | Low (incident detail; the diff-signal argument is unaffected). |
| 7 | node-shim.md:26/:81/:114 "npm's programmatic API was removed in npm v8.0.0 (**npm/cli#6407**)" | npm/cli#6407 is "Cannot install firebase package" (a 2023 bug report). The *underlying fact* is verified — npm's README explicitly says "npm is not intended to be a library" and to spawn the CLI in a child process — but the cited issue is wrong/fabricated. | Medium. Fix the citation; the conclusion (use `npm_execpath` delegation) is sound and verified. |
| 8 | verdict-heuristics.md:750 self-check: "Socket's gamma coefficients (c0, c1) **are not published**" | docs.socket.dev/docs/package-scores (page snapshot dated 2026-04-16) publishes the full formula **including c0 = c1 = 0.05**. The body's §5.2 formula is verified; the self-check is wrong. | Low (self-check only; the caution about the formula "not matching deployment" is real). |
| 9 | verdict-heuristics.md:764 self-check: keyv incident "the affected **package names were redacted** in the fetched content" | The Snyk blog names keyv@6.0.0 and all ten sibling releases (cacheable, ecto, etc.) outright. | Low (a misdescription of an openly named incident; no safety impact). |
| 10 | verdict-heuristics.md:213 ua-parser-js "**~8M** weekly downloads" | The report's own cited Mandiant/Google Cloud source says "over **7 million** downloads per week". | Low (rounding drift). |

## UNVERIFIABLE (not traced to a primary source this session)

- TanStack `router_init.js` exact byte count **2,341,681** (diff-engine.md:33). GHSA says "~2.3 MB"; the byte-exact figure appears only in secondary analyses. Report's self-check admits it didn't reverse the tarballs.
- "Detection came **20-26 minutes** after each publish batch" (verdict-heuristics.md:265). Not present in GHSA/OSV. Attributed to TanStack postmortem/StepSecurity.
- "two per package, **about 6 minutes apart**" — GHSA says only "published a few minutes apart".
- node-ipc Snyk "**CVSS 9.8**" — Snyk's vuln page is a JS shell; the number could not be fetched this session. Consistent with common documentation, but not independently confirmed.
- OSV "npm ≈ **70.5%** of vulnerability records" — OSV's stats surface wasn't fetchable; the report quotes OSV's own disclaimer. Correctly hedged.
- ACSAC 2023 "**81%** of confirmed-malicious packages used install hooks" — the report itself hedges ("citation needed; couldn't re-verify from the PDF"). Correctly hedged.
- sandworm "publishes no weights" — not fetched; the report correctly refuses to assert SWRM-201. Correctly hedged.
- socket "depscore = average of factor scores" (older API docs) — not re-fetched.

## VERIFIED (primary-source, high confidence)

**Dependencies (crates.io API):**
- similar 3.1.2 current (2026-08-04, Apache-2.0); features std/text/unicode/bytes/inline/serde(implicit)/wasm32_web_time/hashbrown; default build has zero deps; Rust 1.88 MSRV claim supported.
- comfy-table 7.2.2 default features = `["tty"]` → **crossterm is pulled by default** (the report's core "disable `tty`" argument is correct). `custom_styling` exists only in 8.0.0.
- tabled 0.21.0 (2026-05-31) default features = `derive`, `macros`, `assert`.
- owo-colors 4.3.0 (2026-02-22): MSRV 1.81; normal deps = `supports-color` (optional) → zero deps by default.
- inquire 0.9.4 (2026-02-24, MIT, MSRV 1.80): default features `macros`, `crossterm`, `one-liners`, `fuzzy`; non-optional deps only bitflags/dyn-clone/unicode-segmentation/unicode-width (chrono/console/crossterm/fuzzy-matcher/tempfile/termion all optional).
- colored 3.1.1 (2026-01-16, MPL-2.0), dialoguer 0.12.0 (2025-08-23, MIT), diff 0.1.13 (2022-06-29, LCS, frozen since) — versions/dates/licenses verified.
- comfy-table reverse-dependents figure: see REFUTED #3.

**Registry mechanics (live registry):**
- Corgi packument omits `time` (full doc has it; `dist-tags`, `modified`, `name`, `versions` only). Verified empirically — exact claim, baseline-resolution.md:11.
- Per-version endpoints: 200 for live versions, 404 for unpublished/removed. Unpublished versions vanish from `versions` but persist in `time` (30 ghosts on one checked package); tarballs 404 (ua-parser-js 0.7.29/0.8.0/1.0.0).
- `dist.signatures` payload = `${name}@${version}:${integrity}`, Ed25519 (registry docs + live probe). npm audit responses carry a `signatures` array (keyid/sig); npm audit docs state the report is signed with an Ed25519 key and npm verifies it.

**npm/ecosystem policy (release notes + RFCs):**
- npm v11.10.0 added `min-release-age` via PR #9173 (release body confirmed; off by default).
- npm v12.0.0: "default ignore-scripts to true #9137", "default allow-scripts=false #9138" (release body confirmed).
- RFC 0054 = `accepted/0054-make-scripts-install-opt-in.md` (title "Make install scripts opt-in", accepted 2026-06-08) — the report cites this exact path. The quoted "Denials are always recorded name-only … conservative for approve and permissive for deny" and "`nx@<21.6.4` would automatically trust future versions" passages are verbatim.
- pnpm `minimum-release-age` default = 1 day since v11.
- npm README: no programmatic API; spawn the CLI. npm/cli#1935 (npx CI auto-confirm) and npm/cli#4828 fixed by PR #4847 "include all platform-specific optional deps in lockfile" (merged 2023-01-04, i.e. the npm 9.1.0 window).
- npm/cli#4828 shape (missing optional deps in lockfiles) is real.

**Launcher patterns (source):**
- biome `bin/biome`: `spawnSync(require.resolve(binPath), process.argv.slice(2), { shell: false, stdio: "inherit" })`, 8 platform optional deps, musl ladder via `ldd --version` — verified against biome main. (Note: the published @biomejs/biome 2.5.8 tarball now ships a compiled `bin/biome`; the JS launcher remains the repo/main pattern and the exit-code logic claim is correct.)
- esbuild PR #1621 = "install using optionalDependencies", merged 2021-09-22.
- Node `util.convertProcessSignalToExitCode` added in v18.14.0, v20.17.0, v22.7.0.

**Diff-engine failure modes:**
- git: `buffer_is_binary` scans the first 8000 bytes for a NUL byte; `bigFileThreshold` default 512 MiB (git source).
- GitHub: diffs capped at 20,000 lines, 300 files, 1 MB per PR; per-file >500KB cannot render (current docs).

**Incident facts:**
- eslint-scope: 3.7.2 + eslint-config-eslint 5.0.2, live 37 minutes, 36,711 downloads, pastebin payload, `~/.npmrc`/`_authToken` theft via Referer to histats/statcounter (ESLint postmortem).
- event-stream: ~2M weekly / "over 8 million times" over the campaign (npm postmortem); AES key = importing package's description; C2 IP 111.90.151.134; dependency merge commit 5e0938e7 "Merge pull request #116 … flatmap-stream" dated 2018-09-09 (GitHub). GHSA-vh95-pgmr-g4p5 exists in OSV.
- coa/rc: versions rc 1.2.9/1.3.9/2.3.9 and coa 2.0.3/2.0.4/2.1.1/2.1.3/3.0.1/3.1.3, `compile.bat`, password-stealer, ~23M weekly downloads, 2021-11-04, UNC3379 (BleepingComputer + Mandiant). All now 404 at per-version endpoints (purged).
- ua-parser-js: 0.7.29/0.8.0/1.0.0, 2021-10-22, account hijack (maintainer issue #536 opened Oct 22, 2021); Monero miner + DANABOT DLL; coa/rc same actor (Mandiant). Weekly figure: see REFUTED #10.
- TanStack (GHSA-g7cv-rxg3-hmpx = CVE-2026-45321, OSV 200): 84 versions / 42 packages, published 2026-05-11 19:20–19:26 UTC; OIDC trusted-publisher via `pull_request_target` "Pwn Request" + Actions cache poisoning + OIDC token extraction; optionalDependencies `@tanstack/setup: github:tanstack/router#79ac49eedf774dd4b0cfa308722bc463cfe5885c`; prepare `bun run tanstack_runner.js && exit 1` (npm silently discards the failed optional install); `router_init.js` ~2.3 MB at tarball root, deliberately not in `files`; cred harvest (AWS/GCP/K8s/Vault/npm/GitHub/SSH); exfil via Session/Oxen (filev2.getsession.org, seed{1,2,3}.getsession.org); self-propagation via `maintainer:` search + republish. **SLSA/provenance is not mentioned in the OSV entry** — the report's own attribution ("valid SLSA provenance" from TanStack/StepSecurity; L3 not asserted) is the honest reading.
- keyv family (Snyk, 2026-08-04): 11 releases, preinstall `node setup.mjs`, 727,680-byte `Math_Symbol.js` stage, 8 releases still `latest` at 11:16 UTC, byte-identical dist vs clean RC, no CVE/GHSA (OSV query for keyv returns empty) — all verified; only the "redacted names" self-check is wrong (REFUTED #9).
- ICSE 2022 "Small World with High Risks" (Zimmermann et al., arXiv 2102.09242): 2022-02-02 snapshot, 1.63M packages, 6,085 (0.37%) with install scripts, 33,249 (2.2%) with a `scripts` field — verified from the paper's abstract.

**Socket formula:** docs.socket.dev/docs/package-scores (2026-04-16): full formula incl. `gamma ≈ 1/2 + c0*log(lines) + c1*log(popularity)` with **c0 = c1 = 0.05**, weights incl. low=4, and CLI score<20 block / `--yolo` override. The report's body is right; only its self-check (REFUTED #8) is wrong.

**npq:** initial commit of lirantal/npq authored by **Rimas Silkaitis** (now maintained by Liran Tal) — the report's attribution is correct. Marshalls 22d/7d/21d/183d/274d/15s verified.

---

## What this means for the reports

The refutations are overwhelmingly in **dependency currency/metadata** (card-and-prompt) and **citation details** (node-shim), not in the engineering argument:

1. **card-and-prompt** must be rebased onto comfy-table **8.0.0** (or pin 7.2.2 explicitly as an intentional, documented stale pin). The structural argument survives: `tty` (default-on) drags crossterm 0.29; drop default features; use explicit width + `IsTerminal`. The presets/modifiers API examples need updating to `TableStyle`.
2. **node-shim**: the design is verified against three real launchers; only the npm/cli#6407 citation is wrong. npm's official position is still "spawn the CLI".
3. **diff-engine**'s failure-mode taxonomy (git 512 MiB / 8000-byte NUL scan, GitHub 20k/300/1MB) is verified; only the walkdir currency claim is wrong.
4. **verdict-heuristics**: the incident spine is verified with two numeric drifts (1000 BTC threshold, ~8M→7M weekly) and two misattributed self-checks (Socket gamma, keyv redaction). The four "couldn't verify" hedges (OSV 70.5%, ACSAC 81%, sandworm weights, TanStack byte count/detection window) are appropriately hedged.
5. **baseline-resolution**: registry mechanics, lockfile semantics, integrity-binding, signing payload, RFC 0054 quotes, and the poisoning-primitive finding in `review.rs`/`store.rs` all verify cleanly.
