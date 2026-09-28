# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Fixed

- The two provenance attestation fetches no longer follow redirects to any host.
  The npm attestations call and the PyPI PEP 740 call each built their own
  `ureq::AgentBuilder` instead of going through `registry_agent`, so they
  inherited ureq's default of five redirects with no SSRF validation on any hop
  and no validating resolver. The configured base is operator config and is
  trusted, but the *response* is not: a registry — or anything able to answer for
  an `http://` base — could reply `302 Location: http://169.254.169.254/...` and
  have blueline follow it, or supply an attestation body from any host it liked.
  `registry_agent`'s documented purpose is that redirects stay off so each hop is
  validated by `follow_redirects` instead of followed blindly, and these were the
  only registry-facing fetches in `src/` bypassing it. Both now use a
  timeout-parameterised variant of the same agent, keeping their original 3s
  budget, and go through `download_bounded`, so every hop is checked.

  The size cap's direction was wrong there too: `take(1 MiB)` silently truncated
  a larger body, and the truncated text then failed to parse, so an over-cap
  response reported *missing* provenance for a release that has some — the
  parser mistaking "too much" for "nothing". Over the cap is now an error.

  Verified with a two-listener fixture that makes the two outcomes
  distinguishable: one server serves a genuinely attesting body, the other (the
  configured base) redirects to it. Following the redirect yields `Attested`;
  refusing it yields `Missing`. Confirmed failing 6 of 6 runs against the old
  code and passing 6 of 6 against the new. The first version of that fixture was
  itself flaky — it replied without reading the request, so closing the socket
  with unread bytes queued made the kernel send RST and truncate the response —
  which is why the control assertion is in the test: it proves the fixture can
  produce the vulnerable outcome at all.

- An advisory lookup that never happened is no longer reported as a clean
  advisory pass. `fetch_advisories` returns `Ok` both for a real answer and for
  an `unverified` report, and the review only inspected the `Err` arm — so a
  refused connection, a timeout, an unparseable body or an ecosystem with no
  coverage all produced `advisory_error = None` and no finding. An
  `unverified` report has no hits, so nothing downstream raised anything on its
  own, and the sole reader of the status anywhere was a colour label on the
  interactive card. CI's text and markdown summaries, the JSON verdict, the MCP
  response and `blueline agent`'s exit code were byte-identical for "the
  advisory host is down" and "OSV says this release is clean". A lockfile diff
  adding one already-baselined package printed `Status: PASSED` and exited 0
  with the network down.

  An unverified report with advisory checking *enabled* now raises
  `R09_ADVISORY_UNVERIFIED` at MEDIUM: a coverage hole worth saying out loud,
  not worth blocking on, and it escalates for anyone running a stricter
  `fail_on`. An actual `Err` stays HIGH. Advisories switched off in policy stays
  silent, because that is the operator's own choice made before the review ran
  rather than a hole discovered during it — the two are told apart by policy,
  not by matching on the message text.

  Consequence worth stating plainly, because it is visible: MEDIUM is above the
  band `blueline shim` and `blueline agent` gate on, so **a review that cannot
  reach the advisory host now refuses the install** rather than passing quietly.
  That is the fail-closed direction and it is what the disclosure is for, but it
  is a behaviour change for anyone behind a proxy, offline, or during an OSV
  outage. The ladder is now: `check_advisories = false` stays silent;
  advisories enabled and reachable answer as asked; enabled and unreachable
  disclose at MEDIUM under the default policy, or stop the review at HIGH under
  `fail_closed_network`.

- The AUR no longer claims clean advisory coverage from a source that has none.
  OSV has no AUR ecosystem, and it answers an unrecognised ecosystem with a
  `400`, so every AUR review fell into the same silent hole above — surfacing as
  an HTTP error string rather than a disclosure anyone wrote. `fetch_advisories`
  now refuses to ask and returns a named `unverified` report, which the review
  discloses at MEDIUM. Every AUR review now carries that disclosure until the
  adapter wires advisory handling properly. The recall index is unaffected: a
  curated revocation still blocks an AUR package exactly as it blocks any other.

- A requirement whose *name* looks like a filename is no longer silently dropped
  from the reviewed graph. The parser classified any token ending in `.txt` or
  `.in` as an option value, on the reasoning that `base.txt` is what `-r`
  consumes — but a PyPI project name may contain dots and end in a letter, so
  `payload.txt` and `payload.in` are valid names and `payload.txt==1.0.0` is a
  valid pin. The two cases are the same string, so the classification did not
  distinguish them; it only decided which one got dropped.
  `requests==2.31.0 --pre payload.txt` parsed as a truncated line: the pin
  survived and `payload.txt` vanished. A base of `payload.txt==1.0.0` plus
  `requests==2.28.0` therefore produced a delta reporting
  `removed: [payload.txt@1.0.0]` — and CI evaluates only `added` and `upgraded`,
  so a package pip still installs was never reviewed, while the report listed it
  under "Removed" as though it had been uninstalled. That is the exact hole the
  previous three entries describe this rule as closing, and it was still open.

  The fix refuses the ambiguous class rather than guessing, because whether `-r`
  consumes the next token is pip's business and this parser deliberately does not
  model it. Behaviour change worth stating plainly: under
  `[ci] allow_requirements_options = true`, `-r other.txt`, `--requirement
  other.txt`, `-c constraints.txt` and `--constraint constraints.txt` are now
  refused instead of tolerated. All four name a second file whose contents the
  parser never reads, so the opt-in cannot honestly claim to have reviewed the
  graph. Options whose value is unambiguously a URL, a path or a bare flag
  (`-i`, `--index-url`, `--extra-index-url`, `-f`, `--find-links`, `-e .`,
  `--pre`) are unaffected, as is a legal dotted requirement on its own line.

- The mutation gate could not pass, and its failures did not mean what they
  said. Three separate numbers were wrong, and each one cost the check its
  meaning rather than its speed.
  `--timeout 30` sat below the cost of the suite that has to run — the warm full
  suite is 64s — so any mutant whose killer is not in the first 30 seconds was
  recorded as a TIMEOUT, an unknown fate rather than a caught mutant. A shard of
  this diff reported `2 caught, 1 unviable, 29 timeouts` and exited 3.
  `timeout-minutes: 15` was below one shard's cost, so shards were CANCELLED
  mid-run; cargo-mutants reports a timed-out job as `cancelled`, which is
  indistinguishable from a fail-fast cancellation and reads as "the other shards
  found survivors". 15 of 16 shards ended that way, so the gate could not go
  green for any reason other than a diff too small to mutate. And the mutant
  scope was a hand-maintained list of 30 modules that omitted `src/cli.rs`,
  `src/lib.rs`, `src/main.rs` and `src/error.rs`; cargo-mutants exits 0 with
  "No mutants to filter" when a diff touches only an omitted file, and the
  aggregate reported success having mutated nothing. Verified by re-introducing
  the condition: a `src/cli.rs`-only diff produced zero mutants under the old
  list and three under the new one. The scope is now a `src/**/*.rs` glob, which
  cannot drift when a module is added; the timeout is 180s and the ceiling 60
  minutes across 32 shards, sized from 503 mutants measured for this diff.

  The comment claiming 16 shards "keep each runner around ~3-4 min" was false by
  roughly 4x, and it is the number a future maintainer would have sized the next
  change against.

  With the gate actually running it immediately reported **54 surviving mutants
  across 12 files** (288 mutants tested, 54 missed). The clusters are the code
  this branch touched most recently: `packument_size_estimate` and
  `PackumentMemo::insert` (12), the recall `SyncLock` and its age helpers (9),
  `decompressed_stream_cap` (7), `compute_delta` (6), the MCP framing helpers
  (6), CVSS v2 parsing and declared-severity banding (4), `rule_title` (3).
  Every "confirmed it kills its mutant" claim made while these shards were
  timing out was checked by hand against one mutation at a time; the automated
  sweep is wider and is finding gaps the hand checks did not reach. None of the
  54 is a known behavioural defect — a surviving mutant means no test
  distinguishes the mutation, which is a coverage gap rather than proof the code
  is wrong. They remain open, listed per shard in the run's logs.

  A trap worth recording, because it cost this investigation its first two
  measurements: the repository sets `diff.mnemonicprefix`, so a bare `git diff`
  emits `i/`/`w/` prefixes and cargo-mutants' diff parser silently discards
  every hunk — "No mutants to filter", exit 0, a green run that mutated nothing.
  CI is unaffected because it diffs two explicit revisions (`a/`/`b/`), but any
  local reproduction must do the same or it will "confirm" a false green.

- A mutant in the CVSS v2 exploitability term survived the whole suite, found
  by `cargo mutants` in CI. Every NVD reference vector used `AV:N`, whose weight
  is 1.0, so turning `20.0 * av` into `20.0 / av` changed nothing. Two tests now
  vary the access vector with impact held constant, one on exact values and one
  on the ordering network > adjacent > local, which kills the mutant without
  depending on the arithmetic.

- CI runs again. A comment added to `ci.yml` in `e8e8fb2` contained the text
  `${{ }}` literally, and GitHub expands expressions inside a `run:` block even
  when they sit in a shell comment, so the workflow failed to compile. Every run
  since then produced zero jobs in 0s with a message that does not name the line,
  and could not be retried, so every check in the repo was down for two days
  while a YAML parser reported the file as valid. The same text sat in the
  `blueline-ci` composite Action, where it would have broken the dogfood jobs at
  runtime rather than at compile time.
- CI now lints its own workflows with `actionlint`, which implements GitHub's
  expression grammar. A YAML parser sees none of what breaks a workflow: trigger
  filters, expression syntax and context typing.

- A requirements line that puts the option *before* the pin is now refused
  rather than dropped. The opt-in truncates at the first non-hash option, which
  for `--index-url https://evil requests==2.31.0` left nothing and skipped the
  line, so an upgrade from `requests==2.28.0` never entered the head graph and
  was never evaluated. An option alone on its line is the ordinary pip layout and
  stays allowed.

- The `[ci] allow_requirements_options` opt-in no longer drops the pin it was
  asked to tolerate. The escape skipped the whole line, so
  `requests==2.31.0 --index-url https://evil.example` left the reviewed graph with
  no entry for `requests` at all — a fail-open wearing a disclosure's clothes.
  Everything from the first non-hash option onward is now dropped and the spec
  before it is parsed as normal, so the pin is reviewed and the redirect is
  ignored. A `--hash` after the first redirecting option would also be lost, so
  such a line is refused too: dropping it left the line with no integrity at all,
  `R10_` never compared the declared hash, and it was neither verified nor
  disclosed. An option-led line carrying an *unpinned* requirement is refused for
  the same reason — dropping it let the gate pass a requirements.txt holding an
  unpinned dependency, and the package read as removed rather than never-pinned.
  The splitting that entry describes was itself replaced, twice over; the rule
  that ships is the total one below, which refuses any line mixing an option
  with a requirement.

- A decompressed-stream budget breach is now classified as a limit everywhere it
  can surface. It was recognised by matching an error message, which fails on
  the `unpack_in` path because tar-rs wraps I/O errors in a `TarError` whose
  `Display` prints only tar-rs's own description and drops the inner error — so
  a real limit was filed as a plain extraction failure. The marker is now a
  type, found by walking the `source` chain and the `io::Error` payload, which
  also closes the other direction: tar-rs echoes raw header bytes into its
  messages, so an archive containing the budget's wording was filed as a breach.
- The memoised npm packument is byte-bounded, on both a single document and the
  memo as a whole, mirroring the tarball memo in `ReviewContext`. A recursive
  review walks a dependency graph, and an unbounded memo is the one place that
  walk's memory grows without limit. An over-ceiling packument is not cached,
  which costs a refetch and nothing else. The size estimate counts the retained
  `dist.signatures` block, which is held as raw JSON: without it a packument
  carrying a 32 MiB signature block measured 1050 bytes, and a ceiling that
  does not bind is worse than none because it looks like a bound.

- The CI composite Action no longer interpolates `${{ inputs.verify-attestation }}`
  into a shell body. Every other input already went through `env:`, for the
  reason this repository records in its own workflow: a value interpolated into
  a script is a value the shell parses.

- A tar metadata bomb is refused on the path that actually reaches it. tar-rs
  recognises a header as ustar only when both the `ustar\0` magic and the `"00"`
  version are present, and then consumes pax and GNU long-name entries inside
  its own iterator, `read_all`ing the declared size with no cap. Those bytes
  never reach the extraction loop, so the 64 KiB per-entry cap and the
  total-unpacked accounting both never saw them, and the declared size field is
  12 octal digits. Measured: a 1,221,702-byte gzip declaring 256 MiB of pax
  metadata was accepted with `unpacked_bytes: 1` while tar-rs held the whole
  256 MiB, and the field allows 64 GiB minus one. A decompressed-stream budget now sits between the
  gunzip and the archive reader, so the bytes have to pass a bound that exists.

  An earlier commit on this branch recorded the opposite conclusion — that the
  cap was not dead code and no budget was needed. That conclusion came from a
  fixture which set the magic but not the version, so tar-rs yielded the
  metadata entry to the extraction loop and the per-entry cap fired. The
  fixture now sets both, which is what a real archive looks like.

- The dogfood CI health gate passed on an empty report. Every assertion held for
  zero items, so a PR that changed `package-lock.json` and had the scan evaluate
  nothing was reported healthy — the exact silent under-reporting the gate
  exists to catch, and `continue-on-error` on the scan step left this script as
  the only thing between a broken scanner and a green job. The job now checks
  whether the lockfile changed, and a changed lockfile with an empty delta
  fails. `total_evaluated == len(items)` was also a tautology of the report
  writer and was replaced with a check that the summary's `max_band` agrees
  with the items carried and that no item is missing a name or version.
- The CI composite Action's authenticated release-lookup branch was dead code:
  the step never wired a token, and Actions does not expose one as an env var,
  so every consumer took the unauthenticated path to a per-IP rate-limited
  endpoint on shared runner IPs.
- The recall cache tests could not tell a cache hit from a fresh read, and the
  inode half of the cache stamp was unpinned. A test now rewrites the file
  byte-identically at the same length and mtime and requires the cached value
  back, and a second replaces the file with one of identical length and mtime
  but a different inode and requires the replacement to be served. Both fail
  when the cache is bypassed or the inode is dropped.
- The concurrent fresh-store test was two sequential opens, so it pinned
  nothing: reverting the migration-error swallow left the whole suite green. It
  is now a real race — eight threads released by a barrier onto a directory
  that has never existed, over six rounds — and it fails if either the WAL
  retry or the swallow is reverted.
- The metadata-cap test in `extract.rs` built and gzipped a gigabyte across four
  header kinds to check a 64 KiB cap, costing about 21 seconds of the suite's
  wall time. The fixture is now sized against the budget the test actually
  exercises, which reaches the same code path for a fraction of the cost.

- The recall sync lock did not cover the sequence check it was added for. The
  comparison ran before the lock was taken, so two syncs could both read the
  stored sequence, both pass, and then land out of order, leaving the older
  snapshot on disk. `sequence` is read nowhere else, so every later review would
  have trusted a rolled-back index and the revocations published in the newer
  one would be invisible. The comparison now happens inside the critical
  section. The comment and the changelog entry for that fix both claimed the
  lock spanned the read-compare-write; it did not.
- The recall snapshot cache key carries the file's inode as well as its length
  and mtime, so a replacement that preserves both — `cp -p`, `rsync --times`, a
  tar or git extraction — is no longer served from cache for the life of the
  process.
- Opening a fresh SQLite store concurrently no longer fails on the journal-mode
  pragma. SQLite does not consult the busy handler for a journal-mode change
  while other connections are attached, so the one statement that runs before
  the migrations could return `SQLITE_BUSY` immediately instead of waiting —
  exactly during the creation race the migration handling exists for.

- A `requirements.txt` line carrying an option flag after the spec was folded
  into the version string and surfaced as a PEP 440 error rather than the
  intended refusal. Every token is inspected now, so a trailing `--index-url` is
  refused as an option.
- A mixed npm+cargo install command recorded the cargo `--registry` denial
  twice, because the same check ran on both sides of an early return.
- A registry base URL carrying a path prefix (`http://127.0.0.1:8080/registry`)
  lost the SSRF resolver's base exemption and had every request refused as a
  private target. Fails closed, but it broke the supported local-mirror setup.
- The dogfood CI job asserted that our own distribution produced no HIGH or
  BLOCK findings, which contradicted the design note directly above it and made
  the job red on every dependency bump of a first-party binary package — the
  binary packages ship an executable at the package root, so a bump is a first
  sighting of one. The gate is now scanner health, including a check that the
  reported `max_band` and `total_evaluated` agree with the items actually
  carried, so a scanner that silently under-reports still fails. Risk findings
  go to the step summary.
- The CI composite Action authenticated its own download with a `SHA256SUMS`
  file published by the same release, which proves only that the download was
  not corrupted. It now verifies the GitHub build-provenance attestation that
  `release.yml` already publishes before running the binary.

- An OSV advisory is now scored by the **strongest** `severity[]` entry rather
  than the first one it can parse. The order those entries happen to appear in
  is attacker-shaped remote data, and it decided the reported severity: an
  advisory listing a 5.0 ahead of a 10.0 CVSS v2 vector was reported MEDIUM, and
  one listing a 7.8 v2 vector ahead of a 9.8 v3 one reported HIGH instead of
  blocking. The v2 path this branch added was only reached when nothing earlier
  parsed, so the under-report outlived it. Every entry is now read and the
  maximum is reported. The change can only raise a reported severity, never
  lower it: the fold takes a maximum over a superset of the entries the old
  path considered, which is asserted over every ordered pair of a corpus
  mixing numeric scores, v2 vectors, v3 vectors and an unscoreable entry.
- `"NaN"` in an advisory's `severity[].score` is no longer read as a score. It
  parses as an `f64` and compares false against every band threshold, so it
  banded as LOW — the weakest verdict a score can produce, reachable by sending
  the four characters `NaN` where a number belongs. An advisory carrying no
  score is unscored, which is the Medium default every unparseable entry
  already got. Scores above 10 are deliberately left as parsed: they already
  read as the strongest band, so refusing one could only lower a reported
  severity.

- A yanked PyPI release now shows the registry's stated reason on the card
  instead of only that a withdrawal happened. The reason was fetched and dropped
  at the `Release` conversion, so R08/R09 could report "yanked" with no cause.
  Remote text is sanitized to a single line and bounded before it reaches a
  terminal; a release yanked with PEP 592's bare `true` now reads "no reason
  published" rather than implying a cause it does not have.
- `[provenance] require_signatures` is satisfiable on the npm lane. The key
  gated on a registry signature block that was never read from the packument, so
  setting it blocked every npm review unconditionally: fail-closed, but a check
  that could never pass. The block is now read for the resolved version and
  reaches the provenance report. Presence is still all that is checked — nothing
  verifies the signature, and the card still says "not verified".

- The MCP stdio server validates the JSON-RPC `jsonrpc` member.
  `"jsonrpc":"1.0"`, or a request with the member absent, was accepted; 2.0 is
  now required and a bad request gets the existing parse-error response without
  killing the server.
- An OSV advisory's declared `severity[].type` is now read. A CVSS v2 vector is
  the one score string with no self-identifying prefix, so the declared type
  was the only thing that said how to read it; v2 vectors were silently
  unscored. v2 base scores are computed per the v2.0 equation and checked
  against NVD reference vectors. When a source declares its own severity band
  *and* carries a score, the strongest of the two now wins, where the score
  path previously returned first and could under-report a source that labelled
  itself CRITICAL. CVSS v4 is still unscored and falls through as before.
- The PyPI Simple API is paginated in reality and `meta.next` was parsed and
  ignored, so a truncated page was indistinguishable from a complete one. A
  release whose live artifact sat on page two was reported as having only its
  withdrawn file. Pages are now walked, with a single byte budget across the
  walk, a 16-page cap, loop detection, and a same-scheme-and-host check on
  every `next` link. A chain that outlives the cap is an error, never a prefix.
- `[provenance] allowed_builders` is enforced. It parsed, validated, and was
  then never read, so a policy pinning trusted Sigstore builders asserted a
  restriction and applied none. A release naming a builder outside the list is
  now `P03_UNAUTHORIZED_BUILD_BUILDER` at Block, mirroring
  `allowed_repositories`.
- `[policy] allow_git_dependencies` is wired. It was also parsed and never read.
  The non-semver dependency findings are now lowered from High to Medium when it
  is set, never suppressed: the finding stays visible and its description says
  policy lowered it. Medium rather than Low, because a Low finding is
  score-neutral and would render as a clean auto-approve, hiding the dependency
  behind a passing verdict.

- `[blocklist] maintainers` now blocks — **on the AUR lane**, which is the only
  lane that supplies a publishing identity. The key parsed, validated, and was
  then never read: `is_maintainer_blocked` had no caller outside its own test,
  so a policy could assert a protection and silently get none. A release
  published by a blocklisted identity is now a `P04_MAINTAINER_BLOCKED` block.
  The AUR adapter also reads the maintainer the RPC declares as a second
  identity channel, so a package whose clone cannot be pinned is no longer
  invisible to the blocklist. The first version of this entry claimed the
  coverage unqualified; npm, crates.io and PyPI take the default `None` from
  `Registry::release_author` and produce no `P04` at all, and
  `ARCHITECTURE.md`'s policy table did too. Both now name the lane, and say
  plainly that on those lanes the key is inert: with no author there is no
  `P04`, no card line and no warning, so a review of an npm, crates.io or PyPI
  release looks the same whether or not the policy sets the key. Nothing in the
  tool discloses the absence, so "a registry that publishes no author" is a
  silent no-signal, not a pass, and the complaint that motivated the key — a
  policy asserting a protection and getting none with no warning anywhere — still
  holds on those lanes.
- The npm lane is deliberately left unwired, and the reason is a data-shape
  decision rather than an oversight. The adapter requests the *abbreviated*
  packument (`application/vnd.npm.install-v1+json`), whose top-level members
  are `name`, `dist-tags`, `modified` and `versions`; the `maintainers` array
  exists only in the full packument. Deserializing it and returning it would
  compile, pass a mock server and be `None` against every real registry — a
  check wired to nothing, which is the failure `require_signatures` just had on
  this same lane. Making it real means either switching the media type (the
  body grows 2.4x-10.5x — `express` 341 KB -> 809 KB, `react` 2.9 MB ->
  7.0 MB, `npm` 2.5 MB -> 25.7 MB — against a 64 MiB fail-closed packument
  cap, so every review would pay for a blocklist signal) or a second full fetch
  per review. And npm publishes a *list*: `express` declares 5 identities,
  `typescript` 7, `react` 2, `lodash` 1, and some entries are bots
  (`react-bot`, `typescript-bot`) rather than people. The seam carries one
  `Option<String>` and P04 compares that one string, so any selection rule
  checks one of N, leaves the rest unchecked, and still says an identity was
  checked. `Registry` (the seam), `Policy::is_maintainer_blocked` and the P04
  call site have to grow a list before this lane can carry the key honestly.
  Until then the behaviour is pinned by a test rather than by prose.
- npm's author is also per package, not per release, which is why wiring it
  would not have restored `R10` either: the target and baseline reads both hit
  the same live packument, so the author-transition comparison can never differ
  on that lane.

- npm and cargo reviews now bind the name the archive declares to the name the
  registry resolved. Only the AUR lane checked, and the check is the one that
  matters: `package_json_path` descends into a single top-level directory, so
  a tarball rooted at `evil/` was read as `evil/package.json` and the name it
  declared was discarded. The allowlist, the blocklist and the baseline key are
  all keyed on the resolved name while the bytes that install are the
  attacker's, so a package that lied about its own identity passed exact-match
  allowlisting. A manifest with no `name` at all, which deserialised to `""`
  through `#[serde(default)]`, reviewed cleanly and is now refused.

- `blueline recall sync` no longer writes through a planted symlink. The
  temporary file was named after the process id, so its path was fully
  predictable and `fs::write` follows a symlink: a link in the data
  directory turned a sync into an overwrite of any file the user could
  write. The write now goes to an `O_EXCL` tempfile, is flushed, and is
  renamed into place.
- Concurrent `recall sync` runs are serialised by a lock around the
  read-compare-write. Two syncs could both pass the sequence check and
  then land out of order, leaving a stale snapshot in place. A sync that
  cannot take the lock within 30 s now fails loudly instead of racing, and
  a lock left behind by a killed process is reaped once it is older than
  the five-minute staleness window, so one crash cannot brick the sync
  path — `Drop` does not run on SIGKILL or an abort, so without reaping
  every later sync would wait out the full timeout and then fail forever.
  A fresh lock is never stolen from.
- The recall snapshot cache is keyed by path as well as timestamp, and
  carries the file length. A `OnceLock` froze at the first snapshot it
  saw, so the cache stopped hitting exactly when the file changed, and
  two data directories sharing a timestamp could serve each other's
  index.

- A `.SRCINFO` that declares the same dependency twice now keeps both
  expressions. A split package repeats the pkgbase `depends` inside its own
  `pkgname` block, and the parser overwrote rather than merged, so a
  constraint could change invisibly. The union is sorted and deduped, so an
  unchanged set renders identically on both sides of a diff. The existing
  test asserted the last expression read, which was the defect.

- AUR dependency changes are now read from the PKGBUILD as well as the
  committed `.SRCINFO`. The dependency delta came from `.SRCINFO` alone,
  while `makepkg` executes the PKGBUILD, so a release could add
  `depends=('backdoor-git')` to the PKGBUILD, leave `.SRCINFO` untouched,
  and produce no finding at all. `R29_PKGBUILD_DEPENDS_NOT_IN_SRCINFO` fires
  at HIGH when the PKGBUILD names a dependency the `.SRCINFO` does not. Split
  packages (`depends_<pkgname>`) are in scope, since comparing only the bare
  `depends` array would fire on every one of them. The rule lives in
  `review_roots` rather than `check` so the 139-fixture benign corpus gate,
  which has no `.SRCINFO`, stays as it was.

- A lockfile entry's declared `name` is no longer trusted over its address. A
  different name at the same `node_modules/...` key and version was counted
  unchanged, so the new package was never evaluated. Under `node_modules`, a
  declared name that differs from the directory is an npm alias, and npm
  records the real source in `resolved`, so the two must now agree; a
  mismatch, or a mismatch with no `resolved` at all, fails closed. Every
  honest alias still parses.

- `blueline ci` on a requirements file no longer ignores options that change
  which packages pip installs. `-r`, `-e`, `-c`, `--index-url`,
  `--extra-index-url`, `--find-links` and friends were skipped, so the gate
  reviewed the pinned lines and certified a graph that was never the one
  installed. They are refused, per token, so a flag trailing a spec is caught
  too. `[ci] allow_requirements_options = true` opts in for mirrored-index
  files, which is a real pattern; the test that previously asserted the
  options were skipped was pinning the defect.

- The SSRF guard now runs where the hostname becomes an address. It resolved
  a name once for validation while the HTTP client resolved it again for the
  connection, so a name answering publicly and then privately passed the check
  and connected to loopback, RFC1918, or a metadata address. The registry
  agent now carries a validating resolver, so the address that is checked and
  the address that is connected to are the same answer by construction. No new
  dependency: `ureq` already exposes a resolver seam. Addresses are validated
  per call rather than pinned, because the agent is long-lived in the MCP
  server. The configured registry base stays exempt, since pointing a review
  at a local fixture registry is supported.

- A `ci.fail_on` typo now refuses the policy instead of weakening the gate.
  `fail_on = "blockk"` parsed fine and fell back to `HIGH`, so a policy meant
  to block turned into one that failed at high. The `--fail-on` flag already
  refused the same spelling; the policy key did not. Band parsing is now one
  shared function used by both.
- `R04_DEPENDENCY_MODIFIED` fires on a range-to-range dependency change, not
  only when the new value is a URL. A plain `1.4.1` to `1.4.2` produced no
  finding of any band, which is the shape a dependency-takeover payload takes
  when the attacker re-pins to a compromised patch release. It is disclosed at
  `LOW`, which is score-neutral and cannot move a verdict, because a benign
  patch bump is the common case and this fires on every one of them. Moving
  off a URL is now covered as the mirror of the redirect it already caught.
- The diff engine no longer aborts on a non-UTF-8 filename. Trees were keyed
  by a lossy string and that string was joined back onto the root to read the
  file, so any name with invalid UTF-8 failed the whole review with "No such
  file or directory", and two names differing only in those bytes collided
  into one. Trees are keyed by path now; the report fields still carry a
  display string.

- `fail_closed_network` now stops the review. A failed advisory lookup was
  collapsed into an `unverified` report, which carries no hits, so the
  heuristic produced no finding and the verdict came out identical to a clean
  pass. It is now `R09_ADVISORY_UNVERIFIED` at HIGH, raised at the boundary
  that discarded it so `review`, `ci`, `agent` and `mcp` all inherit it. A
  check that is merely switched off by policy stays silent, so `check_advisories
  = false` is unaffected. The flag also outranks the cached report now: a
  stale CLEAN cache entry produced neither a hit nor a staleness disclosure,
  so it read exactly like a fresh clean pass.

- `blueline install` no longer takes its program from `npm_execpath`. That
  variable decides which binary runs, and it is environment-supplied;
  `TODO.md` already records it as user-controllable and unfit for a security
  decision, but the install path was built to trust it. `NODE` chose the
  interpreter for the same reason. The real npm is now resolved from PATH
  through the same helper the shims use, which also excludes the shim
  directory so a shimmed PATH cannot recurse. When no real npm is found the
  install fails rather than falling back.
- The install path also read its environment with `vars()`, which panics on a
  non-UTF-8 entry, and now uses `vars_os()`.

- The MCP stdio server bounds its request lines and survives a bad one. It
  read with `lines()`, which has no per-line cap, so a request containing no
  newline grew without limit; and a non-UTF-8 line broke the loop into a
  clean exit 0, telling the host the gate had succeeded while an in-flight
  request went unanswered. Lines are now capped at 64 KiB (an oversized one
  is answered and the server exits nonzero, since newline framing cannot be
  resynchronised) and a non-UTF-8 line is answered with a parse error while
  the server keeps serving.

- Provenance is no longer reported as verified when nothing was verified.
  Blueline base64-decoded the in-toto statement, compared the subject digest
  to the bytes under review, and returned `Verified` with a hardcoded SLSA
  level 3. No DSSE signature and no Sigstore certificate chain was ever
  checked, yet `require_provenance` accepted the result and the card rendered
  it green. The status is now `Attested` with no earned level, the renderer
  says the signature is not verified, and `require_provenance` requires
  actual cryptographic verification, which this build does not perform and
  therefore refuses. **Behaviour change:** a policy with
  `require_provenance = true` now blocks every release until Sigstore
  verification is implemented, which needs a dependency that has not been
  approved. An attestation that no policy requires is disclosed at `LOW`,
  which cannot move a verdict.

- Opening the store now checks the declared shape of the columns whose
  default decides trust, not only their names. `record_verified` never
  supplies `clean`, so a database declaring `clean INTEGER NOT NULL
  DEFAULT 1` would write a package nobody approved straight into the set
  that `list_clean_versions` hands back as an approved baseline, while
  every column name still checked out. `known_clean.clean` and
  `provenance_cache.signature_valid` are now required to be `INTEGER NOT
  NULL DEFAULT 0`; the default is parsed as an integer so `''`, `NULL`,
  `'yes'` and a parenthesised `(0)` are refused too.
- Tar extraction refuses a repeated path and a directory entry that declares
  a payload. A repeated path was unpacked twice and the second copy
  overwrote the first, so the tree blueline diffed depended on entry order;
  the check is on the normalized path, since `a/b` and `a//b` are the same
  destination. A directory's declared bytes were decompressed in full while
  counting as zero against every cap, and no tar writer emits them.

- The PKGBUILD tokenizer no longer loses the rest of a file to a parameter
  expansion. `${#N}` and `${x#prefix}` are shell expansions, but a `#` after
  `{` was read as the start of a comment, which both truncated the line and
  left the brace uncounted. The unbalanced depth counter then swallowed every
  later top-level assignment into the first function body, so R11 through R20
  all went dark on a PKGBUILD that skips checksum verification, with no
  disclosure. Both the comment stripper and the function-body extractor now
  track `${...}` as one unit.

- The npm dogfood CI gate no longer swallows a real risk verdict. The scan
  step runs with `continue-on-error` because this repo legitimately BLOCKs on
  itself, but the health script only checked which packages were evaluated,
  never the bands, so a HIGH or BLOCK finding in an otherwise healthy delta
  reported success. The bands are read now: the health check requires every
  reported band to parse and requires the summary's `max_band` and
  `total_evaluated` to agree with the items it actually carries, so a scanner
  that silently under-reports still fails. The hard gate is scanner health, not
  risk level — our own first-party binary packages legitimately produce HIGH
  findings, and the scan step is `continue-on-error` precisely so a
  dependency-bump PR is not red for one — so HIGH and BLOCK go to the step
  summary instead. The first version of this entry claimed the report was gated
  on its own findings, which is not what ships.
- The mutation-testing aggregate fails instead of reporting `skipped`. Without
  `always()` plus an explicit result check, GitHub skips the job when a shard
  fails, and a skipped required check counts as satisfied.
- The cargo dogfood job reads the base ref through the environment instead of
  `${{ }}` interpolation, and reads the full changed-file list before matching,
  so a branch named `main$(id)` cannot inject a command and a `git diff |
  grep -q` SIGPIPE under `pipefail` can no longer skip the gate.

- The install scanner no longer lets four classes of registry redirect
  through: npm alias schemes `file:`, `link:`, `npm:` and `workspace:`
  (which name a payload no registry vouches for, and which previously
  matched no rule and were dropped entirely), `pip` redirect flags in
  `--flag=value` form (npm already handled `=`, pip did not, so
  `--index-url=https://...` was reviewed against PyPI and installed from
  the attacker's index), `npm ci`, and `cargo --registry`. All are now
  denied on shape before any operand is resolved.

- `agent gate` no longer panics on a non-UTF-8 environment variable. It read
  the environment with `std::env::vars()`, which unwraps every entry, so one
  odd variable exited 101 — and hook hosts treat any exit other than 2 as
  non-blocking, meaning the install would have run ungated. Names now come
  from `vars_os` converted lossily, so the gate denies with its documented code.
- The heuristic engine no longer panics on a multi-byte dependency value. The
  non-semver-URL check byte-sliced the value by prefix length, so any manifest
  carrying a dependency such as `"💩"` crashed the whole review instead of
  returning a verdict. The comparison is a bounds-checked byte-slice now.
- Recall lookups fold case for npm and crates.io, not only validation. A
  curator writing `React` or `Serde` produced an entry that validated and then
  never matched the queried name, which is the worst shape a revocation can
  take: present, trusted, and inert. AUR pkgbases stay case-sensitive.
- The registry agent keeps a whole-request deadline again. Dropping it for
  per-read timeouts fixed a 90-second stall but left total transfer time
  unbounded, because a peer dribbling one byte per interval keeps every read
  inside its own ceiling. The 10s connect ceiling and the 90s total both
  remain; `ureq` 2.x cannot express a short stall guard and a long budget at
  once.
- The AUR test fixture clones over a `file://` URL instead of a bare local
  path. Git ignores `--depth` on a local clone and falls back to copying loose
  objects one at a time, so `history_walk_caps_at_200_commits_and_states_truncation`
  failed roughly one run in twelve with `failed to copy file to
  .git/objects/...`. Over a real transport git honours the depth and fetches a
  packfile, which is what the adapter does against the AUR itself. Thirty
  consecutive runs pass, up from eleven in twelve. The clone-URL pin test also
  gained a sibling-base case, since a base that only shares a prefix must not
  pass the pin.
- Opening the store now verifies the schema itself instead of trusting
  `PRAGMA user_version`. A database file carrying the right version counter
  with the wrong shape behind it opened successfully and then failed partway
  through a review with a confusing missing-column error. Every table and
  column the store queries is checked on open, the check is unconditional, and
  the refusal names the file and what is missing so a user knows what to move
  aside. The version-counter guess it replaces also decided lost migration
  races, which the schema check now decides directly.
- `agent gate` now refuses an unreviewable invocation shape before it resolves
  any operand. A command carrying a registry override (or any other hard-deny
  shape) used to be scanned, then still reviewed, downloading tarballs from the
  registry the command was explicitly redirecting away from and writing
  evidence rows for an install that never ran. The denial is unchanged and
  still exit 2; only the wasted and misleading work is gone.
- Registry requests no longer stall against a peer that accepts the connection
  and then goes quiet. All four adapters share one agent, with a 10s connect
  ceiling and a 90s whole-request deadline, and response size stays bounded by
  `RegistryLimits` as before. An earlier version of this entry described the
  opposite arrangement -- a 30s per-read/write ceiling and no whole-request
  timeout -- which is what the first attempt shipped. The per-read ceiling was
  dropped because a peer dribbling one byte per interval keeps every read
  inside it and so runs unbounded, and `ureq` 2.x cannot express a short stall
  guard and a long total budget at once. What ships is the 90s total budget
  with no per-read ceiling.
- Concurrent first runs against one data directory no longer fail. `record_verified`
  inserts-then-verifies rather than checking-then-inserting, which removed a
  primary-key collision between two reviewers recording the same package; the
  schema check above absorbs the matching creation race.
- The unreviewed-baseline refusal hint now names the
  `allow_unreviewed_baseline = true` policy rule alongside the
  predecessor-approval command, and warns that walking the chain costs one run
  per version back. The README quickstart documents the same onboarding path.
- Recall snapshots validate each entry's package name against its own
  ecosystem grammar instead of a shared character class, so a path-shaped name
  such as `../etc` is refused instead of served. npm names are compared
  case-insensitively, since npm folds case on publish and packages published
  before that rule still carry capitals; otherwise a single legacy spelling
  would refuse the whole index and silently stop every revocation in it from
  blocking.
- The extraction section of `ARCHITECTURE.md` claimed a Landlock sandbox,
  capability drop, seccomp filter and open-FD cap. No such code exists and
  `Cargo.lock` carries none of those crates. The claim is now marked as planned
  and the document says plainly that the parser-level budget is what bounds a
  hostile archive today.
- The docs stopped describing code that does not exist and stopped
  contradicting themselves. In this section: the MCP request cap was attributed
  to `BufReader::split` when the base loop read with `lines()` and had no cap at
  all, and to a "64 KiB check" that is `MAX_HOOK_STDIN_BYTES` in `src/agent.rs`,
  a different component; the strongest-`severity[]`-entry fix was attributed to a
  PyPI Simple index when `severity[]` is an OSV advisory field and PEP 691
  carries no severity at all; the sync lock's ceiling was five seconds when the
  loop was 250 × 20 ms and `LOCK_WAIT` is now 30 s; the dogfood gate was said to
  be "gated on its own findings" when it gates on scanner health, which the entry
  now records as its own over-claim; and the registry agent was described as a
  30 s per-read ceiling with no whole-request timeout, which is the reverse of
  `src/registry/http_util.rs` (a 90 s whole-request deadline, no per-read
  ceiling). Both false entries were duplicates of correct ones already in this
  section and are gone. In `ARCHITECTURE.md`: the "full" heuristic inventory
  stopped at R28 and omitted every `P01`–`P04` rule; the `ci` policy table
  omitted `allow_requirements_options`; an open risk still said `ci` was "Phase
  3, not Phase 1" with every phase shipped; and two sections were both numbered
  5. Its "disclosed no-signal" wording is also gone — on npm, crates.io and PyPI
  the `[blocklist] maintainers` key is inert and nothing discloses that, which
  is the very complaint the key was wired to answer.

### Removed

- `BaselineResolution::display_summary`, which had no caller outside its own
  test.
- `Policy::calculate_band`, which had no caller outside its own test and
  disagreed with the live band ladder: it was a pure function of score, while
  the production ladder is monotonic and never lowers an already-raised band. A
  package with one High finding and 25 points is High in production and Medium
  through `calculate_band`. Wiring it in as written would have silently weakened
  severity. The two identical inline copies of the ladder are now one shared
  helper, so they cannot drift.
- Dead code that made the codebase look safer than it was: `Delta::is_empty`
  (zero callers, and its semantics were wrong for an "unchanged" check anyway),
  `DiskFileMeta.size` (written, never read, already re-derived by
  `classify_bytes`), an unused wheel test helper, and an unreferenced
  `ci::render_text_summary` print wrapper.
- Three `#[allow(dead_code)]` suppressions that were hiding live checks from
  the compiler: `Packument.name` (guards `validate_package_name`),
  `AurRpcResponse.version` (guards the RPC protocol version), and
  `Delta.binding_gyp_added` (drives a Block-severity native-build trigger), plus
  a blanket suppression on `PackageJson`. If any of those checks were deleted,
  the build would have stayed silent.

### Changed

- `AGENTS.md` and `ARCHITECTURE.md` now state the defect policy explicitly:
  a bug is fixed even when it predates the branch, "pre-existing" is not a
  reason to leave it live, and a fix without a test that fails without it is
  a guess. Both record why, using this store bug as the worked example.


- Docs refresh: `ROADMAP.md` marks the local-first recall index shipped
  (hosted API stays under Someday); `ARCHITECTURE.md` drops the stale
  Phase-0/1 notes, lists the heuristic inventory, and records
  the recursion (D12), local-first recall (D13), and agent-enforcement
  (D14) decisions. The inventory was first written as "the full R00–R28"; it
  now carries `R29_PKGBUILD_DEPENDS_NOT_IN_SRCINFO` and the `P01`–`P04` policy
  rules as well, so the list is actually complete.
- Mutation testing now covers the verdict path: `heuristic.rs`, `diff.rs`,
  `advisory.rs`, `provenance.rs`, `verdict.rs`, and the crates.io / AUR /
  `http_util` / registry-mod files join the `--file` scope in both mutants
  jobs.
- The `blueline-ci` composite action downloads the checksum-verified
  prebuilt release binary (new `version` input, default `latest`) instead
  of `cargo run --release` on every run; `build-from-source: true`
  preserves the source build for unreleased code, and this repo's dogfood
  job pins it.

## [0.3.1] - 2026-09-21

### Added

- PATH-shim routing (`blueline shim install|uninstall <npm|npx|pip|cargo|yay|paru>
  [--dir <path>]`): generated bash shims that rebuild the invocation and
  route it through `blueline agent gate` before the real package manager
  (resolved on PATH at install time, excluding the shim directory) runs.
  Fail closed everywhere — blueline missing, errored, or refusing means the
  install does not run, and a missing real binary refuses shim creation.
  The scanner gained `cargo install`, and `yay`/`paru -S` operands
  (AUR-grammar specs with `name=version` pinning), so all six managers are
  reviewed through one grammar; pip flags that name non-registry sources
  (`-r`, `-e`, `--constraint`, …) are refused with a pointer to
  `blueline ci`. `BLUELINE_REGISTRY` and `BLUELINE_POLICY` environment
  variables scope a shimmed shell to a mirror and a project policy.
- Agent-native enforcement (`blueline agent`): `agent review <pkg>` gives
  autonomous agents a policy-bound, never-interactive gate — single-line
  JSON verdict on stdout (the D7 schema, recursive reviews included),
  exit 0 when the policy allows and 2 when it refuses, human hints on
  stderr, no known_clean mutation (an agent cannot bless baselines), and
  an audit-log entry with `decided_by = "agent:<identity>"` where the
  identity comes from the agent's process environment (Claude Code,
  Cursor, Codex CLI; env names only, never values — no telemetry beyond
  the local store). `agent gate` is the hook binding: it polices a command
  line via `--command` or hook stdin (Claude Code PreToolUse and Cursor
  `beforeShellExecution` payloads both accepted), scans it with the same
  install-reference scanner the review engine uses, reviews every named
  install with the recursive engine, and answers with exit codes or the
  native decision JSON (`--format claude|cursor`). Dynamic or unresolvable
  targets deny fail closed; bare installs are allowed with a note that
  manifest dependencies are policed by `blueline ci`.
- Recursive review (`src/recursive.rs`): an install reference found in a
  reviewed payload — npm lifecycle scripts, PKGBUILD `npm`/`bun` delivery
  (R23), or PyPI wheel `.data/scripts` — is now piped through the same
  review engine as a second-order review instead of only being named.
  Referenced packages are re-reviewed with a depth cap (policy
  `recursion.max_depth`, default 3), a per-review child budget
  (`max_child_reviews`, default 8), cycle detection (A → B → A is cut and
  disclosed), and a session tarball memo so referenced packages are never
  re-downloaded. Every reference is disclosed as
  `R24_LIFECYCLE_INSTALL_REF` (HIGH when pinned, MEDIUM when unpinned,
  unresolvable, or dynamic; HIGH for non-registry git/URL/path specs, which
  are not recursively reviewed), cap overruns as `R25_RECURSION_DEPTH` and
  cycles as `R26_RECURSION_CYCLE` (both HIGH, fail closed), and a child
  finding at or above `recursion.child_block_band` (default HIGH) rolls up
  into the parent verdict as `R27_SECOND_ORDER` — a HIGH finding in a
  referenced package can BLOCK the parent. The JSON verdict schema grows a
  `recursive` array of child reviews (delivery chain, band, score,
  findings), so the CLI, CI reports, and the MCP `structuredVerdict` all
  carry the second-order results from the single source of truth; the
  review card renders each child's delivery chain and worst findings.
- Install-reference extraction (`src/install_ref.rs`), the scanning layer for
  recursive review: static detection of package-manager invocations that
  resolve another install at install/build time — npm lifecycle scripts
  (`preinstall`/`install`/`postinstall`/`prepare`/kin) invoking
  `npm`/`npx`/`pnpm`/`yarn`/`bun`/`pip` with a named spec, PKGBUILD npm/bun
  delivery specs exposed by the new `pkgbuild::npm_delivery_refs`, and wheel
  `.data/scripts` payloads. Each reference records its manager, origin, raw
  spec, whether the spec is exactly pinned, and whether it was statically
  parseable (dynamic shell payloads are disclosed unparseable, never
  guessed). Nothing executes or fetches — pure parsing of already-extracted
  bytes, bounded per line, with non-UTF-8 `.data/scripts` files surfaced as
  unparseable references instead of silently skipped.

- AUR integration (`feat/aur-integration`): `blueline --ecosystem aur ci
  --lockfile aur.lock` reviews added and version-changed pins from a file of
  one `pkgbase@pkgver-pkgrel` per line (blank lines and `#` comments
  skipped, malformed lines and double pins fail closed with line numbers,
  4096-entry cap, base read via `git show` like other ecosystems); a yay v13
  `AURPreInstall` Lua hook recipe in the README gating the build on
  `blueline review --yes`, with the re-review-on-drift timing note;
  `ecosystem = "aur"` policy scoping through the existing generic matcher;
  and README threat-model copy stating the repo-scripts-only scope, the
  review-with-blueline-build-with-yay flow, and the commit-bound audit
  integrity.
- PKGBUILD static heuristics (`src/pkgbuild.rs`, AUR reviews only): a
  hand-rolled tokenizer with quote-aware lexing (`$'...'` ANSI-C, line
  continuations, word-boundary comments), multi-pass variable folding,
  indexed and associative array writes, brace expansion, and fail-closed
  bounds (1 MiB, 64k lines, no new dependencies, nothing executed). Rules
  R11-R23 fire as verdict findings: R13 pipe-to-shell, R14 eval family, and
  R18 homoglyph at HIGH; R12 source drift, R15 true indirection, R16 command
  substitution in metadata, R19 validpgpkeys change, and R20 install/hook
  change at MEDIUM; R11 checksum SKIP, R17 build-time network, R21 unpinned
  VCS, R22 conditional guards, and R23 npm delivery at INFO after the benign
  corpus (137 real AUR PKGBUILDs in `tests/fixtures/pkgbuild_benign/`)
  showed each fires on legitimate packages. Baseline pair rules (R12, R19)
  run when a baseline exists; unparseable PKGBUILDs fail closed at HIGH;
  every card carries the scope disclosure that downloaded upstream sources
  are not reviewed. Fuzz target `fuzz/fuzz_targets/pkgbuild_tokenizer.rs`.
- AUR registry adapter (`blueline --ecosystem aur review <pkg>@<pkgver-pkgrel>`):
  a git-history-backed `AurRegistry` on the RPC v5 client — pkgname → pkgbase
  mapping, shallow clone (history cap + 1) of `{base}/{pkgbase}.git` through
  the system `git` binary (argv-only, never a shell, capped output reads,
  120s wall-clock kill per git invocation, clone urls pinned to the
  configured base at the verify boundary, any git failure fails closed), a
  200-commit-bounded history walk that states truncation and
  refuses to resolve when the cap could hide the requested version, per-commit
  static `.SRCINFO` parsing (PKGBUILDs are never sourced or executed and
  `makepkg` is never invoked), newest-commit-wins version identity under
  `AurVersionInfo` (commits sharing a `pkgver-pkgrel` collapse to the newest),
  `git archive` review bytes extracted by the existing hardened tar path and
  verified against a resolve-time sha256 digest so the store's baseline-tamper
  check catches history rewrites, `list_releases`/`default_version` over
  distinct parsed versions with commit timestamps as publish times, and a
  `release_author` hook exposing the pinned commit's self-declared author
  email.
- `R10_MAINTAINER_TRANSITION` (MEDIUM): fires when the target release's
  author identity differs from the baseline release's — the AUR maintainer
  transition that is the Atomic-Arch adoption signal. Unknown authorship on
  either side is treated as no signal, and other ecosystems are unaffected
  (the hook defaults to `None`).
- AUR review manifests: a static `.SRCINFO` reader (`read_aur_srcinfo`,
  bounded to 1 MiB and 64k lines, fail-closed on duplicate pkgbase sections,
  malformed lines, or unparseable `pkgver`/`pkgrel`/`epoch`) projecting onto
  the engine's manifest view with `depends` + `makedepends` merged; extracted
  AUR archives must carry `PKGBUILD` and `.SRCINFO` at their root or the
  review fails closed.
- The MCP `ecosystem` parameter now accepts all four ecosystems (`npm`,
  `cargo`, `pypi`, `aur`); AUR tool calls route to the AUR base URL, derived
  from the `--registry` override exactly like the CLI.
- AUR foundation (`--ecosystem aur`): `Ecosystem::Aur` plumbed through the
  store, policy, CLI, and MCP ecosystem keys; `AurVersionInfo` implementing
  the `VersionInfo` seam as a faithful port of libalpm's `vercmp` (validated
  against pacman's `vercmptest.sh` vectors, separator-run and
  alpha-segment semantics included) with strict fail-closed parsing and a
  fuzz target; and an AUR RPC v5 metadata client on the shared `http_util`
  plumbing (name grammar validation, query encoding, bounded reads,
  fail-closed response shape checks, verbatim name comparison,
  pkgname → pkgbase resolution). `blueline install` refuses AUR packages
  (building a PKGBUILD executes its shell script); `review` and `ci` fail
  closed until the AUR adapter PR lands.

### Changed

- npm distribution renamed to `blueline-cli` (alias `@kridaydave/blueline-cli`)
  with platform binaries under `@kridaydave/binary-*`: the previous names
  `blueline` and `@bluelinecli/cli` are frozen at 0.3.0 under a lost
  publisher account and receive no further updates. Install with
  `npx blueline-cli` / `npm install -g blueline-cli`; the installed
  command and the Rust binary stay `blueline`.
- The policy loader honors `BLUELINE_POLICY` (an absolute path) ahead of
  the default search, so shimmed shells and agent hooks running outside a
  project directory keep their policy scoping; a set-but-unreadable path
  fails closed, and an explicit `--policy` flag wins over the environment.
- `R23_NPM_DELIVERY` graduates from INFO to MEDIUM: recursive review now
  resolves and reviews the npm/bun packages a PKGBUILD delivery line names,
  so the delivery line is a true second-order signal. The three
  benign-corpus fixtures that fire it (joplin, bitwarden-cli, insomnia) are
  pinned as documented true positives in the corpus gate.
- Push-to-main mutation testing now mutates only the lines of the pushed
  commit (`git diff HEAD~1..HEAD` fed to `cargo mutants --in-diff`) instead of
  re-running the full trust-boundary file set on every merge, spread across a
  16-shard matrix.
- The MCP stdio server no longer prints an stderr note when it receives the
  client's `notifications/initialized` message.
- AUR adapter resource use: one shallow clone per pkgbase is now reused
  across the read-only history operations of a review (resolve walk,
  releases walk, author lookup), halving the clones each evaluation
  performs; the cache is keyed by the full clone url and capped, and
  `fetch_verified` still re-clones so its archive bytes remain a second,
  independent sample from the remote. AUR CI reports now carry a
  `removed_count` (rendered in the text and markdown summaries) so pins
  deleted from the pin file are visible instead of silently dropped.
  PKGBUILD `$'...'` `\xHH` and octal escapes now decode as raw bytes the
  way bash emits them (`\xc3\xa9` is `é`, not `Ã©`), with non-UTF-8 byte
  sequences becoming U+FFFD and over-one-byte octal escapes failing closed.

### Fixed

- Mutation-testing survivors in the close-the-loop trust boundary:
  `valid_npm_name` rejects a missing `@` up front (empty scope/pkg
  segments were already rejected by the segment grammar, so the extra
  disjuncts were dead logic); the pip non-registry scan and the yay/paru
  verb search drop inert index arithmetic; npm/cargo recall matching is
  pinned as exact (strict semver has no distinct-but-equal forms, the old
  parse-and-compare arm could never fire); the serve size cap is a
  boundary-tested predicate and the oversized-index refusal test kills a
  hung server instead of hanging the suite; `is_executable_file` is one
  function with cfg branches inside; and both `scan_words` walks carry
  fuel so a stalled index trips instead of looping. New pinning tests:
  pip exactness for non-semver (`2.31`), single-disjunct non-registry
  shapes, repeated `--package=` flags, and chained managers.
- A mutation-testing survivor in the recursive-review reference cap: the
  overflow disclosure fired one reference early (`>` vs `>=`), which would
  have flagged a payload carrying exactly the cap as overflowing. The
  boundary is now pinned by a test at exactly 32 references.
- The npm dogfood CI gate no longer hardcodes which shipped packages must
  appear in the evaluated set: a lockfile delta that adds platform
  binaries (as the completed platform matrix does) shifted the evaluated
  names and failed the assert even though the scan was healthy. The gate
  now asserts that every evaluated package is a shipped package, that the
  delta produces evaluations, and that unchanged packages are counted.
- Agent-gate hardening from the campaign review: every gate error path now
  DENIES instead of exiting 1 (hook hosts treat non-2 exits as
  non-blocking, so a hostile stdin payload sized to break the UTF-8 read,
  a corrupt store, or an unreadable policy previously let the command run
  ungated); gate-managed installs route to their own registries (`cargo
  install` → crates.io, `yay`/`paru -S` → the AUR, `pip` → PyPI — the
  wrong-registry routing previously reviewed an npm namesake); and the
  scanner + gate close the silent-allow shapes: `pip install -r/-e/-c`
  (non-registry sources), `npx --package=<pkg>`, `npm exec`/`npm x`/`bun x`
  (which execute packages exactly like npx), and manager tokens hidden
  behind quoting or backslash escapes. Oversized hook stdin is refused, a
  missing-real-binary or hostile-character install path refuses shim
  creation, real binaries are checked for the exec bit, each manager's
  shim passes only its own registry override, `pip3` ships as a shim
  target, and gate denials are audited.
- The gate scanner finds verbs behind leading global flags
  (`npm --no-fund install evil` was a silent allow), denies npm registry
  and config overrides in gated installs (`--registry=`, `--userconfig`,
  `--tag=`, `npm_config_*` env assignments, `npm config set registry` —
  reviewing one registry while installing from another), discloses
  dynamic `--package` values as unparseable markers instead of dropping
  them behind decoy positionals, and stops scanning at shell comments.
- The README hook recipes pin `BLUELINE_POLICY` for the hook environment
  (a repo's committed blueline.toml otherwise governs hooks fired with the
  repository as cwd) and disclose the remaining bypass surface.

## [0.3.0] - 2026-08-31

### Added

- PyPI registry adapter (`blueline --ecosystem pypi review <package>==<version>` / `<package>@<version>`):
  PEP 440 `Pep440Version` (`VersionInfo` seam, epoch, zero-padded release, `a<b<rc` with `c→rc`, `post`/`dev`/`local`) validated against `pypa/packaging` vectors, PEP 503 name normalization (`[-_.]+→-`, lowercased, strict validation), `zip` crate (`default-features=false, features=["deflate"]`) wheel extraction wrapped with stored+deflate-only, encrypted/duplicate/symlink/traversal/absolute/NUL/Corruption and `ExtractionLimits` plus inflated-size-vs-declared checks and CRC propagation, Simple API `GET /simple/{norm}/` (`hashes.sha256`, `yanked` bool|string, `upload-time` RFC3339) powering `list_releases` / `default_version` / `resolve` with deterministic wheel choice (`py3-none-any` preferred, else lex-min) and `sha256` pre-extract verification. `blueline install` refuses PyPI (sdist builds execute arbitrary code).
- PEP 740 provenance: PyPI provenance endpoint (`GET /integrity/{norm}/{ver}/{filename}/provenance`) parsing DSSE in-toto statements and verifying subject sha256 checksums with cache integration.
- PyPI security findings: `R09_YANKED_TARGET` for yanked releases, `R02_ENTRY_POINTS_SCRIPT` for console_scripts / .data/scripts, `R06_NATIVE_PLATFORM_WHEEL` for compiled binary extensions, and `R04_SDIST_BUILD_CODE` for source distributions.
- Pinned `requirements.txt` CI scanning: `blueline ci` parses `name==version` requirements, rejects unpinned range operators with line-numbered errors, and enforces `--hash=sha256:...` checksum validation with `BLOCK` verdicts on mismatch.
- PEP 440 parser fuzz target under `fuzz/fuzz_targets/pypi_version.rs`.
- Wheel extraction hardening (`src/wheel_extract.rs`) reusing `validate_entry_path` and `ExtractionLimits` with `0o644`/`0o755` and symlink-via-mode checks.
- crates.io registry adapter (`blueline --ecosystem cargo review <crate>@<ver>`):
  sparse-index NDJSON client with fail-closed parsing (bad `vers` on a
  recognized row aborts; unknown schema `v > 2` rows are skipped with a note;
  missing `yanked` reads as false), `config.json` handling that refuses
  authenticated registries, canonical crate names (`serde_json` → `serde-json`),
  and `.crate` downloads verified by sha256 against the index checksum before
  extraction. Extracted archives must unpack to exactly one top-level
  `{name}-{version}` directory.
- Packed `Cargo.toml` reader: `[package] build`/`links`, `[[bin]]` targets,
  dependency maps, and `[features]`; dependencies project onto the existing
  diff/heuristic engine.
- Global `--ecosystem` flag (default npm) and `--index` override for cargo
  reviews; `blueline install` refuses cargo packages (building a crate executes
  its `build.rs`).
- Yanked-aware baselines: the diff anchor skips yanked releases, an all-yanked
  history degrades to first sighting, and a new `R08_YANKED_PREDECESSOR`
  (MEDIUM) finding fires when the release immediately before the target was
  yanked.
- Review card/JSON gain an `ecosystem` field; integrity displays as the
  canonical digest (`sha256:<hex>` / `sha512:<hex>`) instead of the old
  "verified (sha512)" label.
- MCP `review_install`, `inspect_diff`, and `check_known_clean` accept an
  optional `ecosystem` parameter (`npm` default, `cargo`); unknown values are
  rejected.
- Cargo.lock CI dogfood: `blueline ci` now scans `Cargo.lock` (TOML) alongside
  `package-lock.json` (bounded, `__`/`_` canonicalization, `source = "git+…"`
  honored via `allow_git_dependencies`); new `dogfood-cargo` job in
  `.github/workflows/ci.yml:110` runs
  `cargo run -- --ecosystem cargo ci --lockfile Cargo.lock --fail-on high`
  on PRs touching `Cargo.lock` (diff check for `Cargo.lock`),
  bootstrapped via committed `blueline.toml:1` with
  `allow_unreviewed_baseline = true` for the current crate set (content
  heuristics still apply in full).

### Changed

- Baseline predecessor selection now consults `list_releases` (yank flags)
  instead of the plain version list.

- Multi-registry foundation: `Ecosystem` enum (`npm`/`cargo`/`pypi`) with a
  `Registry::ecosystem()` accessor, a typed `Checksum { alg, value_hex }`
  replacing raw SRI strings, and `Release { version, yanked, publish_time }`
  with `list_releases` + `default_version` replacing `resolve_dist_tag`.
- `VersionInfo` seam in `src/version.rs`: baseline selection and the store's
  clean-version listing now work over any version grammar (semver today,
  PEP 440 later).
- Shared registry HTTP plumbing in `src/registry/http_util.rs`: URL scheme
  validation, private/local-host SSRF guards, capped redirect following, and
  bounded reads, reusable by future registry adapters.
- Optional `ecosystem` field on policy allow/blocklist rules; absent means the
  rule matches every ecosystem. Plain-string blocklist entries keep working.
- Store schema v3: every table gains an `ecosystem` column with composite
  primary keys `(ecosystem, name, version)`; existing rows become npm-scoped.
- Advisory lookups send the resolved ecosystem to OSV.dev with exact schema
  casing (`npm`, `CratesIO`, `PyPI`).
- Provenance attestation endpoint is threaded from the configured registry
  base instead of hardcoding `registry.npmjs.org`; DSSE subject digests are
  compared against the typed checksum.
- Baseline integrity tamper checks compare normalized digest content, so
  legacy `sha512-<base64>` rows and new `sha512:<hex>` display forms are
  judged alike (fail-closed behavior unchanged).

### Fixed

- Registry 404s now report "package not found in registry" instead of a
  generic network error, in both the review and CI paths.
- Lockfile parse errors no longer print their cause twice.
- Interactive reviews can approve the unreviewed registry-predecessor
  baseline in the same session (`[y/N]` prompt after approving the target);
  non-interactive behavior is unchanged.
- Isolated `BLUELINE_DATA_DIR` in the remaining CLI tests that spawn the
  binary while asserting success (`ci_writes_report_to_output_file`,
  `ci_fail_on_case_insensitive`, `mcp_ping_heartbeat`,
  `mcp_stdio_handles_initialize_and_tools_list`), eliminating a flaky race on
  the real user data dir under parallel test runs.
- Pinned the fail-closed rejection of npm packuments advertising a non-sha512
  `dist.integrity` with an explicit regression test asserting the algorithm
  error, closing a surviving mutation-testing gap in `registry::npm`.

## [0.2.0] - 2026-08-22

### Added

- Tag-triggered release pipeline (`.github/workflows/release.yml`): cross-built
  native binaries for linux (x64 glibc/musl, arm64), macOS (x64, arm64), and
  Windows (x64, arm64), published as `@bluelinecli/binary-*` npm packages with
  provenance and attached to GitHub releases with SHA256SUMS.
- Release smoke gate: the shipped artifact must review a real package
  end-to-end through the npm path before shims publish.
- Dogfood CI job: our own composite Action reviews our own npm distribution
  lockfile (`package-lock.json`) on every PR.

- Published npm distribution: `blueline` and `@bluelinecli/cli` shims with the
  native binary delivered via `@bluelinecli/binary-*` platform packages
  (linux-x64-gnu at v0.1.0; other platforms build from source).

## [0.1.0] - 2026-08-22

### Added

- `blueline review <pkg@ver>` command with text and JSON output, `--registry`
  override, and a fail-closed `--yes` flag.
- `blueline install` command with sandboxed extraction and fail-closed script
  execution.
- `blueline ci --output-file <path>` parameter to save formatted CI review
  reports directly to disk.
- npm registry client with SHA-512 integrity verification before extraction.
- Line-level diff engine against the last known-clean release.
- Heuristic verdict engine with an ASCII review card and stable JSON verdict
  schema.
- Interactive `[a]pprove · [h]old · [d]iff` prompt persisting clean versions
  to the SQLite store.
- OSV and GitHub Advisory revocation cache and engine.
- Sigstore / SLSA provenance and attestation surfacing.
- Policy-as-code via `blueline.toml` (advisories, provenance, allow/blocklists).
- `allow_unreviewed_baseline` allowlist rule for scripted onboarding of packages without an approved baseline; bootstrap findings stay visible but stop contributing risk (rendered as `[INFO]`, `"LOW"` in JSON), while content heuristics still apply in full. Note: the declared package name can reach a LOW verdict with zero interaction, so both `review --yes` and non-interactive `install` will proceed for it when nothing else is wrong; approving via `--yes` also marks the version known-clean as the diff anchor for future releases. Old binaries ignore this config key and fail closed.
- `blueline ci` lockfile diff scanner and PR reporting.
- Model Context Protocol (MCP) server and agent tools (`blueline mcp`).
- npm/npx wrapper shim (`@blueline/cli`).
- GitHub composite Action for PR checks.
- SQLite store with known-clean baselines, advisory/provenance caches, and an
  audit log.

### Changed

- Hardened static diff scanner against `String.fromCharCode` /
  `String.fromCodePoint` module-name reconstruction: charcode calls with
  plain integer arguments are folded to string literals before heuristic
  matching, closing one obfuscation route to `require(child_process)`.
- Hardened static AST/diff scanner with adjacent string literal folding to prevent concatenation evasion, dynamic global bracket invocations, String.fromCharCode property indexing, and indirect constructor/prototype references.
- Hardened static AST/diff scanner to detect reflection-based code execution (`Reflect.get`), global dynamic execution lookups (`globalThis['eval']`, `window['Function']`), and Node.js `worker_threads` imports without triggering false positives on benign JavaScript.
- Hardened archive extraction, SSRF checks, and executor isolation to fail
  closed on any doubt.
- Bounded registry reads with exact limits for packuments, tarballs, and
  redirects.
- Validated package name grammar, scoped URLs, and terminal escape sequences.
- Optimized static diff heuristic scanning, lockfile delta merging, SSRF IP validation, and terminal formatting with zero-allocation slice processing and O(N) two-pointer iteration.
- Optimized diff scanning performance.
- Clarified diagnostic stderr explanations when non-interactive input is piped
  without `--yes`.

### Fixed

- Isolated temporary build environment git repository resolution in CI test suites.

- IPv6 mutation testing by eliminating redundant address checks.
- Doubled `baseline store:` prefix in error messages caused by redundant error wrapping in `review`, `ci`, and `mcp` entry points.
- Baseline refusals now print an actionable hint naming the exact command to run (which predecessor version to approve) or the policy escape hatch, instead of failing with no next step.
- Redirect handling and false-equivalent bounds in registry metadata.
- JSON output purity by suppressing trailing human messages under `--output json --yes`.
- Timer string dynamic code evaluation (`setTimeout`, `setInterval`, `setImmediate`) in diff scanner heuristics.
- Zero-width and bidirectional unicode formatting character evasion in JavaScript token stripping.
- In-toto attestation empty subject bypass in SLSA provenance verification by enforcing matching subject digest.
- MCP standard heartbeat `ping` method handling returning empty JSON object.
- Case-insensitive parsing and uppercase aliases for `--fail-on` verdict risk bands.
- GitHub Actions composite step hardening mapping action inputs into environment variables to prevent shell injection.
- MCP tool output terminal escape and BiDi control character sanitization.

### Security

- Fail-closed on every parse, extract, and verify boundary.
- Integrated `cargo-deny` in CI to enforce licenses, bans, sources, and security advisories using `deny.toml`.
- Expanded PR diff and matrix mutation testing to guard `executor.rs`, `lockfile.rs`, `ci.rs`, and `mcp.rs` boundaries against regressions.
- Hardened static heuristic scanner against inline module requires, paren-wrapped constructors, http2/dns primitives, timer string eval, zero-width unicode obfuscation, indirect eval aliases, dynamic `this[...]` evaluation, `process.dlopen`, `cluster`, `WebAssembly` compilation, and external HTTP client libraries.
- Mutation testing and supply-chain audits run on every PR (CI gate).
