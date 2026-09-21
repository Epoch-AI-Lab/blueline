# GOAL: Close the Loop — a four-campaign mega-run for blueline

You are executing one large goal in `/home/kriday/code/blueline` (repo: blueline,
a release-diff review desk for the package install line — a fail-closed
security CLI in Rust). This prompt is self-contained: read `AGENTS.md` first;
its guardrails are hard constraints on every line you write.

## Mission

Take blueline from a single-release delta reviewer to a closed-loop,
agent-enforced, networked, self-distributed supply-chain gate, via four
campaigns in this order:

1. **Recursive review** — close the second-order delivery gap (R23 follow-up,
   generalized).
2. **Agent-native enforcement** — make the gate impossible for autonomous
   agents to bypass.
3. **Recall / revocation index** — the last unchecked box in README/ROADMAP.
4. **Dogfood & distribution** — ship it, and eat it (D9).

Order rationale: each campaign creates the conditions for the next — closure
findings feed agent enforcement, enforcement creates demand for a revocation
index, the index and enforcement ship together in the distribution pass.

## Ground rules (every campaign, no exceptions)
- Dont bother the user with questions or for external input since they will 
  not be at their computer during this massive goal.
- The CI gate is exactly `cargo fmt --all && cargo clippy --all-targets -- -D
  warnings && cargo test --all-targets --locked` and it must pass after every
  single commit. Toolchain is pinned in `rust-toolchain.toml`.
- Fail closed on every new parse/extract/verify boundary. Treat all fetched or
  extracted bytes as untrusted data. On any doubt, error out loud (`{e:#}`
  formatting) — never guess.
- `anyhow` at the boundary, `thiserror` inside modules. No `unsafe`. No new
  `unwrap()`/`expect()` on untrusted input.
- Never push to `main` (protected). Work on feature branches. At kickoff,
  state your branch strategy: one stacked branch per campaign with explicit
  `--base <previous>` per the night-run convention in `TODO.md`.For this one use a 
  branch for the entire 4 phases. 
- Small commits: **3–4 focused changes per commit, maximum.** No mega-commits.
  Conventional style matching repo history (`feat(scope): …`, `fix(scope): …`,
  `test(scope): …`). Every commit independently passes the CI gate.
- CHANGELOG: every slice adds its entry under `[Unreleased]` in the same
  branch (AGENTS.md rule).
- No code comments unless they earn their place. Unit tests beside code,
  integration tests in `tests/`.
- Read `ARCHITECTURE.md` before touching any module boundary. `extract.rs`
  and the SQLite `known_clean` store in `store.rs` are ask-first surfaces.
- FOLLOW ATOMIC COMMITS
## Phase 0 — Research (before ANY implementation, and again per campaign)

Research is a deliverable, not a formality. Do it up front and refresh it at
each campaign boundary. **No implementation code until each campaign's
research brief is written.**

Up front, in one pass:

- Read fully: `ARCHITECTURE.md`, `TODO.md`, `ROADMAP.md`, `CHANGELOG.md`,
  `README.md`, `deny.toml`, `.github/workflows/{ci,release}.yml`.
- Map the current surfaces you will touch: `src/review.rs`, `src/heuristic.rs`,
  `src/pkgbuild.rs`, `src/executor.rs`, `src/mcp.rs`, `src/cli.rs`,
  `src/policy.rs`, `src/advisory.rs`, `src/registry/*`, `src/lockfile.rs`,
  `src/ci.rs`, `src/store.rs`, and the `packages/` npm shim tree.

Then, per campaign, produce a **written research brief** in the ruling style
of the night runs in `TODO.md` (decisions locked, numbered, "no re-litigating"):

1. **Recursive review:** how the TanStack router worm and Atomic Arch actually
   delivered second-order payloads (Unit42 writeup, Atomic Arch postmortems);
   every mechanism by which a reviewed release can reference another install
   (npm lifecycle scripts spawning `npm install`, PKGBUILD npm/bun delivery,
   wheel `entry_points.txt`/console scripts, `.data/scripts`, Cargo build
   script `build.rs` declarations); prior art and its failure modes
   (`ignore-scripts`, pnpm `allow-build`, pip's build isolation).
2. **Agent enforcement:** how Claude Code hooks/permission modes, Cursor,
   Codex CLI, and other autonomous agents execute shell commands and where an
   interception point can actually bind; PATH-shim prior art (corepack, pipx,
   npx resolution order) and its bypass modes; the MCP `review_install` tool
   as primary (per ARCHITECTURE.md MCP design) with the shim as the
   enforcement backstop.
3. **Recall index:** the OSV API and schema, GitHub Advisory, deps.dev, and
   their publication lag windows (the TanStack-worm gap is the motivating
   scenario); local-first vs hosted trade-offs; sync/subscription protocol
   options; curation workflow for human-verified revocations.
4. **Dogfood & distribution:** sigstore/cosign, SLSA GitHub generators, npm
   `--provenance` (already in `release.yml`), Homebrew formula conventions,
   AUR packaging guidelines (blueline itself belongs on the AUR), and what
   `packages/` already contains.

Each brief states: goals, non-goals, locked rulings, the slice/PR plan, the
test + corpus strategy, and risks. Surface veto-worthy decisions instead of
guessing. **Ask first** on any dependency or any change to `extract.rs` /
`store.rs`.

## Campaign 1 — Recursive review (close the delivery loop)

Today blueline reviews one release delta. Both documented attacks (TanStack
worm, Atomic Arch) delivered through a *second-order* install nobody reviewed.
Fix that.

- Implement the deferred `R23_NPM_DELIVERY` follow-up from `TODO.md`: when a
  review discovers an install reference, pipe that referenced spec through the
  npm review engine rather than only naming it.
- **Generalize** into a recursive review pass: any install reference found in
  a reviewed payload — npm lifecycle script invoking a package manager,
  PKGBUILD `npm install`/`bun install` delivery, wheel entry points and
  `.data/scripts` — triggers a recursive blueline review of the referenced
  package, with:
  - a depth cap (fail closed, stated on the card, never silent);
  - cycle detection (A → B → A);
  - re-use of the existing cache machinery so referenced packages are not
    re-downloaded;
  - roll-up of child findings into the parent verdict (a HIGH finding in a
    referenced package must be able to BLOCK the parent — policy decides the
    threshold, fail closed when ambiguous).
- The review card renders the delivery chain ("delivered via: pkgbase →
  npm:package@ver"), the JSON verdict schema grows a recursive-findings field
  (it is the single source of truth per D7 — CLI, CI, and MCP all get it).
- Rules R23 (npm delivery) and friends graduate from INFO to their earned
  bands once recursive review covers what they point at.

## Campaign 2 — Agent-native enforcement

ARCHITECTURE.md marks the "invasive PATH shim" as secondary. Promote it: the
MCP `review_install` tool is what a well-behaved agent calls; the shim is what
makes bypass impossible.

- Non-interactive `--agent` mode: policy-bound approval (no interactive
  prompt), machine-readable verdict on stdout, exit codes CI and hooks can
  branch on, and an audit-log entry that records the invoking agent context.
- PATH-shim routing: installable shims that route `npm`, `npx`, `pip`,
  `cargo install`, and (where applicable) `yay`/`paru` invocations through
  blueline before the real package manager runs. Every shim is fail closed:
  if blueline errors or the policy cannot be resolved, the install does not
  run. Document every known bypass honestly on the card/docs (e.g. direct
  binary invocation, version flags that skip scripts) — no security theater.
- First-class integration recipes: Claude Code hook config, Cursor and Codex
  CLI equivalents — copy-paste configs like the yay `AURPreInstall` recipe in
  the README.
- Keep "no default telemetry" (D8): agent audit trails stay local unless the
  user explicitly opts in.
- Rework cli to be slightly more simple for an external agent who may be using it.
## Campaign 3 — Recall / revocation index

The one unchecked box in README and ROADMAP ("Revocation index and recall
API"), motivated by the TanStack-worm lag window in OSV.

- Build it **local-first and self-hostable**: an index service (in-repo,
  respecting the dependency rule) serving curated revocations; a client sync
  path in blueline that folds index hits into the existing advisory/revocation
  engine (`src/advisory.rs`) and the verdict as a BLOCK-class finding.
- Fail closed on sync failure that matters: a stale-beyond-threshold index is
  disclosed on the card, and a policy flag can make staleness BLOCK.
- Seeding: blueline's own audit log (approvals, holds, blocks) can export
  candidate revocations for human curation — the curation workflow is part of
  this campaign, even if minimal.
- Hosted deployment, tokens, and any paid-tier gating (D6) are **out of scope
  until the user approves** — the service must run end-to-end locally first.

## Campaign 4 — Dogfood & distribution

D9 says "we audit supply chains — we must eat our own dog food." Make it true.

- Fill the gaps in `packages/` so the npm shim is genuinely installable;
  verify `npx blueline-cli` works from a cold environment.
- Ship the CLI for real distribution paths: crates.io publish config, Homebrew
  formula, and blueline itself packaged for the AUR (reviewed by its own AUR
  reviewer, of course).
- Gate blueline's own supply chain with blueline: run `blueline ci` against
  this repo's `Cargo.lock` and `package-lock.json` on every PR, and review
  every blueline dependency delta before release.
- Signed, provenance-attested release binaries per D9 (wire into
  `release.yml`; npm publishing already uses `--provenance`).
- **Any external publish (npm, crates.io, AUR, Homebrew) requires explicit
  user confirmation — run `--dry-run`/packaging checks first and present the
  result.** Publishing is outward-facing; never auto-publish.
- Add as much dog-fooding as possible.

## Per-slice loop (inside every campaign)

A **slice** is one PR-shaped, reviewable unit from the campaign's brief
(e.g. Campaign 1 might be: slice 1 = install-reference detection + data
plumbing; slice 2 = recursive engine + caps/cycles; slice 3 = card/JSON/
policy roll-up; slice 4 = corpus + fuzz targets).

After **every** slice:

1. Run the full CI gate; fix before proceeding.
2. Dispatch **subagents in parallel** (Agent tool, `Explore`/`general-purpose`
   as appropriate) for three independent reviews:
   - **Adversarial security reviewer:** walk every new parse/extract/verify
     boundary as hostile input. Hunt for: anything executed or sourced that
     should only be parsed, missing bounds/caps, silent truncation, unwrap on
     untrusted data, shell injection in any subprocess invocation (argv-only,
     never a shell), fail-open paths.
   - **Test auditor (non-bloat):** tests must pin behavior and kill mutants —
     no snapshot theater, no redundant fixtures, no tests that pass under
     mutation. Flag BOTH gaps in coverage AND bloat; recommend deletions
     where a test adds nothing.
   - **Fresh-eyes code reviewer:** module boundaries vs ARCHITECTURE.md,
     error surfacing with `{e:#}`, naming, dead code, comment discipline.
3. Fix every P1/P2 finding, then **re-dispatch the reviewers** on the fixed
   diff. Repeat until clean. A slice is not done until reviewers pass it.
4. Add the CHANGELOG `[Unreleased]` entry and commit in small commits (3–4
   changes each).

## After each campaign — use the thing (use-it skill)

After each campaign passes review, use the `use-it` skill to actually use
what you built, end to end, in this environment. Reading the code is not
using it.

1. **Recursive review:** build an adversarial fixture registry where package
   A's lifecycle script references package B whose delta contains a backdoored
   script — the real CLI must surface the recursive finding and BLOCK without
   executing anything. Also run a real `blueline --ecosystem aur review`
   against a PKGBUILD with npm delivery and confirm the chain renders.
2. **Agent enforcement:** install the shim in a sandboxed project, run a real
   `npm install` through it (approved version passes, unapproved blocks, audit
   trail written), and wire a Claude Code hook config and trigger it.
3. **Recall index:** run the service locally, seed one human-verified
   revocation, query it from the client, and verify: hit → BLOCK, stale index
   → disclosed, service down → fail-closed behavior per the brief.
4. **Distribution:** install the artifact through the real channel in a clean
   environment (or dry-run equivalent pending publish approval) and re-run the
   Campaign 1–3 verifications against the distributed binary, not the local
   build. Gate blueline's own dependency delta with `blueline ci`.

If a use-it pass exposes gaps: fix, re-run the slice review loop, re-run
use-it. Do not start the next campaign until the current one survives being
used.

## Completion — the PR

After all four campaigns are implemented, reviewed, and use-it verified:

- Use the **`make-a-pr` skill** to open the PR. Given the size, prefer
  **stacked PRs per campaign** with explicit `--base <previous-branch>` and
  the base declared in each body (the TODO.md night-run convention) over one
  unreviewable mega-PR — state the choice in the first PR body.
- Each PR body includes: per-slice summary, the research brief (rulings),
  use-it evidence (commands run and outcomes), and subagent review results.
- `CHANGELOG.md` `[Unreleased]` is complete and accurate for everything in
  the PRs. Mark your campaign's checkbox in this file's status list below in
  the same branch.

## Definition of done

- [x] Campaign 1: recursive review — implemented, reviewed clean, use-it pass
- [x] Campaign 2: agent enforcement — implemented, reviewed clean, use-it pass
- [x] Campaign 3: recall index — implemented (local-first), reviewed clean,
      use-it pass
- [x] Campaign 4: dogfood & distribution — packaged, signed config wired,
      self-CI gated, publish pending user confirmation
- [x] CI gate green on the final branch of each campaign
- [x] PR(s) open via make-a-pr with the full evidence trail

Start with Phase 0 research. Do not write implementation code before the
Campaign 1 brief exists.
