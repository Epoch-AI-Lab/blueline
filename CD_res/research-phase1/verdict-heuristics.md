# Verdict heuristics research

Research for the Blueline Phase 1 heuristic verdict engine and scoring, in support of
ARCHITECTURE.md section 2 (rule set v1, verdict bands LOW / MEDIUM / HIGH / BLOCK).
Compiled 2026-08-13. Every claim is grounded in the cited URL; things that could not be
verified are called out in the adversarial self-check at the end.

---

## 1. How existing npm supply chain tools actually score

### npq (lirantal/npq, Rimas Silkaitis' original; now Liran Tal's)

npq is a pre-install auditor built on pluggable checks called "marshalls" and it does
**not** produce a numeric score. It has two severity outputs: Warning and Error. Warnings
auto-continue the install after a 15-second countdown; errors prompt with a default of
"no". `NPQ_DISABLE_AUTO_CONTINUE=true` removes the countdown and forces an explicit
answer ([npq README](https://github.com/lirantal/npq)). The marshall framework is
documented at [deepwiki.com/lirantal/npq](https://deepwiki.com/lirantal/npq) and the
per-check documentation lives in [docs/](https://github.com/lirantal/npq/tree/master/docs).

Concrete npq thresholds (these are the most useful public "calibration" numbers in the
ecosystem):

- Age marshall: warns if package age on npm is less than 22 days
  ([npq README, marshall table](https://github.com/lirantal/npq)).
- Version maturity: error if the installed version was published less than 7 days ago;
  suggests the highest older semver outside a 30-day recency window
  ([README marshall table](https://github.com/lirantal/npq)).
- Author marshall ([docs/feature/author-marshall.md](https://github.com/lirantal/npq/blob/main/docs/feature/author-marshall.md)):
  - New author: error if the publisher's first release on the package and published
    within the last 21 days.
  - Dormant maintainer: error if the same `_npmUser.email` published, then went silent
    > 274 days (~9 months) before publishing again; warning at > 183 days (~6 months).
  - Version recency: error if the tarball is <= 7 days old, warning if 8-30 days.
  - Check order matters: "The first thrown Error or Warning ends validation."
- Provenance marshall: verifies Sigstore attestations and **errors** on provenance
  regression (an older semver had attestations, the target version does not); missing
  provenance on a package that never had it is warning-only
  ([docs/feature/provenance.md](https://github.com/lirantal/npq/blob/main/docs/feature/provenance.md)).
- Security marshall severity split: vulnerabilities and known-malicious packages are
  hard errors; missing provenance, signature verification failures, and registry key
  fetch problems are warnings (graceful degradation)
  ([DeepWiki security marshalls](https://deepwiki.com/lirantal/npq/5-security-marshalls)).
- Typosquatting, install scripts, expired maintainer domains, downloads, README/LICENSE/
  repo presence are the remaining signals
  ([OpenReplay write-up](https://blog.openreplay.com/npm-package-security-checks-npq/)).

Design takeaway: npq's model is "signals you weigh, not a binary verdict", with exactly
two bands (Warning vs Error) where Error maps to Blueline's BLOCK-ish behavior (default
no) and Warning maps to MEDIUM/HIGH (proceed after a countdown). There is no weighted
sum anywhere in npq.

### socket.dev

Socket publishes its scoring formula and weights openly, which makes it the primary
reference for scoring math.

- Categories scored 0-100: supply chain risk, quality, maintenance, vulnerabilities,
  license; the overall `depscore` is the average of the factor scores
  ([docs, package scores](https://docs.socket.dev/docs/package-scores),
  [deprecated score API reference](https://docs.socket.dev/reference/getscorebynpmpackage)).
- Formula per category:
  `S_i = 100 * min( max(0, min_j l_i,j), sum_j w_j * N_j(x_j) / sum_j w_j )^gamma`
  with `gamma ≈ 1/2 + c0*log(lines of code) + c1*log(popularity)`. The power exponent
  "compresses low scores and softens the impact of penalties, especially for large or
  popular packages"
  ([docs, package scores](https://docs.socket.dev/docs/package-scores)).
- Alert normalization functions and caps (public, same page):
  - Critical alerts: limit = min(0.25, weighted average). With gamma = 0.8, a cap of
    0.25 lands a final score around 33; a lower weighted average pushes it further down.
  - High alerts: `e^-x`, capped at `max(0.25, 1 - x/10)`, bottoming at 0.25 at 8+ alerts.
  - Medium alerts: `e^(-x/20)`, capped at `max(0.5, 1.15 - x/20)`, leveling at 0.5 after
    about 13 alerts.
  - Low alerts: `e^(-x/40)`, no cap.
- Weights (public, same page): critical 1, high 2, medium 2, low 3; license quality 12;
  maintainer count 5; versions last year 5; download count 5; versions last two months 3;
  versions last month 2; versions last week 1; open/closed issues 1/1; commits 1-1; readme
  length 5; bundle size 2; stargazers/forks/watchers 1/1/1; lines of code 0.5; transitive/
  total/dependency counts 1/1/1; dev dependency count 0.5; dependency vulnerability count 1
  (limit 0.5 if x > 0); vulnerability count 1.
- Deep scores aggregate across transitive dependencies with **min** ("The function used
  to calculate the values in aggregate is: min")
  ([docs, socket package](https://docs.socket.dev/docs/socket-package)).
- Capability alerts are tiered by risk: network access = Medium, shell access = Medium,
  filesystem access = Low
  ([supply chain risk](https://docs.socket.dev/docs/supply-chain-risk),
  [networkAccess](https://socket.dev/alerts/networkAccess),
  [shellAccess](https://socket.dev/alerts/shellAccess)).
- Detection scope: 70+ red flags covering new install scripts, obfuscated code, high
  entropy strings, `eval()`, shell/network/filesystem/env access, remote code loaded via
  git/HTTP URLs, typosquats, permission creep
  ([FAQ](https://docs.socket.dev/docs/faq), [introducing socket](https://socket.dev/blog/introducing-socket)).
- Threshold guidance (their own docs, non-official): 90-100 strong, 70-80 minor but
  acceptable, 50-60 review carefully, below 50 look for alternatives
  ([Socket MCP docs](https://docs.socket.dev/docs/socket-mcp-for-claude-desktop)); their
  Claude Code hook blocks installs when the supply chain score is below 20
  ([socket-mcp repo](https://github.com/socketdev/socket-mcp)).

Important caveat from Socket itself: "The contents of this document may not exactly
represent the scoring system as deployed in Socket at this point in time"
([docs, package scores](https://docs.socket.dev/docs/package-scores)).

### sandworm-audit

Sandworm has **no composite numeric score**. It builds a dependency graph from manifest +
lockfile, then emits severity-tagged issues: CVEs (from `npm audit`/`yarn audit`/
`pnpm audit`, which read the GitHub Advisory Database), license issues, and "meta" issues
such as install scripts (`SWRM-201`, one per preinstall/postinstall script) and
non-registry dependencies (`SWRM-203/204/205` for `http:`, `git:`, `file:` sources)
([docs, how it works](https://docs.sandworm.dev/audit/how-it-works),
[docs, issue types](https://docs.sandworm.dev/audit/issue-types)).
CI gating is a configurable `--fail-on` policy of the form `type.severity` with
severities critical/high/moderate/low; nothing fails by default
([docs, fail policies](https://docs.sandworm.dev/audit/fail-policies)). No weights or
scoring math are published.

### osv-scanner

osv-scanner is detection-only: it resolves the dependency tree, matches against the OSV
database, and reports the advisories it finds. Severity comes from the advisory record
(CVSS vector and/or ecosystem severity); osv-scanner itself has no risk model, no
composite score, and no malware heuristics
([osv.dev blog](https://osv.dev/blog/posts/announcing-transitive-dependency-support-for-maven-pomxml-in-osv-scanner/),
[OSV API discussion confirming no calculated score is exposed](https://github.com/google/osv.dev/discussions/2643)).
Relevance to Blueline: the OSV database now also carries malware records (the TanStack
advisories GHSA-g7cv-rxg3-hmpx and CVE-2026-45321 are OSV entries) which is exactly the
"revocation" corpus Blueline already plans to use.

### npm audit

npm audit queries the GitHub Advisory Database (via the npm database mirror) and buckets
findings as info/low/moderate/high/critical. `--audit-level` sets the minimum severity
that causes a non-zero exit; the default is "any vulnerability". Transitive paths are
computed by `@npmcli/metavuln-calculator`
([npm audit docs](https://docs.npmjs.com/cli/v9/commands/npm-audit),
[about audit reports](https://docs.npmjs.com/about-audit-reports/)). Advisory severity is
assigned by GitHub curation from CVSS, optionally enriched with EPSS
([GitHub Advisory database docs](https://docs.github.com/code-security/security-advisories/working-with-global-security-advisories-from-the-github-advisory-database/about-the-github-advisory-database),
[GitHub blog, EPSS table](https://github.blog/security/github-advisory-database-by-the-numbers-known-security-vulnerabilities-and-what-you-can-do-about-them/)).

### Snyk

Snyk maps CVSS base score to severity with fixed bands: Critical 9.0-10.0, High 7.0-8.9,
Medium 4.0-6.9, Low 0.0-3.9
([Snyk severity levels](https://docs.snyk.io/scan-fix-and-prevent/fix/prioritize-issues-for-fixing/severity-levels.md)).
Snyk's "Priority Score" combines CVSS with reachability, exploit maturity and other
factors, but the formula is not publicly documented. Its incident ratings provide a
useful external sanity check on severity of real events: node-ipc wiper was rated 9.8
(critical) while peacenotwar alone was 3.7 (low)
([Snyk node-ipc analysis](https://snyk.io/blog/peacenotwar-malicious-npm-node-ipc-package-vulnerability/)).

**Summary table:**

| Tool | Score model | Bands | Thresholds | Weights public |
| --- | --- | --- | --- | --- |
| npq | signal checks, no sum | Warning / Error | age <22d warn; version <7d err, <30d warn; new author <21d err; dormant >274d err, >183d warn | n/a |
| socket.dev | weighted sum + per-metric caps + power scaling | 0-100 continuous | <20 block (their hook); <50 avoid; 90-100 strong | yes (full table) |
| sandworm-audit | issue list with severities | critical/high/moderate/low | user `--fail-on` policy, default none | no (none exists) |
| osv-scanner | none | none | none | n/a |
| npm audit | advisory match, no scoring | info/low/moderate/high/critical | `--audit-level` default = any | n/a |
| Snyk | CVSS bands + unpublicized priority score | low/medium/high/critical | 0-3.9 / 4-6.9 / 7-8.9 / 9-10 | band mapping only |

---

## 2. Evidence based signals: what actually caught real npm attacks

### event-stream / flatmap-stream (2018)

- ~2 million weekly downloads of event-stream at the time (~8M downloads over the
  campaign window); malicious code reached Copay versions 5.0.2-5.1.0
  ([npm blog postmortem](https://blog.npmjs.org/post/180565383195/details-about-the-event-stream-incident),
  [incident paper](https://es-incident.github.io/paper.html)).
- Attack shape: a social engineering takeover. `@right9ctrl` volunteered to maintain
  `event-stream`; on 2018-09-09 added `flatmap-stream` (a brand new, near-zero-download
  package, created 3 months earlier, 1 commit, unmaintained) as a dependency of
  `event-stream@3.3.6` using a caret range `^0.1.0`. On 2018-10-05,
  `flatmap-stream@0.1.1` shipped the payload: minified code plus a file of hex string
  literals; the payload decrypted itself using the parent package's
  `npm_package_description` as an AES key, targeted the Copay Bitcoin wallet, and
  exfiltrated private keys to 111.90.151.134 when balances exceeded 1000 BTC / 1000 BCH
  ([Snyk postmortem](https://snyk.io/blog/a-post-mortem-of-the-malicious-event-stream-backdoor/),
  [GHSA-9x64-5r7x-2q53](https://github.com/advisories/GHSA-9x64-5r7x-2q53)).
- **Diff signal that should have caught it:** new maintainer with no track record; a
  brand-new near-zero-download dependency added with an unbounded caret range; minified/
  obfuscated code with hex string tables; tarball contents that did not exist in the
  GitHub repo; a new file in the tarball that was the only change of substance.
- **Signals absent:** no install script. The payload ran at `require()` time inside the
  package's own code, which is exactly the "if we took away install scripts, attackers
  would move payloads inside the package code" scenario npm later described
  ([npm blog, eslint follow-up](https://blog.npmjs.org/post/176488970320/community-questions-following-the-eslint-security.html)).
- Detection was incidental: a deprecation warning for `crypto.createDecipher` surfaced in
  a nodemon issue and a user connected it to event-stream
  ([incident paper](https://es-incident.github.io/paper.html)).

### eslint-scope + eslint-config-eslint (2018)

- Account takeover: a maintainer reused a password and had no 2FA. The attacker published
  `eslint-scope@3.7.2` and `eslint-config-eslint@5.0.2`, each adding a `postinstall`
  script (`node ./lib/build.js`); `build.js` fetched a paste from pastebin and `eval`'d
  it; the payload read `~/.npmrc`, stripped `_authToken`, and exfiltrated it via Referer
  headers to histats/statcounter. npm revoked all pre-2018-07-12 12:30 UTC tokens
  ([ESLint postmortem](https://eslint.org/blog/2018/07/postmortem-for-malicious-package-publishes/),
  [issue #39](https://github.com/eslint/eslint-scope/issues/39)).
- **Diff signal:** the postinstall script and `build.js` appeared from nowhere; the new
  script reached the network and used `eval`. Amalfi (githubnext) cites this exact case:
  "the above-mentioned eslint-scope package uses runtime code generation and an install
  script in its (malicious) version 3.7.2, capabilities it had never used before"
  ([Amalfi paper](https://dl.acm.org/doi/10.1145/3510003.3510104)).

### ua-parser-js (2021)

- Account takeover via credential reuse with no MFA. >7M weekly downloads (per Mandiant). On 2021-10-22
  three versions were published at once (0.7.29, 0.8.0, 1.0.0), deliberately spanning
  three major lines so every caret range downstream resolved to a bad version. The
  package gained a `preinstall` script (`preinstall.js`) plus `preinstall.sh`/`preinstall.bat`
  which downloaded an XMRig miner (`jsextension`) and a DanaBot credential stealer DLL,
  with geo-conditional activation (skipped Russia, Ukraine, Belarus, Kazakhstan) and
  throttled CPU. CISA alert AA21-295A followed within a day
  ([safeguard analysis](https://safeguard.sh/resources/blog/ua-parser-js-npm-hijack-october-2021),
  [BleepingComputer](https://www.bleepingcomputer.com/news/security/popular-npm-library-hijacked-to-install-password-stealers-miners/),
  [CISA alert](https://www.cisa.gov/news-events/alerts/2021/10/22/malware-discovered-popular-npm-package-ua-parser-js)).
- **Diff signal:** a brand-new preinstall script added to an established package; new
  OS-specific script files; download-then-execute URLs; the multi-major simultaneous
  version bump (version-squat pattern).

### coa + rc (2021)

- Same attacker as ua-parser-js, one week later. Both packages had been dormant for about
  3 years (coa last stable 2.0.2 in Dec 2018, rc similarly stale) before a burst of
  versions appeared in hours: coa 2.0.3, 2.0.4, 2.1.1, 2.1.3, 3.0.1, 3.1.3; rc 1.2.9,
  1.3.9, 2.3.9. Combined ~23M weekly downloads. The `preinstall` field ran
  `start /B node compile.js & node compile.js`; `compile.js` was obfuscated and launched
  an obfuscated `compile.bat` (variable-expansion obfuscation) which downloaded
  `sdd.dll` (Danabot) via curl/wget/certutil fallbacks and loaded it with regsvr32
  ([BleepingComputer](https://www.bleepingcomputer.com/news/security/popular-coa-npm-library-hijacked-to-steal-user-passwords/),
  [Sonatype](https://www.sonatype.com/blog/npm-hijackers-at-it-again-popular-coa-and-rc-open-source-libraries-taken-over-to-spread-malware),
  [FOSSA](https://fossa.com/blog/embedded-malware-npm-coa-rc-ua-parser/),
  [GHSA-73qr-pfmq-6rp8](https://github.com/advisories/GHSA-73qr-pfmq-6rp8),
  [GHSA-g2q5-5433-rhrf](https://github.com/advisories/GHSA-g2q5-5433-rhrf)).
- **Diff signal:** dormant-package resurrection (release after years of inactivity, which
  CI failures in React pipelines flagged first); new preinstall; obfuscated JS/batch
  payloads; LOLBin usage (certutil); multiple versions across majors in one burst.

### node-ipc / peacenotwar (2022)

- Author-led protestware (not a hijack). Versions 10.1.1/10.1.2 contained base64-encoded
  code that geolocated the user and, if in Russia or Belarus, recursively overwrote files
  with a heart emoji. After the destructive payload was pulled in 10.1.3, `11.0.0`
  (released under four hours later) imported the new `peacenotwar` package, and later
  `9.2.2` (the stable patch line used by @vue/cli) also added it; `colors@*` wildcard was
  bundled in too. Snyk rated node-ipc 9.8 critical
  ([Snyk analysis](https://snyk.io/blog/peacenotwar-malicious-npm-node-ipc-package-vulnerability/),
  [SNYK-JS-NODEIPC-2426370](https://security.snyk.io/vuln/SNYK-JS-NODEIPC-2426370),
  [Ars Technica](https://arstechnica.com/information-technology/2022/03/sabotage-code-added-to-popular-npm-package-wiped-files-in-russia-and-belarus/)).
- **Diff signal:** base64-encoded strings inside the diff; a new near-zero-download
  dependency on the stable patch line; rapid multi-version churn; wildcard dependency
  additions. Maintainer-change signals would have missed this one entirely because it was
  the maintainer.

### TanStack/router worm (2026)

- On 2026-05-11 between 19:20 and 19:26 UTC, 84 malicious versions across 42
  `@tanstack/*` packages were published (two per package, about 6 minutes apart).
  Detection by an external researcher came 20-26 minutes after each publish batch
  ([TanStack postmortem](https://tanstack.com/blog/npm-supply-chain-compromise-postmortem),
  [GHSA-g7cv-rxg3-hmpx](https://github.com/TanStack/router/security/advisories/GHSA-g7cv-rxg3-hmpx),
  [tracking issue #7383](https://github.com/TanStack/router/issues/7383)).
- Every modern control was in place and none was "broken": 2FA on maintainers, npm OIDC
  trusted publishing scoped to a workflow and ref, no long-lived tokens, and **valid SLSA
  provenance attestations signed by the legitimate tanstack/router repository**. The
  attacker chained a `pull_request_target` "Pwn Request" pattern, GitHub Actions cache
  poisoning across the fork-to-base boundary, and OIDC token extraction from runner
  memory
  ([Endor Labs explainer](https://www.endorlabs.com/learn/how-a-misconfigured-ci-workflow-became-an-npm-supply-chain-compromise),
  [StepSecurity report](https://github.com/tanstack/router/issues/7383)).
- Payload mechanics: each malicious manifest added an
  `optionalDependencies` entry `"@tanstack/setup": "github:tanstack/router#79ac49ee..."`
  pointing at an orphan commit in a renamed fork. npm resolves git deps by "build from
  source", runs the commit's `prepare` script (`bun run tanstack_runner.js && exit 1`;
  the `exit 1` makes npm silently discard the failed optional install), and that script
  executes `router_init.js`, a ~2.3 MB obfuscated file smuggled into each tarball at the
  package root and deliberately omitted from the package's `files` array
  ([advisory](https://github.com/TanStack/router/security/advisories/GHSA-g7cv-rxg3-hmpx)).
- Impact: harvest of AWS IMDS/Secrets Manager, GCP metadata, Kubernetes SA tokens, Vault
  tokens, `~/.npmrc`, GitHub tokens, SSH keys; exfiltration over the Session messenger
  file-upload network (end-to-end encrypted dead drops with no attacker-controlled C2);
  and self-propagation by republishing other packages the victim maintains
  ([advisory](https://github.com/TanStack/router/security/advisories/GHSA-g7cv-rxg3-hmpx)).
- **Diff signal that should have caught it:** a brand-new `optionalDependencies` entry
  resolving to a `github:` URL (non-registry, non-semver source) when every prior release
  used registry semver deps; a new ~2.3 MB minified/obfuscated file at the tarball root
  absent from `files`; two versions published minutes apart (churn); `latest` flipping
  twice in six minutes.
- **Signals absent:** no maintainer change, no stolen token, provenance valid and
  present, tarballs built in a legitimate CI run. The TanStack follow-up blog states
  plainly: "the npm provenance, SLSA, OIDC, and 2FA all worked as advertised and still
  didn't stop this attack" and "Provenance shouldn't be confused with innocence"
  ([TanStack hardening blog](https://tanstack.com/blog/incident-followup)).
- The 2026-08-04 `keyv` family incident (Snyk) repeats the pattern: malicious source was
  present in the tagged repository state, so the legitimate workflow built and attested
  the malicious artifact; every file in the library was byte-identical to the clean
  release candidate while the lifecycle hook executed separately, so "that small diff is
  a useful detection clue and an effective concealment technique"
  ([Snyk keyv analysis](https://snyk.io/blog/inside-keyv-npm-compromise-preinstall-malware-trusted-provenance-ide-hooks/)).

### What the incidents teach Blueline

| Incident | New install script | New near-zero dep | Obfuscation | Dormant resurrection | Multi-version burst | Maintainer change | Provenance present |
| --- | --- | --- | --- | --- | --- | --- | --- |
| event-stream 2018 | no | yes | yes (hex/minified) | n/a (active) | no | yes | no |
| eslint-scope 2018 | yes | no | yes (pastebin+eval) | no | no | no (token theft) | no |
| ua-parser-js 2021 | yes | no | partial (scripts) | no | yes (3 majors at once) | no (token theft) | no |
| coa+rc 2021 | yes | no | yes (obfuscated js/bat) | yes (3y dormant) | yes (6 versions/hours) | no (token theft) | no |
| node-ipc 2022 | no | yes | yes (base64) | no | yes (10.1.1 to 11.0.0 in hours) | n/a (author) | no |
| TanStack 2026 | via git-dep `prepare` | yes (fake pkg) | yes (2.3 MB minified) | no | yes (2 versions/6 min) | no | yes (valid SLSA) |

Every single attack except node-ipc is detectable from the **diff against the previous
known-good version**, and even node-ipc's wiper was base64-obfuscated in the diff.
Obfuscation, new near-zero-popularity dependencies, and version-burst churn are the three
signals present in the majority of cases. Provenance was present in the most recent
attack and did not help; it must stay "surfaced, never trusted" exactly as ARCHITECTURE
D5/D6 and the rule set say.

---

## 3. Known-bad fingerprints: can install scripts alone be classified?

### Prevalence data (why "install script present" is noisy)

- Only 2.2% of npm packages (33,249 of 1.63M) use install scripts; among the top
  popular packages 362 (2.5%) do. When the researchers scanned install scripts for
  threatening keywords (curl, wget, /etc/shadow, /etc/passwd), 74 packages matched and
  only 11 were actually malicious; the rest were benign
  ([Weak Links in the npm Supply Chain, ICSE 2022](https://patricegodefroid.github.io/public_psfiles/icse2022.pdf)).
- In a cross-language study, 81% of confirmed-malicious npm packages used install hooks,
  versus 8% of false positives and 2% of benign packages. Presence alone is a strong
  prior for brand-new packages, but because benign packages vastly outnumber malicious
  ones, raw "has install script" flags produce many false positives
  ([ACSAC 2023](https://inria.hal.science/hal-04423806/document)).
- Auto-detection false positive rates in the literature are high: Cerebro's real-world
  npm detection had a 58.3% false positive rate across flagged versions, though the
  flagged set was small enough for one person to triage in an hour a day
  ([Cerebro](https://export.arxiv.org/pdf/2309.02637v1.pdf)); Amalfi got false positives
  below 1 in 1000 only after iterative retraining, with roughly 40% recall on a decision
  tree ([Amalfi](https://dl.acm.org/doi/10.1145/3510003.3510104)). A CodeQL-based,
  precision-first approach found 125 malicious packages with zero false alarms by
  deliberately sacrificing recall
  ([CodeQL poster](https://www.plai.ifi.lmu.de/publications/ccs23poster-codeql.pdf)).
- Latch (dynamic install-time sandboxing) found that even a strict developer policy that
  blocks network and file writes blocks 82% of "potentially undesirable" packages but
  also blocks many benign script users; a registry-maintainer policy was far more
  permissive (14%), showing the sensitivity of any single "restrict scripts" rule to
  policy design
  ([Latch paper](https://ldklab.github.io/assets/papers/asiaccs22-latch.pdf)).

### What legit install scripts look like

- Optional-dependency platform binaries instead of postinstall: esbuild -> `@esbuild/linux-x64`
  and similar per-platform packages; SWC, sharp -> `@img/sharp-linux-x64`, rollup,
  lightningcss, Biome, oxc all follow the prebuilt pattern
  ([npm RFC 0054](https://github.com/npm/rfcs/blob/main/accepted/0054-make-scripts-install-opt-in.md)).
- Genuine postinstall that stays: `canvas` (node-gyp rebuild), `sharp` (node install/libvips),
  `prisma` / `@prisma/engines` (downloads platform engine binaries), and `core-js` (a
  funding banner that only writes a file and reads env vars)
  ([RFC 0054](https://github.com/npm/rfcs/blob/main/accepted/0054-make-scripts-install-opt-in.md),
  [npm-script-lens demo report](https://github.com/Booyak101/npm-script-lens),
  [dev.to walkthrough](https://dev.to/booyak101/npm-v12-stopped-running-install-scripts-which-ones-do-you-approve-a-real-audit-walkthrough-b1l)).
- A concrete capability classification that separates them (from npm-script-lens, which
  statically analyzes scripts and their require-chains):
  - HIGH: spawns processes (child_process, execa, node-gyp, unresolved binaries) or runs
    constructed code (eval, new Function, vm, string-built require, base64/char-code
    payload decoding);
  - MEDIUM: network access without exec;
  - LOW: filesystem writes or process.env reads only;
  - SAFE: none
  ([npm-script-lens](https://github.com/Booyak101/npm-script-lens)).

### What malicious install scripts look like

- Conditional activation: geo-check and skip regions (ua-parser-js skipped Russia/
  Ukraine/Belarus/Kazakhstan; node-ipc targeted exactly those; peacenotwar wrote to the
  Desktop) ([safeguard](https://safeguard.sh/resources/blog/ua-parser-js-npm-hijack-october-2021),
  [Snyk node-ipc](https://snyk.io/blog/peacenotwar-malicious-npm-node-ipc-package-vulnerability/)).
- Download-then-execute with LOLBin fallbacks: curl, then wget, then certutil, executed
  via regsvr32 (coa, rc, ua-parser-js)
  ([Sonatype coa/rc](https://www.sonatype.com/blog/npm-hijackers-at-it-again-popular-coa-and-rc-open-source-libraries-taken-over-to-spread-malware)).
- Obfuscated script bodies: variable-expansion obfuscated batch (coa), base64 string
  tables (node-ipc), encrypted/hex data (flatmap-stream), 2.3 MB minified payload
  (TanStack) ([BleepingComputer coa](https://www.bleepingcomputer.com/news/security/popular-coa-npm-library-hijacked-to-steal-user-passwords/),
  [GHSA-9x64-5r7x-2q53](https://github.com/advisories/GHSA-9x64-5r7x-2q53)).
- Scripts that reach remote code: eslint-scope's postinstall fetched a pastebin paste
  and eval'd it ([eslint postmortem](https://eslint.org/blog/2018/07/postmortem-for-malicious-package-publishes/)).
- Files present in the tarball but not the repo or the `files` array (flatmap-stream's
  hex file; TanStack's router_init.js) ([incident paper](https://es-incident.github.io/paper.html),
  [TanStack advisory](https://github.com/TanStack/router/security/advisories/GHSA-g7cv-rxg3-hmpx)).

### Verdict on "install script presence" as a BLOCK signal

Research is unambiguous on two points:

1. Presence alone is too noisy to BLOCK for established packages. 97.5% of popular
   packages avoid install scripts, but the ones that have them include legitimate native
   tooling (sharp, canvas, prisma, core-js), and the ecosystem's answer is review-and-
   allowlist, not block: npm v12 blocks dependency install scripts by default behind an
   `allowScripts` allowlist ([RFC 0054](https://github.com/npm/rfcs/blob/main/accepted/0054-make-scripts-install-opt-in.md),
   [npm install-scripts docs](https://docs.npmjs.com/cli/v12/commands/npm-install-scripts/)),
   pnpm has `allowBuilds` / "block risky postinstall scripts"
   ([pnpm supply chain docs](https://pnpm.io/supply-chain-security)), bun has
   `trustedDependencies` ([bun lifecycle docs](https://bun.com/docs/pm/lifecycle)).
2. A **change** in install script capability is the highest-value signal: "a package
   suddenly starts using capabilities it has never used before" is Amalfi's stated
   detection rationale and matches eslint-scope, ua-parser-js, coa, rc, and the 2026
   keyv/TanStack incidents ([Amalfi](https://dl.acm.org/doi/10.1145/3510003.3510104),
   [Snyk keyv](https://snyk.io/blog/inside-keyv-npm-compromise-preinstall-malware-trusted-provenance-ide-hooks/)).

So: BLOCK on "install script that did not exist in the baseline" is defensible (that is
the small-diff, capability-change case). BLOCK on "install script present at all on first
sighting" is not; that case must be HIGH plus a separate human decision, matching
Blueline's D11 (approve = `--ignore-scripts`, script surfaced for a separate decision).

---

## 4. Scoring math

### What the tools actually do

- **socket.dev: additive-with-caps.** Weighted sum of normalized per-metric scores,
  bounded by a per-metric cap (`min(l, weighted avg)`), then raised to a popularity-and-
  size-dependent power gamma. A single critical alert cannot drag the score below ~0.25
  via caps alone; many high alerts converge to a floor; the gamma exponent lets popular
  packages recover. Deep (transitive) scores use **min** across the tree
  ([docs, package scores](https://docs.socket.dev/docs/package-scores),
  [docs, socket package](https://docs.socket.dev/docs/socket-package)).
- **npq: first-thrown-signal-wins, two bands.** No arithmetic at all; the first Error or
  Warning in marshall check order terminates the audit for that package
  ([author marshall docs](https://github.com/lirantal/npq/blob/main/docs/feature/author-marshall.md)).
- **sandworm, npm audit, osv-scanner:** no composite math; severity comes from issue type
  or advisory metadata.
- **Snyk:** fixed CVSS band mapping; priority score formula not public
  ([Snyk severity docs](https://docs.snyk.io/scan-fix-and-prevent/fix/prioritize-issues-for-fixing/severity-levels.md)).

### Monotonic, additive, capped, or multiplicative

- Monotonicity: all published models are monotonic in the "worse" direction for a given
  signal. Socket's normalization functions are monotonic decaying in alert count and its
  caps are floors, not ceilings on risk. For Blueline, every signal must add risk only;
  no "good" signal may subtract risk (a maintainer's popularity is context, not a
  discount).
- Additive vs max vs product: socket uses a weighted sum plus caps; the incidents argue
  that a **single decisive signal must be able to dominate** (a new install script that
  downloads and executes is BLOCK-worthy regardless of the package's other attributes),
  which a pure unweighted sum cannot guarantee but caps-plus-triggers can. Product models
  (as in EPSS-style probability) are not used publicly by any npm tool for this decision
  problem; EPSS is a calibration precedent for probability thresholds, not a scoring
  scheme for diffs ([GitHub EPSS table](https://github.blog/security/github-advisory-database-by-the-numbers-known-security-vulnerabilities-and-what-you-can-do-about-them/)).
- Caps/floors: socket's soft caps are the published precedent and are worth copying in a
  simplified form. A hard BLOCK latch (revocation, new install script, non-registry git
  dependency) is the analogue of socket's critical-alert cap of 0.25, only expressed as a
  policy flag instead of a number.
- No published rubric for how socket or sandworm weight *heuristic diff signals* against
  each other beyond socket's alert table. Socket's docs explicitly disclaim that the
  published formulas may drift from deployment. Sandworm publishes no rubric at all.
  Blueline's weights therefore cannot be "imported" from a public source; they must be a
  first-principles v1 with incident-derived magnitudes (section 2), documented as such.

---

## 5. Threshold calibration

### Precedents to anchor band boundaries

- CVSS v4 qualitative scale (FIRST spec, Table 22): None 0.0, Low 0.1-3.9, Medium
  4.0-6.9, High 7.0-8.9, Critical 9.0-10.0
  ([CVSS v4 spec](https://www.first.org/cvss/specification-document)).
  Snyk's bands match these ranges exactly
  ([Snyk severity docs](https://docs.snyk.io/scan-fix-and-prevent/fix/prioritize-issues-for-fixing/severity-levels.md)).
- npm audit severity names and `--audit-level` (default: fail on any)
  ([npm audit docs](https://docs.npmjs.com/cli/v9/commands/npm-audit)).
- npq's two-band model with time thresholds: < 7 day old version = Error, 8-30 days =
  Warning; new author < 21 days = Error; dormant > 274 days = Error, > 183 days =
  Warning ([author marshall docs](https://github.com/lirantal/npq/blob/main/docs/feature/author-marshall.md),
  [README](https://github.com/lirantal/npq)).
- socket.dev guidance: 90-100 strong, 70-80 minor, 50-60 review carefully, < 50 look for
  alternatives, and supplyChain < 20 as a hard block in their own hook
  ([Socket MCP docs](https://docs.socket.dev/docs/socket-mcp-for-claude-desktop),
  [socket-mcp repo](https://github.com/socketdev/socket-mcp)).
- EPSS threshold guidance: focusing on vulnerabilities with EPSS >= 10% (about 7% of the
  corpus) covers nearly 86% of vulnerabilities that see exploit activity; an illustration
  of thresholding by marginal coverage rather than arbitrary splits
  ([GitHub blog](https://github.blog/security/github-advisory-database-by-the-numbers-known-security-vulnerabilities-and-what-you-can-do-about-them/)).

### What makes a defensible set for Blueline

The lesson from the tool landscape: band boundaries should sit where the *meaning* of the
signal set changes, not at arbitrary percentile splits, and BLOCK should be reserved for
reversibly harmful classes that a human should never rubber-stamp:

- BLOCK: a hard policy latch for (a) integrity/verification failure (already in
  ARCHITECTURE), (b) a revocation/malware record for this package@version, (c) a new
  install script on a package with a clean baseline, (d) a newly added dependency
  resolving outside the registry (git:/file:/http:), (e) provenance regression on a
  package that previously published with provenance (npq precedent).
- HIGH: any combination of obfuscation, new exec/network capability, dormant resurrection,
  version-burst churn, or first-sighting install script. Must block auto-approve and
  demand review, but does not forbid install.
- MEDIUM: moderate-weight context signals (maintainer change, new deps, version recency
  warnings).
- LOW: none of the above on an established, low-churn release; eligible for the
  auto-approve path.

npq's default behavior (warnings auto-continue after a countdown, errors default to no)
is the closest published analogue to Blueline's "LOW auto-approves, everything above
LOW demands the sign-off" and is a good defense of the two-pole design even before the
weights are tuned.

---

## 6. Verdict stability and the failure modes of deterministic heuristics

Same diff must yield the same verdict: deterministic, offline, auditable (D2). Known
failure modes and mitigations, grounded in observed incidents:

- **Minified and transpiled files.** The flatmap-stream payload lived in minified code
  with a hex string table; a raw line diff of minified files shows massive churn for one
  tiny semantic change, so a naive "percent lines changed" feature is meaningless and an
  obfuscation detector must be robust to legitimate bundler output (rollup/webpack emit
  eval-free but dense code). Signal extraction must be token/capability based, not
  raw-diff-count based ([incident paper](https://es-incident.github.io/payloads.html),
  [socket FAQ on static analysis](https://docs.socket.dev/docs/faq)).
- **Tarball-versus-repo drift.** The flatmap-stream malicious file existed in the tarball
  but not the GitHub repo; TanStack's router_init.js was deliberately omitted from
  `files`. Verdicts must diff the *tarball contents*, never the git diff
  ([LWN event-stream](https://lwn.net/Articles/773121/),
  [TanStack advisory](https://github.com/TanStack/router/security/advisories/GHSA-g7cv-rxg3-hmpx)).
- **Whitespace and formatting churn.** Reformatting-only releases must not shift bands;
  capabilities and manifests are the stable units, not formatting.
- **Registry metadata ordering is not guaranteed.** npq's author marshall documents that
  registry JSON iteration order is not chronological; baseline selection must use explicit
  semver ordering, never object insertion order
  ([author marshall docs](https://github.com/lirantal/npq/blob/main/docs/feature/author-marshall.md)).
- **Cross-tool severity drift.** pnpm briefly reported tough-cookie as high while npm and
  yarn said moderate, before realigning
  ([Safeguard blog](https://safeguard.sh/resources/blog/npm-audit-vs-pnpm-audit-vs-yarn-audit)).
  The GitHub Advisory Database even shipped a transient `>= 0` affected-range false
  positive during the TanStack incident
  ([TanStack issue #7383](https://github.com/TanStack/router/issues/7383)).
  Blueline must treat advisory records as Boolean block facts, not re-derived severities.
- **Time-varying inputs.** Downloads, package age, and "published X days ago" change
  between runs, so the same tarball could score differently tomorrow. Either exclude them
  from the score (keep as displayed context) or snapshot the registry metadata date into
  the verdict JSON so the verdict is reproducible from the record.
- **Network and database availability.** A failing OSV/advisory lookup must not silently
  change the verdict; npq's precedent is to surface infrastructure failures as warnings,
  never as evidence of safety ([DeepWiki security marshalls](https://deepwiki.com/lirantal/npq/5-security-marshalls)).
  AGENTS.md's fail-closed rule applies: on any doubt, error, and stamp the verdict
  "unknown".
- **Lockfile noise.** For the Phase 3 `ci` path, the diff is whole-lockfile; the score
  must operate per-resolved-version (hash the resolved version, not the range string),
  otherwise semver-range rewrites create verdict churn for identical resolved code.

---

## Recommendations for Blueline

A concrete, minimal v1 (YAGNI): no ML, no download-count signals, no README/license
quality scoring, no weight tuning by team. Weights are incident-derived magnitudes from
section 2, additive and capped, with a separate BLOCK latch. Verdict is a typed Rust enum
feeding the stable JSON schema (D7).

### Verdict enum and JSON schema (D7)

```rust
pub enum Verdict { Low, Medium, High, Block }
```

Verdict JSON (one struct used by CLI card, CI comment, and MCP tool):

```json
{
  "schema_version": 1,
  "package": "@tanstack/router",
  "version": "1.169.8",
  "baseline_version": "1.169.5",
  "score": 72,
  "verdict": "High",
  "block_reasons": [],
  "signals": [
    { "id": "new_script", "name": "new install script", "weight": 60,
      "score": 60, "evidence": "postinstall added vs 1.169.5" }
  ],
  "baseline_present": true,
  "advisory_hits": [],
  "registry_snapshot_at": "2026-05-11T19:30:00Z",
  "deterministic": true
}
```

Rules: `verdict` is derived from `score` plus `block_reasons`; consumers must honor
`block_reasons` first and never let a low score override them. `registry_snapshot_at`
makes time-varying context auditable. Offline-deterministic fields (signals, score,
verdict) are separated from advisory lookups (cached, dated).

### BLOCK triggers (hard latch, not scored)

Emit `verdict: "Block"` and one or more `block_reasons` when any of:

1. Integrity failure: sha512 SRI, registry signature, or extraction bound violation
   (already BLOCK per ARCHITECTURE, before scoring).
2. Revocation hit: OSV `MAL-*` or GitHub Advisory record matching this package@version
   (Boolean presence only; never re-derive severity from the advisory).
3. New install script: `preinstall`/`install`/`postinstall` (or a `prepare` that runs for
   a git/registry source) present in the target and absent in the baseline. With no
   baseline, script presence is HIGH, not BLOCK, and flows to the separate human decision
   in D11.
4. Unpinned dangerous delta: any newly added dependency whose spec is not registry semver
   (`git:`, `github:`, `file:`, `http:`, `https:`, bare URL). This is the direct
   generalization of the TanStack git-dep payload.
5. Provenance regression: an older semver had `dist.attestations` and the target does not
   (npq precedent).

BLOCK never auto-approves and is not soften-able by any other signal.

### Scored signals, weights, and bands

Sum of weights of the signals that fire, capped at 100. Every signal adds risk only.
Time-varying signals (downloads, package age, recency) are displayed as context and
excluded from the score so the score is offline-deterministic from tarball + baseline.

| Signal (id) | Weight | Rationale evidence |
| --- | --- | --- |
| `obfuscation` | 45 | Present in flatmap-stream, eslint-scope, node-ipc, coa, TanStack. Base64/hex string tables, `eval`/`new Function`/string-built `require`, high-entropy literals in *new* diff content. |
| `new_install_script` (only when baseline absent) | 40 | eslint-scope, ua-parser-js, coa, rc. When baseline exists this is a BLOCK trigger instead. |
| `new_exec_or_net_capability` | 35 | child_process/shell/network introduced in diff; ua-parser-js downloads+exec, coa LOLBins, eslint-scope pastebin fetch. |
| `maintainer_change` | 30 | event-stream (new maintainer), every account takeover. Includes new `_npmUser`, new maintainer added, or republished-from-different-user. |
| `dormant_resurrection` | 30 | Baseline older than ~365 days and a new release now; coa/rc after 3 dormant years. |
| `version_burst` | 25 | More than one release in a rolling 24h window, especially across major lines; ua-parser-js 3 majors, coa 6 versions in hours, TanStack 2 versions in 6 minutes. |
| `new_dependency` | 10 per new dep, cap 30 | flatmap-stream, peacenotwar: new near-zero-popularity deps were the actual delivery channel. |
| `new_binary_or_native` | 25 | New executable bit, `.exe`/`.dll`/`.so`, `binding.gyp`, or platform binaries in diff. |
| `semver_major_large_delta` | 15 | Context amplifier only; never decisive alone. |
| `missing_or_regressed_provenance` | 10 | Surfaced, never trusted (D5/D6). Present-and-valid provenance adds 0; its absence on a package that never had it is context, not risk. |

Bands (score only; BLOCK latch wins regardless):

- LOW: score 0-19 and no latch. Auto-approve path only for established packages with a
  baseline; first sighting never auto-approves (per ARCHITECTURE open-risk note).
- MEDIUM: 20-49. Sign-off required, no auto-approve.
- HIGH: 50+. Sign-off required; rendered with the full signal evidence on the card.
- BLOCK: any latch fired. Never installable without the explicit override flow.

### Why these are the smallest defensible v1

- The signal set is exactly ARCHITECTURE section 2 rule set mapped to weights, minus the
  signals the research shows are noise in v1 (downloads, package age, README quality,
  provenance-as-safety).
- Every weight is anchored to a real incident from section 2, so each number is
  explainable and reviewable on the card.
- The design (additive points, soft cap 100, hard BLOCK latch, monotonic risk-only,
  offline-deterministic score, advisory records as Boolean) is the minimal structure that
  matches how socket.dev (additive + caps), npq (warning/error latch), and CVSS/Snyk
  (band calibration) each solved the same problem, without importing any of their tuning
  complexity.
- v1 intentionally has no per-line ML, no cross-run time-varying inputs in the score, and
  no transitive deep scoring (that is `ci` Phase 3).

---

## Sources

- npq README and marshall table: https://github.com/lirantal/npq
- npq docs index: https://github.com/lirantal/npq/tree/master/docs
- npq author marshall: https://github.com/lirantal/npq/blob/main/docs/feature/author-marshall.md
- npq provenance marshall: https://github.com/lirantal/npq/blob/main/docs/feature/provenance.md
- npq DeepWiki overview: https://deepwiki.com/lirantal/npq
- npq security marshalls DeepWiki: https://deepwiki.com/lirantal/npq/5-security-marshalls
- npq write-up (OpenReplay): https://blog.openreplay.com/npm-package-security-checks-npq/
- Socket package scores formula and weights: https://docs.socket.dev/docs/package-scores
- Socket score API reference: https://docs.socket.dev/reference/getscorebynpmpackage
- Socket deep score (min aggregation): https://docs.socket.dev/docs/socket-package
- Socket supply chain risk tiers: https://docs.socket.dev/docs/supply-chain-risk
- Socket alerts (network/shell/filesystem): https://socket.dev/alerts/networkAccess , https://socket.dev/alerts/shellAccess
- Socket MCP score thresholds: https://docs.socket.dev/docs/socket-mcp-for-claude-desktop
- Socket MCP hook block threshold: https://github.com/socketdev/socket-mcp
- Socket FAQ (70+ signals, static analysis): https://docs.socket.dev/docs/faq
- Socket launch blog: https://socket.dev/blog/introducing-socket
- Socket seed blog (attack pattern research): https://socket.dev/blog/series-seed
- Sandworm how it works: https://docs.sandworm.dev/audit/how-it-works
- Sandworm issue types (SWRM-201 etc): https://docs.sandworm.dev/audit/issue-types
- Sandworm fail policies: https://docs.sandworm.dev/audit/fail-policies
- Sandworm repo: https://github.com/sandworm-hq/sandworm-audit
- osv.dev blog (transitive scanning): https://osv.dev/blog/posts/announcing-transitive-dependency-support-for-maven-pomxml-in-osv-scanner/
- osv.dev discussion (no calculated score in API): https://github.com/google/osv.dev/discussions/2643
- npm audit command docs: https://docs.npmjs.com/cli/v9/commands/npm-audit
- npm audit report docs: https://docs.npmjs.com/about-audit-reports/
- GitHub Advisory Database docs: https://docs.github.com/code-security/security-advisories/working-with-global-security-advisories-from-the-github-advisory-database/about-the-github-advisory-database
- GitHub blog, EPSS table and advisory stats: https://github.blog/security/github-advisory-database-by-the-numbers-known-security-vulnerabilities-and-what-you-can-do-about-them/
- Snyk severity levels: https://docs.snyk.io/scan-fix-and-prevent/fix/prioritize-issues-for-fixing/severity-levels.md
- CVSS v4 specification (Table 22 qualitative scale): https://www.first.org/cvss/specification-document
- npm blog, event-stream incident: https://blog.npmjs.org/post/180565383195/details-about-the-event-stream-incident
- Snyk postmortem, event-stream: https://snyk.io/blog/a-post-mortem-of-the-malicious-event-stream-backdoor/
- Event-stream incident paper: https://es-incident.github.io/paper.html
- Event-stream payloads page: https://es-incident.github.io/payloads.html
- GHSA flatmap-stream: https://github.com/advisories/GHSA-9x64-5r7x-2q53
- GHSA event-stream: https://github.com/advisories/GHSA-mh6f-8j2x-4483
- LWN, event-stream and trust: https://lwn.net/Articles/773121/
- ESLint postmortem: https://eslint.org/blog/2018/07/postmortem-for-malicious-package-publishes/
- eslint-scope issue #39: https://github.com/eslint/eslint-scope/issues/39
- npm blog, eslint follow-up (install scripts and ignore-scripts): https://blog.npmjs.org/post/176488970320/community-questions-following-the-eslint-security.html
- ua-parser-js analysis (safeguard): https://safeguard.sh/resources/blog/ua-parser-js-npm-hijack-october-2021
- ua-parser-js BleepingComputer: https://www.bleepingcomputer.com/news/security/popular-npm-library-hijacked-to-install-password-stealers-miners/
- ua-parser-js CISA alert: https://www.cisa.gov/news-events/alerts/2021/10/22/malware-discovered-popular-npm-package-ua-parser-js
- ua-parser-js GitHub issue #536: https://github.com/faisalman/ua-parser-js/issues/536
- ua-parser-js Sonatype: https://www.sonatype.com/blog/npm-project-used-by-millions-hijacked-in-supply-chain-attack
- ua-parser-js Rapid7: https://www.rapid7.com/blog/post/2021/10/25/npm-library-ua-parser-js-hijacked-what-you-need-to-know/
- ua-parser-js Sophos: https://www.sophos.com/en-us/blog/node-poisoning-hijacked-package-delivers-coin-miner-and-credential-stealing-backdoor
- coa/rc BleepingComputer: https://www.bleepingcomputer.com/news/security/popular-coa-npm-library-hijacked-to-steal-user-passwords/
- coa/rc Sonatype: https://www.sonatype.com/blog/npm-hijackers-at-it-again-popular-coa-and-rc-open-source-libraries-taken-over-to-spread-malware
- coa/rc FOSSA: https://fossa.com/blog/embedded-malware-npm-coa-rc-ua-parser/
- coa/rc Rapid7: https://www.rapid7.com/blog/post/2021/11/05/new-npm-library-hijacks-coa-and-rc/
- GHSA coa: https://github.com/advisories/GHSA-73qr-pfmq-6rp8 ; GHSA rc: https://github.com/advisories/GHSA-g2q5-5433-rhrf
- node-ipc Snyk blog: https://snyk.io/blog/peacenotwar-malicious-npm-node-ipc-package-vulnerability/
- node-ipc Snyk advisory: https://security.snyk.io/vuln/SNYK-JS-NODEIPC-2426370
- node-ipc Ars Technica: https://arstechnica.com/information-technology/2022/03/sabotage-code-added-to-popular-npm-package-wiped-files-in-russia-and-belarus/
- node-ipc Vice: https://www.vice.com/en/article/open-source-sabotage-node-ipc-wipe-russia-belraus-computers/
- TanStack postmortem: https://tanstack.com/blog/npm-supply-chain-compromise-postmortem
- TanStack follow-up (hardening): https://tanstack.com/blog/incident-followup
- TanStack advisory GHSA-g7cv-rxg3-hmpx: https://github.com/TanStack/router/security/advisories/GHSA-g7cv-rxg3-hmpx
- TanStack tracking issue #7383: https://github.com/TanStack/router/issues/7383
- OSV CVE-2026-45321: https://osv.dev/vulnerability/CVE-2026-45321
- Endor Labs TanStack explainer: https://www.endorlabs.com/learn/how-a-misconfigured-ci-workflow-became-an-npm-supply-chain-compromise
- Snyk keyv compromise analysis: https://snyk.io/blog/inside-keyv-npm-compromise-preinstall-malware-trusted-provenance-ide-hooks/
- npm RFC 0054 (install scripts opt-in): https://github.com/npm/rfcs/blob/main/accepted/0054-make-scripts-install-opt-in.md
- npm install-scripts command docs (v12): https://docs.npmjs.com/cli/v12/commands/npm-install-scripts/
- pnpm supply chain security: https://pnpm.io/supply-chain-security
- bun lifecycle docs: https://bun.com/docs/pm/lifecycle
- npm-script-lens: https://github.com/Booyak101/npm-script-lens
- npm v12 audit walkthrough (dev.to): https://dev.to/booyak101/npm-v12-stopped-running-install-scripts-which-ones-do-you-approve-a-real-audit-walkthrough-b1l
- Latch paper: https://ldklab.github.io/assets/papers/asiaccs22-latch.pdf
- Weak Links in the npm Supply Chain (ICSE 2022): https://patricegodefroid.github.io/public_psfiles/icse2022.pdf
- Amalfi (ICSE 2022): https://dl.acm.org/doi/10.1145/3510003.3510104
- Cross-language detection of malicious packages (ACSAC 2023): https://inria.hal.science/hal-04423806/document
- Cerebro (behavior-sequence detection): https://export.arxiv.org/pdf/2309.02637v1.pdf
- CodeQL malware poster (CCS 2023): https://www.plai.ifi.lmu.de/publications/ccs23poster-codeql.pdf
- npm audit vs pnpm vs yarn (severity drift): https://safeguard.sh/resources/blog/npm-audit-vs-pnpm-audit-vs-yarn-audit

## Adversarial self-check

Things I could not fully verify or that are explicitly uncertain:

- Socket's gamma coefficients (c0, c1) ARE published (c0 = c1 = 0.05), but the docs
  disclaim the published formula may not match deployment. I treated the formula as the
  *published reference model*, not ground truth about their live system.
- Snyk's Priority Score composition is not publicly documented; only the CVSS severity
  band mapping is. Sandworm publishes no weights or scoring math at all; its install
  script issue default severity (SWRM-201) was not confirmed in my fetches and I have
  not asserted it.
- The TanStack provenance level: Endor Labs and TanStack describe "valid SLSA provenance
  attestations" and that "provenance, SLSA, OIDC, and 2FA worked as advertised". The
  specific "SLSA L3" label comes from the task prompt; I did not find an authoritative
  source stating the exact SLSA level and have not asserted L3 as fact.
- event-stream download counts: the npm blog says "8 million downloads" over the
  campaign; the incident paper says ~2 million weekly downloads. Both figures are cited
  as stated by their sources.
- The keyv family incident (Snyk, 2026-08-04): Snyk's post names the affected packages
  (the `keyv` family); an early fetch appeared redacted and was corrected.
- npm v12's default-block behavior: I verified the RFC and the npm docs page, and the
  July 2026 GitHub changelog is referenced via the dev.to write-up; I did not fetch the
  changelog directly.
- The npq marshall list may be incomplete in the sources I fetched (some marshalls are
  optional or new); I treated the marshall set as illustrative of a two-band model, not
  as an exhaustive enumeration.
- The node-ipc download figure (~1M/week) comes from Vice and was not independently
  confirmed by Snyk's write-up.
- No published research I found gives precision/recall for the specific composite "diff
  against last known good" scoring model Blueline proposes; the recall figures cited
  (Amalfi ~40% decision-tree recall, Cerebro 58.3% FPR, CodeQL zero-FP) are for
  different, package-level detectors and transfer only directionally.
- "EPSS >= 10% covers ~86% of exploited vulns" is GitHub's framing of their own data;
  the underlying EPSS threshold guidance is FIRST's and I did not re-derive the number.
