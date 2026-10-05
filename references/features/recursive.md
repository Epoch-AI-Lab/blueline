# Recursive Review

`src/recursive.rs`. R24–R27. One `ReviewContext` spans a whole top-level
evaluation; every install reference in a payload is piped through the *same*
review engine as a second-order review. Protects the property that a depth,
budget, or cycle overrun is **disclosed as a HIGH finding, never a silent skip**.

## Sub-features
- `ReviewContext` — caps, cycle stack, chain labels, review cache, tarball memo.
- `enter_scope` / `exit_scope` — the scope discipline.
- `review_children` — the fan-out with caps, cycle cut, and reuse.
- `install_ref_findings` / `depth_cap_finding` / `cycle_finding` /
  `resolve_child_version` / `child_review_failed_finding` / `second_order_finding`.
- `child_ecosystem(manager)` — one mapping, shared with the gate.
- `registry_for` / `dropped_key`.
- `MAX_TARBALL_MEMO_BYTES`.

## How to get to it (user POV)
```sh
blueline review demo@1.0.0 --output json | jq '.recursive'
# [{"chain":["demo@1.0.0","npm:evil@2.0.0"], "name":"evil", "band":"BLOCK", …}]
blueline review demo@1.0.0 --output json | jq -r '.findings[].rule_id' | grep -E 'R2[4-7]'
```

## Driving it
`ReviewKey = (Ecosystem, String, String)` — ecosystem + canonical name + version.
`MAX_TARBALL_MEMO_BYTES = 256 MiB` (268435456). Policy caps: `max_depth ≤ 16`
(default 3), `max_child_reviews ≤ 256` (default 8), `child_block_band` default
`HIGH`, compared with `>=` in `review.rs`.

| Rule | Severity |
|---|---|
| `R24_LIFECYCLE_INSTALL_REF` | `High` pinned · `Medium` unpinned/unresolvable/dynamic · `High` non-registry (git/URL/path) · `High` cap overflow |
| `R25_RECURSION_DEPTH` | `High` (shared by depth and budget causes) |
| `R26_RECURSION_CYCLE` | `High` |
| `R27_SECOND_ORDER` | `child.band` — inherits, not fixed |

Chain labels: root is `"{name}@{version}"`; children are
`"{ecosystem.key()}:{name}@{version}"`, rendered as
`["a@1.0.0", "npm:b@1.0.0"]`.

## Gotchas
- **`exit_scope` pops after the evaluation *including its children*.** Moving it
  earlier lets a cycle key be re-entered and turns a legitimate diamond into a
  false cycle.
- **Cycle keys are version-sensitive.** `a@1.0.0 → b@1.0.0 → a@2.0.0` is not a
  cycle. The check compares the full 3-tuple against `self.stack`.
- **Depth is computed once per `review_children` call**, before the loop, as
  `self.stack.len() as u32 > self.max_depth` (strict `>`). The root has already
  pushed itself, so `child_depth == 1` at the root; `max_depth = 0` denies every
  child. Computing it per-ref would let a hostile payload spend round-trips on
  unresolvable depth.
- **Budget is checked *after* the cache-reuse lookup and *before*
  `resolve_child_version`,** and it `continue`s (not `break`s) so every
  remaining reference still gets its own R25 disclosure. Moving it above the
  reuse lookup breaks `repeated_reference_reuses_cached_review_after_budget_spent`.
- **An unpinned reference never reuses a pinned review.**
  `version_part == None` sets `same_version = false` unconditionally, so
  `foo@1.0.0 && npm install foo` produces two children at `1.0.0` and `2.0.0`.
  Reusing the 1.0.0 review "would vouch for bytes the install never fetches."
- **`child_reviews` increments only immediately before a genuinely fresh
  `evaluate_scoped`.** Failed children are *not* entered into `completed` /
  `completed_names`, so a later identical reference retries and re-spends
  budget.
- **`child_review_failed_finding` is `Medium` only when the error chain
  contains `BluelineError::NotFound`;** every other failure is `High`. It
  downcasts through `e.chain()`.
- **Memo overflow is a cache eviction, not a failure.** `if memo_bytes + len >
  MAX` → `tarballs.clear(); memo_bytes.set(0)`, then add. The strict `>` means a
  fetch landing exactly on the cap keeps everything. The overflow fetch still
  returns its bytes.
- **Memo key uses the *raw* name; the cycle/reuse key uses the canonical name.**
  Two different identity spaces in one struct.
- **`evaluate_scoped` is called with the raw `name`** — canonicalization only
  ever keys caches and cycles. Do not pass `canon_name` there.
- **Only `registry_spec().is_some()` references get an R25.** Dynamic and
  non-registry references keep their own R24 shape and never consume depth.
- **`ReviewContext` is not `Sync`** (`RefCell`/`Rc`/`Cell` throughout). It is
  single-threaded by construction; do not wrap it for parallel child review
  without a redesign of the memo.