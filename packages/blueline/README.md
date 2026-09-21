# @kridaydave/blueline-cli

Approve the delta, not the download.

Blueline is a release-diff review desk for the package install line. It resolves, downloads, integrity-verifies, sandboxes, and scores diffs before any code runs.

## Usage

Run directly via `npx`:

```bash
# Review a package release diff
npx @kridaydave/blueline-cli review express@4.21.2

# Review and install with --ignore-scripts upon approval
npx @kridaydave/blueline-cli install express
```

Or install globally:

```bash
npm install -g @kridaydave/blueline-cli
blueline install express
```

## Security Invariants

- **Zero install scripts:** `@kridaydave/blueline-cli` contains no `postinstall` or lifecycle scripts.
- **Fail closed:** On any signature, integrity, extraction, or resolution doubt, Blueline aborts rather than guess.
- **`--ignore-scripts` enforcement:** On approval, package installation executes with `--ignore-scripts` so reviewed package lifecycle scripts never run automatically.
