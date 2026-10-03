//! Running the real `blueline` binary against a fixture, and reading what it
//! decided back as a typed value. Every run gets its own data directory, so no
//! scenario can be influenced by another scenario's baseline store.

use std::fmt;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use assert_cmd::Command;
use serde_json::Value;

/// Verdict bands, as printed in the verdict JSON.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Band {
    Low,
    Medium,
    High,
    Block,
}

impl Band {
    pub fn as_str(self) -> &'static str {
        match self {
            Band::Low => "LOW",
            Band::Medium => "MEDIUM",
            Band::High => "HIGH",
            Band::Block => "BLOCK",
        }
    }
}

impl fmt::Display for Band {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Band {
    type Err = String;

    fn from_str(raw: &str) -> Result<Band, String> {
        match raw {
            "LOW" => Ok(Band::Low),
            "MEDIUM" => Ok(Band::Medium),
            "HIGH" => Ok(Band::High),
            "BLOCK" => Ok(Band::Block),
            other => Err(format!("unknown verdict band `{other}`")),
        }
    }
}

/// A parsed verdict document. Findings are read by rule id, which is the
/// stable contract; descriptions are for humans.
#[derive(Debug, Clone)]
pub struct Verdict {
    document: Value,
}

impl Verdict {
    pub fn band(&self) -> Band {
        Band::from_str(
            self.document["band"]
                .as_str()
                .unwrap_or_else(|| panic!("verdict carries no band: {}", self.raw())),
        )
        .unwrap_or_else(|e| panic!("{e}: {}", self.raw()))
    }

    pub fn risk_score(&self) -> u64 {
        self.document["risk_score"]
            .as_u64()
            .unwrap_or_else(|| panic!("verdict carries no risk_score: {}", self.raw()))
    }

    pub fn field(&self, key: &str) -> &Value {
        &self.document[key]
    }

    pub fn rule_ids(&self) -> Vec<String> {
        self.findings()
            .iter()
            .filter_map(|f| f["rule_id"].as_str().map(str::to_string))
            .collect()
    }

    pub fn has_rule(&self, rule: &str) -> bool {
        self.findings().iter().any(|f| f["rule_id"] == rule)
    }

    /// The finding carrying `rule`, or a panic naming what was found instead:
    /// a scenario that asserts on a rule id should never silently pass
    /// because the rule was renamed.
    pub fn finding(&self, rule: &str) -> &Value {
        self.findings()
            .iter()
            .find(|f| f["rule_id"] == rule)
            .unwrap_or_else(|| {
                panic!(
                    "verdict carries no finding `{rule}`; it has {:?}",
                    self.rule_ids()
                )
            })
    }

    /// Recursive child verdicts (`verdict["recursive"]`).
    pub fn children(&self) -> Vec<Verdict> {
        self.document["recursive"]
            .as_array()
            .map(|children| {
                children
                    .iter()
                    .map(|child| Verdict {
                        document: child.clone(),
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn raw(&self) -> String {
        self.document.to_string()
    }

    fn findings(&self) -> &[Value] {
        self.document["findings"]
            .as_array()
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }
}

/// One finished CLI run: exit code and both streams.
#[derive(Debug, Clone)]
pub struct Run {
    code: Option<i32>,
    stdout: String,
    stderr: String,
    argv: Vec<String>,
}

impl Run {
    pub fn code(&self) -> Option<i32> {
        self.code
    }

    pub fn stdout(&self) -> &str {
        &self.stdout
    }

    pub fn stderr(&self) -> &str {
        &self.stderr
    }

    /// The verdict JSON the CLI printed. Accepts either a whole JSON document
    /// or a single JSON line (the agent lane prints one line).
    /// Print the observed outcome of this run: the verdict band and rules if
    /// there was one, otherwise the refusal.
    ///
    /// This is what answers "did the fix work?" — `run.sh <name>` shows the
    /// band a scenario actually observed, not just that its assertions held.
    /// Printed unconditionally so `--nocapture` surfaces it.
    pub fn report(&self) {
        let summary = match self.json() {
            Ok(document) if document.get("band").is_some() => {
                let rules = document["findings"]
                    .as_array()
                    .map(|findings| {
                        findings
                            .iter()
                            .filter_map(|f| f["rule_id"].as_str())
                            .collect::<std::collections::BTreeSet<_>>()
                            .into_iter()
                            .collect::<Vec<_>>()
                            .join(", ")
                    })
                    .unwrap_or_default();
                let child = match document["recursive"].as_array() {
                    Some(children) if !children.is_empty() => format!(
                        ", children: [{}]",
                        children
                            .iter()
                            .map(|c| format!(
                                "{} {}",
                                c["name"].as_str().unwrap_or("?"),
                                c["band"].as_str().unwrap_or("?")
                            ))
                            .collect::<Vec<_>>()
                            .join("; ")
                    ),
                    _ => String::new(),
                };
                format!(
                    "{} band={} score={} rules=[{}]{child}",
                    self.spec_summary(),
                    document["band"].as_str().unwrap_or("?"),
                    document["risk_score"]
                        .as_u64()
                        .map(|s| s.to_string())
                        .unwrap_or_default(),
                    rules
                )
            }
            _ => format!(
                "{} exit={:?} refused: {}",
                self.spec_summary(),
                self.code,
                self.stderr.lines().next().unwrap_or("(no stderr)").trim()
            ),
        };
        eprintln!("[scenario] {summary}");
    }

    /// The subcommand this run issued, for the report line.
    fn spec_summary(&self) -> String {
        format!("`{}`", self.argv.join(" "))
    }

    pub fn json(&self) -> Result<serde_json::Value, String> {
        let trimmed = self.stdout.trim();
        serde_json::from_str(trimmed)
            .or_else(|_| {
                let first = trimmed
                    .lines()
                    .find(|line| !line.trim().is_empty())
                    .unwrap_or_default();
                serde_json::from_str(first).map_err(|e| e.to_string())
            })
            .map_err(|e| format!("{e}: {trimmed}"))
    }

    pub fn verdict(&self) -> Verdict {
        let trimmed = self.stdout.trim();
        let parsed = serde_json::from_str::<Value>(trimmed).or_else(|_| {
            let first = trimmed
                .lines()
                .find(|line| !line.trim().is_empty())
                .unwrap_or_default();
            serde_json::from_str::<Value>(first)
                .map_err(|e| anyhow::anyhow!("stdout is not a verdict document ({e}): {trimmed}"))
        });
        Verdict {
            document: parsed.unwrap_or_else(|e| panic!("{e}\n{}", self)),
        }
    }

    pub fn has_stdout(&self, needle: &str) -> bool {
        self.stdout.contains(needle)
    }

    pub fn has_stderr(&self, needle: &str) -> bool {
        self.stderr.contains(needle)
    }

    /// Assert the run held or blocked (`exit 2`) and explain on failure.
    pub fn assert_blocked(&self) -> &Run {
        assert_eq!(
            self.code,
            Some(super::EXIT_BLOCKED),
            "expected a BLOCK-held exit, got {:?}\n{self}",
            self.code
        );
        self
    }

    /// Assert the engine refused before producing any verdict (`exit 1`) and
    /// that it said why. This is the fail-closed shape: no band, no approval.
    pub fn assert_refused(&self, needle: &str) -> &Run {
        assert_eq!(
            self.code,
            Some(super::EXIT_ERROR),
            "expected a refusal before any verdict, got {:?}\n{self}",
            self.code
        );
        assert!(
            self.stderr.contains(needle),
            "refusal must name `{needle}`\n{self}"
        );
        assert!(
            self.stdout.trim().is_empty(),
            "a refused run must print no verdict at all\n{self}"
        );
        self
    }
}

impl fmt::Display for Run {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "exit: {:?}", self.code)?;
        writeln!(f, "stdout: {}", self.stdout.trim())?;
        write!(f, "stderr: {}", self.stderr.trim())
    }
}

/// A `blueline` invocation bound to one fixture registry and one private data
/// directory.
pub struct Cli {
    /// Shared so one scenario can hold several `Cli` handles against the same
    /// engine state — a synced recall snapshot, a stored baseline — without
    /// either one deleting the directory the other is using.
    data_dir: std::sync::Arc<tempfile::TempDir>,
    _policy_dir: Option<std::sync::Arc<tempfile::TempDir>>,
    policy: Option<PathBuf>,
    ecosystem: &'static str,
    registry: Option<String>,
    env: Vec<(String, String)>,
}

impl Cli {
    pub fn npm(registry: &str) -> Cli {
        Cli::with_registry("npm", Some(registry))
    }

    pub fn aur(registry: &str) -> Cli {
        Cli::with_registry("aur", Some(registry))
    }

    /// A run with no registry override at all, for subcommands that must not
    /// talk to one (`recall sync`). Handing such a run a base URL would be a
    /// fixture that lies about what it exercises.
    pub fn without_registry() -> Cli {
        Cli::with_registry("npm", None)
    }

    fn with_registry(ecosystem: &'static str, registry: Option<&str>) -> Cli {
        Cli {
            data_dir: std::sync::Arc::new(
                tempfile::tempdir().expect("create private BLUELINE_DATA_DIR"),
            ),
            _policy_dir: None,
            policy: None,
            ecosystem,
            registry: registry.map(str::to_string),
            env: Vec::new(),
        }
    }

    /// Write a policy file and bind it to every run. Scenarios pass the
    /// policy under attack, not a fixture convenience.
    pub fn policy(mut self, toml: &str) -> Cli {
        let dir = tempfile::tempdir().expect("create private policy dir");
        let path = dir.path().join("blueline.toml");
        std::fs::write(&path, toml).expect("write fixture policy");
        self._policy_dir = Some(std::sync::Arc::new(dir));
        self.policy = Some(path);
        self
    }

    /// The same engine state — the same data directory and policy — pointed at
    /// a different registry. Needed when a scenario must first put something in
    /// the engine's store (`recall sync`) and then have a review see it: a
    /// freshly constructed `Cli` would get its own empty data directory and the
    /// review would silently not exercise the synced state.
    pub fn at(&self, ecosystem: &'static str, registry: &str) -> Cli {
        Cli {
            data_dir: self.data_dir.clone(),
            _policy_dir: self._policy_dir.clone(),
            policy: self.policy.clone(),
            ecosystem,
            registry: Some(registry.to_string()),
            env: self.env.clone(),
        }
    }

    /// An allowlist entry marking a package as legitimately unreviewed, so a
    /// scenario about a *different* rule can reach LOW.
    pub fn allow_unreviewed_baseline(self, package: &str) -> Cli {
        self.policy(&format!(
            "[[allowlist.packages]]\nname = \"{package}\"\nallow_unreviewed_baseline = true\n"
        ))
    }

    pub fn env(mut self, key: &str, value: &str) -> Cli {
        self.env.push((key.to_string(), value.to_string()));
        self
    }

    pub fn data_dir(&self) -> &Path {
        self.data_dir.path()
    }

    /// The private data directory joined with `relative`.
    pub fn data_path(&self, relative: &str) -> PathBuf {
        self.data_dir.path().join(relative)
    }

    /// Run any subcommand. Global flags are added for you. Takes `&self` so
    /// one fixture (one private data directory, one policy) can drive several
    /// runs — the sequence matters in the recall and shim scenarios.
    pub fn run(&self, args: &[&str]) -> Run {
        let mut command = Command::cargo_bin("blueline").expect("locate blueline binary");
        if self.ecosystem != "npm" {
            command.args(["--ecosystem", self.ecosystem]);
        }
        if let Some(registry) = &self.registry {
            command.args(["--registry", registry]);
        }
        if let Some(policy) = &self.policy {
            command.arg("--policy").arg(policy);
        }
        command.args(args);
        command.env("BLUELINE_DATA_DIR", self.data_dir.path());
        for (key, value) in &self.env {
            command.env(key, value);
        }
        let output = command.output().expect("spawn blueline");
        let run = Run {
            code: output.status.code(),
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
            argv: args.iter().map(|a| (*a).to_string()).collect(),
        };
        run.report();
        run
    }

    /// `review <spec> --output json --yes`: the machine-readable, never
    /// prompting path.
    pub fn review(&self, spec: &str) -> Run {
        self.run(&["review", spec, "--output", "json", "--yes"])
    }

    /// `agent review <spec>`: the agent lane (exit 0 on LOW, 2 when held).
    pub fn agent_review(&self, spec: &str) -> Run {
        self.run(&["agent", "review", spec])
    }

    /// `agent gate --command <line>`: the hook binding.
    pub fn gate(&self, command: &str) -> Run {
        self.run(&["agent", "gate", "--command", command])
    }

    /// `recall sync --url <url>`.
    pub fn recall_sync(&self, url: &str) -> Run {
        self.run(&["recall", "sync", "--url", url])
    }
}
