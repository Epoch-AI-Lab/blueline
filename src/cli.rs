use clap::{Parser, Subcommand, ValueEnum};

fn trim_pkg(s: &str) -> Result<String, String> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return Err("package spec cannot be empty".to_string());
    }
    if trimmed.starts_with('-') {
        return Err(format!(
            "package spec `{trimmed}` cannot start with a hyphen"
        ));
    }
    Ok(trimmed.to_string())
}

#[derive(Debug, Parser)]
#[command(
    name = "blueline",
    version,
    about = "Approve the delta, not the download.",
    long_about = "Blueline is a release-diff review desk for the package install line. \
                  It resolves, downloads, integrity-verifies, and safely extracts package \
                  releases before they run anywhere."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,

    /// npm registry base URL (override for mirrors / local fixtures)
    #[arg(long, global = true, default_value = "https://registry.npmjs.org")]
    pub registry: String,

    /// Path to blueline.toml policy file
    #[arg(long, global = true)]
    pub policy: Option<std::path::PathBuf>,
}

#[derive(Debug, Subcommand, PartialEq, Eq)]
pub enum Command {
    /// Fetch, verify, and baseline a package release
    Review {
        /// `<name>@<version>` to review, e.g. `express@4.21.2`
        #[arg(value_parser = trim_pkg)]
        pkg: String,

        /// Output format: auto (text on a TTY, JSON otherwise), text, or json
        #[arg(long, value_enum, default_value_t = Output::Auto)]
        output: Output,
    },

    /// Review and install a package with `--ignore-scripts` upon approval
    Install {
        /// `<name>` or `<name>@<version>` to review and install
        #[arg(value_parser = trim_pkg)]
        pkg: String,

        /// Additional arguments forwarded to npm install
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        npm_args: Vec<String>,
    },

    /// Scan lockfile diffs across Git base ref for CI pull request review
    Ci {
        /// Git base ref to diff against (e.g. origin/main, HEAD~1)
        #[arg(long, default_value = "origin/main")]
        base: String,

        /// Path to package-lock.json to inspect
        #[arg(long, default_value = "package-lock.json")]
        lockfile: std::path::PathBuf,

        /// Output format: auto, text, markdown, or json
        #[arg(long, value_enum, default_value_t = CiOutput::Auto)]
        format: CiOutput,

        /// Minimum verdict band that triggers failure exit code (low, medium, high, block)
        #[arg(long)]
        fail_on: Option<crate::verdict::VerdictBand>,
    },

    /// Start Model Context Protocol (MCP) JSON-RPC 2.0 stdio server
    Mcp,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum CiOutput {
    Auto,
    Text,
    Markdown,
    Json,
}

impl CiOutput {
    pub fn to_ci_format(self) -> crate::ci::CiOutputFormat {
        match self {
            CiOutput::Auto => crate::ci::CiOutputFormat::Auto,
            CiOutput::Text => crate::ci::CiOutputFormat::Text,
            CiOutput::Markdown => crate::ci::CiOutputFormat::Markdown,
            CiOutput::Json => crate::ci::CiOutputFormat::Json,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum Output {
    Auto,
    Text,
    Json,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutputFormat {
    Text,
    Json,
}

impl Output {
    pub fn resolve(self, stdout_is_tty: bool) -> OutputFormat {
        match self {
            Output::Auto if stdout_is_tty => OutputFormat::Text,
            Output::Auto => OutputFormat::Json,
            Output::Text => OutputFormat::Text,
            Output::Json => OutputFormat::Json,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trims_package_spec_in_review() {
        let cli = Cli::try_parse_from(["blueline", "review", "  express@4.21.2  "]).unwrap();
        match cli.command {
            Command::Review { pkg, .. } => assert_eq!(pkg, "express@4.21.2"),
            _ => panic!("expected Review command"),
        }
    }

    #[test]
    fn trims_package_spec_in_install() {
        let cli = Cli::try_parse_from(["blueline", "install", "\tlodash@4.17.21\n"]).unwrap();
        match cli.command {
            Command::Install { pkg, .. } => assert_eq!(pkg, "lodash@4.17.21"),
            _ => panic!("expected Install command"),
        }
    }

    #[test]
    fn rejects_empty_package_spec() {
        let res = Cli::try_parse_from(["blueline", "review", "   "]);
        assert!(res.is_err());
    }
}
