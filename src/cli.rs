use clap::{Parser, Subcommand, ValueEnum};

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
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Fetch, verify, and baseline a package release
    Review {
        /// `<name>@<version>` to review, e.g. `express@4.21.2`
        pkg: String,

        /// Output format: auto (text on a TTY, JSON otherwise), text, or json
        #[arg(long, value_enum, default_value_t = Output::Auto)]
        output: Output,
    },
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
