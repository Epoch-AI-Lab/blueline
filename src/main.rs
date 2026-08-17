#![forbid(unsafe_code)]

use blueline::{ci, cli, mcp, review};

use clap::Parser;

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}

fn run() -> anyhow::Result<()> {
    let cli = cli::Cli::parse();
    match cli.command {
        cli::Command::Review { pkg, output, yes } => {
            review::run(&pkg, &cli.registry, output, cli.policy.as_deref(), yes)
        }
        cli::Command::Install { pkg, npm_args, yes } => {
            review::install(&pkg, &cli.registry, &npm_args, cli.policy.as_deref(), yes)
        }
        cli::Command::Ci {
            base,
            lockfile,
            format,
            fail_on,
        } => ci::run(
            &base,
            &lockfile,
            &cli.registry,
            cli.policy.as_deref(),
            format.to_ci_format(),
            fail_on,
        ),
        cli::Command::Mcp => mcp::run_stdio(&cli.registry, cli.policy.as_deref()),
    }
}
