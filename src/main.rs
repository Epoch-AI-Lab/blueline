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
    let ecosystem = cli.ecosystem.into();
    // npm talks to the registry base; cargo reviews use the sparse index base.
    let registry_base = match ecosystem {
        blueline::registry::Ecosystem::Npm => cli.registry.clone(),
        blueline::registry::Ecosystem::Cargo => cli.index.clone(),
        blueline::registry::Ecosystem::PyPi => {
            if cli.index != "https://index.crates.io" {
                cli.index.clone()
            } else if cli.registry != "https://registry.npmjs.org" {
                cli.registry.clone()
            } else {
                "https://pypi.org".to_string()
            }
        }
    };
    match cli.command {
        cli::Command::Review { pkg, output, yes } => review::run(
            &pkg,
            ecosystem,
            &registry_base,
            output,
            cli.policy.as_deref(),
            yes,
        ),
        cli::Command::Install { pkg, npm_args, yes } => review::install(
            &pkg,
            ecosystem,
            &registry_base,
            &npm_args,
            cli.policy.as_deref(),
            yes,
        ),
        cli::Command::Ci {
            base,
            lockfile,
            format,
            fail_on,
            output_file,
        } => ci::run(
            &base,
            &lockfile,
            &registry_base,
            ecosystem,
            cli.policy.as_deref(),
            format.to_ci_format(),
            fail_on,
            output_file.as_deref(),
        ),
        cli::Command::Mcp => mcp::run_stdio(&cli.registry, &cli.index, cli.policy.as_deref()),
    }
}
