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
    let bases = cli::RegistryBases::from_flags(&cli.registry, &cli.index);
    match cli.command {
        cli::Command::Review { pkg, output, yes } => review::run(
            &pkg,
            ecosystem,
            bases.for_ecosystem(ecosystem),
            output,
            cli.policy.as_deref(),
            yes,
        ),
        cli::Command::Install { pkg, npm_args, yes } => review::install(
            &pkg,
            ecosystem,
            bases.for_ecosystem(ecosystem),
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
            bases.for_ecosystem(ecosystem),
            ecosystem,
            cli.policy.as_deref(),
            format.to_ci_format(),
            fail_on,
            output_file.as_deref(),
        ),
        cli::Command::Mcp => mcp::run_stdio(&bases, cli.policy.as_deref()),
    }
}
