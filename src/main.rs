#![forbid(unsafe_code)]

mod baseline;
mod cli;
mod diff;
mod error;
mod executor;
mod extract;
mod heuristic;
mod manifest;
mod registry;
mod render;
mod review;
mod store;
mod verdict;

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
        cli::Command::Review { pkg, output } => review::run(&pkg, &cli.registry, output),
        cli::Command::Install { pkg, npm_args } => review::install(&pkg, &cli.registry, &npm_args),
    }
}
