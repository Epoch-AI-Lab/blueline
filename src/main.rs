mod cli;
mod error;
mod extract;
mod manifest;
mod registry;
mod review;
mod store;

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
    }
}
