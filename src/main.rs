#![forbid(unsafe_code)]

use blueline::{agent, ci, cli, mcp, recall, review, shim};

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
        cli::Command::Review { pkg, output, yes } => {
            review::run(&pkg, ecosystem, &bases, output, cli.policy.as_deref(), yes)
        }
        cli::Command::Install { pkg, npm_args, yes } => review::install(
            &pkg,
            ecosystem,
            &bases,
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
            &bases,
            ecosystem,
            cli.policy.as_deref(),
            format.to_ci_format(),
            fail_on,
            output_file.as_deref(),
        ),
        cli::Command::Mcp => mcp::run_stdio(&bases, cli.policy.as_deref()),
        cli::Command::Agent { action } => match action {
            cli::AgentAction::Review { pkg } => {
                agent::run(&pkg, ecosystem, &bases, cli.policy.as_deref())
            }
            cli::AgentAction::Gate { command, format } => agent::gate(
                command.as_deref(),
                format.into(),
                &bases,
                cli.policy.as_deref(),
            ),
        },
        cli::Command::Recall { action } => match action {
            cli::RecallAction::Sync { url } => {
                let synced = recall::sync(&url)?;
                println!(
                    "synced recall snapshot: sequence {}, {} revocations, fetched {}s ago (0)",
                    synced.snapshot.sequence,
                    synced.snapshot.revocations.len(),
                    synced.age_secs()
                );
                Ok(())
            }
            cli::RecallAction::Serve { port, snapshot } => recall::serve(port, &snapshot),
            cli::RecallAction::ExportCandidates { out, limit } => {
                let store = blueline::store::BaselineStore::open()?;
                let candidates: Vec<blueline::store::AuditEntry> = store
                    .audit_entries(limit)?
                    .into_iter()
                    .filter(|e| {
                        matches!(e.action.as_str(), "hold" | "agent_gate" | "agent_review")
                            || e.verdict == "BLOCK"
                            || e.verdict == "HIGH"
                    })
                    .collect();
                let json = serde_json::to_string_pretty(&candidates)?;
                std::fs::write(&out, json)
                    .map_err(|e| anyhow::anyhow!("writing {}: {e}", out.display()))?;
                println!(
                    "exported {} candidate(s) to {}",
                    candidates.len(),
                    out.display()
                );
                Ok(())
            }
        },
        cli::Command::Shim { action } => match action {
            cli::ShimAction::Install { managers, dir } => shim::install(&managers, dir.as_deref()),
            cli::ShimAction::Uninstall { managers, dir } => {
                shim::uninstall(&managers, dir.as_deref())
            }
        },
    }
}
