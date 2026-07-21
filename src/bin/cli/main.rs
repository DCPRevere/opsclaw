//! `opsclaw-cli` — operator/developer CLI. Links the library crate and drives
//! the same orchestrator path as every channel (gianna pattern). Wave 4 fills
//! the subcommands; Wave 0 ships the skeleton so the binary exists from the
//! first commit.

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "opsclaw-cli", version, about = "OpsClaw operator CLI")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// First-run wizard: provider key, channels, memory, gateway.
    Onboard,
    /// Config + dependency health check.
    Doctor,
    /// Run the daemon (identical to the `opsclaw` binary).
    Daemon,
    /// Freeze all agent action across all targets instantly.
    Estop {
        /// Resume normal operation.
        #[arg(long)]
        resume: bool,
    },
    /// List incidents.
    Incidents,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    match cli.command {
        Command::Daemon => {
            // Same path as the daemon binary.
            let config = opsclaw::config::Config::load(None).expect("config");
            config.validate().expect("config invalid");
            opsclaw::http::server::run(opsclaw::http::AppState::new(config)).await.expect("server");
        }
        _ => {
            eprintln!("not yet implemented (lands in Wave 4 — see docs/plans/IMPLEMENTATION.md)");
            std::process::exit(1);
        }
    }
}
