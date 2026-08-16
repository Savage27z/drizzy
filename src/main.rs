#![forbid(unsafe_code)]

use std::process::ExitCode;

use clap::Parser;
use opensea_mint::{
    command::{Cli, CommandError, execute},
    logging,
    terminal::TerminalError,
};

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    match execute(cli).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(CommandError::Terminal(TerminalError::Cancelled)) => {
            logging::info("Operation cancelled.");
            ExitCode::SUCCESS
        }
        Err(error) => {
            logging::error(error);
            ExitCode::FAILURE
        }
    }
}
