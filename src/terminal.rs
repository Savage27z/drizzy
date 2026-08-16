use std::{
    collections::BTreeSet,
    fmt,
    io::{self, Write},
};

use alloy_primitives::{Address, U256};
use crossterm::style::{Color, Stylize};
use thiserror::Error;

use crate::logging;

#[derive(Debug, Error)]
pub enum TerminalError {
    #[error("terminal input or output failed: {0}")]
    Io(#[from] io::Error),
    #[error("mint setup was cancelled")]
    Cancelled,
    #[error("OpenSea reported no selectable phase for this wallet")]
    NoSelectablePhase,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PhaseOption {
    pub stage_index: u32,
    pub stage_type: String,
    pub starts_at: String,
    pub ends_at: String,
    pub state: String,
    pub eligibility: String,
    pub max_quantity: u64,
    pub token_range: Option<(u64, u64)>,
    pub is_selectable: bool,
}

#[must_use]
pub fn undelegate_command() -> String {
    "opensea-mint mint --undelegate".into()
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfiguredPhase {
    pub option_index: usize,
    pub token_id: String,
    pub quantity: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TopUpDecision {
    Recheck,
    Skip,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExecutorDeploymentConfirmation {
    pub chain_id: u64,
    pub deployer: Address,
    pub deployer_delegation: Option<Address>,
    pub deterministic_factory: Address,
    pub salt: alloy_primitives::B256,
    pub predicted_executor: Address,
    pub estimated_gas: u64,
    pub gas_limit: u64,
    pub initial_max_fee_per_gas: U256,
    pub final_max_fee_per_gas: U256,
    pub maximum_cost: U256,
    pub maximum_attempts: u32,
}

const CONFIGURED_COLOR: Color = Color::White;

pub fn prompt_collection_locator() -> Result<String, TerminalError> {
    logging::section_break();
    logging::input("Paste an OpenSea slug, collection or mint URL, or NFT contract address.");
    loop {
        let input = prompt("Mint target: ")?;
        if !input.is_empty() {
            return Ok(input);
        }
        logging::warn("Collection input cannot be empty.");
    }
}

pub fn select_phases(options: &[PhaseOption]) -> Result<Vec<usize>, TerminalError> {
    logging::section_break();
    print_phase_options(options);
    let selectable = options
        .iter()
        .enumerate()
        .filter_map(|(index, option)| option.is_selectable.then_some(index))
        .collect::<Vec<_>>();
    match selectable.as_slice() {
        [] => return Err(TerminalError::NoSelectablePhase),
        [only] => {
            logging::success(format!(
                "Selected stage {} {} automatically.",
                options[*only].stage_index, options[*only].stage_type
            ));
            return Ok(vec![*only]);
        }
        _ => {}
    }

    logging::input("Choose selectable phase numbers separated by commas, or q to cancel.");
    loop {
        let input = prompt("Phases: ")?;
        if input.eq_ignore_ascii_case("q") {
            return Err(TerminalError::Cancelled);
        }
        match parse_phase_selection(&input, options) {
            Some(selection) => return Ok(selection),
            None => logging::warn("Select only selectable phase numbers."),
        }
    }
}

pub fn configure_multi_token(option: &PhaseOption) -> Result<String, TerminalError> {
    logging::section_break();
    println!(
        "{}",
        format!("Stage {} | {}", option.stage_index, option.stage_type)
            .cyan()
            .bold()
    );
    option.token_range.map_or_else(
        || Ok("0".into()),
        |(from, to)| prompt_number("Token ID: ", from, from, to).map(|value| value.to_string()),
    )
}

pub fn confirm_multi_mint(
    options: &[PhaseOption],
    configured: &[ConfiguredPhase],
    manifest_wallet_count: usize,
    gas_limit: u64,
    mode: &str,
    recipient: &str,
) -> Result<(), TerminalError> {
    logging::section_break();
    for selection in configured {
        let option = options
            .get(selection.option_index)
            .ok_or(TerminalError::NoSelectablePhase)?;
        println!(
            "{}",
            format!(
                "Stage {} | {} | {} | {} | token={} | requested quantity={}",
                option.stage_index,
                option.stage_type,
                option.state,
                option.eligibility,
                selection.token_id,
                selection.quantity
            )
            .with(CONFIGURED_COLOR)
            .bold()
        );
    }
    for line in [
        format!(
            "Mode: {mode} | phases={} | manifest wallets={manifest_wallet_count}",
            configured.len()
        ),
        format!("Per-wallet mint gas limit: {gas_limit}"),
        format!("NFT recipient: {recipient}"),
    ] {
        println!("{}", line.with(CONFIGURED_COLOR).bold());
    }
    println!();
    logging::input("Approve this multi-wallet mint?");
    let answer = prompt("Answer [y/N]: ")?;
    if matches!(answer.to_ascii_lowercase().as_str(), "y" | "yes") {
        logging::section_break();
        Ok(())
    } else {
        Err(TerminalError::Cancelled)
    }
}

pub fn confirm_executor_deployment(
    confirmation: &ExecutorDeploymentConfirmation,
) -> Result<(), TerminalError> {
    logging::section_break();
    let delegation = confirmation.deployer_delegation.map_or_else(
        || "none".to_owned(),
        |delegate| format!("EIP-7702 delegate {delegate}"),
    );
    for line in [
        format!("Network chain ID: {}", confirmation.chain_id),
        format!("Deployer: {}", confirmation.deployer),
        format!("Deployer delegation: {delegation}"),
        format!(
            "Deterministic factory: {}",
            confirmation.deterministic_factory
        ),
        format!("Sponsor deployment salt: {}", confirmation.salt),
        format!("Predicted executor: {}", confirmation.predicted_executor),
        format!(
            "Deployment gas: estimate={} | buffered limit={}",
            confirmation.estimated_gas, confirmation.gas_limit
        ),
        format!(
            "Max fee per gas: initial={} wei | final replacement={} wei",
            confirmation.initial_max_fee_per_gas, confirmation.final_max_fee_per_gas
        ),
        format!(
            "Estimated maximum cost at confirmation: {} wei across at most {} attempt(s)",
            confirmation.maximum_cost, confirmation.maximum_attempts
        ),
        "Nonce and fees: refreshed immediately before signing".into(),
    ] {
        println!("{}", line.with(CONFIGURED_COLOR).bold());
    }
    println!();
    logging::input("Deploy this audited executor build on the configured network?");
    let answer = prompt("Answer [y/N]: ")?;
    if matches!(answer.to_ascii_lowercase().as_str(), "y" | "yes") {
        Ok(())
    } else {
        Err(TerminalError::Cancelled)
    }
}

pub fn confirm_native_funds(question: &str) -> Result<(), TerminalError> {
    logging::input(question);
    let answer = prompt("Answer [y/N]: ")?;
    if matches!(answer.to_ascii_lowercase().as_str(), "y" | "yes") {
        Ok(())
    } else {
        Err(TerminalError::Cancelled)
    }
}

pub fn prompt_top_up() -> Result<TopUpDecision, TerminalError> {
    logging::input(
        "Top up the listed address(es), then press Enter to recheck; enter s to skip underfunded wallets or q to cancel.",
    );
    loop {
        match prompt("Funding: ")?.to_ascii_lowercase().as_str() {
            "" | "r" | "recheck" => return Ok(TopUpDecision::Recheck),
            "s" | "skip" => return Ok(TopUpDecision::Skip),
            "q" | "quit" => return Err(TerminalError::Cancelled),
            _ => logging::warn("Press Enter to recheck, s to skip, or q to cancel."),
        }
    }
}

pub fn configure_phases(
    options: &[PhaseOption],
    selected: &[usize],
) -> Result<Vec<ConfiguredPhase>, TerminalError> {
    logging::section_break();
    let mut configured = Vec::with_capacity(selected.len());
    for option_index in selected {
        let option = &options[*option_index];
        println!(
            "{}",
            format!("Stage {} | {}", option.stage_index, option.stage_type)
                .cyan()
                .bold()
        );
        let token_id = if let Some((from, to)) = option.token_range {
            prompt_number("Token ID: ", from, from, to)?.to_string()
        } else {
            "0".into()
        };
        let quantity = prompt_number("Quantity: ", 1, 1, option.max_quantity)?;
        println!();
        configured.push(ConfiguredPhase {
            option_index: *option_index,
            token_id,
            quantity,
        });
    }
    Ok(configured)
}

pub fn confirm_schedule(
    options: &[PhaseOption],
    configured: &[ConfiguredPhase],
    gas_limit: u64,
    fee_mode: &str,
) -> Result<(), TerminalError> {
    logging::section_break();
    for selection in configured {
        let option = &options[selection.option_index];
        println!(
            "{}",
            format!(
                "Stage {} | {} | {} | {} | token={} | quantity={}",
                option.stage_index,
                option.stage_type,
                option.state,
                option.eligibility,
                selection.token_id,
                selection.quantity
            )
            .with(CONFIGURED_COLOR)
            .bold()
        );
    }
    println!(
        "{}",
        format!("Gas limit: {gas_limit}")
            .with(CONFIGURED_COLOR)
            .bold()
    );
    println!(
        "{}",
        format!("Fee mode: {fee_mode}")
            .with(CONFIGURED_COLOR)
            .bold()
    );
    println!();
    logging::input(approval_instruction(options, configured));
    let answer = prompt("Answer [y/N]: ")?;
    if matches!(answer.to_ascii_lowercase().as_str(), "y" | "yes") {
        Ok(())
    } else {
        Err(TerminalError::Cancelled)
    }
}

fn approval_instruction(options: &[PhaseOption], configured: &[ConfiguredPhase]) -> &'static str {
    let has_live = configured
        .iter()
        .any(|selection| options[selection.option_index].state == "active");
    let has_upcoming = configured
        .iter()
        .any(|selection| options[selection.option_index].state == "upcoming");
    match (has_live, has_upcoming) {
        (true, true) => "Approve the selected live mint and upcoming schedule?",
        (true, false) => "Approve the selected live mint?",
        (false, true) => "Approve the selected upcoming mint schedule?",
        (false, false) => "Approve the selected mint?",
    }
}

fn print_phase_options(options: &[PhaseOption]) {
    for (index, option) in options.iter().enumerate() {
        let number = format!("{:>2}.", index + 1);
        let availability_label = phase_availability_label(option);
        let availability = if option.is_selectable {
            format!("{}", availability_label.green())
        } else {
            format!("{}", availability_label.red())
        };
        println!(
            "  {number} Stage {} | {} | {} | {} | {availability}",
            option.stage_index, option.stage_type, option.state, option.eligibility
        );
        println!(
            "      {}",
            format!(
                "start={} | end={} | max={} | token={}",
                option.starts_at,
                option.ends_at,
                option.max_quantity,
                format_token_range(option.token_range)
            )
            .dark_grey()
        );
        println!();
    }
}

fn phase_availability_label(option: &PhaseOption) -> &'static str {
    if !option.is_selectable {
        "unavailable"
    } else if option.state == "upcoming" {
        "schedulable"
    } else {
        "available"
    }
}

fn parse_phase_selection(input: &str, options: &[PhaseOption]) -> Option<Vec<usize>> {
    let mut selected = BTreeSet::new();
    for value in input.split(',').map(str::trim) {
        let display_index = value.parse::<usize>().ok()?;
        let option_index = display_index.checked_sub(1)?;
        if !options.get(option_index)?.is_selectable {
            return None;
        }
        selected.insert(option_index);
    }
    (!selected.is_empty()).then(|| selected.into_iter().collect())
}

fn prompt_number(
    label: &str,
    default: u64,
    minimum: u64,
    maximum: u64,
) -> Result<u64, TerminalError> {
    logging::input(format!(
        "Choose a whole number from {minimum} to {maximum}; default={default}."
    ));
    loop {
        let input = prompt(label)?;
        if input.eq_ignore_ascii_case("q") {
            return Err(TerminalError::Cancelled);
        }
        if input.is_empty() {
            return Ok(default);
        }
        if let Ok(value) = input.parse::<u64>()
            && (minimum..=maximum).contains(&value)
        {
            return Ok(value);
        }
        logging::warn(format!("Enter a whole number from {minimum} to {maximum}."));
    }
}

fn prompt(label: &str) -> Result<String, TerminalError> {
    print!("{}", label.green().bold());
    io::stdout().flush()?;
    let mut input = String::new();
    if io::stdin().read_line(&mut input)? == 0 {
        return Err(TerminalError::Cancelled);
    }
    Ok(input.trim().to_owned())
}

fn format_token_range(range: Option<(u64, u64)>) -> impl fmt::Display {
    range.map_or_else(
        || "ERC-721".to_owned(),
        |(from, to)| format!("{from}..={to}"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_unique_comma_separated_eligible_phase_numbers() {
        let options = [phase(true), phase(false), phase(true)];
        assert_eq!(parse_phase_selection("3, 1,3", &options), Some(vec![0, 2]));
        assert_eq!(parse_phase_selection("2", &options), None);
        assert_eq!(parse_phase_selection("0", &options), None);
        assert_eq!(parse_phase_selection("", &options), None);
    }

    #[test]
    fn approval_instruction_matches_selected_phase_timing() {
        let mut options = vec![phase(true), phase(true)];
        options[0].state = "active".into();
        options[1].state = "upcoming".into();
        let configured = vec![configured_phase(0), configured_phase(1)];

        assert_eq!(
            approval_instruction(&options, &configured),
            "Approve the selected live mint and upcoming schedule?"
        );
        assert_eq!(
            approval_instruction(&options, &configured[..1]),
            "Approve the selected live mint?"
        );
        assert_eq!(
            approval_instruction(&options, &configured[1..]),
            "Approve the selected upcoming mint schedule?"
        );
    }

    #[test]
    fn labels_upcoming_selection_as_schedulable_not_available() {
        let mut option = phase(true);
        option.state = "upcoming".into();
        assert_eq!(phase_availability_label(&option), "schedulable");

        option.state = "active".into();
        assert_eq!(phase_availability_label(&option), "available");

        option.is_selectable = false;
        assert_eq!(phase_availability_label(&option), "unavailable");
    }

    #[test]
    fn undelegation_command_uses_the_cross_platform_installed_binary_name() {
        assert_eq!(undelegate_command(), "opensea-mint mint --undelegate");
    }

    fn configured_phase(option_index: usize) -> ConfiguredPhase {
        ConfiguredPhase {
            option_index,
            token_id: "0".into(),
            quantity: 1,
        }
    }

    fn phase(is_selectable: bool) -> PhaseOption {
        PhaseOption {
            stage_index: 0,
            stage_type: "PUBLIC_SALE".into(),
            starts_at: "open".into(),
            ends_at: "no end".into(),
            state: "active".into(),
            eligibility: "eligible".into(),
            max_quantity: 1,
            token_range: None,
            is_selectable,
        }
    }
}
