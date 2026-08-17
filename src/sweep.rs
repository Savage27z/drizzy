//! Sweep every wallet in a manifest to one destination address.
//!
//! This is the exit door. A bot that generates wallets for someone and then
//! offers no way to move funds out leaves their ETH stranded behind a CLI they
//! do not have access to, so `/withdraw` is a correctness requirement for a
//! shared bot rather than a convenience.
//!
//! Deliberately independent of the `.env`-backed `AppConfig` used by the
//! `funds` CLI path: the bot is configured from process environment and has no
//! `.env` file, so reusing that path would fail before it began.

use std::{path::PathBuf, time::Duration};

use alloy_primitives::{Address, Bytes, U256};
use thiserror::Error;
use url::Url;

use crate::{
    chain::{ChainError, ChainGateway},
    config::ChainConfig,
    multi_wallet::{WalletManifest, WalletManifestError},
    transaction::{Eip1559Transaction, TransactionError, sign_eip1559_transaction},
};

const READ_TIMEOUT: Duration = Duration::from_secs(10);
/// Intrinsic cost of a plain value transfer with no calldata. A sweep never
/// carries input, so this is exact rather than an estimate.
const TRANSFER_GAS_LIMIT: u64 = 21_000;

#[derive(Debug, Error)]
pub enum SweepError {
    #[error("invalid destination address: {0}")]
    InvalidDestination(String),
    #[error("no RPC endpoint could be reached for {chain}")]
    NoWorkingRpc { chain: String },
    #[error("unknown chain: {0}")]
    UnknownChain(String),
    #[error(transparent)]
    Chain(#[from] ChainError),
    #[error(transparent)]
    Manifest(#[from] WalletManifestError),
    #[error(transparent)]
    Transaction(#[from] TransactionError),
}

#[derive(Debug)]
pub struct SweepOptions {
    pub wallets_file: PathBuf,
    pub destination: Address,
    pub chain: String,
    /// Explicit endpoints; falls back to the chain's public nodes when empty.
    pub rpc_urls: Vec<String>,
    pub notify: Option<tokio::sync::mpsc::UnboundedSender<String>>,
}

/// What happened to one wallet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WalletOutcome {
    Swept {
        sent: U256,
        tx_hash: String,
    },
    /// Balance did not cover its own transfer gas, so there was nothing to move.
    Dust {
        balance: U256,
    },
    Failed {
        reason: String,
    },
}

#[derive(Clone, Debug)]
pub struct SweepReport {
    pub outcomes: Vec<(Address, WalletOutcome)>,
}

impl SweepReport {
    #[must_use]
    pub fn total_sent(&self) -> U256 {
        self.outcomes
            .iter()
            .filter_map(|(_, outcome)| match outcome {
                WalletOutcome::Swept { sent, .. } => Some(*sent),
                _ => None,
            })
            .fold(U256::ZERO, |total, sent| {
                total.checked_add(sent).unwrap_or(total)
            })
    }

    #[must_use]
    pub fn swept_count(&self) -> usize {
        self.outcomes
            .iter()
            .filter(|(_, outcome)| matches!(outcome, WalletOutcome::Swept { .. }))
            .count()
    }
}

macro_rules! emit {
    ($options:expr, $line:expr) => {{
        let line = $line;
        if let Some(channel) = &$options.notify {
            let _ = channel.send(line.clone());
        }
        crate::logging::info(line);
    }};
}

/// Move every wallet's spendable balance to `destination`.
///
/// Each wallet is swept independently: one failure is reported and the rest
/// continue, because a partial sweep is strictly better than aborting with
/// funds left behind.
pub async fn sweep(options: SweepOptions) -> Result<SweepReport, SweepError> {
    let manifest = WalletManifest::load(&options.wallets_file)?;
    let gateway = ChainGateway::new(READ_TIMEOUT)?;

    let (chain_id, rpc_urls) = resolve_endpoints(&gateway, &options).await?;
    let config = ChainConfig { chain_id, rpc_urls };

    emit!(
        options,
        format!(
            "Sweeping {} wallet(s) on {} to {}",
            manifest.len(),
            options.chain,
            options.destination
        )
    );

    let mut outcomes = Vec::with_capacity(manifest.len());
    for entry in manifest.wallets() {
        let address = entry.address();
        let outcome = sweep_one(&gateway, &config, entry.signer(), options.destination).await;
        match &outcome {
            WalletOutcome::Swept { sent, tx_hash } => {
                emit!(options, format!("✅ {address} → {sent} wei ({tx_hash})"));
            }
            WalletOutcome::Dust { balance } => emit!(
                options,
                format!("• {address} — {balance} wei, below its own gas cost; skipped")
            ),
            WalletOutcome::Failed { reason } => {
                emit!(options, format!("❌ {address} — {reason}"));
            }
        }
        outcomes.push((address, outcome));
    }

    Ok(SweepReport { outcomes })
}

async fn sweep_one(
    gateway: &ChainGateway,
    config: &ChainConfig,
    wallet: &crate::signing::WalletSigner,
    destination: Address,
) -> WalletOutcome {
    let address = wallet.identity().address;

    let inputs = match gateway.submission_inputs(config, 1, address).await {
        Ok(inputs) => inputs,
        Err(error) => {
            return WalletOutcome::Failed {
                reason: error.to_string(),
            };
        }
    };
    let account = match gateway.account_state(config, 1, address).await {
        Ok(account) => account,
        Err(error) => {
            return WalletOutcome::Failed {
                reason: error.to_string(),
            };
        }
    };

    let max_fee_per_gas = inputs.fee_estimate.max_fee_per_gas;
    let Some(gas_cost) = U256::from(TRANSFER_GAS_LIMIT).checked_mul(max_fee_per_gas) else {
        return WalletOutcome::Failed {
            reason: "gas cost overflow".to_owned(),
        };
    };

    // Send balance minus the worst-case fee. Using max_fee (not base fee) means
    // the transaction stays valid even if the base fee rises before inclusion;
    // the unspent difference is refunded to this wallet, not lost.
    let Some(value) = account.balance.checked_sub(gas_cost) else {
        return WalletOutcome::Dust {
            balance: account.balance,
        };
    };
    if value.is_zero() {
        return WalletOutcome::Dust {
            balance: account.balance,
        };
    }

    let transaction = Eip1559Transaction {
        chain_id: config.chain_id,
        nonce: account.pending_nonce,
        max_priority_fee_per_gas: inputs.fee_estimate.max_priority_fee_per_gas,
        max_fee_per_gas,
        gas_limit: TRANSFER_GAS_LIMIT,
        target: destination,
        value,
        calldata: Bytes::new(),
    };
    let raw = match sign_eip1559_transaction(&transaction, wallet) {
        Ok(raw) => raw,
        Err(error) => {
            return WalletOutcome::Failed {
                reason: error.to_string(),
            };
        }
    };
    match gateway.send_raw_transaction(config, 1, &raw).await {
        Ok(hash) => WalletOutcome::Swept {
            sent: value,
            tx_hash: hash.to_string(),
        },
        Err(error) => WalletOutcome::Failed {
            reason: error.to_string(),
        },
    }
}

/// Explicit endpoints win; otherwise fall back to the chain's public nodes.
/// Endpoints that fail a chain-id probe are dropped, so a send-only sequencer
/// is never chosen as the sweep endpoint.
async fn resolve_endpoints(
    gateway: &ChainGateway,
    options: &SweepOptions,
) -> Result<(u64, Vec<Url>), SweepError> {
    let (chain_id, defaults) = crate::snipe::public_rpcs_for(&options.chain)
        .ok_or_else(|| SweepError::UnknownChain(options.chain.clone()))?;

    let mut candidates: Vec<Url> = Vec::new();
    for raw in &options.rpc_urls {
        let trimmed = raw.trim();
        if trimmed.is_empty() || !trimmed.contains("://") {
            continue;
        }
        if let Ok(url) = Url::parse(trimmed) {
            candidates.push(url);
        }
    }
    if candidates.is_empty() {
        for raw in defaults {
            if let Ok(url) = Url::parse(raw) {
                candidates.push(url);
            }
        }
    }

    let mut working = Vec::new();
    for url in candidates {
        if gateway.probe_rpc(&url).await.is_ok() {
            working.push(url);
        }
    }
    if working.is_empty() {
        return Err(SweepError::NoWorkingRpc {
            chain: options.chain.clone(),
        });
    }
    Ok((chain_id, working))
}

/// Parse a user-supplied destination address.
pub fn parse_destination(raw: &str) -> Result<Address, SweepError> {
    raw.trim()
        .parse()
        .map_err(|_| SweepError::InvalidDestination(raw.trim().to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn swept(sent: u128) -> WalletOutcome {
        WalletOutcome::Swept {
            sent: U256::from(sent),
            tx_hash: "0xabc".to_owned(),
        }
    }

    #[test]
    fn destination_parsing_accepts_addresses_and_rejects_junk() {
        assert!(parse_destination("0x1234567890abcdef1234567890abcdef12345678").is_ok());
        assert!(parse_destination("  0x1234567890abcdef1234567890abcdef12345678  ").is_ok());
        assert!(parse_destination("not-an-address").is_err());
        assert!(parse_destination("").is_err());
        // Too short to be an address — must not be silently zero-padded.
        assert!(parse_destination("0xdeadbeef").is_err());
    }

    #[test]
    fn report_totals_only_count_swept_wallets() {
        let report = SweepReport {
            outcomes: vec![
                (Address::ZERO, swept(1_000)),
                (
                    Address::ZERO,
                    WalletOutcome::Dust {
                        balance: U256::from(5),
                    },
                ),
                (
                    Address::ZERO,
                    WalletOutcome::Failed {
                        reason: "nope".to_owned(),
                    },
                ),
                (Address::ZERO, swept(2_500)),
            ],
        };

        assert_eq!(report.swept_count(), 2);
        assert_eq!(
            report.total_sent(),
            U256::from(3_500),
            "dust and failures must not be counted as swept value"
        );
    }

    #[test]
    fn an_empty_report_totals_zero() {
        let report = SweepReport { outcomes: vec![] };
        assert_eq!(report.swept_count(), 0);
        assert_eq!(report.total_sent(), U256::ZERO);
    }
}
