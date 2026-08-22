//! Sponsored (EIP-7702 delegated) `SeaDrop` snipe.
//!
//! Same local, no-`OpenSea`-API philosophy as `snipe.rs`: `mintPublic`
//! calldata is built from on-chain state, not `OpenSea`'s API. The difference
//! is who pays gas — instead of every wallet signing and broadcasting its own
//! transaction, every wallet signs one EIP-712 mint intent, and a single
//! sponsor wallet broadcasts one transaction that executes the whole batch
//! through the audited `SponsoredMintExecutor` (see `contracts/README.md`).
//! Each wallet still pays its own mint value from its own balance; only gas
//! is sponsored. A wallet gets a fresh EIP-7702 authorization only when it
//! is not already correctly delegated to the executor — delegation persists
//! in account state, so a wallet armed in an earlier batch costs no
//! authorization gas here.

use std::{path::PathBuf, time::Duration};

use alloy_primitives::{Address, B256, U256};
use rand_core::{OsRng, RngCore};
use thiserror::Error;
use tokio::{sync::mpsc::UnboundedSender, time::Instant};

use crate::{
    blast,
    chain::{ChainError, ChainGateway},
    config::ChainConfig,
    logging,
    multi_wallet::{WalletManifest, WalletManifestError},
    seadrop::{self, SeadropError},
    signing::{WalletSigner, WalletSignerError},
    snipe::{
        SnipeError, chain_by_id, explorer_url, resolve_chain, resolve_nft_contract,
        resolve_rpc_candidates, run_probe, unix_millis, wait_for_receipt, wait_until_fire,
    },
    sponsored::{
        DelegationState, MAX_SPONSORED_BATCH_SIZE, SponsoredMintError, SponsoredMintOperation,
        UnsignedSponsoredMintOperation, classify_delegation, encode_execute_batch, sign_delegation,
        sign_operation, sponsored_outer_gas_limit, sponsored_wallet_gas_limit,
    },
    transaction::{
        Eip1559Transaction, Eip7702Transaction, TransactionError, sign_eip1559_transaction,
        sign_eip7702_transaction,
    },
};

const READ_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Error)]
pub enum SponsoredSnipeError {
    #[error("sponsored snipes support at most {MAX_SPONSORED_BATCH_SIZE} wallets per batch")]
    TooManyWallets,
    #[error("no wallet keys configured — a manifest is required")]
    NoWallets,
    #[error(
        "wallet {address} cannot cover its mint value: balance {balance} wei, required {required} wei — the sponsor covers gas, not mint price"
    )]
    UnderfundedWallet {
        address: Address,
        balance: U256,
        required: U256,
    },
    #[error("sponsor cannot cover outer gas: balance {balance} wei, required {required} wei")]
    UnderfundedSponsor { balance: U256, required: U256 },
    #[error(
        "mint simulation reverted for {address} while the stage is live — the batch was not signed"
    )]
    SimulationReverted { address: Address },
    #[error("collection has no public stage on the SeaDrop singleton")]
    NoPublicStage,
    #[error("recipient must not equal any minting wallet")]
    RecipientIsWallet,
    #[error(transparent)]
    Snipe(#[from] SnipeError),
    #[error(transparent)]
    Chain(#[from] ChainError),
    #[error(transparent)]
    Seadrop(#[from] SeadropError),
    #[error(transparent)]
    Manifest(#[from] WalletManifestError),
    #[error(transparent)]
    Wallet(#[from] WalletSignerError),
    #[error(transparent)]
    Sponsored(#[from] SponsoredMintError),
    #[error(transparent)]
    Transaction(#[from] TransactionError),
    #[error(transparent)]
    Blast(#[from] blast::BlastError),
}

#[derive(Debug)]
pub struct SponsoredSnipeOptions {
    pub collection: String,
    pub quantity: Option<u64>,
    pub wallets_file: PathBuf,
    /// Optional 0-based subset of manifest wallets to include in the batch.
    pub wallet_indices: Option<Vec<usize>>,
    pub rpc_urls: Vec<String>,
    pub chain: Option<String>,
    pub sponsor: WalletSigner,
    pub executor: Address,
    /// Every minted NFT is forwarded here — the executor never leaves an NFT
    /// in the delegated wallet. Must differ from every minting wallet.
    pub recipient: Address,
    /// Per-wallet mint gas headroom; the wallet's full execution envelope is
    /// derived from this via `sponsored_wallet_gas_limit`.
    pub mint_gas_limit: u64,
    pub operation_deadline_seconds: u64,
    pub max_fee_per_gas: Option<U256>,
    pub max_priority_fee_per_gas: Option<U256>,
    pub early_fire_ms: u64,
    pub fire_now: bool,
    pub notify: Option<UnboundedSender<String>>,
}

#[derive(Debug)]
pub struct SponsoredSnipePreview {
    pub nft_contract: Address,
    pub chain_id: u64,
    pub chain_name: String,
    pub price: U256,
    pub start_time: u64,
    pub end_time: u64,
    pub wallet_count: usize,
    pub sponsor: Address,
    pub recipient: Address,
}

fn load_sponsored_wallets(
    options: &SponsoredSnipeOptions,
) -> Result<Vec<(WalletSigner, u64)>, SponsoredSnipeError> {
    let manifest = WalletManifest::load(&options.wallets_file)?;
    let mut wallets: Vec<(WalletSigner, u64)> = manifest
        .wallets()
        .iter()
        .map(|entry| {
            let quantity = options.quantity.unwrap_or_else(|| entry.quantity());
            (entry.signer().clone(), quantity)
        })
        .collect();
    if let Some(indices) = &options.wallet_indices {
        let mut selected = Vec::with_capacity(indices.len());
        for index in indices {
            let wallet = wallets.get(*index).ok_or(SponsoredSnipeError::NoWallets)?;
            selected.push(wallet.clone());
        }
        wallets = selected;
    }
    if wallets.is_empty() {
        return Err(SponsoredSnipeError::NoWallets);
    }
    if wallets.len() > MAX_SPONSORED_BATCH_SIZE {
        return Err(SponsoredSnipeError::TooManyWallets);
    }
    if wallets
        .iter()
        .any(|(signer, _)| signer.identity().address == options.recipient)
    {
        return Err(SponsoredSnipeError::RecipientIsWallet);
    }
    Ok(wallets)
}

/// Resolve collection + chain + public stage and report what a sponsored
/// snipe would do, without touching any wallet's funds or signing anything.
pub async fn preview(
    options: &SponsoredSnipeOptions,
) -> Result<SponsoredSnipePreview, SponsoredSnipeError> {
    let _ = dotenvy::dotenv();
    let read_client = reqwest::Client::new();
    let nft_contract = resolve_nft_contract(&options.collection, &read_client).await?;
    let candidates = resolve_rpc_candidates(&options.rpc_urls, options.chain.as_deref())?;
    let gateway = ChainGateway::new(READ_TIMEOUT)?;
    let expected_chain_id = options
        .chain
        .as_deref()
        .and_then(resolve_chain)
        .map(|p| p.chain_id);
    let (chain_id, rpc_urls) = run_probe(&gateway, &candidates, expected_chain_id).await?;
    let config = ChainConfig { chain_id, rpc_urls };
    let base = seadrop::build_local_mint_plan(&gateway, &config, 1, nft_contract, 1)
        .await?
        .ok_or(SponsoredSnipeError::NoPublicStage)?;
    let wallet_count = load_sponsored_wallets(options)?.len();
    Ok(SponsoredSnipePreview {
        nft_contract,
        chain_id,
        chain_name: chain_by_id(chain_id)
            .map_or_else(|| "unknown".to_owned(), |p| p.key.to_owned()),
        price: base.drop.mint_price,
        start_time: base.drop.start_time,
        end_time: base.drop.end_time,
        wallet_count,
        sponsor: options.sponsor.identity().address,
        recipient: options.recipient,
    })
}

#[allow(clippy::too_many_lines)]
pub async fn run_sponsored_snipe(
    options: SponsoredSnipeOptions,
) -> Result<(), SponsoredSnipeError> {
    let notify = options.notify.clone();
    macro_rules! emit_info {
        ($msg:expr) => {{
            let msg: String = $msg.into();
            logging::info(&msg);
            if let Some(tx) = &notify {
                let _ = tx.send(msg);
            }
        }};
    }
    macro_rules! emit_success {
        ($msg:expr) => {{
            let msg: String = $msg.into();
            logging::success(&msg);
            if let Some(tx) = &notify {
                let _ = tx.send(msg);
            }
        }};
    }
    macro_rules! emit_warn {
        ($msg:expr) => {{
            let msg: String = $msg.into();
            logging::warn(&msg);
            if let Some(tx) = &notify {
                let _ = tx.send(msg);
            }
        }};
    }

    let _ = dotenvy::dotenv();
    // See the matching comment in `snipe.rs::run_snipe` — same naming, same
    // caveat: no independent "time to seen" without a third-party observer.
    let run_start = Instant::now();
    let read_client = reqwest::Client::new();
    let nft_contract = resolve_nft_contract(&options.collection, &read_client).await?;
    let candidates = resolve_rpc_candidates(&options.rpc_urls, options.chain.as_deref())?;

    let gateway = ChainGateway::new(READ_TIMEOUT)?;
    let expected_chain_id = options
        .chain
        .as_deref()
        .and_then(resolve_chain)
        .map(|p| p.chain_id);
    let (chain_id, rpc_urls) = run_probe(&gateway, &candidates, expected_chain_id).await?;
    let config = ChainConfig {
        chain_id,
        rpc_urls: rpc_urls.clone(),
    };
    let chain_name = chain_by_id(chain_id).map_or("unknown", |p| p.key);

    logging::section_break();
    emit_info!(format!(
        "SPONSORED SNIPE {nft_contract} on {chain_name} (chain id {chain_id}) — executor {}",
        options.executor
    ));

    let base = seadrop::build_local_mint_plan(&gateway, &config, 1, nft_contract, 1)
        .await?
        .ok_or(SponsoredSnipeError::NoPublicStage)?;
    let drop = base.drop;
    let wallets = load_sponsored_wallets(&options)?;
    emit_info!(format!(
        "SeaDrop: {} | price {} wei × {} wallet(s) sponsored by {}",
        base.to,
        drop.mint_price,
        wallets.len(),
        options.sponsor.identity().address
    ));

    let deadline =
        u64::try_from(unix_millis() / 1000).unwrap_or(0) + options.operation_deadline_seconds;

    let sign_start = Instant::now();

    // ── Per wallet: check balance, check delegation, build + sign the mint
    // intent, and (only where needed) sign a fresh EIP-7702 authorization ──
    let mut operations: Vec<SponsoredMintOperation> = Vec::with_capacity(wallets.len());
    let mut authorizations = Vec::new();
    for (signer, quantity) in &wallets {
        let wallet_address = signer.identity().address;
        let mint_value = drop.mint_price * U256::from(*quantity);
        let balance = gateway
            .account_state(&config, 1, wallet_address)
            .await?
            .balance;
        if balance < mint_value {
            return Err(SponsoredSnipeError::UnderfundedWallet {
                address: wallet_address,
                balance,
                required: mint_value,
            });
        }

        let code = gateway
            .account_code(&config, 1, wallet_address, None)
            .await?;
        match classify_delegation(&code, options.executor) {
            DelegationState::Expected => {}
            DelegationState::Clear
            | DelegationState::Unexpected(_)
            | DelegationState::OtherCode => {
                let wallet_nonce = gateway
                    .transaction_count(&config, 1, wallet_address)
                    .await?;
                let signed = sign_delegation(chain_id, options.executor, wallet_nonce, signer)?;
                authorizations.push(signed);
            }
        }

        let wallet_gas_limit = sponsored_wallet_gas_limit(options.mint_gas_limit)
            .ok_or(SponsoredMintError::InvalidGasLimits)?;
        let operation = SponsoredMintOperation::unsigned(UnsignedSponsoredMintOperation {
            wallet: wallet_address,
            mint_target: base.to,
            nft_contract,
            recipient: options.recipient,
            mint_value,
            expected_units: U256::from(*quantity),
            mint_gas_limit: options.mint_gas_limit,
            wallet_gas_limit,
            deadline,
            mint_calldata: seadrop::encode_mint_public(nft_contract, base.fee_recipient, *quantity),
        });
        // Signed below once the sponsor address and batch id are fixed, since
        // the EIP-712 digest binds both plus this operation's batch index.
        operations.push(operation);
    }

    let sponsor_address = options.sponsor.identity().address;
    let mut batch_id_bytes = [0_u8; 32];
    OsRng.fill_bytes(&mut batch_id_bytes);
    let batch_id = B256::from(batch_id_bytes);

    for (index, operation) in operations.iter_mut().enumerate() {
        let signer = &wallets[index].0;
        sign_operation(
            chain_id,
            options.executor,
            sponsor_address,
            batch_id,
            index,
            operation,
            signer,
        )?;
    }

    let calldata = encode_execute_batch(
        chain_id,
        options.executor,
        sponsor_address,
        batch_id,
        &operations,
    )?;
    let outer_gas_limit = sponsored_outer_gas_limit(&calldata, &operations)?;

    emit_info!(format!(
        "Batch built: {} operation(s), {} needing a fresh delegation, outer gas ~{outer_gas_limit}",
        operations.len(),
        authorizations.len()
    ));

    // ── Sponsor fees + nonce ──
    let sponsor_inputs = gateway
        .submission_inputs(&config, 1, sponsor_address)
        .await?;
    let (max_fee_per_gas, max_priority_fee_per_gas) =
        match (options.max_fee_per_gas, options.max_priority_fee_per_gas) {
            (Some(max), Some(priority)) => (max, priority),
            (Some(max), None) => (max, sponsor_inputs.fee_estimate.max_priority_fee_per_gas),
            (None, Some(priority)) => (sponsor_inputs.fee_estimate.max_fee_per_gas, priority),
            (None, None) => (
                sponsor_inputs.fee_estimate.max_fee_per_gas,
                sponsor_inputs.fee_estimate.max_priority_fee_per_gas,
            ),
        };
    let outer_gas_cost = U256::from(outer_gas_limit)
        .checked_mul(max_fee_per_gas)
        .ok_or(SponsoredMintError::GasOverflow)?;
    let sponsor_balance = gateway
        .account_state(&config, 1, sponsor_address)
        .await?
        .balance;
    if sponsor_balance < outer_gas_cost {
        return Err(SponsoredSnipeError::UnderfundedSponsor {
            balance: sponsor_balance,
            required: outer_gas_cost,
        });
    }
    emit_info!(format!(
        "Sponsor gas: limit {outer_gas_limit} | max fee {max_fee_per_gas} wei | priority {max_priority_fee_per_gas} wei"
    ));

    // ── Simulate before the stage is live to catch a bad executor/wallet
    // wiring early; a revert once the stage is live means the mint would
    // actually fail, so nothing gets signed. ──
    let stage_is_live = {
        let now = unix_millis().max(0);
        let stage_open = i64::try_from(drop.start_time)
            .unwrap_or(i64::MAX)
            .saturating_mul(1000);
        now >= stage_open
    };
    let simulation = gateway
        .estimate_transaction(
            &config,
            1,
            sponsor_address,
            options.executor,
            U256::ZERO,
            &calldata,
        )
        .await;
    match simulation {
        Ok(gas) => emit_info!(format!("Simulation OK — batch would use ~{gas} gas")),
        Err(_) if !stage_is_live => {
            emit_info!(
                "Simulation reverted, as expected before the stage opens — continuing to arm"
            );
        }
        Err(_) => {
            return Err(SponsoredSnipeError::SimulationReverted {
                address: sponsor_address,
            });
        }
    }

    // ── Sign the sponsor's one outer transaction ──
    let signed = if authorizations.is_empty() {
        // Every wallet is already correctly delegated — no authorization
        // needed, so a plain EIP-1559 call is cheaper than a type-4 tx.
        sign_eip1559_transaction(
            &Eip1559Transaction {
                chain_id,
                nonce: sponsor_inputs.pending_nonce,
                max_priority_fee_per_gas,
                max_fee_per_gas,
                gas_limit: outer_gas_limit,
                target: options.executor,
                value: U256::ZERO,
                calldata: calldata.clone(),
            },
            &options.sponsor,
        )?
    } else {
        sign_eip7702_transaction(
            &Eip7702Transaction {
                chain_id,
                nonce: sponsor_inputs.pending_nonce,
                max_priority_fee_per_gas,
                max_fee_per_gas,
                gas_limit: outer_gas_limit,
                target: options.executor,
                value: U256::ZERO,
                calldata: calldata.clone(),
                authorization_list: authorizations,
            },
            &options.sponsor,
        )?
    };

    let sign_ms = sign_start.elapsed().as_millis();
    emit_success!("Batch signed — nothing left to compute at fire time".to_owned());
    emit_info!(format!(
        "Latency: worker pickup ~0ms (no queue) | sign/pre-sign {sign_ms}ms | armed {}ms after start",
        run_start.elapsed().as_millis()
    ));

    let blast_client = blast::build_client()?;
    let endpoints = blast::parse_endpoints(&rpc_urls);
    let warm_handle = {
        let client = blast_client.clone();
        let eps = endpoints.clone();
        tokio::spawn(async move { blast::warm_connections(&client, &eps).await })
    };

    let fire_time = i64::try_from(drop.start_time)
        .unwrap_or(i64::MAX)
        .saturating_mul(1000)
        - i64::try_from(options.early_fire_ms).unwrap_or(0);
    let now = unix_millis();
    if !options.fire_now && fire_time > now {
        let _ = warm_handle.await;
        wait_until_fire(fire_time, "Sponsored batch").await;
    } else {
        let _ = warm_handle.await;
        emit_info!("Stage is live (or --fire-now) — dispatching immediately");
    }

    let dispatch_start = Instant::now();
    let prepared = blast::prepare_blast(&signed);
    let handles = blast::blast_to_all(&blast_client, &prepared, &endpoints);
    let mut results = Vec::with_capacity(handles.len());
    for handle in handles {
        if let Ok(result) = handle.await {
            results.push(result);
        }
    }
    if let Some((label, latency_ms)) = blast::winning_endpoint(&results) {
        emit_info!(format!(
            "First accept: {label} ({latency_ms}ms sendRaw latency)"
        ));
    }

    if blast::is_accepted(&results) {
        emit_success!(format!(
            "Batch accepted — tx {}",
            explorer_url(chain_id, &prepared.tx_hash.to_string())
        ));
        let receipt_result =
            wait_for_receipt(&gateway, &config, &prepared.tx_hash.to_string()).await;
        let landed_ms = dispatch_start.elapsed().as_millis();
        match receipt_result {
            Ok(Some(receipt)) if receipt.is_success => {
                emit_success!(format!(
                    "Confirmed in block {} — time to landed {landed_ms}ms — check the executor's WalletExecution events for per-wallet results",
                    receipt.block_number
                ));
            }
            Ok(Some(receipt)) => {
                emit_warn!(format!(
                    "Included in block {} but reverted — time to landed {landed_ms}ms — nothing minted, wallet balances unchanged",
                    receipt.block_number
                ));
            }
            Ok(None) => emit_warn!(
                "Accepted but not confirmed within the receipt timeout — check the explorer"
                    .to_owned()
            ),
            Err(error) => emit_warn!(format!("Could not confirm receipt: {error}")),
        }
    } else {
        let reasons = blast::rejection_reasons(&results);
        emit_warn!(format!("Batch rejected by every RPC: {reasons:?}"));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use tempfile::tempdir;

    use super::*;
    use crate::sponsored::MAX_SPONSORED_BATCH_SIZE;

    const FIRST_KEY: &str = "0x0000000000000000000000000000000000000000000000000000000000000001";

    fn key_for(byte: u8) -> String {
        format!("0x{:064x}", u128::from(byte))
    }

    fn manifest_with_wallet_count(count: usize) -> PathBuf {
        let entries: Vec<String> = (1..=count)
            .map(|i| {
                let key = key_for(u8::try_from(i).expect("test count fits in u8"));
                format!(r#"{{"private_key":"{key}","quantity":1}}"#)
            })
            .collect();
        let json = format!(r#"{{"version":1,"wallets":[{}]}}"#, entries.join(","));
        let dir = tempdir().expect("tempdir");
        let path = dir.keep().join("wallets.json");
        std::fs::File::create(&path)
            .expect("create")
            .write_all(json.as_bytes())
            .expect("write");
        path
    }

    fn base_options(wallets_file: PathBuf) -> SponsoredSnipeOptions {
        SponsoredSnipeOptions {
            collection: "example".to_owned(),
            quantity: None,
            wallets_file,
            wallet_indices: None,
            rpc_urls: Vec::new(),
            chain: None,
            sponsor: WalletSigner::from_private_key(FIRST_KEY).expect("sponsor signer"),
            executor: format!("0x{:040x}", 0x99_u32).parse().expect("executor"),
            recipient: format!("0x{:040x}", 0xfee_u32).parse().expect("recipient"),
            mint_gas_limit: 250_000,
            operation_deadline_seconds: 120,
            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
            early_fire_ms: 0,
            fire_now: false,
            notify: None,
        }
    }

    #[test]
    fn rejects_batches_larger_than_the_executor_supports() {
        let path = manifest_with_wallet_count(MAX_SPONSORED_BATCH_SIZE + 1);
        let options = base_options(path);

        assert!(matches!(
            load_sponsored_wallets(&options),
            Err(SponsoredSnipeError::TooManyWallets)
        ));
    }

    #[test]
    fn accepts_a_batch_at_exactly_the_executor_limit() {
        let path = manifest_with_wallet_count(MAX_SPONSORED_BATCH_SIZE);
        let options = base_options(path);

        assert_eq!(
            load_sponsored_wallets(&options)
                .expect("within limit")
                .len(),
            MAX_SPONSORED_BATCH_SIZE
        );
    }

    #[test]
    fn rejects_a_recipient_that_is_also_a_minting_wallet() {
        let path = manifest_with_wallet_count(1);
        let wallet_address = WalletSigner::from_private_key(&key_for(1))
            .expect("wallet signer")
            .identity()
            .address;
        let mut options = base_options(path);
        options.recipient = wallet_address;

        assert!(matches!(
            load_sponsored_wallets(&options),
            Err(SponsoredSnipeError::RecipientIsWallet)
        ));
    }

    #[test]
    fn selecting_wallet_indices_narrows_the_batch() {
        let path = manifest_with_wallet_count(3);
        let mut options = base_options(path);
        options.wallet_indices = Some(vec![1]);

        let wallets = load_sponsored_wallets(&options).expect("narrowed batch");
        assert_eq!(wallets.len(), 1);
        assert_eq!(
            wallets[0].0.identity().address,
            WalletSigner::from_private_key(&key_for(2))
                .expect("wallet 2 signer")
                .identity()
                .address
        );
    }
}
