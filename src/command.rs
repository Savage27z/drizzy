use std::{
    collections::{HashMap, HashSet},
    io::{self, Write},
    path::PathBuf,
    time::Duration,
};

use alloy_primitives::{Address, B256, Bytes, U256, keccak256};
use clap::{Parser, Subcommand};
use thiserror::Error;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use tokio::time::{Instant, sleep};
use zeroize::Zeroizing;

use crate::{
    bot::{self, BotError},
    chain::{
        AccountState, ChainError, ChainGateway, CodeHashCheck, FeeEstimate, ReceiptPollingPolicy,
        SubmissionInputs, TransactionReceipt,
    },
    config::{
        AppConfig, ChainConfig, ConfigError, DeploymentConfig, FeeMode, LoadedConfig,
        MultiWalletConfig, MultiWalletMode,
    },
    domain::{AutomaticFeePolicy, Eip1559Fees, ExecutionTiming, FeeError, PhaseWindow},
    executor_deployment::{
        DETERMINISTIC_FACTORY_ADDRESS, DETERMINISTIC_FACTORY_RUNTIME, ExecutorDeploymentError,
        audited_executor_creation_code, buffered_deployment_gas, deterministic_deployment_calldata,
        deterministic_executor_salt, maximum_deployment_cost, predicted_executor_address,
    },
    fee::{initial_transaction_fees, maximum_transaction_fees},
    funds::{self, NativeAmount, NativeFundsError},
    logging,
    multi_mint::{self, MultiMintError},
    multi_wallet::{
        FundingRequirement, MAX_SELF_FUNDED_WALLETS, WalletManifest, WalletManifestError,
    },
    opensea::{
        CAPTURE_REVISION, CollectionMetadata, EligibilitySnapshot, EligibleMinterRelation,
        MintTransactionAction, OpenSeaError, StageEligibility, StageMetadata, WalletOpenSeaClient,
        parse_collection_locator,
    },
    signing::{WalletSigner, WalletSignerError},
    snipe::{self, SnipeError},
    sponsored::{
        AUDITED_EXECUTOR_RUNTIME_HASH, DelegationState, SponsoredMintError, classify_delegation,
    },
    terminal::{self, ConfiguredPhase, ExecutorDeploymentConfirmation, PhaseOption, TerminalError},
    transaction::{
        Eip1559Transaction, SignedTransaction, TransactionError, sign_eip1559_transaction,
    },
    wallet_generator::{WalletGeneratorError, create_wallet_manifest},
};

const STANDARD_WAKE_LEAD_SECONDS: u64 = 10;
const CALLDATA_HOT_LEAD_MS: u64 = 2_000;

#[derive(Debug, Parser)]
#[command(
    name = "opensea-mint",
    bin_name = "opensea-mint",
    version,
    about = "OpenSea single-wallet and multi-wallet mint scheduler"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Validate the active wallet mode, RPC, and local protocol boundary.
    Doctor,
    /// Deploy and verify the deterministic per-sponsor executor on the configured RPC chain.
    DeployExecutor,
    /// Mint, fund, withdraw, or revoke using the configured wallet mode.
    Mint {
        /// Fund every manifest wallet with this native-token amount.
        #[arg(
            long,
            value_name = "NATIVE_AMOUNT",
            conflicts_with_all = ["withdraw", "undelegate"]
        )]
        fund: Option<NativeAmount>,
        /// Withdraw each manifest wallet's maximum safe native-token balance.
        #[arg(long, conflicts_with_all = ["fund", "undelegate"])]
        withdraw: bool,
        /// Revoke EIP-7702 delegation for every wallet in `WALLETS_FILE`.
        #[arg(long, conflicts_with_all = ["fund", "withdraw"])]
        undelegate: bool,
    },
    /// Authenticate manifest wallets and fetch validated mint calldata without signing.
    Calldata {
        /// `OpenSea` collection slug, collection URL, or NFT contract address.
        #[arg(long)]
        collection: String,
        /// Strict version-1 wallet manifest to inspect.
        #[arg(long, short)]
        wallets: PathBuf,
        /// Token ID used for the active stage; ERC-721 drops conventionally use zero.
        #[arg(long, default_value = "0")]
        token_id: String,
    },
    /// Create a strict JSON manifest containing new cryptographically random wallets.
    Wallets {
        #[command(subcommand)]
        command: WalletCommand,
    },
    /// Snipe a public `SeaDrop` stage with locally built calldata — no `OpenSea`
    /// API on the critical path. Signs every wallet before the stage opens and
    /// blasts pre-built transactions to every RPC in parallel.
    Snipe {
        /// `OpenSea` collection slug, collection URL, or NFT contract address.
        #[arg(long)]
        collection: String,
        /// Mint quantity per wallet (default: 1, or the manifest quantity with --wallets).
        #[arg(long)]
        quantity: Option<u64>,
        /// Private key for a minting wallet (repeatable).
        #[arg(long = "key", value_name = "PRIVATE_KEY")]
        keys: Vec<String>,
        /// Wallet manifest (wallets.json) to use instead of --key.
        #[arg(long, value_name = "FILE")]
        wallets: Option<PathBuf>,
        /// RPC endpoint to probe, read from, and blast to (repeatable).
        #[arg(long = "rpc", value_name = "URL")]
        rpc_urls: Vec<String>,
        /// Chain key when no --rpc is given: ethereum, base, or robinhood.
        #[arg(long, value_name = "CHAIN")]
        chain: Option<String>,
        /// Max fee per gas in gwei (default: automatic from the chain).
        #[arg(long, value_name = "GWEI")]
        max_fee_gwei: Option<String>,
        /// Max priority fee per gas in gwei (default: automatic from the chain).
        #[arg(long, value_name = "GWEI")]
        priority_fee_gwei: Option<String>,
        /// Gas limit per mint (default: 250000).
        #[arg(long, default_value_t = 250_000)]
        gas_limit: u64,
        /// Fire this many ms before the stage opens (mempool trick).
        #[arg(long, default_value_t = 0)]
        early_fire_ms: u64,
        /// Fire immediately even if the stage opens later.
        #[arg(long)]
        fire_now: bool,
    },
    /// Run the Telegram bot control surface (long-polling, owner-only).
    /// Requires `BOT_TOKEN` and `ALLOWED_CHAT_IDS` in .env.
    Bot,
}

#[derive(Debug, Subcommand)]
pub enum WalletCommand {
    /// Generate a new wallet manifest without connecting to `OpenSea` or an RPC.
    Create {
        /// Number of distinct wallets to generate.
        #[arg(long, default_value_t = 1)]
        count: usize,
        /// Mint quantity stored for every generated wallet.
        #[arg(long, default_value_t = 1)]
        quantity: u64,
        /// New output file; an existing path is never overwritten.
        #[arg(long, short, default_value = "wallets.json")]
        output: PathBuf,
    },
}

#[derive(Debug, Error)]
pub enum CommandError {
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error(transparent)]
    Signer(#[from] WalletSignerError),
    #[error(transparent)]
    WalletManifest(#[from] WalletManifestError),
    #[error(transparent)]
    SponsoredMint(#[from] SponsoredMintError),
    #[error(transparent)]
    Chain(#[from] ChainError),
    #[error(transparent)]
    OpenSea(#[from] OpenSeaError),
    #[error(transparent)]
    Fee(#[from] FeeError),
    #[error(transparent)]
    ExecutorDeployment(#[from] ExecutorDeploymentError),
    #[error(transparent)]
    Transaction(#[from] TransactionError),
    #[error(transparent)]
    Terminal(#[from] TerminalError),
    #[error(transparent)]
    MultiMint(#[from] MultiMintError),
    #[error(transparent)]
    WalletGenerator(#[from] WalletGeneratorError),
    #[error(transparent)]
    NativeFunds(#[from] NativeFundsError),
    #[error(transparent)]
    Snipe(#[from] SnipeError),
    #[error(transparent)]
    Bot(#[from] BotError),
    #[error("quantity and gas limit must both be greater than zero")]
    InvalidMintSelection,
    #[error("selected stage was not found")]
    StageNotFound,
    #[error("selected stage has an invalid or incompatible time window")]
    InvalidStageWindow,
    #[error("selected stage has ended")]
    StageEnded,
    #[error("collection or selected stage changed while the mint was waiting")]
    CollectionChanged,
    #[error("selected token ID is outside the stage or drop type")]
    InvalidTokenId,
    #[error("selected quantity exceeds the wallet eligibility limit")]
    QuantityExceedsEligibility,
    #[error(
        "more than one mint stage is active, so OpenSea's action cannot be bound to the selection"
    )]
    AmbiguousActiveStage,
    #[error(
        "transaction remained pending after every configured replacement attempt; inspect: {transaction_hashes}"
    )]
    PendingAfterRetries { transaction_hashes: String },
    #[error(
        "transaction broadcast outcome is uncertain for locally calculated hash {transaction_hash}; inspect it before retrying"
    )]
    BroadcastOutcomeUncertain { transaction_hash: B256 },
    #[error(
        "RPC receipt tracking failed after broadcast; inspect these hashes before retrying: {transaction_hashes}"
    )]
    ReceiptTrackingUncertain { transaction_hashes: String },
    #[error(
        "a same-nonce replacement could not be constructed; inspect the pending hashes: {transaction_hashes}"
    )]
    ReplacementUnavailable { transaction_hashes: String },
    #[error(
        "the phase ended while a transaction was pending, so no replacement was sent; inspect: {transaction_hashes}"
    )]
    PhaseEndedWithPendingTransaction { transaction_hashes: String },
    #[error("mint transaction reverted in block {0}")]
    TransactionReverted(u64),
    #[error("failed to write the transaction hash before submission: {0}")]
    SubmissionOutput(#[source] io::Error),
    #[error("the locally prepared first transaction is unavailable")]
    PreparedTransactionUnavailable,
    #[error("OpenSea calldata remained unavailable after {attempts} attempt(s): {last_error}")]
    CalldataRetriesExhausted { attempts: u32, last_error: String },
    #[error(
        "wallet balance is below the locally calculated maximum mint cost by {shortfall_wei} wei"
    )]
    WalletUnderfunded { shortfall_wei: U256 },
    #[error(
        "RPC chain {rpc_chain_id} did not pass the EIP-7702 liveness probe; sponsored minting is unavailable, so set SPONSORED=false and fund each manifest wallet for self-funded minting"
    )]
    Eip7702Unavailable { rpc_chain_id: u64 },
    #[error(
        "RPC chain {rpc_chain_id} lacks live EIP-1153 transient storage required by the sponsored executor"
    )]
    Eip1153Unavailable { rpc_chain_id: u64 },
    #[error("sponsored executor deployment does not match the compiled audited runtime hash")]
    SponsoredDeploymentMismatch,
    #[error("RPC chain {chain_id} does not contain the required canonical deterministic factory")]
    DeterministicFactoryUnavailable { chain_id: u64 },
    #[error("the canonical deterministic factory address contains unexpected code")]
    DeterministicFactoryMismatch,
    #[error(
        "the configured sponsor account code is neither empty nor an exact EIP-7702 delegation designator"
    )]
    DeploymentSignerHasInvalidCode,
    #[error("the deterministic executor address already has unexpected state")]
    DeploymentAddressOccupied,
    #[error(
        "the sponsor balance is below the maximum configured deployment cost of {required_wei} wei"
    )]
    DeploymentUnderfunded { required_wei: U256 },
    #[error("the sponsor delegation changed after confirmation; rerun deployment")]
    DeploymentSignerDelegationChanged,
    #[error("executor deployment reverted in block {0}")]
    DeploymentReverted(u64),
}

#[allow(clippy::too_many_lines)]
pub async fn execute(cli: Cli) -> Result<(), CommandError> {
    let command = match cli.command {
        Command::Wallets { command } => return create_wallets(command),
        Command::DeployExecutor => return deploy_executor().await,
        Command::Bot => return bot::run_bot().await.map_err(Into::into),
        Command::Snipe {
            collection,
            quantity,
            keys,
            wallets,
            rpc_urls,
            chain,
            max_fee_gwei,
            priority_fee_gwei,
            gas_limit,
            early_fire_ms,
            fire_now,
        } => {
            return snipe::run_snipe(snipe::SnipeOptions {
                collection,
                quantity,
                keys: keys.into_iter().map(Zeroizing::new).collect(),
                wallets_file: wallets,
                wallet_indices: None,
                rpc_urls,
                chain,
                max_fee_per_gas: max_fee_gwei.as_deref().map(snipe::parse_gwei).transpose()?,
                max_priority_fee_per_gas: priority_fee_gwei
                    .as_deref()
                    .map(snipe::parse_gwei)
                    .transpose()?,
                gas_limit,
                early_fire_ms,
                fire_now,
                notify: None,
            })
            .await
            .map_err(Into::into);
        }
        command => command,
    };
    let loaded = LoadedConfig::load()?;
    let config = loaded.app.clone();
    let command = match command {
        Command::Calldata {
            collection,
            wallets,
            token_id,
        } => {
            return multi_mint::inspect_calldata(&config, &wallets, &collection, &token_id)
                .await
                .map_err(Into::into);
        }
        command => command,
    };
    if let Some(multi_wallet) = loaded.multi_wallet() {
        return match command {
            Command::Doctor => {
                multi_wallet_doctor(&config, multi_wallet, &loaded, loaded.source_path()).await
            }
            Command::Mint {
                fund: Some(amount),
                withdraw: false,
                undelegate: false,
            } => funds::fund(&config, multi_wallet, loaded.sponsor_key(), amount)
                .await
                .map_err(Into::into),
            Command::Mint {
                fund: None,
                withdraw: true,
                undelegate: false,
            } => funds::withdraw(&config, multi_wallet)
                .await
                .map_err(Into::into),
            Command::Mint {
                fund: None,
                withdraw: false,
                undelegate: true,
            } => multi_mint::undelegate(&config, multi_wallet, loaded.sponsor_key())
                .await
                .map_err(Into::into),
            Command::Mint {
                fund: None,
                withdraw: false,
                undelegate: false,
            } => multi_mint::run(&config, multi_wallet, loaded.sponsor_key())
                .await
                .map_err(Into::into),
            Command::Mint { .. } => unreachable!("clap enforces exclusive mint operations"),
            Command::Wallets { .. }
            | Command::DeployExecutor
            | Command::Snipe { .. }
            | Command::Bot => unreachable!("handled before configuration loading"),
            Command::Calldata { .. } => unreachable!("handled before wallet mode routing"),
        };
    }
    if let Command::Mint {
        fund,
        withdraw,
        undelegate,
    } = &command
    {
        if fund.is_some() || *withdraw {
            return Err(NativeFundsError::MultiWalletRequired.into());
        }
        if *undelegate {
            return Err(MultiMintError::SingleWalletUndelegate.into());
        }
    }
    let signer = WalletSigner::from_private_key(
        loaded
            .wallet_key()
            .ok_or(ConfigError::MissingSetting("WALLET_KEY"))?,
    )?;
    match command {
        Command::Doctor => doctor(&config, &signer, loaded.source_path()).await,
        Command::Mint {
            fund: None,
            withdraw: false,
            undelegate: false,
        } => mint(&config, &signer).await,
        Command::Mint { .. } => unreachable!("handled above"),
        Command::Wallets { .. }
        | Command::DeployExecutor
        | Command::Snipe { .. }
        | Command::Bot => unreachable!("handled before configuration loading"),
        Command::Calldata { .. } => unreachable!("handled before wallet mode routing"),
    }
}

fn create_wallets(command: WalletCommand) -> Result<(), CommandError> {
    let WalletCommand::Create {
        count,
        quantity,
        output,
    } = command;
    let generated = create_wallet_manifest(&output, count, quantity)?;
    logging::success(format!(
        "Created {} wallet(s) with quantity {} in {}.",
        generated.addresses().len(),
        generated.quantity(),
        generated.path().display()
    ));
    for (index, address) in generated.addresses().iter().enumerate() {
        logging::info(format!("Wallet {}: {address}", index + 1));
    }
    logging::warn("This file contains private keys. Keep it private and never commit or share it.");
    Ok(())
}

struct ExecutorDeploymentPlan {
    config: AppConfig,
    gateway: ChainGateway,
    chain: ChainConfig,
    rpc_index: usize,
    deployer: WalletSigner,
    deployer_address: Address,
    deployer_delegation: Option<Address>,
    nonce: u64,
    salt: B256,
    predicted_address: Address,
    deployment_calldata: Bytes,
    estimated_gas: u64,
    gas_limit: u64,
    initial_fees: Eip1559Fees,
    maximum_fees: Eip1559Fees,
    prepared_maximum_cost: U256,
    expected_runtime_hash: B256,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ExecutorDeploymentSubmission {
    nonce: u64,
    fees: Eip1559Fees,
    maximum_cost: U256,
}

struct DeploymentNetwork {
    gateway: ChainGateway,
    chain: ChainConfig,
    rpc_index: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ExecutorCodeStatus {
    Missing,
    Verified,
    Mismatch,
}

async fn deploy_executor() -> Result<(), CommandError> {
    let loaded = DeploymentConfig::load()?;
    logging::success(format!(
        "Deployment config loaded: {}",
        loaded.source_path().display()
    ));
    let deployer = WalletSigner::from_private_key(loaded.deployer_key())?;
    let deployer_address = deployer.identity().address;
    let creation_code = audited_executor_creation_code()?;
    let predicted_address = predicted_executor_address(deployer_address);
    let network = load_deployment_network(&loaded.app).await?;
    require_deterministic_factory(&network).await?;
    require_eip7702_liveness(&network.gateway, &network.chain, network.rpc_index).await?;
    let status = inspect_executor_code(&network, predicted_address).await?;
    if status == ExecutorCodeStatus::Mismatch {
        return Err(CommandError::DeploymentAddressOccupied);
    }
    if loaded.configured_executor() != Some(predicted_address) {
        if let Some(configured) = loaded.configured_executor() {
            logging::warn(format!(
                "Configured executor {configured} is not the deterministic address for this sponsor and will not be reused on this chain."
            ));
        }
        logging::info(format!(
            "Use SPONSORED_EXECUTOR_ADDRESS={predicted_address} for this sponsor on every supported chain."
        ));
    }
    if status == ExecutorCodeStatus::Verified {
        logging::success(format!(
            "Deterministic executor is already deployed and verified: {predicted_address}. No transaction was sent."
        ));
        return Ok(());
    }
    logging::info(format!(
        "Deterministic executor {predicted_address} is not deployed on chain {}; preparing deployment.",
        network.chain.chain_id
    ));
    let plan =
        prepare_executor_deployment(&loaded, network, deployer, creation_code, predicted_address)
            .await?;
    if let Some(delegate) = plan.deployer_delegation {
        logging::warn(format!(
            "Sponsor is EIP-7702 delegated to {delegate}; deployment is allowed and will not revoke or change that delegation."
        ));
    }
    confirm_executor_deployment_plan(&plan)?;
    let submission = refresh_executor_deployment_plan(&plan).await?;
    if submission.nonce != plan.nonce || submission.maximum_cost != plan.prepared_maximum_cost {
        logging::info(format!(
            "Deployment transaction refreshed: nonce={}, maximum cost={} wei.",
            submission.nonce, submission.maximum_cost
        ));
    }
    let receipt = submit_executor_deployment(&plan, submission).await?;
    verify_executor_deployment(&plan, &receipt).await?;

    logging::success(format!(
        "Executor deployed and verified: {} in block {}.",
        plan.predicted_address, receipt.block_number
    ));
    logging::info(format!(
        "Set SPONSORED_EXECUTOR_ADDRESS={} in {}.",
        plan.predicted_address,
        loaded.source_path().display()
    ));
    Ok(())
}

async fn inspect_executor_code(
    network: &DeploymentNetwork,
    executor: Address,
) -> Result<ExecutorCodeStatus, CommandError> {
    let code = logging::animate(
        "Inspecting deterministic executor",
        network
            .gateway
            .account_code(&network.chain, network.rpc_index, executor, None),
    )
    .await?;
    Ok(classify_executor_code(&code, AUDITED_EXECUTOR_RUNTIME_HASH))
}

fn classify_executor_code(code: &[u8], expected_hash: B256) -> ExecutorCodeStatus {
    if code.is_empty() {
        ExecutorCodeStatus::Missing
    } else if keccak256(code) == expected_hash {
        ExecutorCodeStatus::Verified
    } else {
        ExecutorCodeStatus::Mismatch
    }
}

async fn prepare_executor_deployment(
    loaded: &DeploymentConfig,
    network: DeploymentNetwork,
    deployer: WalletSigner,
    creation_code: Bytes,
    predicted_address: Address,
) -> Result<ExecutorDeploymentPlan, CommandError> {
    let config = loaded.app.clone();
    let deployer_address = deployer.identity().address;
    let DeploymentNetwork {
        gateway,
        chain,
        rpc_index,
    } = network;
    let expected_runtime_hash = AUDITED_EXECUTOR_RUNTIME_HASH;
    let salt = deterministic_executor_salt(deployer_address);
    let deployment_calldata = deterministic_deployment_calldata(deployer_address, &creation_code);
    let snapshot = gateway
        .wallet_snapshot(&chain, rpc_index, deployer_address)
        .await?;
    let inputs = snapshot.submission_inputs;
    let account_state = snapshot.account_state;
    let deployer_delegation = deployment_signer_delegation(&account_state.code)?;
    ensure_deployment_address_clear(&gateway, &chain, rpc_index, predicted_address).await?;
    let estimated_gas = logging::animate(
        "Estimating deterministic executor deployment gas",
        gateway.estimate_transaction(
            &chain,
            rpc_index,
            deployer_address,
            DETERMINISTIC_FACTORY_ADDRESS,
            U256::ZERO,
            &deployment_calldata,
        ),
    )
    .await?;
    let gas_limit = buffered_deployment_gas(estimated_gas)?;
    let initial_fees = initial_transaction_fees(config.fees, inputs.fee_estimate)?;
    let maximum_fees =
        maximum_transaction_fees(config.fees, config.retry.max_attempts, initial_fees)?;
    let prepared_maximum_cost = maximum_deployment_cost(gas_limit, maximum_fees.max_fee_per_gas)?;
    ensure_deployment_funding(account_state.balance, prepared_maximum_cost)?;

    Ok(ExecutorDeploymentPlan {
        config,
        gateway,
        chain,
        rpc_index,
        deployer,
        deployer_address,
        deployer_delegation,
        nonce: inputs.pending_nonce,
        salt,
        predicted_address,
        deployment_calldata,
        estimated_gas,
        gas_limit,
        initial_fees,
        maximum_fees,
        prepared_maximum_cost,
        expected_runtime_hash,
    })
}

async fn require_deterministic_factory(network: &DeploymentNetwork) -> Result<(), CommandError> {
    let code = logging::animate(
        "Verifying canonical deterministic factory",
        network.gateway.account_code(
            &network.chain,
            network.rpc_index,
            DETERMINISTIC_FACTORY_ADDRESS,
            None,
        ),
    )
    .await?;
    if code.is_empty() {
        Err(CommandError::DeterministicFactoryUnavailable {
            chain_id: network.chain.chain_id,
        })
    } else if code.as_ref() != DETERMINISTIC_FACTORY_RUNTIME {
        Err(CommandError::DeterministicFactoryMismatch)
    } else {
        Ok(())
    }
}

async fn load_deployment_network(config: &AppConfig) -> Result<DeploymentNetwork, CommandError> {
    let gateway = ChainGateway::new(Duration::from_millis(config.opensea.request_timeout_ms))?;
    let probe = logging::animate(
        "Checking configured deployment network",
        gateway.probe_rpc(&config.rpc_url),
    )
    .await?;
    Ok(DeploymentNetwork {
        gateway,
        chain: derived_chain(config, probe.chain_id),
        rpc_index: probe.rpc_index,
    })
}

fn confirm_executor_deployment_plan(plan: &ExecutorDeploymentPlan) -> Result<(), CommandError> {
    terminal::confirm_executor_deployment(&ExecutorDeploymentConfirmation {
        chain_id: plan.chain.chain_id,
        deployer: plan.deployer_address,
        deployer_delegation: plan.deployer_delegation,
        deterministic_factory: DETERMINISTIC_FACTORY_ADDRESS,
        salt: plan.salt,
        predicted_executor: plan.predicted_address,
        estimated_gas: plan.estimated_gas,
        gas_limit: plan.gas_limit,
        initial_max_fee_per_gas: plan.initial_fees.max_fee_per_gas,
        final_max_fee_per_gas: plan.maximum_fees.max_fee_per_gas,
        maximum_cost: plan.prepared_maximum_cost,
        maximum_attempts: plan.config.retry.max_attempts,
    })?;
    Ok(())
}

async fn refresh_executor_deployment_plan(
    plan: &ExecutorDeploymentPlan,
) -> Result<ExecutorDeploymentSubmission, CommandError> {
    let snapshot = plan
        .gateway
        .wallet_snapshot(&plan.chain, plan.rpc_index, plan.deployer_address)
        .await?;
    let inputs = snapshot.submission_inputs;
    let account_state = snapshot.account_state;
    let deployer_delegation = deployment_signer_delegation(&account_state.code)?;
    if deployer_delegation != plan.deployer_delegation {
        return Err(CommandError::DeploymentSignerDelegationChanged);
    }
    require_deterministic_factory(&DeploymentNetwork {
        gateway: plan.gateway.clone(),
        chain: plan.chain.clone(),
        rpc_index: plan.rpc_index,
    })
    .await?;
    ensure_deployment_address_clear(
        &plan.gateway,
        &plan.chain,
        plan.rpc_index,
        plan.predicted_address,
    )
    .await?;
    deployment_submission_inputs(
        &plan.config,
        plan.gas_limit,
        inputs.pending_nonce,
        inputs.fee_estimate,
        account_state.balance,
    )
}

fn deployment_submission_inputs(
    config: &AppConfig,
    gas_limit: u64,
    nonce: u64,
    fee_estimate: FeeEstimate,
    balance: U256,
) -> Result<ExecutorDeploymentSubmission, CommandError> {
    let fees = initial_transaction_fees(config.fees, fee_estimate)?;
    let maximum_fees = maximum_transaction_fees(config.fees, config.retry.max_attempts, fees)?;
    let maximum_cost = maximum_deployment_cost(gas_limit, maximum_fees.max_fee_per_gas)?;
    ensure_deployment_funding(balance, maximum_cost)?;
    Ok(ExecutorDeploymentSubmission {
        nonce,
        fees,
        maximum_cost,
    })
}

async fn submit_executor_deployment(
    plan: &ExecutorDeploymentPlan,
    submission: ExecutorDeploymentSubmission,
) -> Result<TransactionReceipt, CommandError> {
    let mut fees = submission.fees;
    let replacement = AutomaticFeePolicy::new(10_000, plan.config.fees.replacement_bump_bps)?;
    let mut submitted = Vec::new();
    loop {
        let attempt = u32::try_from(submitted.len())
            .map_err(|_| ExecutorDeploymentError::CostOverflow)?
            .checked_add(1)
            .ok_or(ExecutorDeploymentError::CostOverflow)?;
        let transaction = Eip1559Transaction {
            chain_id: plan.chain.chain_id,
            nonce: submission.nonce,
            max_priority_fee_per_gas: fees.max_priority_fee_per_gas,
            max_fee_per_gas: fees.max_fee_per_gas,
            gas_limit: plan.gas_limit,
            target: DETERMINISTIC_FACTORY_ADDRESS,
            value: U256::ZERO,
            calldata: plan.deployment_calldata.clone(),
        };
        let signed_transaction = sign_eip1559_transaction(&transaction, &plan.deployer)?;
        let transaction_hash = broadcast_signed_transaction(
            &plan.gateway,
            &plan.chain,
            plan.rpc_index,
            &signed_transaction,
        )
        .await?;
        submitted.push((attempt, transaction_hash));
        logging::info(format!(
            "Deployment submitted: {transaction_hash} (attempt {attempt})."
        ));
        let receipt = logging::animate(
            format!("Waiting for deployment receipt: {transaction_hash}"),
            wait_for_submitted_receipt(
                &plan.gateway,
                &plan.chain,
                plan.rpc_index,
                &submitted,
                ReceiptPollingPolicy::from(plan.config.retry),
            ),
        )
        .await
        .map_err(|_| CommandError::ReceiptTrackingUncertain {
            transaction_hashes: format_transaction_hashes(&submitted),
        })?;
        if let Some((_, receipt)) = receipt {
            return Ok(receipt);
        }
        if attempt >= plan.config.retry.max_attempts {
            return Err(CommandError::PendingAfterRetries {
                transaction_hashes: format_transaction_hashes(&submitted),
            });
        }
        fees = replacement
            .replacement(fees)
            .map_err(|_| CommandError::ReplacementUnavailable {
                transaction_hashes: format_transaction_hashes(&submitted),
            })?;
    }
}

async fn verify_executor_deployment(
    plan: &ExecutorDeploymentPlan,
    receipt: &TransactionReceipt,
) -> Result<(), CommandError> {
    if !receipt.is_success {
        return Err(CommandError::DeploymentReverted(receipt.block_number));
    }
    let verified = logging::animate(
        "Verifying deployed executor runtime at the receipt block",
        plan.gateway.wait_for_account_code_hash(
            &plan.chain,
            plan.rpc_index,
            executor_code_hash_check(
                &plan.config,
                plan.predicted_address,
                Some(receipt.block_number),
                plan.expected_runtime_hash,
            ),
        ),
    )
    .await?;
    if !verified {
        return Err(CommandError::SponsoredDeploymentMismatch);
    }
    Ok(())
}

fn executor_code_hash_check(
    config: &AppConfig,
    account: Address,
    block_number: Option<u64>,
    expected_hash: B256,
) -> CodeHashCheck {
    CodeHashCheck {
        account,
        block_number,
        expected_hash,
        timeout_seconds: config.retry.pending_timeout_seconds,
        poll_interval_ms: config.retry.base_delay_ms,
        max_poll_interval_ms: config.retry.max_delay_ms,
    }
}

async fn ensure_deployment_address_clear(
    gateway: &ChainGateway,
    chain: &ChainConfig,
    rpc_index: usize,
    address: Address,
) -> Result<(), CommandError> {
    let state = gateway.account_state(chain, rpc_index, address).await?;
    if state.code.is_empty() && state.pending_nonce == 0 {
        Ok(())
    } else {
        Err(CommandError::DeploymentAddressOccupied)
    }
}

fn ensure_deployment_funding(balance: U256, required: U256) -> Result<(), CommandError> {
    if balance >= required {
        Ok(())
    } else {
        Err(CommandError::DeploymentUnderfunded {
            required_wei: required,
        })
    }
}

fn deployment_signer_delegation(code: &[u8]) -> Result<Option<Address>, CommandError> {
    match classify_delegation(code, Address::ZERO) {
        DelegationState::Clear => Ok(None),
        DelegationState::Expected => Ok(Some(Address::ZERO)),
        DelegationState::Unexpected(delegate) => Ok(Some(delegate)),
        DelegationState::OtherCode => Err(CommandError::DeploymentSignerHasInvalidCode),
    }
}

async fn multi_wallet_doctor(
    config: &AppConfig,
    multi_wallet: &MultiWalletConfig,
    loaded: &LoadedConfig,
    source_path: &std::path::Path,
) -> Result<(), CommandError> {
    let manifest = WalletManifest::load(&multi_wallet.manifest_path)?;
    logging::success(format!("Config loaded: {}", source_path.display()));
    logging::success(format!(
        "Wallet manifest loaded: {} distinct wallet(s).",
        manifest.len()
    ));
    multi_mint::validate_mode_wallet_limit(&multi_wallet.mode, manifest.len())?;
    let gateway = ChainGateway::new(Duration::from_millis(config.opensea.request_timeout_ms))?;
    let probe = logging::animate(
        "Checking RPC connection",
        gateway.probe_rpc(&config.rpc_url),
    )
    .await?;
    let chain = derived_chain(config, probe.chain_id);

    match &multi_wallet.mode {
        MultiWalletMode::SelfFunded => {
            logging::success(format!(
                "Self-funded mode ready for at most {MAX_SELF_FUNDED_WALLETS} wallets."
            ));
        }
        MultiWalletMode::Sponsored(sponsored) => {
            if manifest.len() > crate::sponsored::MAX_SPONSORED_BATCH_SIZE {
                return Err(SponsoredMintError::InvalidBatchSize.into());
            }
            require_eip7702_liveness(&gateway, &chain, probe.rpc_index).await?;
            let sponsor = WalletSigner::from_private_key(
                loaded
                    .sponsor_key()
                    .ok_or(ConfigError::MissingSetting("SPONSOR_KEY"))?,
            )?;
            let verified = logging::animate(
                "Verifying sponsored executor runtime",
                gateway.wait_for_account_code_hash(
                    &chain,
                    probe.rpc_index,
                    executor_code_hash_check(
                        config,
                        sponsored.executor,
                        None,
                        AUDITED_EXECUTOR_RUNTIME_HASH,
                    ),
                ),
            )
            .await?;
            if !verified {
                return Err(CommandError::SponsoredDeploymentMismatch);
            }
            let _ = gateway
                .submission_inputs(&chain, probe.rpc_index, sponsor.identity().address)
                .await?;
            logging::success(format!(
                "Sponsored deployment verified for {} wallet(s).",
                manifest.len()
            ));
            logging::success(format!(
                "Per-wallet gas ready: mint limit={}, derived execution envelope={}.",
                config.gas_limit, sponsored.wallet_gas_limit
            ));
        }
    }
    let _client = WalletOpenSeaClient::new(&config.opensea)?;
    logging::success(format!("OpenSea client ready: {CAPTURE_REVISION}"));
    Ok(())
}

async fn doctor(
    config: &AppConfig,
    signer: &WalletSigner,
    source_path: &std::path::Path,
) -> Result<(), CommandError> {
    logging::success(format!("Config loaded: {}", source_path.display()));
    logging::success("Wallet signer loaded.");
    let gateway = ChainGateway::new(Duration::from_millis(config.opensea.request_timeout_ms))?;
    let probe = logging::animate(
        "Checking RPC connection",
        gateway.probe_rpc(&config.rpc_url),
    )
    .await?;
    let chain = derived_chain(config, probe.chain_id);
    let _inputs = logging::animate(
        "Preparing RPC submission data",
        gateway.submission_inputs(&chain, probe.rpc_index, signer.identity().address),
    )
    .await?;
    logging::success(format!("RPC ready: chain_id={}", probe.chain_id));
    let _client = WalletOpenSeaClient::new(&config.opensea)?;
    logging::success(format!("OpenSea client ready: {CAPTURE_REVISION}"));
    Ok(())
}

async fn mint(config: &AppConfig, signer: &WalletSigner) -> Result<(), CommandError> {
    let locator_text = terminal::prompt_collection_locator()?;
    let locator = parse_collection_locator(&locator_text)?;
    logging::section_break();
    let gateway = ChainGateway::new(Duration::from_millis(config.opensea.request_timeout_ms))?;
    let probe = logging::animate("Connecting to RPC", gateway.probe_rpc(&config.rpc_url)).await?;
    let chain = derived_chain(config, probe.chain_id);
    logging::success(format!("RPC connected: chain_id={}", chain.chain_id));
    let mut client = WalletOpenSeaClient::new(&config.opensea)?;
    let metadata = logging::animate(
        "Resolving OpenSea collection",
        client.resolve_collection(&locator, chain.chain_id),
    )
    .await?;
    validate_stage_windows(&metadata)?;
    logging::success(format!("Collection resolved: {}", metadata.slug));
    logging::animate(
        "Authenticating wallet",
        client.authenticate(
            signer,
            signer.identity().address,
            chain.chain_id,
            &metadata.slug,
        ),
    )
    .await?;
    logging::success("Wallet authenticated.");
    let eligibility = logging::animate(
        "Fetching wallet eligibility",
        client.eligibility(&metadata.slug, signer.identity().address),
    )
    .await?;
    validate_snapshot_shape(&metadata, &eligibility)?;
    let private_phase_probes = probe_active_private_phases(
        config,
        &client,
        &metadata,
        &eligibility,
        unix_timestamp()?,
        signer.identity().address,
        chain.chain_id,
    )
    .await?;
    logging::success(format!(
        "Eligibility loaded: {} phase(s).",
        eligibility.stages.len()
    ));

    let options = build_phase_options(
        &metadata,
        &eligibility,
        &private_phase_probes,
        unix_timestamp()?,
    )?;
    let selected = terminal::select_phases(&options)?;
    let configured = terminal::configure_phases(&options, &selected)?;
    validate_configured_phases(&options, &configured)?;
    terminal::confirm_schedule(
        &options,
        &configured,
        config.gas_limit,
        fee_mode_label(config.fees.mode),
    )?;
    logging::section_break();

    let jobs = build_jobs(&metadata, &configured)?;
    run_schedule(
        config,
        &chain,
        &gateway,
        probe.rpc_index,
        &mut client,
        signer,
        metadata,
        eligibility,
        private_phase_probes,
        unix_timestamp()?,
        jobs,
    )
    .await
}

fn derived_chain(config: &AppConfig, chain_id: u64) -> ChainConfig {
    ChainConfig {
        chain_id,
        rpc_urls: vec![config.rpc_url.clone()],
    }
}

async fn require_eip7702_liveness(
    gateway: &ChainGateway,
    chain: &ChainConfig,
    rpc_index: usize,
) -> Result<(), CommandError> {
    let (eip7702_is_live, eip1153_is_live) = logging::animate(
        "Probing EIP-7702 delegation and EIP-1153 transient storage",
        async {
            tokio::join!(
                gateway.eip7702_is_live(chain, rpc_index),
                gateway.eip1153_is_live(chain, rpc_index)
            )
        },
    )
    .await;
    if !eip7702_is_live? {
        return Err(CommandError::Eip7702Unavailable {
            rpc_chain_id: chain.chain_id,
        });
    }
    if !eip1153_is_live? {
        return Err(CommandError::Eip1153Unavailable {
            rpc_chain_id: chain.chain_id,
        });
    }
    logging::success(format!(
        "RPC chain {} supports live EIP-7702 delegated execution and EIP-1153 transient storage.",
        chain.chain_id
    ));
    Ok(())
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
struct PhaseIdentity {
    stage_index: u32,
    stage_type: String,
    token_range: Option<(u64, u64)>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EligibilityEvidence {
    PublicSale,
    OpenSeaResponse,
    ActiveMintAction,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ActivePrivatePhaseProbe {
    Eligible,
    Ineligible,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WalletEligibility {
    Eligible(EligibilityEvidence),
    Ineligible,
    Unknown,
}

impl WalletEligibility {
    fn is_selectable(self) -> bool {
        !matches!(self, Self::Ineligible)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum PhaseJobState {
    Pending { phase: PhaseWindow },
    Suspended { reason: String },
    Completed,
    Failed { reason: String },
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PhaseJob {
    identity: PhaseIdentity,
    token_id: String,
    quantity: u64,
    state: PhaseJobState,
}

impl PhaseJob {
    fn is_finished(&self) -> bool {
        matches!(
            self.state,
            PhaseJobState::Completed | PhaseJobState::Failed { .. }
        )
    }
}

fn build_phase_options(
    metadata: &CollectionMetadata,
    eligibility: &EligibilitySnapshot,
    private_phase_probes: &HashMap<PhaseIdentity, ActivePrivatePhaseProbe>,
    block_timestamp: u64,
) -> Result<Vec<PhaseOption>, CommandError> {
    validate_snapshot_shape(metadata, eligibility)?;
    metadata
        .stages
        .iter()
        .map(|stage| {
            let stage_eligibility = matching_eligibility_stage(eligibility, stage)?;
            let phase = stage_window(stage)?;
            let timing = phase.execution_timing(block_timestamp);
            let max_quantity = available_quantity(stage, stage_eligibility, eligibility);
            let identity = phase_identity(stage);
            let assessment = assess_wallet_eligibility(
                stage_eligibility,
                private_phase_probes.get(&identity).copied(),
            );
            let is_selectable =
                assessment.is_selectable() && max_quantity > 0 && timing != ExecutionTiming::Ended;
            Ok(PhaseOption {
                stage_index: stage.stage_index,
                stage_type: stage.stage_type.clone(),
                starts_at: stage.start_time.clone().unwrap_or_else(|| "open".into()),
                ends_at: stage.end_time.clone().unwrap_or_else(|| "no end".into()),
                state: match timing {
                    ExecutionTiming::Immediate => "active".into(),
                    ExecutionTiming::ScheduledAt(_) => "upcoming".into(),
                    ExecutionTiming::Ended => "ended".into(),
                },
                eligibility: eligibility_label(stage_eligibility, assessment).into(),
                max_quantity,
                token_range: stage.token_range,
                is_selectable,
            })
        })
        .collect()
}

async fn probe_active_private_phases(
    config: &AppConfig,
    client: &WalletOpenSeaClient,
    metadata: &CollectionMetadata,
    eligibility: &EligibilitySnapshot,
    block_timestamp: u64,
    wallet: alloy_primitives::Address,
    chain_id: u64,
) -> Result<HashMap<PhaseIdentity, ActivePrivatePhaseProbe>, CommandError> {
    let mut probes = HashMap::new();
    for stage in &metadata.stages {
        let stage_eligibility = matching_eligibility_stage(eligibility, stage)?;
        if stage.stage_type == "PUBLIC_SALE"
            || stage_eligibility.is_eligible == Some(true)
            || available_quantity(stage, stage_eligibility, eligibility) == 0
            || stage_window(stage)?.execution_timing(block_timestamp) != ExecutionTiming::Immediate
        {
            continue;
        }

        let token_id = stage.token_range.map_or(0, |(from, _)| from).to_string();
        if !has_unique_active_stage_for_token(metadata, stage, &token_id, block_timestamp)? {
            logging::warn(format!(
                "Stage {} eligibility is ambiguous while another stage is active.",
                stage.stage_index
            ));
            continue;
        }

        logging::info(format!(
            "Verifying active private stage {} with a wallet-specific mint action.",
            stage.stage_index
        ));

        match probe_mint_action_with_retry(
            config, client, metadata, stage, wallet, &token_id, chain_id,
        )
        .await
        {
            Ok(()) => {
                probes.insert(phase_identity(stage), ActivePrivatePhaseProbe::Eligible);
            }
            Err(OpenSeaError::MintWalletIneligible | OpenSeaError::MintLimitExceeded) => {
                probes.insert(phase_identity(stage), ActivePrivatePhaseProbe::Ineligible);
            }
            Err(error) if should_retry_calldata(&error) => {
                logging::warn(format!(
                    "Stage {} eligibility remains unverified after {} attempt(s).",
                    stage.stage_index, config.opensea.max_attempts
                ));
            }
            Err(error) => return Err(error.into()),
        }
    }
    Ok(probes)
}

#[allow(clippy::too_many_arguments)]
async fn probe_mint_action_with_retry(
    config: &AppConfig,
    client: &WalletOpenSeaClient,
    metadata: &CollectionMetadata,
    stage: &StageMetadata,
    wallet: alloy_primitives::Address,
    token_id: &str,
    chain_id: u64,
) -> Result<(), OpenSeaError> {
    for attempt in 1..=config.opensea.max_attempts {
        match client
            .mint_transaction_action(metadata, stage, wallet, token_id, 1, chain_id)
            .await
        {
            Ok(_) => return Ok(()),
            Err(error)
                if should_retry_calldata(&error) && attempt < config.opensea.max_attempts =>
            {
                sleep(Duration::from_millis(config.opensea.retry_interval_ms)).await;
            }
            Err(error) => return Err(error),
        }
    }
    Err(OpenSeaError::MintActionRejected)
}

fn has_unique_active_stage_for_token(
    metadata: &CollectionMetadata,
    expected_stage: &StageMetadata,
    token_id: &str,
    block_timestamp: u64,
) -> Result<bool, CommandError> {
    let token_id = token_id
        .parse::<u64>()
        .map_err(|_| CommandError::InvalidTokenId)?;
    let mut active = Vec::new();
    for stage in &metadata.stages {
        if stage_supports_token(stage, token_id)
            && stage_window(stage)?.execution_timing(block_timestamp) == ExecutionTiming::Immediate
        {
            active.push(stage);
        }
    }
    let Some(only_stage) = active.first() else {
        return Ok(false);
    };
    Ok(active.len() == 1 && phase_identity(only_stage) == phase_identity(expected_stage))
}

fn validate_configured_phases(
    options: &[PhaseOption],
    configured: &[ConfiguredPhase],
) -> Result<(), CommandError> {
    let mut unique = HashSet::new();
    for selection in configured {
        let option = options
            .get(selection.option_index)
            .ok_or(CommandError::InvalidMintSelection)?;
        if !option.is_selectable
            || selection.quantity == 0
            || selection.quantity > option.max_quantity
            || !unique.insert(selection.option_index)
        {
            return Err(CommandError::InvalidMintSelection);
        }
        let token_id = selection
            .token_id
            .parse::<u64>()
            .map_err(|_| CommandError::InvalidTokenId)?;
        match option.token_range {
            Some((from, to)) if (from..=to).contains(&token_id) => {}
            None if token_id == 0 => {}
            _ => return Err(CommandError::InvalidTokenId),
        }
    }
    Ok(())
}

fn build_jobs(
    metadata: &CollectionMetadata,
    configured: &[ConfiguredPhase],
) -> Result<Vec<PhaseJob>, CommandError> {
    configured
        .iter()
        .map(|selection| {
            let stage = metadata
                .stages
                .get(selection.option_index)
                .ok_or(CommandError::StageNotFound)?;
            Ok(PhaseJob {
                identity: PhaseIdentity {
                    stage_index: stage.stage_index,
                    stage_type: stage.stage_type.clone(),
                    token_range: stage.token_range,
                },
                token_id: selection.token_id.clone(),
                quantity: selection.quantity,
                state: PhaseJobState::Pending {
                    phase: stage_window(stage)?,
                },
            })
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
async fn run_schedule(
    config: &AppConfig,
    chain: &ChainConfig,
    gateway: &ChainGateway,
    rpc_index: usize,
    client: &mut WalletOpenSeaClient,
    signer: &WalletSigner,
    mut metadata: CollectionMetadata,
    mut eligibility: EligibilitySnapshot,
    mut private_phase_probes: HashMap<PhaseIdentity, ActivePrivatePhaseProbe>,
    mut block_timestamp: u64,
    mut jobs: Vec<PhaseJob>,
) -> Result<(), CommandError> {
    refresh_job_states(
        &metadata,
        &eligibility,
        &private_phase_probes,
        block_timestamp,
        &mut jobs,
    )?;
    report_job_states(&jobs, block_timestamp);
    let mut next_refresh =
        Instant::now() + Duration::from_secs(config.scheduling.refresh_interval_seconds);

    loop {
        if jobs.iter().all(PhaseJob::is_finished) {
            logging::success("Mint session finished.");
            return Ok(());
        }

        if Instant::now() >= next_refresh {
            match refresh_schedule_snapshot(config, client, signer, chain, &metadata).await {
                Ok(snapshot) => {
                    metadata = snapshot.metadata;
                    eligibility = snapshot.eligibility;
                    private_phase_probes = snapshot.private_phase_probes;
                    block_timestamp = snapshot.block_timestamp;
                    refresh_job_states(
                        &metadata,
                        &eligibility,
                        &private_phase_probes,
                        block_timestamp,
                        &mut jobs,
                    )?;
                    logging::section_break();
                    report_job_states(&jobs, block_timestamp);
                    next_refresh = Instant::now()
                        + Duration::from_secs(config.scheduling.refresh_interval_seconds);
                }
                Err(error) if is_recoverable_refresh_error(&error) => {
                    logging::warn(format!("Schedule refresh deferred: {error}"));
                    next_refresh = Instant::now()
                        + Duration::from_secs(config.scheduling.refresh_interval_seconds.min(60));
                }
                Err(error) => return Err(error),
            }
            continue;
        }

        if let Some((job_index, is_scheduled)) = runnable_job(
            &jobs,
            block_timestamp,
            unix_timestamp()?,
            STANDARD_WAKE_LEAD_SECONDS,
        ) {
            logging::section_break();
            let outcome = execute_job(
                config,
                chain,
                gateway,
                rpc_index,
                client,
                signer,
                &metadata,
                &eligibility,
                &jobs[job_index],
                is_scheduled,
            )
            .await;
            if apply_job_outcome(&mut jobs[job_index], outcome)? {
                next_refresh = Instant::now();
            }
            continue;
        }

        block_timestamp = wait_for_schedule_progress(&jobs, next_refresh).await?;
    }
}

fn runnable_job(
    jobs: &[PhaseJob],
    block_timestamp: u64,
    wall_clock_timestamp: u64,
    preauthenticate_seconds: u64,
) -> Option<(usize, bool)> {
    active_job_index(jobs, block_timestamp)
        .map(|index| (index, false))
        .or_else(|| {
            next_scheduled_job(jobs).and_then(|(index, starts_at)| {
                let preparation_at = starts_at.saturating_sub(preauthenticate_seconds);
                (wall_clock_timestamp >= preparation_at).then_some((index, true))
            })
        })
}

async fn wait_for_schedule_progress(
    jobs: &[PhaseJob],
    next_refresh: Instant,
) -> Result<u64, CommandError> {
    let refresh_wait = next_refresh.saturating_duration_since(Instant::now());
    if let Some((_, starts_at)) = next_scheduled_job(jobs) {
        let preparation_at = starts_at.saturating_sub(STANDARD_WAKE_LEAD_SECONDS);
        let launch_wait = Duration::from_secs(preparation_at.saturating_sub(unix_timestamp()?));
        logging::countdown_until(starts_at, launch_wait.min(refresh_wait)).await;
    } else {
        sleep(refresh_wait).await;
    }
    unix_timestamp()
}

struct ScheduleSnapshot {
    metadata: CollectionMetadata,
    eligibility: EligibilitySnapshot,
    private_phase_probes: HashMap<PhaseIdentity, ActivePrivatePhaseProbe>,
    block_timestamp: u64,
}

async fn refresh_schedule_snapshot(
    config: &AppConfig,
    client: &mut WalletOpenSeaClient,
    signer: &WalletSigner,
    chain: &ChainConfig,
    original: &CollectionMetadata,
) -> Result<ScheduleSnapshot, CommandError> {
    let metadata_future = client.collection_metadata(&original.slug);
    let eligibility_future = client.eligibility(&original.slug, signer.identity().address);
    let (metadata, eligibility) = tokio::join!(metadata_future, eligibility_future);
    let metadata = metadata?;
    let eligibility = match eligibility {
        Ok(snapshot) => snapshot,
        Err(OpenSeaError::AuthenticationRequired | OpenSeaError::Http(401)) => {
            client
                .authenticate(
                    signer,
                    signer.identity().address,
                    chain.chain_id,
                    &original.slug,
                )
                .await?;
            client
                .eligibility(&original.slug, signer.identity().address)
                .await?
        }
        Err(error) => return Err(error.into()),
    };
    if metadata.address != original.address
        || metadata.drop_address != original.drop_address
        || metadata.drop_kind != original.drop_kind
        || metadata.network_id != chain.chain_id
    {
        return Err(CommandError::CollectionChanged);
    }
    validate_stage_windows(&metadata)?;
    validate_snapshot_shape(&metadata, &eligibility)?;
    let private_phase_probes = probe_active_private_phases(
        config,
        client,
        &metadata,
        &eligibility,
        unix_timestamp()?,
        signer.identity().address,
        chain.chain_id,
    )
    .await?;
    Ok(ScheduleSnapshot {
        metadata,
        eligibility,
        private_phase_probes,
        block_timestamp: unix_timestamp()?,
    })
}

fn refresh_job_states(
    metadata: &CollectionMetadata,
    eligibility: &EligibilitySnapshot,
    private_phase_probes: &HashMap<PhaseIdentity, ActivePrivatePhaseProbe>,
    block_timestamp: u64,
    jobs: &mut [PhaseJob],
) -> Result<(), CommandError> {
    validate_snapshot_shape(metadata, eligibility)?;
    for job in jobs.iter_mut().filter(|job| !job.is_finished()) {
        let Some(stage) = metadata.stages.iter().find(|stage| {
            stage.stage_index == job.identity.stage_index
                && stage.stage_type == job.identity.stage_type
                && stage.token_range == job.identity.token_range
        }) else {
            job.state = PhaseJobState::Suspended {
                reason: "phase is absent; monitoring for its return".into(),
            };
            continue;
        };
        let stage_eligibility = matching_eligibility_stage(eligibility, stage)?;
        let assessment = assess_wallet_eligibility(
            stage_eligibility,
            private_phase_probes.get(&phase_identity(stage)).copied(),
        );
        if let Some(reason) = eligibility_suspension_reason(assessment) {
            job.state = PhaseJobState::Suspended {
                reason: reason.into(),
            };
            continue;
        }
        if job.quantity > available_quantity(stage, stage_eligibility, eligibility) {
            job.state = PhaseJobState::Suspended {
                reason: "selected quantity is currently above the wallet limit".into(),
            };
            continue;
        }
        let phase = stage_window(stage)?;
        job.state = match phase.execution_timing(block_timestamp) {
            ExecutionTiming::Ended => PhaseJobState::Suspended {
                reason: "phase is currently ended; monitoring for a changed window".into(),
            },
            ExecutionTiming::Immediate | ExecutionTiming::ScheduledAt(_) => {
                PhaseJobState::Pending { phase }
            }
        };
    }
    Ok(())
}

fn active_job_index(jobs: &[PhaseJob], block_timestamp: u64) -> Option<usize> {
    jobs.iter().position(|job| {
        matches!(
            job.state,
            PhaseJobState::Pending { phase }
                if phase.execution_timing(block_timestamp) == ExecutionTiming::Immediate
        )
    })
}

fn next_scheduled_job(jobs: &[PhaseJob]) -> Option<(usize, u64)> {
    jobs.iter()
        .enumerate()
        .filter_map(|(index, job)| match job.state {
            PhaseJobState::Pending { phase } => Some((index, phase.starts_at())),
            _ => None,
        })
        .min_by_key(|(_, starts_at)| *starts_at)
}

fn report_job_states(jobs: &[PhaseJob], block_timestamp: u64) {
    logging::info("Phase status updated.");
    let stage_type_width = jobs
        .iter()
        .map(|job| job.identity.stage_type.len())
        .max()
        .unwrap_or_default();
    for job in jobs {
        println!(
            "    Stage {} | {:<stage_type_width$} | quantity={} | {}",
            job.identity.stage_index,
            job.identity.stage_type,
            job.quantity,
            phase_job_status(job, block_timestamp)
        );
    }
}

fn phase_job_status(job: &PhaseJob, block_timestamp: u64) -> String {
    match &job.state {
        PhaseJobState::Pending { phase } => match phase.execution_timing(block_timestamp) {
            ExecutionTiming::Immediate => "active".into(),
            ExecutionTiming::ScheduledAt(starts_at) => format!("scheduled at {starts_at}"),
            ExecutionTiming::Ended => "ended".into(),
        },
        PhaseJobState::Suspended { reason } => format!("suspended: {reason}"),
        PhaseJobState::Completed => "completed".into(),
        PhaseJobState::Failed { reason } => format!("failed: {reason}"),
    }
}

fn apply_job_outcome(
    job: &mut PhaseJob,
    outcome: Result<(), CommandError>,
) -> Result<bool, CommandError> {
    match outcome {
        Ok(()) => {
            job.state = PhaseJobState::Completed;
            Ok(true)
        }
        Err(error) if must_stop_session(&error) => Err(error),
        Err(CommandError::TransactionReverted(block)) => {
            job.state = PhaseJobState::Failed {
                reason: format!("transaction reverted in block {block}"),
            };
            Ok(false)
        }
        Err(error) => {
            let should_refresh_immediately = matches!(&error, CommandError::CollectionChanged);
            job.state = PhaseJobState::Suspended {
                reason: error.to_string(),
            };
            logging::warn(format!(
                "Stage {} suspended before broadcast: {error}",
                job.identity.stage_index
            ));
            Ok(should_refresh_immediately)
        }
    }
}

fn must_stop_session(error: &CommandError) -> bool {
    matches!(
        error,
        CommandError::BroadcastOutcomeUncertain { .. }
            | CommandError::ReceiptTrackingUncertain { .. }
            | CommandError::PendingAfterRetries { .. }
            | CommandError::ReplacementUnavailable { .. }
            | CommandError::PhaseEndedWithPendingTransaction { .. }
            | CommandError::OpenSea(
                OpenSeaError::Compatibility | OpenSeaError::UnsafeMintAction { .. }
            )
    )
}

fn is_recoverable_refresh_error(error: &CommandError) -> bool {
    matches!(
        error,
        CommandError::Chain(_)
            | CommandError::OpenSea(
                OpenSeaError::Transport
                    | OpenSeaError::RateLimited
                    | OpenSeaError::AuthenticationRequired
                    | OpenSeaError::Authentication(408 | 409 | 425 | 429 | 500..=599)
                    | OpenSeaError::Http(401 | 408 | 409 | 425 | 429 | 500..=599)
            )
    )
}

#[allow(clippy::too_many_arguments)]
async fn execute_job(
    config: &AppConfig,
    chain: &ChainConfig,
    gateway: &ChainGateway,
    rpc_index: usize,
    client: &mut WalletOpenSeaClient,
    signer: &WalletSigner,
    metadata: &CollectionMetadata,
    eligibility: &EligibilitySnapshot,
    job: &PhaseJob,
    is_scheduled: bool,
) -> Result<(), CommandError> {
    let stage = metadata
        .stages
        .iter()
        .find(|stage| {
            stage.stage_index == job.identity.stage_index
                && stage.stage_type == job.identity.stage_type
                && stage.token_range == job.identity.token_range
        })
        .ok_or(CommandError::StageNotFound)?;
    validate_mint_limits(metadata, stage, eligibility, job.quantity)?;
    let phase = stage_window(stage)?;
    execute_mint(MintExecutionContext {
        config,
        chain,
        gateway,
        rpc_index,
        client,
        signer,
        metadata,
        selected_stage: stage,
        phase,
        is_scheduled,
        token_id: &job.token_id,
        quantity: job.quantity,
        gas_limit: config.gas_limit,
    })
    .await
}

struct MintExecutionContext<'a> {
    config: &'a AppConfig,
    chain: &'a ChainConfig,
    gateway: &'a ChainGateway,
    rpc_index: usize,
    client: &'a mut WalletOpenSeaClient,
    signer: &'a WalletSigner,
    metadata: &'a CollectionMetadata,
    selected_stage: &'a StageMetadata,
    phase: PhaseWindow,
    is_scheduled: bool,
    token_id: &'a str,
    quantity: u64,
    gas_limit: u64,
}

struct SingleWalletLaunchSnapshot {
    metadata: CollectionMetadata,
    eligibility: EligibilitySnapshot,
    inputs: SubmissionInputs,
    account_state: AccountState,
    expected_mint_value: Option<U256>,
}

async fn execute_mint(mut context: MintExecutionContext<'_>) -> Result<(), CommandError> {
    let wallet = context.signer.identity().address;
    let snapshot = logging::animate(
        format!(
            "Preparing stage {} launch snapshot",
            context.selected_stage.stage_index
        ),
        prepare_single_wallet_launch(&mut context, wallet),
    )
    .await?;
    ensure_single_wallet_funding(
        context.config,
        context.gas_limit,
        snapshot.expected_mint_value.unwrap_or(U256::ZERO),
        snapshot.inputs.fee_estimate,
        snapshot.account_state.balance,
    )?;
    logging::success(format!(
        "Stage {} nonce, fees, balance, eligibility, and metadata captured outside the hot path.",
        context.selected_stage.stage_index
    ));
    logging::success("Wallet passed the local preflight value-plus-maximum-gas funding check.");
    validate_unambiguous_active_stage(
        &snapshot.metadata,
        &snapshot.eligibility,
        context.selected_stage.stage_index,
        context.token_id,
        context.quantity,
        context.phase.starts_at().max(unix_timestamp()?),
    )?;

    let hot_at_ms = schedule_deadline_millis(context.phase.starts_at(), CALLDATA_HOT_LEAD_MS)?;
    if context.is_scheduled {
        logging::animate(
            format!(
                "Waiting for stage {} calldata hot path",
                context.selected_stage.stage_index
            ),
            wait_until_unix_millis(hot_at_ms),
        )
        .await;
    }
    logging::info(format!(
        "Calldata hot path started for stage {}; only OpenSea calldata requests run before submission.",
        context.selected_stage.stage_index
    ));
    let action =
        request_single_wallet_action_hot(&context, wallet, snapshot.expected_mint_value).await?;
    ensure_single_wallet_funding(
        context.config,
        context.gas_limit,
        action.value,
        snapshot.inputs.fee_estimate,
        snapshot.account_state.balance,
    )?;
    logging::success("Wallet funding verified with the local value-plus-gas formula.");
    let submission_context = SubmissionContext {
        config: context.config,
        chain: context.chain,
        gateway: context.gateway,
        rpc_index: context.rpc_index,
        signer: context.signer,
        gas_limit: context.gas_limit,
        phase_ends_at: context.phase.ends_at(),
    };
    let mut prepared = prepare_mint_submission(&submission_context, action, snapshot.inputs)?;
    submit_replacements(&submission_context, &mut prepared, unix_timestamp()?).await
}

async fn request_single_wallet_action_hot(
    context: &MintExecutionContext<'_>,
    wallet: alloy_primitives::Address,
    expected_mint_value: Option<U256>,
) -> Result<MintTransactionAction, CommandError> {
    for attempt in 1..=context.config.opensea.calldata_max_attempts {
        if context
            .phase
            .ends_at()
            .is_some_and(|ends_at| unix_timestamp().is_ok_and(|now| now >= ends_at))
        {
            return Err(CommandError::StageEnded);
        }
        let action = context
            .client
            .mint_transaction_action(
                context.metadata,
                context.selected_stage,
                wallet,
                context.token_id,
                context.quantity,
                context.chain.chain_id,
            )
            .await
            .and_then(|action| {
                if expected_mint_value.is_some_and(|expected| action.value != expected) {
                    Err(OpenSeaError::UnsafeMintAction {
                        reason: "transaction value differs from the captured eligible price",
                    })
                } else {
                    Ok(action)
                }
            });
        match action {
            Ok(action) => return Ok(action),
            Err(error)
                if should_retry_hot_calldata(&error)
                    && attempt < context.config.opensea.calldata_max_attempts =>
            {
                logging::warn(format!(
                    "OpenSea calldata attempt {attempt}/{} is not ready ({error}); retrying in {} ms.",
                    context.config.opensea.calldata_max_attempts,
                    context.config.opensea.retry_interval_ms
                ));
                sleep(Duration::from_millis(
                    context.config.opensea.retry_interval_ms,
                ))
                .await;
            }
            Err(error) if should_retry_hot_calldata(&error) => {
                return Err(CommandError::CalldataRetriesExhausted {
                    attempts: context.config.opensea.calldata_max_attempts,
                    last_error: error.to_string(),
                });
            }
            Err(error) => return Err(error.into()),
        }
    }
    unreachable!("bounded calldata retry loop always returns")
}

async fn prepare_single_wallet_launch(
    context: &mut MintExecutionContext<'_>,
    wallet: alloy_primitives::Address,
) -> Result<SingleWalletLaunchSnapshot, CommandError> {
    context
        .client
        .authenticate(
            context.signer,
            wallet,
            context.chain.chain_id,
            &context.metadata.slug,
        )
        .await?;
    let metadata_future = context.client.collection_metadata(&context.metadata.slug);
    let eligibility_future = context.client.eligibility(&context.metadata.slug, wallet);
    let wallet_snapshot_future =
        context
            .gateway
            .wallet_snapshot(context.chain, context.rpc_index, wallet);
    let (metadata, eligibility, wallet_snapshot) =
        tokio::join!(metadata_future, eligibility_future, wallet_snapshot_future);
    let metadata = metadata?;
    let eligibility = eligibility?;
    let wallet_snapshot = wallet_snapshot?;
    let inputs = wallet_snapshot.submission_inputs;
    let account_state = wallet_snapshot.account_state;
    let selected_stage = find_selected_stage(
        &metadata,
        context.selected_stage.stage_index,
        context.token_id,
    )?;
    if !has_unchanged_collection(
        context.metadata,
        &metadata,
        context.selected_stage,
        selected_stage,
    ) {
        return Err(CommandError::CollectionChanged);
    }
    validate_mint_limits(&metadata, selected_stage, &eligibility, context.quantity)?;
    let expected_mint_value = matching_eligibility_stage(&eligibility, selected_stage)?
        .eligible_native_price_wei
        .map(|price| {
            price
                .checked_mul(U256::from(context.quantity))
                .ok_or(CommandError::InvalidMintSelection)
        })
        .transpose()?;

    Ok(SingleWalletLaunchSnapshot {
        metadata,
        eligibility,
        inputs,
        account_state,
        expected_mint_value,
    })
}

fn ensure_single_wallet_funding(
    config: &AppConfig,
    gas_limit: u64,
    mint_value: U256,
    estimate: FeeEstimate,
    balance: U256,
) -> Result<(), CommandError> {
    let initial_fees = initial_transaction_fees(config.fees, estimate)?;
    let maximum_fees =
        maximum_transaction_fees(config.fees, config.retry.max_attempts, initial_fees)?;
    let requirement = FundingRequirement {
        mint_value,
        gas_limit,
        max_fee_per_gas: maximum_fees.max_fee_per_gas,
    };
    let shortfall = requirement.shortfall(balance)?;
    if shortfall == U256::ZERO {
        Ok(())
    } else {
        Err(CommandError::WalletUnderfunded {
            shortfall_wei: shortfall,
        })
    }
}

fn schedule_deadline_millis(starts_at: u64, lead_ms: u64) -> Result<u64, CommandError> {
    starts_at
        .checked_mul(1_000)
        .map(|starts_at_ms| starts_at_ms.saturating_sub(lead_ms))
        .ok_or(CommandError::InvalidStageWindow)
}

fn millis_until_deadline(target_ms: u64, now_ms: i128) -> u64 {
    let remaining = i128::from(target_ms).saturating_sub(now_ms);
    u64::try_from(remaining).unwrap_or(if remaining.is_positive() { u64::MAX } else { 0 })
}

async fn wait_until_unix_millis(target_ms: u64) {
    const MAX_SLEEP_SLICE_MS: u64 = 30_000;
    loop {
        let now_ms = OffsetDateTime::now_utc()
            .unix_timestamp_nanos()
            .div_euclid(1_000_000);
        let remaining_ms = millis_until_deadline(target_ms, now_ms);
        if remaining_ms == 0 {
            return;
        }
        sleep(Duration::from_millis(remaining_ms.min(MAX_SLEEP_SLICE_MS))).await;
    }
}

fn should_retry_calldata(error: &OpenSeaError) -> bool {
    matches!(
        error,
        OpenSeaError::Transport
            | OpenSeaError::RateLimited
            | OpenSeaError::Compatibility
            | OpenSeaError::AuthenticationRequired
            | OpenSeaError::MintStageNotOpen
            | OpenSeaError::MintActionRejected
            | OpenSeaError::InvalidProtocolValue
            | OpenSeaError::UnsafeMintAction { .. }
            | OpenSeaError::Http(408 | 409 | 425 | 429 | 500..=599)
    )
}

fn should_retry_hot_calldata(error: &OpenSeaError) -> bool {
    matches!(
        error,
        OpenSeaError::Transport
            | OpenSeaError::RateLimited
            | OpenSeaError::Compatibility
            | OpenSeaError::MintStageNotOpen
            | OpenSeaError::MintActionRejected
            | OpenSeaError::InvalidProtocolValue
            | OpenSeaError::UnsafeMintAction { .. }
            | OpenSeaError::Http(408 | 409 | 425 | 429 | 500..=599)
    )
}

fn has_unchanged_collection(
    original: &CollectionMetadata,
    refreshed: &CollectionMetadata,
    original_stage: &StageMetadata,
    refreshed_stage: &StageMetadata,
) -> bool {
    original.address == refreshed.address
        && original.drop_address == refreshed.drop_address
        && original.network_id == refreshed.network_id
        && original.drop_kind == refreshed.drop_kind
        && original_stage == refreshed_stage
}

struct SubmissionContext<'a> {
    config: &'a AppConfig,
    chain: &'a ChainConfig,
    gateway: &'a ChainGateway,
    rpc_index: usize,
    signer: &'a WalletSigner,
    gas_limit: u64,
    phase_ends_at: Option<u64>,
}

struct PreparedMintSubmission {
    action: MintTransactionAction,
    nonce: u64,
    replacement_policy: AutomaticFeePolicy,
    fees: Eip1559Fees,
    first_signed: Option<SignedTransaction>,
}

fn prepare_mint_submission(
    context: &SubmissionContext<'_>,
    action: MintTransactionAction,
    inputs: SubmissionInputs,
) -> Result<PreparedMintSubmission, CommandError> {
    let replacement_policy =
        AutomaticFeePolicy::new(10_000, context.config.fees.replacement_bump_bps)?;
    let fees = initial_transaction_fees(context.config.fees, inputs.fee_estimate)?;
    let first_signed = sign_mint_transaction(context, &action, inputs.pending_nonce, fees)?;
    Ok(PreparedMintSubmission {
        action,
        nonce: inputs.pending_nonce,
        replacement_policy,
        fees,
        first_signed: Some(first_signed),
    })
}

async fn submit_replacements(
    context: &SubmissionContext<'_>,
    prepared: &mut PreparedMintSubmission,
    confirmed_open_timestamp: u64,
) -> Result<(), CommandError> {
    let mut submitted = Vec::new();
    for attempt_number in 1..=context.config.retry.max_attempts {
        let block_timestamp = if attempt_number == 1 {
            confirmed_open_timestamp
        } else {
            match context
                .gateway
                .latest_block(context.chain, context.rpc_index)
                .await
            {
                Ok(latest) => latest.timestamp,
                Err(_) => {
                    return Err(CommandError::ReceiptTrackingUncertain {
                        transaction_hashes: format_transaction_hashes(&submitted),
                    });
                }
            }
        };
        if context
            .phase_ends_at
            .is_some_and(|end| block_timestamp >= end)
        {
            if submitted.is_empty() {
                return Err(CommandError::StageEnded);
            }
            return Err(CommandError::PhaseEndedWithPendingTransaction {
                transaction_hashes: format_transaction_hashes(&submitted),
            });
        }
        let signed_transaction = if attempt_number == 1 {
            prepared
                .first_signed
                .take()
                .ok_or(CommandError::PreparedTransactionUnavailable)?
        } else {
            sign_mint_transaction(context, &prepared.action, prepared.nonce, prepared.fees)?
        };
        let transaction_hash = broadcast_signed_attempt(context, &signed_transaction).await?;
        submitted.push((attempt_number, transaction_hash));
        logging::info(format!(
            "Transaction submitted: {transaction_hash} (attempt {attempt_number})."
        ));

        let Ok(receipt) = logging::animate(
            format!("Waiting for transaction receipt: {transaction_hash}"),
            wait_for_submitted_receipt(
                context.gateway,
                context.chain,
                context.rpc_index,
                &submitted,
                ReceiptPollingPolicy::from(context.config.retry),
            ),
        )
        .await
        else {
            return Err(CommandError::ReceiptTrackingUncertain {
                transaction_hashes: format_transaction_hashes(&submitted),
            });
        };
        if let Some((_, receipt)) = receipt {
            return finalize_mined_receipt(&receipt);
        }
        if attempt_number < context.config.retry.max_attempts {
            prepared.fees = prepared
                .replacement_policy
                .replacement(prepared.fees)
                .map_err(|_| CommandError::ReplacementUnavailable {
                    transaction_hashes: format_transaction_hashes(&submitted),
                })?;
        }
    }
    Err(CommandError::PendingAfterRetries {
        transaction_hashes: format_transaction_hashes(&submitted),
    })
}

fn sign_mint_transaction(
    context: &SubmissionContext<'_>,
    action: &MintTransactionAction,
    nonce: u64,
    fees: Eip1559Fees,
) -> Result<SignedTransaction, CommandError> {
    if action.network_id != context.chain.chain_id {
        return Err(OpenSeaError::UnsafeMintAction {
            reason: "transaction network ID changed before signing",
        }
        .into());
    }
    let transaction = Eip1559Transaction {
        chain_id: context.chain.chain_id,
        nonce,
        max_priority_fee_per_gas: fees.max_priority_fee_per_gas,
        max_fee_per_gas: fees.max_fee_per_gas,
        gas_limit: context.gas_limit,
        target: action.target,
        value: action.value,
        calldata: action.calldata.clone(),
    };
    sign_eip1559_transaction(&transaction, context.signer).map_err(Into::into)
}

async fn broadcast_signed_attempt(
    context: &SubmissionContext<'_>,
    signed_transaction: &SignedTransaction,
) -> Result<B256, CommandError> {
    broadcast_signed_transaction(
        context.gateway,
        context.chain,
        context.rpc_index,
        signed_transaction,
    )
    .await
}

async fn broadcast_signed_transaction(
    gateway: &ChainGateway,
    chain: &ChainConfig,
    rpc_index: usize,
    signed_transaction: &SignedTransaction,
) -> Result<B256, CommandError> {
    let local_hash = signed_transaction.hash();
    logging::info(format!("Submitting transaction: {local_hash}"));
    io::stdout()
        .flush()
        .map_err(CommandError::SubmissionOutput)?;
    let transaction_hash = gateway
        .send_raw_transaction(chain, rpc_index, signed_transaction)
        .await
        .map_err(|_| CommandError::BroadcastOutcomeUncertain {
            transaction_hash: local_hash,
        })?;
    if transaction_hash != local_hash {
        return Err(CommandError::BroadcastOutcomeUncertain {
            transaction_hash: local_hash,
        });
    }
    Ok(transaction_hash)
}

fn format_transaction_hashes(submitted: &[(u32, B256)]) -> String {
    submitted
        .iter()
        .map(|(_, hash)| hash.to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

fn finalize_mined_receipt(receipt: &TransactionReceipt) -> Result<(), CommandError> {
    if receipt.is_success {
        logging::success(format!(
            "Mint confirmed: {} in block {}.",
            receipt.transaction_hash, receipt.block_number
        ));
        return Ok(());
    }
    Err(CommandError::TransactionReverted(receipt.block_number))
}

async fn wait_for_submitted_receipt(
    gateway: &ChainGateway,
    chain: &ChainConfig,
    rpc_index: usize,
    submitted: &[(u32, B256)],
    policy: ReceiptPollingPolicy,
) -> Result<Option<(u32, TransactionReceipt)>, ChainError> {
    let hashes = submitted.iter().map(|(_, hash)| *hash).collect::<Vec<_>>();
    gateway
        .wait_for_any_transaction_receipt(chain, rpc_index, &hashes, policy)
        .await
        .map(|receipt| {
            receipt.map(|(index, receipt)| {
                let (attempt, _) = submitted[index];
                (attempt, receipt)
            })
        })
}

fn find_selected_stage<'a>(
    metadata: &'a CollectionMetadata,
    stage_index: u32,
    token_id: &str,
) -> Result<&'a StageMetadata, CommandError> {
    let token_id = token_id
        .parse::<u64>()
        .map_err(|_| CommandError::InvalidTokenId)?;
    let mut matches = metadata.stages.iter().filter(|stage| {
        if stage.stage_index != stage_index {
            return false;
        }
        match metadata.drop_kind.as_str() {
            "Erc721SeaDropV1" => token_id == 0 && stage.token_range.is_none(),
            "Erc1155SeaDropV2" => stage
                .token_range
                .is_some_and(|(from, to)| (from..=to).contains(&token_id)),
            _ => false,
        }
    });
    let stage = matches.next().ok_or(CommandError::InvalidTokenId)?;
    if matches.next().is_some() {
        return Err(CommandError::InvalidTokenId);
    }
    Ok(stage)
}

fn validate_stage_windows(metadata: &CollectionMetadata) -> Result<(), CommandError> {
    for stage in &metadata.stages {
        stage_window(stage)?;
    }
    Ok(())
}

fn stage_window(stage: &StageMetadata) -> Result<PhaseWindow, CommandError> {
    let starts_at = stage
        .start_time
        .as_deref()
        .map(parse_protocol_time)
        .transpose()?
        .unwrap_or(0);
    let ends_at = stage
        .end_time
        .as_deref()
        .map(parse_protocol_time)
        .transpose()?;
    PhaseWindow::new(starts_at, ends_at).map_err(|_| CommandError::InvalidStageWindow)
}

fn parse_protocol_time(value: &str) -> Result<u64, CommandError> {
    let timestamp = OffsetDateTime::parse(value, &Rfc3339)
        .map_err(|_| CommandError::InvalidStageWindow)?
        .unix_timestamp();
    u64::try_from(timestamp).map_err(|_| CommandError::InvalidStageWindow)
}

fn unix_timestamp() -> Result<u64, CommandError> {
    u64::try_from(OffsetDateTime::now_utc().unix_timestamp())
        .map_err(|_| CommandError::InvalidStageWindow)
}

fn validate_snapshot_shape(
    metadata: &CollectionMetadata,
    eligibility: &EligibilitySnapshot,
) -> Result<(), CommandError> {
    if eligibility.drop_kind != metadata.drop_kind
        || eligibility.stages.len() != metadata.stages.len()
    {
        return Err(CommandError::CollectionChanged);
    }
    for metadata_stage in &metadata.stages {
        let stage = matching_eligibility_stage(eligibility, metadata_stage)?;
        if !has_matching_stage_identity(metadata_stage, stage) {
            return Err(CommandError::CollectionChanged);
        }
        if stage.eligible_native_price_wei.is_some()
            != stage.eligible_price_chain_identifier.is_some()
        {
            return Err(CommandError::CollectionChanged);
        }
    }
    Ok(())
}

fn matching_eligibility_stage<'a>(
    eligibility: &'a EligibilitySnapshot,
    metadata_stage: &StageMetadata,
) -> Result<&'a StageEligibility, CommandError> {
    let mut matching = eligibility.stages.iter().filter(|stage| {
        stage.stage_index == metadata_stage.stage_index
            && stage.token_range == metadata_stage.token_range
    });
    let stage = matching.next().ok_or(CommandError::StageNotFound)?;
    if matching.next().is_some() {
        return Err(CommandError::CollectionChanged);
    }
    Ok(stage)
}

fn phase_identity(stage: &StageMetadata) -> PhaseIdentity {
    PhaseIdentity {
        stage_index: stage.stage_index,
        stage_type: stage.stage_type.clone(),
        token_range: stage.token_range,
    }
}

fn assess_wallet_eligibility(
    stage: &StageEligibility,
    active_probe: Option<ActivePrivatePhaseProbe>,
) -> WalletEligibility {
    if stage.stage_type == "PUBLIC_SALE" {
        return WalletEligibility::Eligible(EligibilityEvidence::PublicSale);
    }
    match active_probe {
        Some(ActivePrivatePhaseProbe::Eligible) => {
            return WalletEligibility::Eligible(EligibilityEvidence::ActiveMintAction);
        }
        Some(ActivePrivatePhaseProbe::Ineligible) => return WalletEligibility::Ineligible,
        None => {}
    }
    match stage.is_eligible {
        Some(true) => WalletEligibility::Eligible(EligibilityEvidence::OpenSeaResponse),
        Some(false) => WalletEligibility::Ineligible,
        None => WalletEligibility::Unknown,
    }
}

fn eligibility_label(stage: &StageEligibility, assessment: WalletEligibility) -> &'static str {
    match assessment {
        WalletEligibility::Eligible(EligibilityEvidence::PublicSale) => "eligible (public)",
        WalletEligibility::Eligible(EligibilityEvidence::ActiveMintAction) => {
            "eligible (verified mint action)"
        }
        WalletEligibility::Eligible(EligibilityEvidence::OpenSeaResponse)
            if stage.eligible_minter_relation == Some(EligibleMinterRelation::LinkedWallet) =>
        {
            "eligible via linked wallet"
        }
        WalletEligibility::Eligible(EligibilityEvidence::OpenSeaResponse) => "eligible",
        WalletEligibility::Ineligible => "ineligible",
        WalletEligibility::Unknown => "no pre-launch verdict from OpenSea",
    }
}

fn eligibility_suspension_reason(assessment: WalletEligibility) -> Option<&'static str> {
    match assessment {
        WalletEligibility::Ineligible => {
            Some("wallet is currently ineligible; monitoring for eligibility")
        }
        WalletEligibility::Eligible(_) | WalletEligibility::Unknown => None,
    }
}

fn available_quantity(
    stage: &StageMetadata,
    eligibility_stage: &StageEligibility,
    eligibility: &EligibilitySnapshot,
) -> u64 {
    let total_cap = eligibility_stage
        .eligible_max_total_mintable_by_wallet
        .or(eligibility_stage.max_total_mintable_by_wallet)
        .or(stage.max_total_mintable_by_wallet)
        .unwrap_or(u64::MAX);
    let minted_by_cap_owner = if eligibility_stage.eligible_minter_relation
        == Some(EligibleMinterRelation::LinkedWallet)
    {
        0
    } else {
        eligibility.minter_quantity_minted.unwrap_or(0)
    };
    let remaining_total = total_cap.saturating_sub(minted_by_cap_owner);
    let per_token_cap = eligibility_stage
        .eligible_max_total_mintable_by_wallet_per_token
        .or(eligibility_stage.eligible_max_total_mintable_by_wallet)
        .or(eligibility_stage.max_total_mintable_by_wallet_per_token)
        .or(stage.max_total_mintable_by_wallet_per_token)
        .unwrap_or(u64::MAX);
    remaining_total.min(per_token_cap)
}

fn validate_mint_limits(
    metadata: &CollectionMetadata,
    selected_stage: &StageMetadata,
    eligibility: &EligibilitySnapshot,
    quantity: u64,
) -> Result<(), CommandError> {
    validate_snapshot_shape(metadata, eligibility)?;
    let stage = matching_eligibility_stage(eligibility, selected_stage)?;
    if quantity == 0 || quantity > available_quantity(selected_stage, stage, eligibility) {
        return Err(CommandError::QuantityExceedsEligibility);
    }
    Ok(())
}

fn has_matching_stage_identity(metadata: &StageMetadata, eligibility: &StageEligibility) -> bool {
    eligibility.stage_type == metadata.stage_type
        && eligibility.kind == metadata.kind
        && eligibility.token_range == metadata.token_range
        && eligibility.max_total_mintable_by_wallet == metadata.max_total_mintable_by_wallet
        && eligibility.max_total_mintable_by_wallet_per_token
            == metadata.max_total_mintable_by_wallet_per_token
}

fn stage_supports_token(stage: &StageMetadata, token_id: u64) -> bool {
    match stage.token_range {
        Some((from, to)) => (from..=to).contains(&token_id),
        None => token_id == 0,
    }
}

fn validate_unambiguous_active_stage(
    metadata: &CollectionMetadata,
    eligibility: &EligibilitySnapshot,
    selected_stage_index: u32,
    token_id: &str,
    quantity: u64,
    block_timestamp: u64,
) -> Result<(), CommandError> {
    let token_id = token_id
        .parse::<u64>()
        .map_err(|_| CommandError::InvalidTokenId)?;
    let mut active_stage_indices = HashSet::new();
    for stage in &metadata.stages {
        let supports_token = stage_supports_token(stage, token_id);
        let stage_eligibility = matching_eligibility_stage(eligibility, stage)?;
        if supports_token
            && quantity <= available_quantity(stage, stage_eligibility, eligibility)
            && stage_window(stage)?.execution_timing(block_timestamp) == ExecutionTiming::Immediate
        {
            active_stage_indices.insert(stage.stage_index);
        }
    }
    if active_stage_indices.is_empty() {
        return Err(CommandError::StageEnded);
    }
    if active_stage_indices.len() != 1 || !active_stage_indices.contains(&selected_stage_index) {
        return Err(CommandError::AmbiguousActiveStage);
    }
    Ok(())
}

fn fee_mode_label(mode: FeeMode) -> &'static str {
    match mode {
        FeeMode::Automatic => "automatic EIP-1559",
        FeeMode::Manual { .. } => "manual EIP-1559 from .env",
    }
}

#[cfg(test)]
mod tests {
    use alloy_primitives::U256;

    use super::*;

    #[test]
    fn deployment_accepts_only_clear_or_exact_eip7702_sender_code() {
        let delegate = Address::repeat_byte(0x11);
        assert_eq!(deployment_signer_delegation(&[]).expect("clear"), None);
        assert_eq!(
            deployment_signer_delegation(&crate::sponsored::delegation_designator(delegate))
                .expect("delegated"),
            Some(delegate)
        );
        assert!(deployment_signer_delegation(&[0xef, 0x01, 0x00]).is_err());
        assert!(deployment_signer_delegation(&[0x60, 0x00]).is_err());
    }

    #[test]
    fn deterministic_executor_deploys_when_missing_and_fails_closed_on_collision() {
        let runtime = [0x60, 0x00, 0x60, 0x00];
        let expected_hash = keccak256(runtime);

        assert_eq!(
            classify_executor_code(&[], expected_hash),
            ExecutorCodeStatus::Missing
        );
        assert_eq!(
            classify_executor_code(&runtime, expected_hash),
            ExecutorCodeStatus::Verified
        );
        assert_eq!(
            classify_executor_code(&[0x60, 0x01], expected_hash),
            ExecutorCodeStatus::Mismatch
        );
    }

    #[test]
    fn deployment_submission_refresh_accepts_a_new_nonce_and_higher_fees() {
        let mut config = test_config(FeeMode::Automatic);
        config.retry.max_attempts = 3;
        let prepared = deployment_submission_inputs(
            &config,
            100_000,
            7,
            FeeEstimate {
                max_fee_per_gas: U256::from(10_u8),
                max_priority_fee_per_gas: U256::from(2_u8),
            },
            U256::MAX,
        )
        .expect("prepared submission");
        let refreshed = deployment_submission_inputs(
            &config,
            100_000,
            8,
            FeeEstimate {
                max_fee_per_gas: U256::from(20_u8),
                max_priority_fee_per_gas: U256::from(4_u8),
            },
            U256::MAX,
        )
        .expect("refreshed submission");

        assert_eq!(refreshed.nonce, 8);
        assert!(refreshed.fees.max_fee_per_gas > prepared.fees.max_fee_per_gas);
        assert!(refreshed.maximum_cost > prepared.maximum_cost);
    }

    #[test]
    fn calculates_the_fixed_calldata_hot_path_millisecond_deadline() {
        assert_eq!(
            schedule_deadline_millis(100, CALLDATA_HOT_LEAD_MS).expect("deadline"),
            98_000
        );
        assert_eq!(millis_until_deadline(98_000, 97_250), 750);
        assert_eq!(millis_until_deadline(98_000, 98_001), 0);
        assert_eq!(STANDARD_WAKE_LEAD_SECONDS, 10);
    }

    #[test]
    fn eligibility_error_policy_retries_only_non_final_results() {
        assert!(should_retry_calldata(&OpenSeaError::MintStageNotOpen));
        assert!(should_retry_calldata(&OpenSeaError::AuthenticationRequired));
        assert!(should_retry_calldata(&OpenSeaError::Compatibility));
        assert!(should_retry_calldata(&OpenSeaError::UnsafeMintAction {
            reason: "stale stage action",
        }));
        assert!(!should_retry_calldata(&OpenSeaError::MintWalletIneligible));
        assert!(!should_retry_calldata(&OpenSeaError::MintLimitExceeded));

        assert!(should_retry_hot_calldata(&OpenSeaError::Transport));
        assert!(should_retry_hot_calldata(&OpenSeaError::Http(429)));
        assert!(should_retry_hot_calldata(&OpenSeaError::Compatibility));
        assert!(should_retry_hot_calldata(
            &OpenSeaError::InvalidProtocolValue
        ));
        assert!(should_retry_hot_calldata(&OpenSeaError::UnsafeMintAction {
            reason: "stale stage action",
        }));
        assert!(!should_retry_hot_calldata(
            &OpenSeaError::AuthenticationRequired
        ));
        assert!(!should_retry_hot_calldata(
            &OpenSeaError::MintWalletIneligible
        ));
    }

    #[test]
    fn phase_status_distinguishes_scheduled_active_and_completed_jobs() {
        let mut job = PhaseJob {
            identity: PhaseIdentity {
                stage_index: 1,
                stage_type: "SIGNED_PRESALE".into(),
                token_range: None,
            },
            token_id: "0".into(),
            quantity: 5,
            state: PhaseJobState::Pending {
                phase: PhaseWindow::new(100, Some(200)).expect("phase"),
            },
        };

        assert_eq!(phase_job_status(&job, 50), "scheduled at 100");
        assert_eq!(phase_job_status(&job, 150), "active");
        job.state = PhaseJobState::Completed;
        assert_eq!(phase_job_status(&job, 150), "completed");
    }

    #[test]
    fn active_mint_action_proves_private_stage_when_query_is_null() {
        let mut stage = eligibility_fixture(&collection_fixture(vec![stage_fixture(
            1,
            "SIGNED_PRESALE",
            100,
            Some(200),
        )]))
        .stages
        .remove(0);
        stage.is_eligible = None;
        stage.eligible_minter_relation = Some(EligibleMinterRelation::LinkedWallet);

        assert_eq!(
            assess_wallet_eligibility(&stage, None),
            WalletEligibility::Unknown
        );
        let verified = assess_wallet_eligibility(&stage, Some(ActivePrivatePhaseProbe::Eligible));
        assert_eq!(
            verified,
            WalletEligibility::Eligible(EligibilityEvidence::ActiveMintAction)
        );
        assert_eq!(
            eligibility_label(&stage, verified),
            "eligible (verified mint action)"
        );
        assert_eq!(
            assess_wallet_eligibility(&stage, Some(ActivePrivatePhaseProbe::Ineligible),),
            WalletEligibility::Ineligible
        );
    }

    #[test]
    fn null_upcoming_private_eligibility_is_scheduled_until_it_can_be_verified() {
        let metadata = collection_fixture(vec![stage_fixture(1, "SIGNED_PRESALE", 100, Some(200))]);
        let mut eligibility = eligibility_fixture(&metadata);
        eligibility.stages[0].is_eligible = None;

        let options = build_phase_options(&metadata, &eligibility, &HashMap::new(), 50)
            .expect("phase options");
        assert_eq!(options[0].state, "upcoming");
        assert_eq!(options[0].eligibility, "no pre-launch verdict from OpenSea");
        assert!(options[0].is_selectable);

        let mut jobs = vec![PhaseJob {
            identity: phase_identity(&metadata.stages[0]),
            token_id: "0".into(),
            quantity: 1,
            state: PhaseJobState::Suspended {
                reason: "previous refresh".into(),
            },
        }];
        refresh_job_states(&metadata, &eligibility, &HashMap::new(), 50, &mut jobs)
            .expect("retain unverified schedule");
        assert!(matches!(jobs[0].state, PhaseJobState::Pending { .. }));

        eligibility.stages[0].is_eligible = Some(false);
        let options = build_phase_options(&metadata, &eligibility, &HashMap::new(), 50)
            .expect("negative phase options");
        assert_eq!(options[0].eligibility, "ineligible");
        assert!(!options[0].is_selectable);
        refresh_job_states(&metadata, &eligibility, &HashMap::new(), 50, &mut jobs)
            .expect("suspend explicit negative");
        assert!(matches!(jobs[0].state, PhaseJobState::Suspended { .. }));
    }

    #[test]
    fn linked_eligible_minter_is_a_label_not_an_ineligibility_veto() {
        let metadata = collection_fixture(vec![stage_fixture(1, "SIGNED_PRESALE", 100, Some(200))]);
        let mut snapshot = eligibility_fixture(&metadata);
        snapshot.minter_quantity_minted = Some(4);
        let mut stage = snapshot.stages.remove(0);
        stage.is_eligible = Some(true);
        stage.eligible_minter_relation = Some(EligibleMinterRelation::LinkedWallet);
        let assessment = assess_wallet_eligibility(&stage, None);

        assert!(assessment.is_selectable());
        assert_eq!(
            eligibility_label(&stage, assessment),
            "eligible via linked wallet"
        );
        assert_eq!(
            available_quantity(&metadata.stages[0], &stage, &snapshot),
            5
        );
    }

    #[test]
    fn erc1155_eligible_total_is_the_captured_per_token_fallback() {
        let mut metadata =
            collection_fixture(vec![stage_fixture(1, "SIGNED_PRESALE", 100, Some(200))]);
        metadata.drop_kind = "Erc1155SeaDropV2".into();
        metadata.stages[0].kind = "Erc1155SeaDropV2Stage".into();
        metadata.stages[0].token_range = Some((10, 12));
        metadata.stages[0].max_total_mintable_by_wallet_per_token = Some(2);
        let mut snapshot = eligibility_fixture(&metadata);
        snapshot.stages[0].eligible_max_total_mintable_by_wallet = Some(10);
        snapshot.stages[0].eligible_max_total_mintable_by_wallet_per_token = None;

        assert_eq!(
            available_quantity(&metadata.stages[0], &snapshot.stages[0], &snapshot),
            10
        );
    }

    #[test]
    fn suspended_phase_reactivates_when_the_same_identity_returns() {
        let stage = stage_fixture(1, "SIGNED_PRESALE", 100, Some(200));
        let metadata = collection_fixture(vec![stage.clone()]);
        let mut eligibility = eligibility_fixture(&metadata);
        eligibility.stages[0].is_eligible = Some(false);
        let mut jobs = vec![PhaseJob {
            identity: PhaseIdentity {
                stage_index: 1,
                stage_type: "SIGNED_PRESALE".into(),
                token_range: None,
            },
            token_id: "0".into(),
            quantity: 1,
            state: PhaseJobState::Pending {
                phase: PhaseWindow::new(100, Some(200)).expect("phase"),
            },
        }];
        refresh_job_states(&metadata, &eligibility, &HashMap::new(), 50, &mut jobs)
            .expect("suspend");
        assert!(matches!(jobs[0].state, PhaseJobState::Suspended { .. }));

        eligibility.stages[0].is_eligible = Some(true);
        refresh_job_states(&metadata, &eligibility, &HashMap::new(), 50, &mut jobs)
            .expect("reactivate");
        assert!(matches!(jobs[0].state, PhaseJobState::Pending { .. }));
    }

    #[test]
    fn changed_phase_time_reschedules_without_changing_identity() {
        let original = stage_fixture(1, "PUBLIC_SALE", 100, Some(200));
        let mut jobs = vec![PhaseJob {
            identity: PhaseIdentity {
                stage_index: 1,
                stage_type: "PUBLIC_SALE".into(),
                token_range: None,
            },
            token_id: "0".into(),
            quantity: 1,
            state: PhaseJobState::Pending {
                phase: stage_window(&original).expect("phase"),
            },
        }];
        let changed = stage_fixture(1, "PUBLIC_SALE", 300, Some(400));
        let metadata = collection_fixture(vec![changed]);
        let eligibility = eligibility_fixture(&metadata);
        refresh_job_states(&metadata, &eligibility, &HashMap::new(), 150, &mut jobs)
            .expect("refresh");
        assert!(matches!(
            jobs[0].state,
            PhaseJobState::Pending { phase } if phase.starts_at() == 300
        ));
    }

    #[test]
    fn manual_fee_mode_ignores_rpc_fee_estimate() {
        let config = test_config(FeeMode::Manual {
            max_fee_per_gas: U256::from(9_u8),
            max_priority_fee_per_gas: U256::from(2_u8),
        });
        assert!(matches!(config.fees.mode, FeeMode::Manual { .. }));
    }

    #[test]
    fn single_wallet_funding_uses_mint_value_and_maximum_replacement_fees() {
        let config = test_config(FeeMode::Automatic);
        let estimate = FeeEstimate {
            max_fee_per_gas: U256::from(10_u8),
            max_priority_fee_per_gas: U256::from(2_u8),
        };
        let mint_value = U256::from(1_000_u64);

        assert!(
            ensure_single_wallet_funding(
                &config,
                300_000,
                mint_value,
                estimate,
                U256::from(3_901_000_u64),
            )
            .is_ok()
        );
        assert!(matches!(
            ensure_single_wallet_funding(
                &config,
                300_000,
                mint_value,
                estimate,
                U256::from(3_900_999_u64),
            ),
            Err(CommandError::WalletUnderfunded { shortfall_wei })
                if shortfall_wei == U256::from(1_u8)
        ));
    }

    #[test]
    fn active_stage_guard_counts_every_active_candidate() {
        let metadata = collection_fixture(vec![
            stage_fixture(1, "SIGNED_PRESALE", 100, Some(200)),
            stage_fixture(2, "SIGNED_PRESALE", 100, Some(200)),
        ]);
        let eligibility = eligibility_fixture(&metadata);
        assert!(matches!(
            validate_unambiguous_active_stage(&metadata, &eligibility, 1, "0", 1, 150),
            Err(CommandError::AmbiguousActiveStage)
        ));
    }

    fn stage_fixture(
        stage_index: u32,
        stage_type: &str,
        starts_at: u64,
        ends_at: Option<u64>,
    ) -> StageMetadata {
        StageMetadata {
            kind: "Erc721SeaDropV1Stage".into(),
            stage_type: stage_type.into(),
            stage_index,
            start_time: Some(
                OffsetDateTime::from_unix_timestamp(i64::try_from(starts_at).expect("timestamp"))
                    .expect("time")
                    .format(&Rfc3339)
                    .expect("format"),
            ),
            end_time: ends_at.map(|timestamp| {
                OffsetDateTime::from_unix_timestamp(i64::try_from(timestamp).expect("timestamp"))
                    .expect("time")
                    .format(&Rfc3339)
                    .expect("format")
            }),
            max_total_mintable_by_wallet: Some(5),
            max_total_mintable_by_wallet_per_token: None,
            token_range: None,
        }
    }

    fn collection_fixture(stages: Vec<StageMetadata>) -> CollectionMetadata {
        CollectionMetadata {
            slug: "fixture".into(),
            address: "0x90a76eca33e635ebb260a699ef9ee65d02335ed9"
                .parse()
                .expect("address"),
            chain_identifier: "base".into(),
            network_id: 8453,
            drop_kind: "Erc721SeaDropV1".into(),
            drop_address: "0x90a76eca33e635ebb260a699ef9ee65d02335ed9"
                .parse()
                .expect("address"),
            stages,
        }
    }

    fn eligibility_fixture(metadata: &CollectionMetadata) -> EligibilitySnapshot {
        EligibilitySnapshot {
            drop_kind: metadata.drop_kind.clone(),
            minter_quantity_minted: Some(0),
            stages: metadata
                .stages
                .iter()
                .map(|stage| StageEligibility {
                    kind: stage.kind.clone(),
                    stage_type: stage.stage_type.clone(),
                    stage_index: stage.stage_index,
                    is_eligible: (stage.stage_type != "PUBLIC_SALE").then_some(true),
                    eligible_minter_relation: None,
                    max_total_mintable_by_wallet: stage.max_total_mintable_by_wallet,
                    eligible_max_total_mintable_by_wallet: None,
                    token_range: stage.token_range,
                    max_total_mintable_by_wallet_per_token: None,
                    eligible_max_total_mintable_by_wallet_per_token: None,
                    eligible_native_price_wei: None,
                    eligible_price_chain_identifier: None,
                })
                .collect(),
        }
    }

    fn test_config(mode: FeeMode) -> AppConfig {
        AppConfig {
            opensea: crate::config::OpenSeaConfig {
                site_url: "https://opensea.io".parse().expect("URL"),
                graphql_url: "https://gql.opensea.io/graphql".parse().expect("URL"),
                app_id: "os2-web".into(),
                request_timeout_ms: 1_000,
                eligibility_request_timeout_ms: 1_000,
                max_attempts: 3,
                retry_interval_ms: 250,
                calldata_max_attempts: 40,
            },
            scheduling: crate::config::SchedulingConfig {
                refresh_interval_seconds: 600,
            },
            retry: crate::config::RetryConfig {
                max_attempts: 1,
                pending_timeout_seconds: 1,
                base_delay_ms: 50,
                max_delay_ms: 100,
            },
            fees: crate::config::FeesConfig {
                mode,
                replacement_bump_bps: 11_250,
            },
            rpc_url: "https://rpc.example.invalid".parse().expect("URL"),
            gas_limit: 300_000,
        }
    }
}
