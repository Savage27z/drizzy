use std::{
    collections::{HashMap, HashSet},
    path::Path,
    sync::Arc,
    time::Duration,
};

use alloy_eip7702::SignedAuthorization;
use alloy_primitives::{Address, B256, Bytes, U256, keccak256};
use thiserror::Error;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use tokio::{sync::Semaphore, task::JoinSet, time::sleep};

use crate::{
    chain::{
        AccountState, ChainError, ChainGateway, CodeHashCheck, FeeEstimate, ReceiptPollingPolicy,
        SubmissionInputs, TransactionReceipt,
    },
    config::{AppConfig, ChainConfig, MultiWalletConfig, MultiWalletMode, SponsoredConfig},
    domain::{AutomaticFeePolicy, Eip1559Fees, ExecutionTiming, FeeError, PhaseWindow},
    fee::{initial_transaction_fees, maximum_transaction_fees},
    logging,
    multi_wallet::{
        FundingRequirement, MAX_SELF_FUNDED_WALLETS, WalletEntry, WalletManifest,
        WalletManifestError,
    },
    nft::{NftError, encode_safe_transfer, extract_minted_assets},
    opensea::{
        CollectionMetadata, EligibilitySnapshot, EligibleMinterRelation,
        MAX_MINT_ACTIONS_PER_GRAPHQL_REQUEST, MintActionRequest, MintTransactionAction,
        OpenSeaError, StageEligibility, StageMetadata, WalletOpenSeaClient,
        parse_collection_locator,
    },
    signing::{WalletSigner, WalletSignerError},
    sponsored::{
        AUDITED_EXECUTOR_RUNTIME_HASH, DelegationState, SponsoredMintError, SponsoredMintOperation,
        UnsignedSponsoredMintOperation, classify_delegation, encode_execute_batch, sign_delegation,
        sign_operation, sponsored_outer_gas_limit, sponsored_outer_gas_limit_upper_bound,
        sponsored_setup_gas_limit,
    },
    terminal::{self, ConfiguredPhase, PhaseOption, TerminalError, TopUpDecision},
    transaction::{
        Eip1559Transaction, Eip7702Transaction, SignedTransaction, TransactionError,
        sign_eip1559_transaction, sign_eip7702_transaction,
    },
};

const REVOCATION_BASE_GAS: u64 = 50_000;
const AUTHORIZATION_GAS: u64 = 25_000;
const SPONSORED_WAKE_LEAD_SECONDS: u64 = 15;
const STANDARD_WAKE_LEAD_SECONDS: u64 = 10;
const CALLDATA_HOT_LEAD_MS: u64 = 2_000;

#[derive(Debug, Error)]
pub enum MultiMintError {
    #[error(transparent)]
    Chain(#[from] ChainError),
    #[error(transparent)]
    OpenSea(#[from] OpenSeaError),
    #[error(transparent)]
    WalletManifest(#[from] WalletManifestError),
    #[error(transparent)]
    Signing(#[from] WalletSignerError),
    #[error(transparent)]
    Sponsored(#[from] SponsoredMintError),
    #[error(transparent)]
    Transaction(#[from] TransactionError),
    #[error(transparent)]
    Terminal(#[from] TerminalError),
    #[error(transparent)]
    Fee(#[from] FeeError),
    #[error(transparent)]
    Nft(#[from] NftError),
    #[error("multi-wallet worker task terminated unexpectedly")]
    Worker,
    #[error("no wallet remains eligible and valid for the selected stage")]
    NoEligibleWallets,
    #[error("self-funded mode supports at most 10 wallets per run")]
    SelfFundedWalletLimit,
    #[error("selected stage changed or became ambiguous")]
    StageChanged,
    #[error("selected stage has ended")]
    StageEnded,
    #[error("multi-wallet arithmetic overflowed")]
    ArithmeticOverflow,
    #[error("transaction {0} remained pending past the configured retry policy")]
    PendingTransaction(B256),
    #[error("transaction broadcast outcome is uncertain for local hash {0}")]
    BroadcastUncertain(B256),
    #[error("transaction reverted in block {0}")]
    TransactionReverted(u64),
    #[error("sponsored mode requires a verified executor deployment on this RPC chain")]
    InvalidSponsoredDeployment,
    #[error(
        "RPC chain {0} did not pass the EIP-7702 liveness probe; sponsored minting is unavailable, so set SPONSORED=false and fund each manifest wallet for self-funded minting"
    )]
    Eip7702Unavailable(u64),
    #[error(
        "RPC chain {0} lacks live EIP-1153 transient storage required by the sponsored executor"
    )]
    Eip1153Unavailable(u64),
    #[error("sponsor wallet is underfunded for the complete sponsored transaction")]
    SponsorUnderfunded,
    #[error("wallet state changed while preparing EIP-7702 revocation: {0}")]
    RevocationWalletChanged(Address),
    #[error("OpenSea did not provide a native mint price for sponsored wallet {0}")]
    SponsoredMintPriceUnavailable(Address),
    #[error("final sponsored calldata exceeded its pre-signing gas upper bound")]
    SponsoredGasBoundExceeded,
    #[error("sponsored receipt did not contain one exact result per submitted wallet")]
    InvalidSponsoredReceipt,
    #[error("--undelegate requires SPONSOR_KEY to pay for the revocation transaction")]
    MissingRevocationSponsor,
    #[error("one or more wallet delegations remain after the revocation transaction")]
    RevocationIncomplete,
    #[error("single-wallet mode does not support --undelegate")]
    SingleWalletUndelegate,
    #[error("calldata inspection requires exactly one active stage for the selected token")]
    NoUniqueActiveStage,
    #[error(
        "OpenSea batch calldata remained unavailable after {attempts} attempt(s): {last_error}"
    )]
    CalldataRetriesExhausted { attempts: u32, last_error: String },
}

struct SessionWallet {
    entry: WalletEntry,
    client: WalletOpenSeaClient,
    eligibility: EligibilitySnapshot,
}

struct PreparedSessions {
    sessions: Vec<SessionWallet>,
    skipped_errors: Vec<(Address, OpenSeaError)>,
}

struct ActionWallet {
    entry: WalletEntry,
    action: MintTransactionAction,
    account_state: AccountState,
    fee_estimate: FeeEstimate,
}

struct ActionCandidate {
    session: SessionWallet,
    account_state: AccountState,
    fee_estimate: FeeEstimate,
    expected_mint_value: Option<U256>,
}

struct SponsoredLaunchSnapshot {
    sponsor_state: AccountState,
    sponsor_inputs: SubmissionInputs,
    authorizations: HashMap<Address, SignedAuthorization>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SponsoredDelegationRequirement {
    Ready,
    AuthorizationRequired { previous_delegate: Option<Address> },
    UnsupportedCode,
}

struct SelfFundedWallet {
    wallet: ActionWallet,
    fees: Eip1559Fees,
    requirement: FundingRequirement,
}

struct RevocationAuthority {
    address: Address,
    initial_state: AccountState,
}

struct ScheduledMultiPhase {
    option_index: usize,
    stage: StageMetadata,
    token_id: String,
    starts_at: u64,
}

struct MultiRunContext<'a> {
    config: &'a AppConfig,
    multi: &'a MultiWalletConfig,
    sponsor_key: Option<&'a str>,
    gateway: &'a ChainGateway,
    chain: &'a ChainConfig,
    rpc_index: usize,
    resolver: &'a WalletOpenSeaClient,
    concurrency: usize,
}

pub(crate) fn validate_mode_wallet_limit(
    mode: &MultiWalletMode,
    wallet_count: usize,
) -> Result<(), MultiMintError> {
    match mode {
        MultiWalletMode::SelfFunded if wallet_count > MAX_SELF_FUNDED_WALLETS => {
            Err(MultiMintError::SelfFundedWalletLimit)
        }
        MultiWalletMode::Sponsored(_)
            if wallet_count > crate::sponsored::MAX_SPONSORED_BATCH_SIZE =>
        {
            Err(SponsoredMintError::InvalidBatchSize.into())
        }
        MultiWalletMode::SelfFunded | MultiWalletMode::Sponsored(_) => Ok(()),
    }
}

#[allow(clippy::too_many_lines)]
pub async fn run(
    config: &AppConfig,
    multi: &MultiWalletConfig,
    sponsor_key: Option<&str>,
) -> Result<(), MultiMintError> {
    let manifest = WalletManifest::load(&multi.manifest_path)?;
    validate_mode_wallet_limit(&multi.mode, manifest.len())?;
    let locator_text = terminal::prompt_collection_locator()?;
    let locator = parse_collection_locator(&locator_text)?;
    let gateway = ChainGateway::new(Duration::from_millis(config.opensea.request_timeout_ms))?;
    let probe = logging::animate("Connecting to RPC", gateway.probe_rpc(&config.rpc_url)).await?;
    let chain = ChainConfig {
        chain_id: probe.chain_id,
        rpc_urls: vec![config.rpc_url.clone()],
    };
    logging::success(format!("RPC connected: chain_id={}", chain.chain_id));

    if let MultiWalletMode::Sponsored(sponsored) = &multi.mode {
        verify_sponsored_environment(
            config,
            &gateway,
            &chain,
            probe.rpc_index,
            sponsored.executor,
        )
        .await?;
    }

    let resolver = WalletOpenSeaClient::new(&config.opensea)?;
    let metadata = logging::animate(
        "Resolving OpenSea collection",
        resolver.resolve_collection(&locator, chain.chain_id),
    )
    .await?;
    validate_stage_windows(&metadata)?;
    logging::success(format!("Collection resolved: {}", metadata.slug));

    let concurrency = match multi.mode {
        MultiWalletMode::SelfFunded => MAX_SELF_FUNDED_WALLETS,
        MultiWalletMode::Sponsored(_) => crate::sponsored::MAX_SPONSORED_BATCH_SIZE,
    };
    let manifest_wallet_count = manifest.len();
    let manifest_total_quantity = manifest.wallets().iter().try_fold(0_u64, |total, wallet| {
        total
            .checked_add(wallet.quantity())
            .ok_or(MultiMintError::ArithmeticOverflow)
    })?;
    let sessions = prepare_sessions_with_feedback(
        config,
        manifest.into_wallets(),
        &metadata,
        chain.chain_id,
        concurrency,
    )
    .await?;
    let options = build_multi_phase_options(&metadata, &sessions, unix_timestamp()?)?;
    let selected_indices = terminal::select_phases(&options)?;
    let mut scheduled = Vec::with_capacity(selected_indices.len());
    for option_index in selected_indices {
        let stage = metadata
            .stages
            .get(option_index)
            .cloned()
            .ok_or(MultiMintError::StageChanged)?;
        scheduled.push(ScheduledMultiPhase {
            option_index,
            starts_at: stage_window(&stage)?.starts_at(),
            stage,
            token_id: terminal::configure_multi_token(&options[option_index])?,
        });
    }
    sort_scheduled_phases(&mut scheduled);
    let context = MultiRunContext {
        config,
        multi,
        sponsor_key,
        gateway: &gateway,
        chain: &chain,
        rpc_index: probe.rpc_index,
        resolver: &resolver,
        concurrency,
    };
    let first_stage = &scheduled
        .first()
        .ok_or(MultiMintError::NoEligibleWallets)?
        .stage;
    let first_sessions = prepare_phase_setup(&context, &metadata, first_stage, sessions).await?;
    let configured = scheduled
        .iter()
        .map(|phase| ConfiguredPhase {
            option_index: phase.option_index,
            token_id: phase.token_id.clone(),
            quantity: manifest_total_quantity,
        })
        .collect::<Vec<_>>();
    terminal::confirm_multi_mint(
        &options,
        &configured,
        manifest_wallet_count,
        config.gas_limit,
        match multi.mode {
            MultiWalletMode::SelfFunded => "self-funded",
            MultiWalletMode::Sponsored(_) => "sponsored EIP-7702",
        },
        &multi.recipient.to_checksum(None),
    )?;
    let mut first_sessions = Some(first_sessions);
    for (position, phase) in scheduled.iter().enumerate() {
        let is_final_phase = position + 1 == scheduled.len();
        let phase_result = async {
            let (phase_metadata, phase_stage, phase_sessions) = if position == 0 {
                (
                    metadata.clone(),
                    phase.stage.clone(),
                    first_sessions
                        .take()
                        .ok_or(MultiMintError::NoEligibleWallets)?,
                )
            } else {
                prepare_later_phase(&context, &metadata, &phase.stage).await?
            };
            execute_multi_phase(
                &context,
                &phase_metadata,
                &phase_stage,
                &phase.token_id,
                phase_sessions,
                is_final_phase,
            )
            .await
        }
        .await;
        if let Err(error) = phase_result {
            if matches!(multi.mode, MultiWalletMode::Sponsored(_)) {
                warn_sponsored_revocation(
                    "Selected sponsored phase sequence stopped; delegation may remain active for manifest wallets. Revoke with:",
                );
            }
            return Err(error);
        }
    }
    Ok(())
}

fn sort_scheduled_phases(phases: &mut [ScheduledMultiPhase]) {
    phases.sort_by_key(|phase| phase.starts_at);
}

fn warn_sponsored_revocation(message: &str) {
    logging::warn_with_command(message, terminal::undelegate_command());
}

async fn prepare_phase_setup(
    context: &MultiRunContext<'_>,
    metadata: &CollectionMetadata,
    stage: &StageMetadata,
    sessions: Vec<SessionWallet>,
) -> Result<Vec<SessionWallet>, MultiMintError> {
    let mut eligible = filter_selected_sessions(sessions, stage);
    if eligible.is_empty() {
        return Err(MultiMintError::NoEligibleWallets);
    }
    match &context.multi.mode {
        MultiWalletMode::SelfFunded => {
            ensure_self_funded_setup_funding(
                context.config,
                context.gateway,
                context.chain,
                context.rpc_index,
                metadata,
                stage,
                context.multi.recipient,
                &mut eligible,
            )
            .await?;
        }
        MultiWalletMode::Sponsored(sponsored) => {
            let sponsor = WalletSigner::from_private_key(
                context
                    .sponsor_key
                    .ok_or(MultiMintError::MissingRevocationSponsor)?,
            )?;
            ensure_sponsored_setup_funding(
                context.config,
                context.gateway,
                context.chain,
                context.rpc_index,
                stage,
                sponsored,
                &sponsor,
                &mut eligible,
            )
            .await?;
        }
    }
    if eligible.is_empty() {
        return Err(MultiMintError::NoEligibleWallets);
    }
    Ok(eligible)
}

async fn prepare_later_phase(
    context: &MultiRunContext<'_>,
    original: &CollectionMetadata,
    selected: &StageMetadata,
) -> Result<(CollectionMetadata, StageMetadata, Vec<SessionWallet>), MultiMintError> {
    let metadata = context.resolver.collection_metadata(&original.slug).await?;
    if !same_collection(original, &metadata) {
        return Err(MultiMintError::StageChanged);
    }
    validate_stage_windows(&metadata)?;
    let stage = matching_metadata_stage(&metadata, selected)?.clone();
    let manifest = WalletManifest::load(&context.multi.manifest_path)?;
    validate_mode_wallet_limit(&context.multi.mode, manifest.len())?;
    let sessions = prepare_sessions_with_feedback(
        context.config,
        manifest.into_wallets(),
        &metadata,
        context.chain.chain_id,
        context.concurrency,
    )
    .await?;
    let sessions = prepare_phase_setup(context, &metadata, &stage, sessions).await?;
    Ok((metadata, stage, sessions))
}

#[allow(clippy::too_many_lines)]
async fn execute_multi_phase(
    context: &MultiRunContext<'_>,
    metadata: &CollectionMetadata,
    selected_stage: &StageMetadata,
    token_id: &str,
    eligible_sessions: Vec<SessionWallet>,
    is_final_phase: bool,
) -> Result<(), MultiMintError> {
    let wake_lead = match context.multi.mode {
        MultiWalletMode::SelfFunded => STANDARD_WAKE_LEAD_SECONDS,
        MultiWalletMode::Sponsored(_) => SPONSORED_WAKE_LEAD_SECONDS,
    };
    let (refreshed, selected_stage) = wait_for_launch_wake(
        context.config,
        context.resolver,
        metadata,
        selected_stage,
        wake_lead,
    )
    .await?;
    validate_unique_active_stage(
        &refreshed,
        &selected_stage,
        token_id,
        stage_window(&selected_stage)?
            .starts_at()
            .max(unix_timestamp()?),
    )?;
    let mut candidates = prepare_action_candidates(
        context.gateway,
        context.chain,
        context.rpc_index,
        &refreshed,
        &selected_stage,
        eligible_sessions,
        context.concurrency,
    )
    .await?;
    if candidates.is_empty() {
        return Err(MultiMintError::NoEligibleWallets);
    }
    match context.multi.mode {
        MultiWalletMode::SelfFunded => filter_underfunded_launch_candidates(
            context.config,
            &refreshed,
            context.multi.recipient,
            &mut candidates,
        )?,
        MultiWalletMode::Sponsored(_) => {
            filter_underfunded_sponsored_candidates(context.config, &mut candidates)?;
        }
    }
    if candidates.is_empty() {
        return Err(MultiMintError::NoEligibleWallets);
    }
    let sponsor = match context.multi.mode {
        MultiWalletMode::Sponsored(_) => Some(WalletSigner::from_private_key(
            context
                .sponsor_key
                .ok_or(MultiMintError::MissingRevocationSponsor)?,
        )?),
        MultiWalletMode::SelfFunded => None,
    };
    let sponsored_launch = match (&context.multi.mode, sponsor.as_ref()) {
        (MultiWalletMode::Sponsored(sponsored), Some(sponsor)) => Some(
            prepare_sponsored_launch(
                context.config,
                context.gateway,
                context.chain,
                context.rpc_index,
                sponsored,
                sponsor,
                &candidates,
            )
            .await?,
        ),
        _ => None,
    };
    wait_for_calldata_hot_path(&selected_stage).await?;
    let actions = fetch_actions_hot(
        context.config,
        &refreshed,
        &selected_stage,
        token_id,
        candidates,
        context.chain.chain_id,
    )
    .await?;
    match &context.multi.mode {
        MultiWalletMode::SelfFunded => {
            run_self_funded(
                context.config,
                context.gateway,
                context.chain,
                context.rpc_index,
                &refreshed,
                token_id,
                context.multi.recipient,
                actions,
                MAX_SELF_FUNDED_WALLETS,
            )
            .await
        }
        MultiWalletMode::Sponsored(sponsored) => {
            run_sponsored(
                context.config,
                context.gateway,
                context.chain,
                context.rpc_index,
                &refreshed,
                context.multi.recipient,
                actions,
                sponsored,
                sponsor
                    .as_ref()
                    .ok_or(MultiMintError::MissingRevocationSponsor)?,
                sponsored_launch.ok_or(MultiMintError::InvalidSponsoredDeployment)?,
                is_final_phase,
            )
            .await
        }
    }
}

pub async fn inspect_calldata(
    config: &AppConfig,
    manifest_path: &Path,
    locator_text: &str,
    token_id: &str,
) -> Result<(), MultiMintError> {
    let manifest = WalletManifest::load(manifest_path)?;
    let locator = parse_collection_locator(locator_text)?;
    let gateway = ChainGateway::new(Duration::from_millis(config.opensea.request_timeout_ms))?;
    let probe = logging::animate("Connecting to RPC", gateway.probe_rpc(&config.rpc_url)).await?;
    let chain = ChainConfig {
        chain_id: probe.chain_id,
        rpc_urls: vec![config.rpc_url.clone()],
    };
    let resolver = WalletOpenSeaClient::new(&config.opensea)?;
    let metadata = resolver
        .resolve_collection(&locator, chain.chain_id)
        .await?;
    validate_stage_windows(&metadata)?;
    let now = unix_timestamp()?;
    let parsed_token_id = token_id
        .parse::<u64>()
        .map_err(|_| MultiMintError::StageChanged)?;
    let mut active = metadata.stages.iter().filter(|stage| {
        stage_supports_token(stage, parsed_token_id)
            && stage_window(stage)
                .is_ok_and(|window| window.execution_timing(now) == ExecutionTiming::Immediate)
    });
    let selected_stage = active
        .next()
        .cloned()
        .ok_or(MultiMintError::NoUniqueActiveStage)?;
    if active.next().is_some() {
        return Err(MultiMintError::NoUniqueActiveStage);
    }
    let concurrency = manifest.len().min(10);
    let sessions = prepare_sessions_with_feedback(
        config,
        manifest.into_wallets(),
        &metadata,
        chain.chain_id,
        concurrency,
    )
    .await?;
    let sessions = filter_selected_sessions(sessions, &selected_stage);
    if sessions.is_empty() {
        return Err(MultiMintError::NoEligibleWallets);
    }
    let candidates = prepare_action_candidates(
        &gateway,
        &chain,
        probe.rpc_index,
        &metadata,
        &selected_stage,
        sessions,
        concurrency,
    )
    .await?;
    let actions = fetch_actions_hot(
        config,
        &metadata,
        &selected_stage,
        token_id,
        candidates,
        chain.chain_id,
    )
    .await?;
    if actions.is_empty() {
        return Err(MultiMintError::NoEligibleWallets);
    }

    logging::success(format!(
        "Read-only calldata inspection completed: collection={}, stage={}#{}, wallets={}.",
        metadata.slug,
        selected_stage.stage_type,
        selected_stage.stage_index,
        actions.len()
    ));
    for action in actions {
        let selector = action
            .action
            .calldata
            .get(..4)
            .ok_or(OpenSeaError::UnsafeMintAction {
                reason: "calldata is shorter than a selector",
            })?;
        logging::info(format!(
            "Wallet {}: target={}, value={} wei, calldata_bytes={}, selector=0x{}.",
            action.entry.address(),
            action.action.target,
            action.action.value,
            action.action.calldata.len(),
            hex::encode(selector)
        ));
    }
    logging::info("No transaction was signed or broadcast.");
    Ok(())
}

async fn prepare_sessions(
    config: &AppConfig,
    entries: Vec<WalletEntry>,
    metadata: &CollectionMetadata,
    chain_id: u64,
    concurrency: usize,
) -> Result<PreparedSessions, MultiMintError> {
    let semaphore = Arc::new(Semaphore::new(concurrency.max(1)));
    let mut tasks = JoinSet::new();
    for (manifest_index, entry) in entries.into_iter().enumerate() {
        let permit = Arc::clone(&semaphore);
        let config = config.opensea.clone();
        let slug = metadata.slug.clone();
        tasks.spawn(async move {
            let address = entry.address();
            let result = async {
                let _permit = permit
                    .acquire_owned()
                    .await
                    .map_err(|_| OpenSeaError::Client)?;
                let mut client = WalletOpenSeaClient::new(&config)?;
                client
                    .authenticate(entry.signer(), address, chain_id, &slug)
                    .await?;
                let eligibility = client.eligibility(&slug, address).await?;
                Ok::<_, OpenSeaError>(SessionWallet {
                    entry,
                    client,
                    eligibility,
                })
            }
            .await;
            (manifest_index, address, result)
        });
    }

    let mut sessions = Vec::new();
    let mut skipped_errors = Vec::new();
    while let Some(result) = tasks.join_next().await {
        let (manifest_index, address, result) = result.map_err(|_| MultiMintError::Worker)?;
        match result {
            Ok(session) => sessions.push((manifest_index, session)),
            Err(OpenSeaError::Compatibility | OpenSeaError::UnsafeMintAction { .. }) => {
                return Err(OpenSeaError::Compatibility.into());
            }
            Err(error) => skipped_errors.push((manifest_index, address, error)),
        }
    }
    if sessions.is_empty() {
        return Err(MultiMintError::NoEligibleWallets);
    }
    sessions.sort_by_key(|(manifest_index, _)| *manifest_index);
    skipped_errors.sort_by_key(|(manifest_index, _, _)| *manifest_index);
    Ok(PreparedSessions {
        sessions: sessions.into_iter().map(|(_, session)| session).collect(),
        skipped_errors: skipped_errors
            .into_iter()
            .map(|(_, address, error)| (address, error))
            .collect(),
    })
}

async fn prepare_sessions_with_feedback(
    config: &AppConfig,
    entries: Vec<WalletEntry>,
    metadata: &CollectionMetadata,
    chain_id: u64,
    concurrency: usize,
) -> Result<Vec<SessionWallet>, MultiMintError> {
    let wallet_count = entries.len();
    let prepared = logging::animate(
        format!("Authenticating {wallet_count} wallet(s)"),
        prepare_sessions(config, entries, metadata, chain_id, concurrency),
    )
    .await?;
    for (address, error) in prepared.skipped_errors {
        logging::warn(format!(
            "Wallet {address} skipped during authentication: {error}"
        ));
    }
    logging::success(format!(
        "Authenticated {} wallet(s).",
        prepared.sessions.len()
    ));
    Ok(prepared.sessions)
}

fn build_multi_phase_options(
    metadata: &CollectionMetadata,
    sessions: &[SessionWallet],
    block_timestamp: u64,
) -> Result<Vec<PhaseOption>, MultiMintError> {
    metadata
        .stages
        .iter()
        .map(|stage| {
            let phase = stage_window(stage)?;
            let timing = phase.execution_timing(block_timestamp);
            let mut eligible = 0_usize;
            let mut pending = 0_usize;
            let mut maximum = 0_u64;
            for session in sessions {
                validate_snapshot_shape(metadata, &session.eligibility)?;
                let eligibility = matching_eligibility_stage(&session.eligibility, stage)?;
                let available = available_quantity(stage, eligibility, &session.eligibility);
                if wallet_can_attempt(eligibility) && session.entry.quantity() <= available {
                    maximum = maximum.max(available);
                    if stage.stage_type == "PUBLIC_SALE" || eligibility.is_eligible == Some(true) {
                        eligible += 1;
                    } else {
                        pending += 1;
                    }
                }
            }
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
                eligibility: if pending == 0 {
                    format!("{eligible}/{} wallet(s) eligible", sessions.len())
                } else {
                    format!(
                        "{eligible}/{} eligible; {pending} pending active verification",
                        sessions.len()
                    )
                },
                max_quantity: maximum,
                token_range: stage.token_range,
                is_selectable: maximum > 0
                    && eligible + pending > 0
                    && timing != ExecutionTiming::Ended,
            })
        })
        .collect()
}

fn filter_selected_sessions(
    sessions: Vec<SessionWallet>,
    stage: &StageMetadata,
) -> Vec<SessionWallet> {
    sessions
        .into_iter()
        .filter(|session| {
            let Ok(eligibility) = matching_eligibility_stage(&session.eligibility, stage) else {
                return false;
            };
            wallet_can_attempt(eligibility)
                && session.entry.quantity()
                    <= available_quantity(stage, eligibility, &session.eligibility)
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
async fn ensure_sponsored_setup_funding(
    config: &AppConfig,
    gateway: &ChainGateway,
    chain: &ChainConfig,
    rpc_index: usize,
    stage: &StageMetadata,
    sponsored: &SponsoredConfig,
    sponsor: &WalletSigner,
    sessions: &mut Vec<SessionWallet>,
) -> Result<(), MultiMintError> {
    let sponsor_address = sponsor.identity().address;
    loop {
        let sponsor_snapshot = gateway
            .wallet_snapshot(chain, rpc_index, sponsor_address)
            .await?;
        let sponsor_state = sponsor_snapshot.account_state;
        let sponsor_inputs = sponsor_snapshot.submission_inputs;
        validate_sponsor_payer_code(&sponsor_state.code, sponsored.executor)?;
        let fees = initial_transaction_fees(config.fees, sponsor_inputs.fee_estimate)?;
        let maximum_fees = maximum_transaction_fees(config.fees, config.retry.max_attempts, fees)?;
        let sponsor_gas_limit =
            sponsored_setup_gas_limit(sponsored.wallet_gas_limit, sessions.len())?;
        let sponsor_requirement = FundingRequirement {
            mint_value: U256::ZERO,
            gas_limit: sponsor_gas_limit,
            max_fee_per_gas: maximum_fees.max_fee_per_gas,
        };
        let sponsor_required = sponsor_requirement.maximum_native_cost()?;
        let sponsor_shortfall = sponsor_requirement.shortfall(sponsor_state.balance)?;
        if sponsor_shortfall == U256::ZERO {
            logging::success(format!(
                "Sponsor gas funding verified: {sponsor_address} | maximum={sponsor_required} wei"
            ));
        } else {
            logging::warn(format!(
                "Sponsor gas funding shortfall: {sponsor_address} | shortfall={sponsor_shortfall} wei"
            ));
        }

        let mut tasks = JoinSet::new();
        for (manifest_index, session) in sessions.iter().enumerate() {
            let eligibility = matching_eligibility_stage(&session.eligibility, stage)?;
            let address = session.entry.address();
            let mint_value = sponsored_wallet_mint_value(
                address,
                eligibility.eligible_native_price_wei,
                session.entry.quantity(),
            )?;
            let requirement = sponsored_wallet_action_requirement(
                mint_value,
                config.gas_limit,
                maximum_fees.max_fee_per_gas,
            );
            let required = requirement.maximum_native_cost()?;
            let gateway = gateway.clone();
            let chain = chain.clone();
            tasks.spawn(async move {
                let balance = gateway
                    .account_state(&chain, rpc_index, address)
                    .await?
                    .balance;
                Ok::<_, MultiMintError>((
                    manifest_index,
                    address,
                    mint_value,
                    required,
                    requirement.shortfall(balance)?,
                ))
            });
        }

        let mut underfunded = HashSet::new();
        let mut funding_results = Vec::with_capacity(sessions.len());
        while let Some(result) = tasks.join_next().await {
            funding_results.push(result.map_err(|_| MultiMintError::Worker)??);
        }
        funding_results.sort_by_key(|(manifest_index, _, _, _, _)| *manifest_index);
        for (_, address, mint_value, required, shortfall) in funding_results {
            if shortfall == U256::ZERO {
                logging::success(format!(
                    "Wallet OpenSea-action funding verified: {address} | mint value={mint_value} wei | required balance={required} wei"
                ));
            } else {
                underfunded.insert(address);
                logging::warn(format!(
                    "Wallet OpenSea-action funding shortfall: {address} | required balance={required} wei | shortfall={shortfall} wei"
                ));
            }
        }
        if sponsor_shortfall == U256::ZERO && underfunded.is_empty() {
            return Ok(());
        }
        match terminal::prompt_top_up()? {
            TopUpDecision::Recheck => {}
            TopUpDecision::Skip if sponsor_shortfall != U256::ZERO => {
                return Err(MultiMintError::SponsorUnderfunded);
            }
            TopUpDecision::Skip => {
                sessions.retain(|session| !underfunded.contains(&session.entry.address()));
                return Ok(());
            }
        }
    }
}

fn sponsored_wallet_mint_value(
    wallet: Address,
    eligible_native_price_wei: Option<U256>,
    quantity: u64,
) -> Result<U256, MultiMintError> {
    eligible_native_price_wei
        .ok_or(MultiMintError::SponsoredMintPriceUnavailable(wallet))?
        .checked_mul(U256::from(quantity))
        .ok_or(MultiMintError::ArithmeticOverflow)
}

fn sponsored_wallet_action_requirement(
    mint_value: U256,
    gas_limit: u64,
    max_fee_per_gas: U256,
) -> FundingRequirement {
    FundingRequirement {
        mint_value,
        gas_limit,
        max_fee_per_gas,
    }
}

#[allow(clippy::too_many_arguments)]
async fn ensure_self_funded_setup_funding(
    config: &AppConfig,
    gateway: &ChainGateway,
    chain: &ChainConfig,
    rpc_index: usize,
    metadata: &CollectionMetadata,
    stage: &StageMetadata,
    recipient: Address,
    sessions: &mut Vec<SessionWallet>,
) -> Result<(), MultiMintError> {
    loop {
        let mut tasks = JoinSet::new();
        for (manifest_index, session) in sessions.iter().enumerate() {
            let eligibility = matching_eligibility_stage(&session.eligibility, stage)?;
            let expected_mint_value = eligibility
                .eligible_native_price_wei
                .map(|price| {
                    price
                        .checked_mul(U256::from(session.entry.quantity()))
                        .ok_or(MultiMintError::ArithmeticOverflow)
                })
                .transpose()?;
            let address = session.entry.address();
            if expected_mint_value.is_none() {
                logging::warn(format!(
                    "Wallet {address} has no captured eligible price; setup reserves maximum forwarding and mint gas, and the action value is checked before signing."
                ));
            }
            let quantity = session.entry.quantity();
            let config = config.clone();
            let gateway = gateway.clone();
            let chain = chain.clone();
            let drop_kind = metadata.drop_kind.clone();
            tasks.spawn(async move {
                let snapshot = gateway.wallet_snapshot(&chain, rpc_index, address).await?;
                let requirement = self_funded_requirement(
                    &config,
                    &drop_kind,
                    recipient,
                    address,
                    quantity,
                    expected_mint_value.unwrap_or(U256::ZERO),
                    snapshot.submission_inputs.fee_estimate,
                )?;
                Ok::<_, MultiMintError>((
                    manifest_index,
                    address,
                    requirement.shortfall(snapshot.account_state.balance)?,
                ))
            });
        }

        let mut underfunded = HashSet::new();
        let mut funding_results = Vec::with_capacity(sessions.len());
        while let Some(result) = tasks.join_next().await {
            funding_results.push(result.map_err(|_| MultiMintError::Worker)??);
        }
        funding_results.sort_by_key(|(manifest_index, _, _)| *manifest_index);
        for (_, address, shortfall) in funding_results {
            if shortfall == U256::ZERO {
                logging::success(format!("Setup funding verified: {address}"));
            } else {
                underfunded.insert(address);
                logging::warn(format!(
                    "Setup funding shortfall for {address}: {shortfall} wei"
                ));
            }
        }
        if underfunded.is_empty() {
            return Ok(());
        }
        match terminal::prompt_top_up()? {
            TopUpDecision::Recheck => {}
            TopUpDecision::Skip => {
                sessions.retain(|session| !underfunded.contains(&session.entry.address()));
                return Ok(());
            }
        }
    }
}

fn filter_underfunded_launch_candidates(
    config: &AppConfig,
    metadata: &CollectionMetadata,
    recipient: Address,
    candidates: &mut Vec<ActionCandidate>,
) -> Result<(), MultiMintError> {
    let mut underfunded = HashSet::new();
    for candidate in candidates.iter() {
        let address = candidate.session.entry.address();
        let requirement = self_funded_requirement(
            config,
            &metadata.drop_kind,
            recipient,
            address,
            candidate.session.entry.quantity(),
            candidate.expected_mint_value.unwrap_or(U256::ZERO),
            candidate.fee_estimate,
        )?;
        let shortfall = requirement.shortfall(candidate.account_state.balance)?;
        if shortfall == U256::ZERO {
            logging::success(format!("T-10 funding safety recheck passed: {address}"));
        } else {
            underfunded.insert(address);
            logging::warn(format!(
                "Wallet skipped after its T-10 funding safety recheck found a {shortfall} wei shortfall: {address}"
            ));
        }
    }
    candidates.retain(|candidate| !underfunded.contains(&candidate.session.entry.address()));
    Ok(())
}

fn filter_underfunded_sponsored_candidates(
    config: &AppConfig,
    candidates: &mut Vec<ActionCandidate>,
) -> Result<(), MultiMintError> {
    let mut underfunded = HashSet::new();
    for candidate in candidates.iter() {
        let address = candidate.session.entry.address();
        let mint_value = candidate
            .expected_mint_value
            .ok_or(MultiMintError::SponsoredMintPriceUnavailable(address))?;
        let fees = initial_transaction_fees(config.fees, candidate.fee_estimate)?;
        let maximum_fees = maximum_transaction_fees(config.fees, config.retry.max_attempts, fees)?;
        let requirement = sponsored_wallet_action_requirement(
            mint_value,
            config.gas_limit,
            maximum_fees.max_fee_per_gas,
        );
        let required = requirement.maximum_native_cost()?;
        let shortfall = requirement.shortfall(candidate.account_state.balance)?;
        if shortfall == U256::ZERO {
            logging::success(format!(
                "Wallet OpenSea-action balance safety recheck passed: {address} | required={required} wei"
            ));
        } else {
            underfunded.insert(address);
            logging::warn(format!(
                "Wallet skipped because its OpenSea-action balance fell short by {shortfall} wei: {address}"
            ));
        }
    }
    candidates.retain(|candidate| !underfunded.contains(&candidate.session.entry.address()));
    Ok(())
}

fn self_funded_requirement(
    config: &AppConfig,
    drop_kind: &str,
    recipient: Address,
    wallet: Address,
    quantity: u64,
    mint_value: U256,
    fee_estimate: FeeEstimate,
) -> Result<FundingRequirement, MultiMintError> {
    let transaction_count = self_funded_transaction_count(drop_kind, recipient, wallet, quantity)?;
    let gas_limit = config
        .gas_limit
        .checked_mul(transaction_count)
        .ok_or(MultiMintError::ArithmeticOverflow)?;
    let fees = initial_transaction_fees(config.fees, fee_estimate)?;
    let maximum_fees = maximum_transaction_fees(config.fees, config.retry.max_attempts, fees)?;
    Ok(FundingRequirement {
        mint_value,
        gas_limit,
        max_fee_per_gas: maximum_fees.max_fee_per_gas,
    })
}

fn self_funded_transaction_count(
    drop_kind: &str,
    recipient: Address,
    wallet: Address,
    quantity: u64,
) -> Result<u64, MultiMintError> {
    let transfer_count = if recipient == wallet {
        0
    } else if drop_kind == "Erc721SeaDropV1" {
        quantity
    } else {
        1
    };
    transfer_count
        .checked_add(1)
        .ok_or(MultiMintError::ArithmeticOverflow)
}

#[allow(clippy::too_many_arguments)]
#[allow(clippy::too_many_lines)]
async fn prepare_action_candidates(
    gateway: &ChainGateway,
    chain: &ChainConfig,
    rpc_index: usize,
    metadata: &CollectionMetadata,
    stage: &StageMetadata,
    sessions: Vec<SessionWallet>,
    concurrency: usize,
) -> Result<Vec<ActionCandidate>, MultiMintError> {
    let semaphore = Arc::new(Semaphore::new(concurrency.max(1)));
    let mut tasks = JoinSet::new();
    for (manifest_index, mut session) in sessions.into_iter().enumerate() {
        let permit = Arc::clone(&semaphore);
        let gateway = gateway.clone();
        let chain = chain.clone();
        let metadata = metadata.clone();
        let stage = stage.clone();
        tasks.spawn(async move {
            let _permit = permit
                .acquire_owned()
                .await
                .map_err(|_| OpenSeaError::Client)?;
            let wallet = session.entry.address();
            session
                .client
                .authenticate(
                    session.entry.signer(),
                    wallet,
                    chain.chain_id,
                    &metadata.slug,
                )
                .await?;
            let eligibility = session.client.eligibility(&metadata.slug, wallet).await?;
            validate_snapshot_shape(&metadata, &eligibility)
                .map_err(|_| OpenSeaError::Compatibility)?;
            let selected = matching_eligibility_stage(&eligibility, &stage)
                .map_err(|_| OpenSeaError::Compatibility)?;
            if !wallet_can_attempt(selected)
                || session.entry.quantity() > available_quantity(&stage, selected, &eligibility)
            {
                return Err(OpenSeaError::MintWalletIneligible);
            }
            let expected_mint_value = selected
                .eligible_native_price_wei
                .map(|price| {
                    price
                        .checked_mul(U256::from(session.entry.quantity()))
                        .ok_or(OpenSeaError::InvalidProtocolValue)
                })
                .transpose()?;
            let wallet_snapshot = gateway.wallet_snapshot(&chain, rpc_index, wallet).await;
            Ok::<_, OpenSeaError>((
                manifest_index,
                session,
                wallet_snapshot,
                expected_mint_value,
            ))
        });
    }

    let mut candidates = Vec::new();
    while let Some(result) = tasks.join_next().await {
        match result.map_err(|_| MultiMintError::Worker)? {
            Ok((manifest_index, session, wallet_snapshot, expected_mint_value)) => {
                let wallet_snapshot = wallet_snapshot.map_err(MultiMintError::Chain)?;
                candidates.push((
                    manifest_index,
                    ActionCandidate {
                        session,
                        account_state: wallet_snapshot.account_state,
                        fee_estimate: wallet_snapshot.submission_inputs.fee_estimate,
                        expected_mint_value,
                    },
                ));
            }
            Err(error @ (OpenSeaError::Compatibility | OpenSeaError::UnsafeMintAction { .. })) => {
                return Err(error.into());
            }
            Err(error) => logging::warn(format!("Wallet skipped while preparing mint: {error}")),
        }
    }
    candidates.sort_by_key(|(manifest_index, _)| *manifest_index);
    Ok(candidates
        .into_iter()
        .map(|(_, candidate)| candidate)
        .collect())
}

#[allow(clippy::too_many_arguments)]
async fn fetch_actions_hot(
    config: &AppConfig,
    metadata: &CollectionMetadata,
    stage: &StageMetadata,
    token_id: &str,
    candidates: Vec<ActionCandidate>,
    chain_id: u64,
) -> Result<Vec<ActionWallet>, MultiMintError> {
    if candidates.is_empty() || candidates.len() > MAX_MINT_ACTIONS_PER_GRAPHQL_REQUEST {
        return Err(MultiMintError::NoEligibleWallets);
    }
    let requests = candidates
        .iter()
        .map(|candidate| MintActionRequest {
            wallet: candidate.session.entry.address(),
            token_id: token_id.to_owned(),
            quantity: candidate.session.entry.quantity(),
        })
        .collect::<Vec<_>>();
    let client = &candidates[0].session.client;
    for attempt in 1..=config.opensea.calldata_max_attempts {
        if stage_window(stage)?
            .ends_at()
            .is_some_and(|ends_at| unix_timestamp().is_ok_and(|now| now >= ends_at))
        {
            return Err(MultiMintError::StageEnded);
        }
        let actions = client
            .mint_transaction_actions(metadata, stage, &requests, chain_id)
            .await
            .and_then(|actions| {
                if candidates.iter().zip(&actions).any(|(candidate, action)| {
                    candidate
                        .expected_mint_value
                        .is_some_and(|expected| action.value != expected)
                }) {
                    Err(OpenSeaError::UnsafeMintAction {
                        reason: "transaction value differs from the captured eligible price",
                    })
                } else {
                    Ok(actions)
                }
            });
        match actions {
            Ok(actions) => {
                logging::success(format!(
                    "Fetched and validated {} wallet-specific mint action(s) in one OpenSea GraphQL request.",
                    actions.len()
                ));
                return Ok(candidates
                    .into_iter()
                    .zip(actions)
                    .map(|(candidate, action)| ActionWallet {
                        entry: candidate.session.entry,
                        action,
                        account_state: candidate.account_state,
                        fee_estimate: candidate.fee_estimate,
                    })
                    .collect());
            }
            Err(error)
                if retryable_action_error(&error)
                    && attempt < config.opensea.calldata_max_attempts =>
            {
                logging::warn(format!(
                    "OpenSea batch calldata attempt {attempt}/{} is not ready ({error}); retrying in {} ms.",
                    config.opensea.calldata_max_attempts, config.opensea.retry_interval_ms
                ));
                sleep(Duration::from_millis(config.opensea.retry_interval_ms)).await;
            }
            Err(error) if retryable_action_error(&error) => {
                return Err(MultiMintError::CalldataRetriesExhausted {
                    attempts: config.opensea.calldata_max_attempts,
                    last_error: error.to_string(),
                });
            }
            Err(error) => return Err(error.into()),
        }
    }
    unreachable!("bounded batch calldata retry loop always returns")
}

#[allow(clippy::too_many_arguments)]
#[allow(clippy::too_many_lines)]
async fn run_self_funded(
    config: &AppConfig,
    gateway: &ChainGateway,
    chain: &ChainConfig,
    rpc_index: usize,
    metadata: &CollectionMetadata,
    token_id: &str,
    recipient: Address,
    actions: Vec<ActionWallet>,
    concurrency: usize,
) -> Result<(), MultiMintError> {
    let mut prepared = Vec::with_capacity(actions.len());
    for wallet in actions {
        let fees = initial_transaction_fees(config.fees, wallet.fee_estimate)?;
        let maximum_fees = maximum_transaction_fees(config.fees, config.retry.max_attempts, fees)?;
        let transfer_count = if recipient == wallet.entry.address() {
            0
        } else if metadata.drop_kind == "Erc721SeaDropV1" {
            wallet.entry.quantity()
        } else {
            1
        };
        let transaction_count = transfer_count
            .checked_add(1)
            .ok_or(MultiMintError::ArithmeticOverflow)?;
        let aggregate_gas = config
            .gas_limit
            .checked_mul(transaction_count)
            .ok_or(MultiMintError::ArithmeticOverflow)?;
        let requirement = FundingRequirement {
            mint_value: wallet.action.value,
            gas_limit: aggregate_gas,
            max_fee_per_gas: maximum_fees.max_fee_per_gas,
        };
        prepared.push(SelfFundedWallet {
            wallet,
            fees,
            requirement,
        });
    }

    let mut funded = Vec::with_capacity(prepared.len());
    for wallet in prepared {
        if wallet
            .requirement
            .shortfall(wallet.wallet.account_state.balance)?
            == U256::ZERO
        {
            funded.push(wallet);
        } else {
            logging::warn(format!(
                "Wallet skipped because its final pre-signing funding check failed: {}",
                wallet.wallet.entry.address()
            ));
        }
    }
    if funded.is_empty() {
        return Err(MultiMintError::NoEligibleWallets);
    }
    let semaphore = Arc::new(Semaphore::new(concurrency.max(1)));
    let mut tasks = JoinSet::new();
    for wallet in funded {
        let permit = Arc::clone(&semaphore);
        let config = config.clone();
        let gateway = gateway.clone();
        let chain = chain.clone();
        let metadata = metadata.clone();
        let token_id = token_id.to_owned();
        tasks.spawn(async move {
            let _permit = permit
                .acquire_owned()
                .await
                .map_err(|_| MultiMintError::Worker)?;
            execute_self_funded_wallet(
                &config, &gateway, &chain, rpc_index, &metadata, &token_id, recipient, wallet,
            )
            .await
        });
    }

    let mut succeeded = 0_usize;
    let mut failed = 0_usize;
    while let Some(result) = tasks.join_next().await {
        match result.map_err(|_| MultiMintError::Worker)? {
            Ok(address) => {
                succeeded += 1;
                logging::success(format!("Wallet mint and forwarding completed: {address}"));
            }
            Err(error) => {
                failed += 1;
                logging::warn(format!("Wallet execution failed: {error}"));
            }
        }
    }
    logging::info(format!(
        "Self-funded batch finished: succeeded={succeeded}, failed={failed}."
    ));
    if succeeded == 0 {
        return Err(MultiMintError::NoEligibleWallets);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn execute_self_funded_wallet(
    config: &AppConfig,
    gateway: &ChainGateway,
    chain: &ChainConfig,
    rpc_index: usize,
    metadata: &CollectionMetadata,
    token_id: &str,
    recipient: Address,
    wallet: SelfFundedWallet,
) -> Result<Address, MultiMintError> {
    let address = wallet.wallet.entry.address();
    if wallet
        .requirement
        .shortfall(wallet.wallet.account_state.balance)?
        != U256::ZERO
    {
        return Err(WalletManifestError::Underfunded.into());
    }
    let receipt = submit_eip1559_with_replacements(
        config,
        gateway,
        chain,
        rpc_index,
        wallet.wallet.entry.signer(),
        wallet.wallet.account_state.pending_nonce,
        wallet.wallet.action.target,
        wallet.wallet.action.value,
        wallet.wallet.action.calldata.clone(),
        config.gas_limit,
        wallet.fees,
    )
    .await?;
    if !receipt.is_success {
        return Err(MultiMintError::TransactionReverted(receipt.block_number));
    }
    logging::success(format!(
        "Mint confirmed for {address}: {} in block {}.",
        receipt.transaction_hash, receipt.block_number
    ));
    if recipient == address {
        return Ok(address);
    }
    let token_id_number = token_id.parse().map_err(|_| MultiMintError::StageChanged)?;
    let assets = extract_minted_assets(
        &receipt,
        metadata.address,
        address,
        &metadata.drop_kind,
        token_id_number,
        wallet.wallet.entry.quantity(),
    )?;
    for asset in assets {
        let inputs = gateway.submission_inputs(chain, rpc_index, address).await?;
        let fees = initial_transaction_fees(config.fees, inputs.fee_estimate)?;
        let calldata = encode_safe_transfer(&asset, address, recipient);
        let transfer_receipt = submit_eip1559_with_replacements(
            config,
            gateway,
            chain,
            rpc_index,
            wallet.wallet.entry.signer(),
            inputs.pending_nonce,
            metadata.address,
            U256::ZERO,
            calldata,
            config.gas_limit,
            fees,
        )
        .await?;
        if !transfer_receipt.is_success {
            return Err(MultiMintError::TransactionReverted(
                transfer_receipt.block_number,
            ));
        }
        logging::success(format!(
            "NFT forwarded for {address}: {}.",
            transfer_receipt.transaction_hash
        ));
    }
    Ok(address)
}

#[allow(clippy::too_many_arguments)]
async fn submit_eip1559_with_replacements(
    config: &AppConfig,
    gateway: &ChainGateway,
    chain: &ChainConfig,
    rpc_index: usize,
    signer: &WalletSigner,
    nonce: u64,
    target: Address,
    value: U256,
    calldata: Bytes,
    gas_limit: u64,
    mut fees: Eip1559Fees,
) -> Result<TransactionReceipt, MultiMintError> {
    let replacement = AutomaticFeePolicy::new(10_000, config.fees.replacement_bump_bps)?;
    let mut last_hash = B256::ZERO;
    let mut submitted = Vec::new();
    for attempt in 1..=config.retry.max_attempts {
        let transaction = Eip1559Transaction {
            chain_id: chain.chain_id,
            nonce,
            max_priority_fee_per_gas: fees.max_priority_fee_per_gas,
            max_fee_per_gas: fees.max_fee_per_gas,
            gas_limit,
            target,
            value,
            calldata: calldata.clone(),
        };
        let signed_transaction = sign_eip1559_transaction(&transaction, signer)?;
        last_hash = signed_transaction.hash();
        logging::info(format!(
            "Submitting transaction: {last_hash} (attempt {attempt})."
        ));
        gateway
            .send_raw_transaction(chain, rpc_index, &signed_transaction)
            .await
            .map_err(|_| MultiMintError::BroadcastUncertain(last_hash))?;
        submitted.push(last_hash);
        if let Some((_, receipt)) = gateway
            .wait_for_any_transaction_receipt(
                chain,
                rpc_index,
                &submitted,
                ReceiptPollingPolicy::from(config.retry),
            )
            .await?
        {
            return Ok(receipt);
        }
        if attempt < config.retry.max_attempts {
            fees = replacement.replacement(fees)?;
        }
    }
    Err(MultiMintError::PendingTransaction(last_hash))
}

fn wallet_can_attempt(stage: &StageEligibility) -> bool {
    stage.eligible_minter_relation != Some(EligibleMinterRelation::LinkedWallet)
        && (stage.stage_type == "PUBLIC_SALE" || stage.is_eligible != Some(false))
}

fn available_quantity(
    stage: &StageMetadata,
    eligibility: &StageEligibility,
    snapshot: &EligibilitySnapshot,
) -> u64 {
    let total = eligibility
        .eligible_max_total_mintable_by_wallet
        .or(eligibility.max_total_mintable_by_wallet)
        .or(stage.max_total_mintable_by_wallet)
        .unwrap_or(u64::MAX);
    let remaining = total.saturating_sub(snapshot.minter_quantity_minted.unwrap_or(0));
    let per_token = eligibility
        .eligible_max_total_mintable_by_wallet_per_token
        .or(eligibility.eligible_max_total_mintable_by_wallet)
        .or(eligibility.max_total_mintable_by_wallet_per_token)
        .or(stage.max_total_mintable_by_wallet_per_token)
        .unwrap_or(u64::MAX);
    remaining.min(per_token)
}

fn validate_snapshot_shape(
    metadata: &CollectionMetadata,
    snapshot: &EligibilitySnapshot,
) -> Result<(), MultiMintError> {
    if metadata.drop_kind != snapshot.drop_kind || metadata.stages.len() != snapshot.stages.len() {
        return Err(MultiMintError::StageChanged);
    }
    for stage in &metadata.stages {
        let eligibility = matching_eligibility_stage(snapshot, stage)?;
        if eligibility.kind != stage.kind
            || eligibility.stage_type != stage.stage_type
            || eligibility.token_range != stage.token_range
            || eligibility.max_total_mintable_by_wallet != stage.max_total_mintable_by_wallet
            || eligibility.max_total_mintable_by_wallet_per_token
                != stage.max_total_mintable_by_wallet_per_token
        {
            return Err(MultiMintError::StageChanged);
        }
        if eligibility.eligible_native_price_wei.is_some()
            != eligibility.eligible_price_chain_identifier.is_some()
        {
            return Err(MultiMintError::StageChanged);
        }
    }
    Ok(())
}

fn matching_eligibility_stage<'a>(
    snapshot: &'a EligibilitySnapshot,
    stage: &StageMetadata,
) -> Result<&'a StageEligibility, MultiMintError> {
    let mut matches = snapshot.stages.iter().filter(|candidate| {
        candidate.stage_index == stage.stage_index && candidate.token_range == stage.token_range
    });
    let found = matches.next().ok_or(MultiMintError::StageChanged)?;
    if matches.next().is_some() {
        return Err(MultiMintError::StageChanged);
    }
    Ok(found)
}

fn matching_metadata_stage<'a>(
    metadata: &'a CollectionMetadata,
    stage: &StageMetadata,
) -> Result<&'a StageMetadata, MultiMintError> {
    let mut matches = metadata.stages.iter().filter(|candidate| {
        candidate.stage_index == stage.stage_index && candidate.token_range == stage.token_range
    });
    let found = matches.next().ok_or(MultiMintError::StageChanged)?;
    if matches.next().is_some() {
        return Err(MultiMintError::StageChanged);
    }
    Ok(found)
}

fn same_collection(original: &CollectionMetadata, refreshed: &CollectionMetadata) -> bool {
    original.address == refreshed.address
        && original.drop_address == refreshed.drop_address
        && original.network_id == refreshed.network_id
        && original.drop_kind == refreshed.drop_kind
}

fn validate_unique_active_stage(
    metadata: &CollectionMetadata,
    selected: &StageMetadata,
    token_id: &str,
    block_timestamp: u64,
) -> Result<(), MultiMintError> {
    let token_id = token_id
        .parse::<u64>()
        .map_err(|_| MultiMintError::StageChanged)?;
    let active = metadata
        .stages
        .iter()
        .filter(|stage| {
            stage_supports_token(stage, token_id)
                && stage_window(stage).is_ok_and(|phase| {
                    phase.execution_timing(block_timestamp) == ExecutionTiming::Immediate
                })
        })
        .collect::<Vec<_>>();
    if active.len() != 1 || active[0] != selected {
        return Err(MultiMintError::StageChanged);
    }
    Ok(())
}

fn stage_supports_token(stage: &StageMetadata, token_id: u64) -> bool {
    stage
        .token_range
        .map_or(token_id == 0, |(from, to)| (from..=to).contains(&token_id))
}

fn validate_stage_windows(metadata: &CollectionMetadata) -> Result<(), MultiMintError> {
    for stage in &metadata.stages {
        stage_window(stage)?;
    }
    Ok(())
}

fn stage_window(stage: &StageMetadata) -> Result<PhaseWindow, MultiMintError> {
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
    PhaseWindow::new(starts_at, ends_at).map_err(|_| MultiMintError::StageChanged)
}

fn parse_protocol_time(value: &str) -> Result<u64, MultiMintError> {
    let timestamp = OffsetDateTime::parse(value, &Rfc3339)
        .map_err(|_| MultiMintError::StageChanged)?
        .unix_timestamp();
    u64::try_from(timestamp).map_err(|_| MultiMintError::StageChanged)
}

fn unix_timestamp() -> Result<u64, MultiMintError> {
    u64::try_from(OffsetDateTime::now_utc().unix_timestamp())
        .map_err(|_| MultiMintError::StageChanged)
}

fn unix_timestamp_millis() -> Result<u64, MultiMintError> {
    let millis = OffsetDateTime::now_utc()
        .unix_timestamp_nanos()
        .div_euclid(1_000_000);
    u64::try_from(millis).map_err(|_| MultiMintError::StageChanged)
}

async fn wait_for_launch_wake(
    config: &AppConfig,
    client: &WalletOpenSeaClient,
    original: &CollectionMetadata,
    selected: &StageMetadata,
    wake_lead_seconds: u64,
) -> Result<(CollectionMetadata, StageMetadata), MultiMintError> {
    let mut stage = selected.clone();
    loop {
        let phase = stage_window(&stage)?;
        if phase.execution_timing(unix_timestamp()?) == ExecutionTiming::Ended {
            return Err(MultiMintError::StageEnded);
        }
        let wake_at_ms = phase
            .starts_at()
            .checked_mul(1_000)
            .map(|starts_at| starts_at.saturating_sub(wake_lead_seconds.saturating_mul(1_000)))
            .ok_or(MultiMintError::ArithmeticOverflow)?;
        let now_ms = unix_timestamp_millis()?;
        if now_ms >= wake_at_ms {
            let refreshed = client.collection_metadata(&original.slug).await?;
            if !same_collection(original, &refreshed) {
                return Err(MultiMintError::StageChanged);
            }
            let refreshed_stage = matching_metadata_stage(&refreshed, selected)?.clone();
            validate_stage_windows(&refreshed)?;
            let refreshed_wake_at_ms = stage_window(&refreshed_stage)?
                .starts_at()
                .checked_mul(1_000)
                .map(|starts_at| starts_at.saturating_sub(wake_lead_seconds.saturating_mul(1_000)))
                .ok_or(MultiMintError::ArithmeticOverflow)?;
            if now_ms < refreshed_wake_at_ms {
                stage = refreshed_stage;
                continue;
            }
            return Ok((refreshed, refreshed_stage));
        }
        let refresh_wait = Duration::from_secs(config.scheduling.refresh_interval_seconds);
        let wake_wait = Duration::from_millis(wake_at_ms.saturating_sub(now_ms));
        let wait = wake_wait.min(refresh_wait);
        logging::countdown_until(phase.starts_at(), wait).await;
        if wait == wake_wait {
            continue;
        }
        let refreshed = client.collection_metadata(&original.slug).await?;
        if !same_collection(original, &refreshed) {
            return Err(MultiMintError::StageChanged);
        }
        stage = matching_metadata_stage(&refreshed, selected)?.clone();
        validate_stage_windows(&refreshed)?;
    }
}

async fn wait_for_calldata_hot_path(stage: &StageMetadata) -> Result<(), MultiMintError> {
    let hot_at_ms = stage_window(stage)?
        .starts_at()
        .checked_mul(1_000)
        .map(|starts_at| starts_at.saturating_sub(CALLDATA_HOT_LEAD_MS))
        .ok_or(MultiMintError::ArithmeticOverflow)?;
    loop {
        let remaining = hot_at_ms.saturating_sub(unix_timestamp_millis()?);
        if remaining == 0 {
            return Ok(());
        }
        sleep(Duration::from_millis(remaining)).await;
    }
}

fn retryable_action_error(error: &OpenSeaError) -> bool {
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

async fn verify_sponsored_environment(
    config: &AppConfig,
    gateway: &ChainGateway,
    chain: &ChainConfig,
    rpc_index: usize,
    executor: Address,
) -> Result<(), MultiMintError> {
    let (eip7702_is_live, eip1153_is_live, executor_verified) = logging::animate(
        "Verifying sponsored chain capabilities and executor runtime",
        async {
            let (eip7702_is_live, eip1153_is_live, executor_verified) = tokio::join!(
                gateway.eip7702_is_live(chain, rpc_index),
                gateway.eip1153_is_live(chain, rpc_index),
                gateway.wait_for_account_code_hash(
                    chain,
                    rpc_index,
                    CodeHashCheck {
                        account: executor,
                        block_number: None,
                        expected_hash: AUDITED_EXECUTOR_RUNTIME_HASH,
                        timeout_seconds: config.retry.pending_timeout_seconds,
                        poll_interval_ms: config.retry.base_delay_ms,
                        max_poll_interval_ms: config.retry.max_delay_ms,
                    },
                )
            );
            (eip7702_is_live, eip1153_is_live, executor_verified)
        },
    )
    .await;
    let eip7702_is_live = eip7702_is_live?;
    if !eip7702_is_live {
        return Err(MultiMintError::Eip7702Unavailable(chain.chain_id));
    }
    if !eip1153_is_live? {
        return Err(MultiMintError::Eip1153Unavailable(chain.chain_id));
    }
    logging::success(format!(
        "RPC chain {} supports live EIP-7702 delegated execution and EIP-1153 transient storage.",
        chain.chain_id
    ));

    let executor_verified = executor_verified?;
    if !executor_verified {
        return Err(MultiMintError::InvalidSponsoredDeployment);
    }
    Ok(())
}

async fn prepare_sponsored_launch(
    config: &AppConfig,
    gateway: &ChainGateway,
    chain: &ChainConfig,
    rpc_index: usize,
    sponsored: &SponsoredConfig,
    sponsor: &WalletSigner,
    candidates: &[ActionCandidate],
) -> Result<SponsoredLaunchSnapshot, MultiMintError> {
    let sponsor_address = sponsor.identity().address;
    let sponsor_snapshot = gateway
        .wallet_snapshot(chain, rpc_index, sponsor_address)
        .await?;
    let sponsor_state = sponsor_snapshot.account_state;
    let sponsor_inputs = sponsor_snapshot.submission_inputs;
    validate_sponsor_payer_code(&sponsor_state.code, sponsored.executor)?;
    let mut authorizations = HashMap::new();
    for candidate in candidates {
        let entry = &candidate.session.entry;
        let requirement = sponsored_delegation_requirement(classify_delegation(
            &candidate.account_state.code,
            sponsored.executor,
        ));
        let nonce = match requirement {
            SponsoredDelegationRequirement::Ready => continue,
            SponsoredDelegationRequirement::AuthorizationRequired { previous_delegate } => {
                if let Some(delegate) = previous_delegate {
                    logging::warn(format!(
                        "Wallet {} will replace its EIP-7702 delegation from {delegate} to {} in the sponsored mint transaction.",
                        entry.address(),
                        sponsored.executor
                    ));
                }
                sponsored_authorization_nonce(
                    entry.address(),
                    sponsor_address,
                    candidate.account_state.pending_nonce,
                )?
            }
            SponsoredDelegationRequirement::UnsupportedCode => {
                logging::warn(format!(
                    "Wallet {} has non-EIP-7702 code and cannot be authorized.",
                    entry.address()
                ));
                continue;
            }
        };
        authorizations.insert(
            entry.address(),
            sign_delegation(chain.chain_id, sponsored.executor, nonce, entry.signer())?,
        );
    }
    let fees = initial_transaction_fees(config.fees, sponsor_inputs.fee_estimate)?;
    let maximum_fees = maximum_transaction_fees(config.fees, config.retry.max_attempts, fees)?;
    let minimum_gas = sponsored
        .wallet_gas_limit
        .checked_mul(
            u64::try_from(candidates.len()).map_err(|_| MultiMintError::ArithmeticOverflow)?,
        )
        .ok_or(MultiMintError::ArithmeticOverflow)?;
    let minimum_requirement = FundingRequirement {
        mint_value: U256::ZERO,
        gas_limit: minimum_gas,
        max_fee_per_gas: maximum_fees.max_fee_per_gas,
    };
    if minimum_requirement.shortfall(sponsor_state.balance)? != U256::ZERO {
        return Err(MultiMintError::SponsorUnderfunded);
    }
    logging::success(format!(
        "Captured sponsored launch state and signed {} EIP-7702 authorization(s) outside the hot path.",
        authorizations.len()
    ));
    Ok(SponsoredLaunchSnapshot {
        sponsor_state,
        sponsor_inputs,
        authorizations,
    })
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn run_sponsored(
    config: &AppConfig,
    gateway: &ChainGateway,
    chain: &ChainConfig,
    rpc_index: usize,
    metadata: &CollectionMetadata,
    recipient: Address,
    actions: Vec<ActionWallet>,
    sponsored: &SponsoredConfig,
    sponsor: &WalletSigner,
    mut launch: SponsoredLaunchSnapshot,
    show_revocation_reminder: bool,
) -> Result<(), MultiMintError> {
    let sponsor_address = sponsor.identity().address;
    let batch_id = create_batch_id(
        chain.chain_id,
        sponsored.executor,
        sponsor_address,
        launch.sponsor_inputs.pending_nonce,
        &actions,
    )?;
    let mut unsigned_operations = Vec::with_capacity(actions.len());
    let mut authorizations: Vec<SignedAuthorization> = Vec::new();

    for wallet in actions {
        if wallet.entry.address() == recipient {
            logging::warn(format!(
                "Sponsored wallet skipped because it equals the recipient: {}",
                wallet.entry.address()
            ));
            continue;
        }
        match sponsored_delegation_requirement(classify_delegation(
            &wallet.account_state.code,
            sponsored.executor,
        )) {
            SponsoredDelegationRequirement::Ready => {}
            SponsoredDelegationRequirement::AuthorizationRequired { .. } => {
                let Some(authorization) = launch.authorizations.remove(&wallet.entry.address())
                else {
                    logging::warn(format!(
                        "Wallet skipped because its T-15 EIP-7702 authorization is unavailable: {}",
                        wallet.entry.address()
                    ));
                    continue;
                };
                authorizations.push(authorization);
            }
            SponsoredDelegationRequirement::UnsupportedCode => {
                logging::warn(format!(
                    "Wallet {} has non-EIP-7702 code and was skipped.",
                    wallet.entry.address()
                ));
                continue;
            }
        }

        let operation = SponsoredMintOperation::unsigned(UnsignedSponsoredMintOperation {
            wallet: wallet.entry.address(),
            mint_target: wallet.action.target,
            nft_contract: metadata.address,
            recipient,
            mint_value: wallet.action.value,
            expected_units: U256::from(wallet.entry.quantity()),
            mint_gas_limit: config.gas_limit,
            wallet_gas_limit: sponsored.wallet_gas_limit,
            deadline: 0,
            mint_calldata: wallet.action.calldata,
        });
        unsigned_operations.push((operation, wallet.entry));
    }
    if unsigned_operations.is_empty() {
        return Err(MultiMintError::NoEligibleWallets);
    }

    let provisional_operations = unsigned_operations
        .iter()
        .map(|(operation, _)| operation.clone())
        .collect::<Vec<_>>();
    let provisional_calldata = encode_execute_batch(
        chain.chain_id,
        sponsored.executor,
        sponsor_address,
        batch_id,
        &provisional_operations,
    )?;
    let provisional_gas_limit =
        sponsored_outer_gas_limit_upper_bound(provisional_calldata.len(), &provisional_operations)?;
    let fees = initial_transaction_fees(config.fees, launch.sponsor_inputs.fee_estimate)?;
    let maximum_fees = maximum_transaction_fees(config.fees, config.retry.max_attempts, fees)?;
    let requirement = FundingRequirement {
        mint_value: U256::ZERO,
        gas_limit: provisional_gas_limit,
        max_fee_per_gas: maximum_fees.max_fee_per_gas,
    };
    if requirement.shortfall(launch.sponsor_state.balance)? != U256::ZERO {
        return Err(MultiMintError::SponsorUnderfunded);
    }
    let deadline = unix_timestamp()?
        .checked_add(sponsored.operation_deadline_seconds)
        .ok_or(MultiMintError::ArithmeticOverflow)?;
    let mut operations = Vec::with_capacity(unsigned_operations.len());
    for (index, (mut operation, entry)) in unsigned_operations.into_iter().enumerate() {
        operation.deadline = deadline;
        sign_operation(
            chain.chain_id,
            sponsored.executor,
            sponsor_address,
            batch_id,
            index,
            &mut operation,
            entry.signer(),
        )?;
        operations.push(operation);
    }
    let calldata = encode_execute_batch(
        chain.chain_id,
        sponsored.executor,
        sponsor_address,
        batch_id,
        &operations,
    )?;
    let final_gas_limit = sponsored_outer_gas_limit(&calldata, &operations)?;
    if calldata.len() != provisional_calldata.len() || final_gas_limit > provisional_gas_limit {
        return Err(MultiMintError::SponsoredGasBoundExceeded);
    }

    let signed = if authorizations.is_empty() {
        sign_eip1559_transaction(
            &Eip1559Transaction {
                chain_id: chain.chain_id,
                nonce: launch.sponsor_inputs.pending_nonce,
                max_priority_fee_per_gas: fees.max_priority_fee_per_gas,
                max_fee_per_gas: fees.max_fee_per_gas,
                gas_limit: final_gas_limit,
                target: sponsored.executor,
                value: U256::ZERO,
                calldata,
            },
            sponsor,
        )?
    } else {
        sign_eip7702_transaction(
            &Eip7702Transaction {
                chain_id: chain.chain_id,
                nonce: launch.sponsor_inputs.pending_nonce,
                max_priority_fee_per_gas: fees.max_priority_fee_per_gas,
                max_fee_per_gas: fees.max_fee_per_gas,
                gas_limit: final_gas_limit,
                target: sponsored.executor,
                value: U256::ZERO,
                calldata,
                authorization_list: authorizations,
            },
            sponsor,
        )?
    };
    logging::info(format!(
        "Submitting one sponsored batch for {} wallet(s): {}",
        operations.len(),
        signed.hash()
    ));
    let receipt = submit_outer(config, gateway, chain, rpc_index, &signed).await?;
    if !receipt.is_success {
        return Err(MultiMintError::TransactionReverted(receipt.block_number));
    }
    let outcomes = decode_sponsored_outcomes(
        &receipt,
        sponsored.executor,
        batch_id,
        sponsor_address,
        &operations,
    )?;
    let succeeded = outcomes.iter().filter(|outcome| outcome.success).count();
    let failed = operations.len() - succeeded;
    let failed_wallets = outcomes
        .iter()
        .filter(|outcome| !outcome.success)
        .map(|outcome| {
            format!(
                "{} (selector=0x{})",
                outcome.wallet,
                hex::encode(outcome.error_selector)
            )
        })
        .collect::<Vec<_>>();
    if failed_wallets.is_empty() {
        logging::success(format!(
            "Sponsored batch confirmed: succeeded={succeeded}, failed=0; all NFTs were forwarded."
        ));
    } else {
        logging::warn(format!(
            "Sponsored batch confirmed: succeeded={succeeded}, failed={failed}; successful NFTs were forwarded and failed wallets retained their mint balances; failed wallets: {}.",
            failed_wallets.join(", ")
        ));
    }
    if show_revocation_reminder {
        warn_sponsored_revocation(
            "Sponsored phase sequence finished; delegation may remain active for manifest wallets. Revoke with:",
        );
    }
    Ok(())
}

const fn sponsored_delegation_requirement(
    delegation: DelegationState,
) -> SponsoredDelegationRequirement {
    match delegation {
        DelegationState::Expected => SponsoredDelegationRequirement::Ready,
        DelegationState::Clear => SponsoredDelegationRequirement::AuthorizationRequired {
            previous_delegate: None,
        },
        DelegationState::Unexpected(delegate) => {
            SponsoredDelegationRequirement::AuthorizationRequired {
                previous_delegate: Some(delegate),
            }
        }
        DelegationState::OtherCode => SponsoredDelegationRequirement::UnsupportedCode,
    }
}

fn sponsored_authorization_nonce(
    wallet: Address,
    sponsor: Address,
    pending_nonce: u64,
) -> Result<u64, MultiMintError> {
    if wallet == sponsor {
        pending_nonce
            .checked_add(1)
            .ok_or(MultiMintError::ArithmeticOverflow)
    } else {
        Ok(pending_nonce)
    }
}

pub async fn undelegate(
    config: &AppConfig,
    multi: &MultiWalletConfig,
    sponsor_key: Option<&str>,
) -> Result<(), MultiMintError> {
    let sponsor = WalletSigner::from_private_key(
        sponsor_key.ok_or(MultiMintError::MissingRevocationSponsor)?,
    )?;
    let manifest = WalletManifest::load(&multi.manifest_path)?;
    let gateway = ChainGateway::new(Duration::from_millis(config.opensea.request_timeout_ms))?;
    let probe = gateway.probe_rpc(&config.rpc_url).await?;
    let chain = ChainConfig {
        chain_id: probe.chain_id,
        rpc_urls: vec![config.rpc_url.clone()],
    };
    if !gateway.eip7702_is_live(&chain, probe.rpc_index).await? {
        return Err(MultiMintError::Eip7702Unavailable(chain.chain_id));
    }
    let mut revoked = 0_usize;
    for chunk in manifest
        .wallets()
        .chunks(crate::sponsored::MAX_SPONSORED_BATCH_SIZE)
    {
        revoked +=
            undelegate_chunk(config, &gateway, &chain, probe.rpc_index, &sponsor, chunk).await?;
    }
    if revoked == 0 {
        logging::success("No EIP-7702 delegations remain in the selected wallet file.");
    } else {
        logging::success(format!("Cleared {revoked} EIP-7702 delegation(s)."));
    }
    Ok(())
}

async fn undelegate_chunk(
    config: &AppConfig,
    gateway: &ChainGateway,
    chain: &ChainConfig,
    rpc_index: usize,
    sponsor: &WalletSigner,
    entries: &[WalletEntry],
) -> Result<usize, MultiMintError> {
    let sponsor_address = sponsor.identity().address;
    let sponsor_snapshot = gateway
        .wallet_snapshot(chain, rpc_index, sponsor_address)
        .await?;
    let (revocations, authorities) =
        prepare_revocations(gateway, chain, rpc_index, sponsor_address, entries).await?;
    if revocations.is_empty() {
        return Ok(0);
    }
    let authorization_gas = u64::try_from(revocations.len())
        .ok()
        .and_then(|count| count.checked_mul(AUTHORIZATION_GAS))
        .ok_or(MultiMintError::ArithmeticOverflow)?;
    let gas_limit = REVOCATION_BASE_GAS
        .checked_add(authorization_gas)
        .ok_or(MultiMintError::ArithmeticOverflow)?;
    let fees =
        initial_transaction_fees(config.fees, sponsor_snapshot.submission_inputs.fee_estimate)?;
    ensure_sponsor_funding(
        gateway,
        chain,
        rpc_index,
        sponsor_address,
        U256::ZERO,
        gas_limit,
        fees.max_fee_per_gas,
    )
    .await?;
    let refreshed_sponsor = validate_revocation_state(
        gateway,
        chain,
        rpc_index,
        sponsor_address,
        &sponsor_snapshot.submission_inputs,
        &authorities,
    )
    .await?;
    let fees = initial_transaction_fees(
        config.fees,
        refreshed_sponsor.submission_inputs.fee_estimate,
    )?;
    let transaction = Eip7702Transaction {
        chain_id: chain.chain_id,
        nonce: refreshed_sponsor.submission_inputs.pending_nonce,
        max_priority_fee_per_gas: fees.max_priority_fee_per_gas,
        max_fee_per_gas: fees.max_fee_per_gas,
        gas_limit,
        target: authorities[0].address,
        value: U256::ZERO,
        calldata: Bytes::new(),
        authorization_list: revocations,
    };
    let signed = sign_eip7702_transaction(&transaction, sponsor)?;
    logging::info(format!(
        "Submitting {} EIP-7702 revocation(s): {}",
        authorities.len(),
        signed.hash()
    ));
    let receipt = submit_outer(config, gateway, chain, rpc_index, &signed).await?;
    if !receipt.is_success {
        logging::warn(
            "Revocation execution reverted; authorization changes are verified independently.",
        );
    }
    verify_revocations_cleared(gateway, chain, rpc_index, &authorities).await?;
    Ok(authorities.len())
}

async fn prepare_revocations(
    gateway: &ChainGateway,
    chain: &ChainConfig,
    rpc_index: usize,
    sponsor: Address,
    entries: &[WalletEntry],
) -> Result<(Vec<SignedAuthorization>, Vec<RevocationAuthority>), MultiMintError> {
    let mut revocations = Vec::new();
    let mut authorities = Vec::new();
    for entry in entries {
        let state = gateway
            .account_state(chain, rpc_index, entry.address())
            .await?;
        match classify_delegation(&state.code, Address::ZERO) {
            DelegationState::Clear => {
                logging::success(format!("Wallet already undelegated: {}", entry.address()));
            }
            DelegationState::Unexpected(_) | DelegationState::Expected => {
                let nonce = if entry.address() == sponsor {
                    state
                        .pending_nonce
                        .checked_add(1)
                        .ok_or(MultiMintError::ArithmeticOverflow)?
                } else {
                    state.pending_nonce
                };
                revocations.push(sign_delegation(
                    chain.chain_id,
                    Address::ZERO,
                    nonce,
                    entry.signer(),
                )?);
                authorities.push(RevocationAuthority {
                    address: entry.address(),
                    initial_state: state,
                });
            }
            DelegationState::OtherCode => logging::warn(format!(
                "Wallet has non-EIP-7702 code and cannot be revoked by this flow: {}",
                entry.address()
            )),
        }
    }
    Ok((revocations, authorities))
}

async fn validate_revocation_state(
    gateway: &ChainGateway,
    chain: &ChainConfig,
    rpc_index: usize,
    sponsor: Address,
    sponsor_inputs: &SubmissionInputs,
    authorities: &[RevocationAuthority],
) -> Result<crate::chain::WalletSnapshot, MultiMintError> {
    for authority in authorities {
        let refreshed = gateway
            .account_state(chain, rpc_index, authority.address)
            .await?;
        if refreshed.pending_nonce != authority.initial_state.pending_nonce
            || refreshed.code != authority.initial_state.code
        {
            return Err(MultiMintError::RevocationWalletChanged(authority.address));
        }
    }
    let refreshed_sponsor = gateway.wallet_snapshot(chain, rpc_index, sponsor).await?;
    if refreshed_sponsor.submission_inputs.pending_nonce != sponsor_inputs.pending_nonce {
        return Err(MultiMintError::RevocationWalletChanged(sponsor));
    }
    Ok(refreshed_sponsor)
}

async fn verify_revocations_cleared(
    gateway: &ChainGateway,
    chain: &ChainConfig,
    rpc_index: usize,
    authorities: &[RevocationAuthority],
) -> Result<(), MultiMintError> {
    let mut remaining = 0_usize;
    for authority in authorities {
        let state = gateway
            .account_state(chain, rpc_index, authority.address)
            .await?;
        if state.code.is_empty() {
            logging::success(format!("Delegation cleared: {}", authority.address));
        } else {
            remaining += 1;
            logging::warn(format!("Delegation remains active: {}", authority.address));
        }
    }
    if remaining == 0 {
        Ok(())
    } else {
        Err(MultiMintError::RevocationIncomplete)
    }
}

fn create_batch_id(
    chain_id: u64,
    executor: Address,
    sponsor: Address,
    sponsor_nonce: u64,
    actions: &[ActionWallet],
) -> Result<B256, MultiMintError> {
    let mut material = Vec::with_capacity(128 + actions.len().saturating_mul(128));
    material.extend_from_slice(&chain_id.to_be_bytes());
    material.extend_from_slice(executor.as_slice());
    material.extend_from_slice(sponsor.as_slice());
    material.extend_from_slice(&sponsor_nonce.to_be_bytes());
    material.extend_from_slice(
        &OffsetDateTime::now_utc()
            .unix_timestamp_nanos()
            .to_be_bytes(),
    );
    for wallet in actions {
        material.extend_from_slice(wallet.entry.address().as_slice());
        material.extend_from_slice(wallet.action.target.as_slice());
        material.extend_from_slice(&wallet.action.value.to_be_bytes::<32>());
        material.extend_from_slice(keccak256(&wallet.action.calldata).as_slice());
    }
    let batch_id = keccak256(material);
    if batch_id == B256::ZERO {
        return Err(MultiMintError::ArithmeticOverflow);
    }
    Ok(batch_id)
}

fn validate_sponsor_payer_code(code: &[u8], executor: Address) -> Result<(), MultiMintError> {
    match classify_delegation(code, executor) {
        DelegationState::Clear | DelegationState::Expected | DelegationState::Unexpected(_) => {
            Ok(())
        }
        DelegationState::OtherCode => Err(MultiMintError::InvalidSponsoredDeployment),
    }
}

async fn ensure_sponsor_funding(
    gateway: &ChainGateway,
    chain: &ChainConfig,
    rpc_index: usize,
    sponsor: Address,
    value: U256,
    gas_limit: u64,
    max_fee_per_gas: U256,
) -> Result<(), MultiMintError> {
    let requirement = FundingRequirement {
        mint_value: value,
        gas_limit,
        max_fee_per_gas,
    };
    loop {
        let state = gateway.account_state(chain, rpc_index, sponsor).await?;
        let shortfall = requirement.shortfall(state.balance)?;
        if shortfall == U256::ZERO {
            return Ok(());
        }
        logging::warn(format!(
            "Sponsor {sponsor} is underfunded by {shortfall} wei."
        ));
        match terminal::prompt_top_up()? {
            TopUpDecision::Recheck => {}
            TopUpDecision::Skip => return Err(MultiMintError::SponsorUnderfunded),
        }
    }
}

async fn submit_outer(
    config: &AppConfig,
    gateway: &ChainGateway,
    chain: &ChainConfig,
    rpc_index: usize,
    signed: &SignedTransaction,
) -> Result<TransactionReceipt, MultiMintError> {
    let hash = signed.hash();
    gateway
        .send_raw_transaction(chain, rpc_index, signed)
        .await
        .map_err(|_| MultiMintError::BroadcastUncertain(hash))?;
    gateway
        .wait_for_any_transaction_receipt(
            chain,
            rpc_index,
            &[hash],
            ReceiptPollingPolicy::from(config.retry),
        )
        .await?
        .map(|(_, receipt)| receipt)
        .ok_or(MultiMintError::PendingTransaction(hash))
}

struct SponsoredOutcome {
    wallet: Address,
    success: bool,
    error_selector: [u8; 4],
}

fn decode_sponsored_outcomes(
    receipt: &TransactionReceipt,
    executor: Address,
    batch_id: B256,
    sponsor: Address,
    operations: &[SponsoredMintOperation],
) -> Result<Vec<SponsoredOutcome>, MultiMintError> {
    let event_topic = keccak256("WalletExecution(bytes32,address,address,uint256,bool,bytes4)");
    let sponsor_topic = address_topic(sponsor);
    let mut outcomes: Vec<Option<SponsoredOutcome>> = std::iter::repeat_with(|| None)
        .take(operations.len())
        .collect();
    for log in receipt
        .logs
        .iter()
        .filter(|log| log.address == executor && log.topics.first() == Some(&event_topic))
    {
        if log.topics.len() != 4
            || log.topics[1] != batch_id
            || log.topics[2] != sponsor_topic
            || log.data.len() != 96
        {
            return Err(MultiMintError::InvalidSponsoredReceipt);
        }
        let index = usize::try_from(abi_u64(&log.data[..32])?)
            .map_err(|_| MultiMintError::InvalidSponsoredReceipt)?;
        let success = match abi_u64(&log.data[32..64])? {
            0 => false,
            1 => true,
            _ => return Err(MultiMintError::InvalidSponsoredReceipt),
        };
        let wallet = topic_address(log.topics[3])?;
        if index >= operations.len()
            || operations[index].wallet != wallet
            || outcomes[index].is_some()
            || log.data[68..] != [0_u8; 28]
        {
            return Err(MultiMintError::InvalidSponsoredReceipt);
        }
        let mut error_selector = [0_u8; 4];
        error_selector.copy_from_slice(&log.data[64..68]);
        if success && error_selector != [0_u8; 4] {
            return Err(MultiMintError::InvalidSponsoredReceipt);
        }
        outcomes[index] = Some(SponsoredOutcome {
            wallet,
            success,
            error_selector,
        });
    }
    outcomes
        .into_iter()
        .map(|outcome| outcome.ok_or(MultiMintError::InvalidSponsoredReceipt))
        .collect()
}

fn address_topic(address: Address) -> B256 {
    let mut topic = [0_u8; 32];
    topic[12..].copy_from_slice(address.as_slice());
    B256::from(topic)
}

fn topic_address(topic: B256) -> Result<Address, MultiMintError> {
    if topic[..12] != [0_u8; 12] {
        return Err(MultiMintError::InvalidSponsoredReceipt);
    }
    Ok(Address::from_slice(&topic[12..]))
}

fn abi_u64(word: &[u8]) -> Result<u64, MultiMintError> {
    if word.len() != 32 || word[..24] != [0_u8; 24] {
        return Err(MultiMintError::InvalidSponsoredReceipt);
    }
    let value: [u8; 8] = word[24..]
        .try_into()
        .map_err(|_| MultiMintError::InvalidSponsoredReceipt)?;
    Ok(u64::from_be_bytes(value))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selected_multi_phases_run_in_chronological_order() {
        let mut phases = vec![scheduled_phase(0, 30), scheduled_phase(1, 10)];

        sort_scheduled_phases(&mut phases);

        assert_eq!(phases[0].option_index, 1);
        assert_eq!(phases[1].option_index, 0);
    }

    #[test]
    fn sponsor_payer_may_use_any_exact_eip7702_delegation() {
        let executor = Address::repeat_byte(0x11);
        let other_delegate = Address::repeat_byte(0x22);

        validate_sponsor_payer_code(&[], executor).expect("clear sponsor");
        validate_sponsor_payer_code(&crate::sponsored::delegation_designator(executor), executor)
            .expect("expected delegation");
        validate_sponsor_payer_code(
            &crate::sponsored::delegation_designator(other_delegate),
            executor,
        )
        .expect("other delegation");
        assert!(validate_sponsor_payer_code(&[0x60, 0x00], executor).is_err());
    }

    #[test]
    fn sponsored_wallet_replaces_an_existing_eip7702_delegation() {
        let previous_delegate = Address::repeat_byte(0x22);

        assert_eq!(
            sponsored_delegation_requirement(DelegationState::Expected),
            SponsoredDelegationRequirement::Ready
        );
        assert_eq!(
            sponsored_delegation_requirement(DelegationState::Clear),
            SponsoredDelegationRequirement::AuthorizationRequired {
                previous_delegate: None
            }
        );
        assert_eq!(
            sponsored_delegation_requirement(DelegationState::Unexpected(previous_delegate)),
            SponsoredDelegationRequirement::AuthorizationRequired {
                previous_delegate: Some(previous_delegate)
            }
        );
        assert_eq!(
            sponsored_delegation_requirement(DelegationState::OtherCode),
            SponsoredDelegationRequirement::UnsupportedCode
        );
    }

    #[test]
    fn sponsored_authorization_nonce_accounts_for_the_outer_sender_nonce() {
        let wallet = Address::repeat_byte(0x11);
        let sponsor = Address::repeat_byte(0x22);

        assert_eq!(
            sponsored_authorization_nonce(wallet, sponsor, 7).expect("wallet nonce"),
            7
        );
        assert_eq!(
            sponsored_authorization_nonce(sponsor, sponsor, 7).expect("sender nonce"),
            8
        );
        assert!(matches!(
            sponsored_authorization_nonce(sponsor, sponsor, u64::MAX),
            Err(MultiMintError::ArithmeticOverflow)
        ));
    }

    fn scheduled_phase(option_index: usize, starts_at: u64) -> ScheduledMultiPhase {
        ScheduledMultiPhase {
            option_index,
            stage: StageMetadata {
                kind: "Erc721SeaDropV1Stage".into(),
                stage_type: "PUBLIC_SALE".into(),
                stage_index: u32::try_from(option_index).expect("stage index"),
                start_time: Some("2026-08-15T23:00:38.000Z".into()),
                end_time: Some("2026-08-15T23:10:38.000Z".into()),
                max_total_mintable_by_wallet: Some(100),
                max_total_mintable_by_wallet_per_token: None,
                token_range: None,
            },
            token_id: "0".into(),
            starts_at,
        }
    }

    #[test]
    fn launch_constants_keep_rpc_state_outside_the_hot_path() {
        assert_eq!(SPONSORED_WAKE_LEAD_SECONDS, 15);
        assert_eq!(STANDARD_WAKE_LEAD_SECONDS, 10);
        assert_eq!(CALLDATA_HOT_LEAD_MS, 2_000);
        assert!(retryable_action_error(&OpenSeaError::MintStageNotOpen));
        assert!(retryable_action_error(&OpenSeaError::InvalidProtocolValue));
        assert!(retryable_action_error(&OpenSeaError::Compatibility));
        assert!(retryable_action_error(&OpenSeaError::UnsafeMintAction {
            reason: "stale stage action",
        }));
        assert!(!retryable_action_error(
            &OpenSeaError::AuthenticationRequired
        ));
    }

    #[test]
    fn setup_funding_reserves_every_required_self_funded_transaction() {
        let wallet = Address::repeat_byte(0x11);
        let recipient = Address::repeat_byte(0x22);

        assert_eq!(
            self_funded_transaction_count("Erc721SeaDropV1", wallet, wallet, 3)
                .expect("wallet recipient"),
            1
        );
        assert_eq!(
            self_funded_transaction_count("Erc721SeaDropV1", recipient, wallet, 3)
                .expect("ERC-721 forwarding"),
            4
        );
        assert_eq!(
            self_funded_transaction_count("Erc1155SeaDropV2", recipient, wallet, 3)
                .expect("ERC-1155 forwarding"),
            2
        );
    }

    #[test]
    fn sponsored_wallet_action_funding_includes_mint_value_and_gas_reserve() {
        let wallet = Address::repeat_byte(0x11);
        let mint_value = sponsored_wallet_mint_value(wallet, Some(U256::from(20_u64)), 3)
            .expect("wallet mint value");
        assert_eq!(mint_value, U256::from(60_u64));
        let requirement =
            sponsored_wallet_action_requirement(mint_value, 300_000, U256::from(4_u8));
        assert_eq!(
            requirement.maximum_native_cost().expect("maximum cost"),
            U256::from(1_200_060_u64)
        );
        assert!(matches!(
            sponsored_wallet_mint_value(wallet, None, 1),
            Err(MultiMintError::SponsoredMintPriceUnavailable(address)) if address == wallet
        ));
        assert!(matches!(
            sponsored_wallet_mint_value(wallet, Some(U256::MAX), 2),
            Err(MultiMintError::ArithmeticOverflow)
        ));
    }

    use crate::chain::{TransactionLog, TransactionReceipt};

    #[test]
    fn enforces_fixed_mode_wallet_limits() {
        assert!(validate_mode_wallet_limit(&MultiWalletMode::SelfFunded, 10).is_ok());
        assert!(matches!(
            validate_mode_wallet_limit(&MultiWalletMode::SelfFunded, 11),
            Err(MultiMintError::SelfFundedWalletLimit)
        ));

        let sponsored = MultiWalletMode::Sponsored(SponsoredConfig {
            executor: Address::repeat_byte(1),
            wallet_gas_limit: 550_000,
            operation_deadline_seconds: 120,
        });
        assert!(validate_mode_wallet_limit(&sponsored, 25).is_ok());
        assert!(matches!(
            validate_mode_wallet_limit(&sponsored, 26),
            Err(MultiMintError::Sponsored(
                SponsoredMintError::InvalidBatchSize
            ))
        ));
    }

    fn operation(wallet: Address) -> SponsoredMintOperation {
        SponsoredMintOperation::unsigned(UnsignedSponsoredMintOperation {
            wallet,
            mint_target: Address::repeat_byte(2),
            nft_contract: Address::repeat_byte(3),
            recipient: Address::repeat_byte(4),
            mint_value: U256::ZERO,
            expected_units: U256::ONE,
            mint_gas_limit: 100_000,
            wallet_gas_limit: 125_000,
            deadline: 2_000_000_000,
            mint_calldata: Bytes::from_static(&[1, 2, 3, 4]),
        })
    }

    fn outcome_data(index: u64, success: bool, selector: [u8; 4]) -> Bytes {
        let mut data = vec![0_u8; 96];
        data[24..32].copy_from_slice(&index.to_be_bytes());
        data[63] = u8::from(success);
        data[64..68].copy_from_slice(&selector);
        Bytes::from(data)
    }

    #[test]
    fn decodes_one_exact_sponsored_result_per_operation() {
        let executor = Address::repeat_byte(1);
        let sponsor = Address::repeat_byte(5);
        let wallet = Address::repeat_byte(6);
        let batch_id = B256::repeat_byte(7);
        let operations = [operation(wallet)];
        let receipt = TransactionReceipt {
            transaction_hash: B256::repeat_byte(8),
            block_number: 9,
            is_success: true,
            contract_address: None,
            logs: vec![TransactionLog {
                address: executor,
                topics: vec![
                    keccak256("WalletExecution(bytes32,address,address,uint256,bool,bytes4)"),
                    batch_id,
                    address_topic(sponsor),
                    address_topic(wallet),
                ],
                data: outcome_data(0, false, [0xde, 0xad, 0xbe, 0xef]),
            }],
        };
        let outcomes =
            decode_sponsored_outcomes(&receipt, executor, batch_id, sponsor, &operations)
                .expect("outcome");
        assert_eq!(outcomes.len(), 1);
        assert!(!outcomes[0].success);
        assert_eq!(outcomes[0].error_selector, [0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn rejects_missing_or_inconsistent_sponsored_results() {
        let executor = Address::repeat_byte(1);
        let sponsor = Address::repeat_byte(5);
        let wallet = Address::repeat_byte(6);
        let batch_id = B256::repeat_byte(7);
        let operations = [operation(wallet)];
        let receipt = TransactionReceipt {
            transaction_hash: B256::repeat_byte(8),
            block_number: 9,
            is_success: true,
            contract_address: None,
            logs: Vec::new(),
        };
        assert!(
            decode_sponsored_outcomes(&receipt, executor, batch_id, sponsor, &operations).is_err()
        );

        let mut inconsistent = receipt;
        inconsistent.logs.push(TransactionLog {
            address: executor,
            topics: vec![
                keccak256("WalletExecution(bytes32,address,address,uint256,bool,bytes4)"),
                batch_id,
                address_topic(sponsor),
                address_topic(wallet),
            ],
            data: outcome_data(0, true, [1, 0, 0, 0]),
        });
        assert!(
            decode_sponsored_outcomes(&inconsistent, executor, batch_id, sponsor, &operations)
                .is_err()
        );
    }
}
