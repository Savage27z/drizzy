use std::{fmt, future::Future, str::FromStr, time::Duration};

use alloy_primitives::{Address, B256, Bytes, U256, address, b256, keccak256};
use alloy_sol_types::{SolCall, sol};
use thiserror::Error;
use tokio::time::sleep;

use crate::{
    chain::{
        AccountState, ChainError, ChainGateway, ReceiptPollingPolicy, SubmissionInputs,
        TransactionReceipt,
    },
    config::{AppConfig, ChainConfig, MultiWalletConfig, MultiWalletMode},
    domain::{AutomaticFeePolicy, Eip1559Fees, FeeError},
    fee::{initial_transaction_fees, maximum_transaction_fees},
    logging,
    multi_wallet::{MAX_SELF_FUNDED_WALLETS, WalletEntry, WalletManifest, WalletManifestError},
    signing::{WalletSigner, WalletSignerError},
    sponsored::{
        AUDITED_EXECUTOR_RUNTIME_HASH, DelegationState, MAX_SPONSORED_BATCH_SIZE,
        classify_delegation,
    },
    terminal::{self, TerminalError},
    transaction::{Eip1559Transaction, TransactionError, sign_eip1559_transaction},
};

pub const MULTICALL3_ADDRESS: Address = address!("cA11bde05977b3631167028862bE2a173976CA11");
pub const MULTICALL3_RUNTIME_HASH: B256 =
    b256!("d5c15df687b16f2ff992fc8d767b4216323184a2bbc6ee2f9c398c318e770891");

const NATIVE_DECIMALS: usize = 18;
const NATIVE_SCALE: u64 = 1_000_000_000_000_000_000;
const DIRECT_TRANSFER_MAX_ATTEMPTS: u32 = 3;
const GAS_BUFFER_BPS: u64 = 12_000;
const GAS_BUFFER_DENOMINATOR: u64 = 10_000;
const MINIMUM_GAS_BUFFER: u64 = 5_000;

sol! {
    #[derive(Debug, PartialEq, Eq)]
    struct Call3Value {
        address target;
        bool allowFailure;
        uint256 value;
        bytes callData;
    }

    #[derive(Debug, PartialEq, Eq)]
    struct CallResult {
        bool success;
        bytes returnData;
    }

    #[derive(Debug, PartialEq, Eq)]
    function aggregate3Value(Call3Value[] calls) external payable returns (CallResult[] returnData);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeAmount(U256);

impl NativeAmount {
    #[must_use]
    pub const fn wei(self) -> U256 {
        self.0
    }
}

impl FromStr for NativeAmount {
    type Err = NativeFundsError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        parse_native_amount(value).map(Self)
    }
}

impl fmt::Display for NativeAmount {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let scale = U256::from(NATIVE_SCALE);
        let whole = self.0 / scale;
        let remainder = self.0 % scale;
        if remainder == U256::ZERO {
            return write!(formatter, "{whole}");
        }
        let fractional = format!("{remainder:018}");
        write!(formatter, "{whole}.{}", fractional.trim_end_matches('0'))
    }
}

#[derive(Debug, Error)]
pub enum NativeFundsError {
    #[error(transparent)]
    Chain(#[from] ChainError),
    #[error(transparent)]
    Fee(#[from] FeeError),
    #[error(transparent)]
    Manifest(#[from] WalletManifestError),
    #[error(transparent)]
    Signer(#[from] WalletSignerError),
    #[error(transparent)]
    Terminal(#[from] TerminalError),
    #[error(transparent)]
    Transaction(#[from] TransactionError),
    #[error("--fund and --withdraw require WALLETS_FILE multi-wallet mode")]
    MultiWalletRequired,
    #[error("--withdraw requires SPONSORED=false")]
    WithdrawSelfFundedOnly,
    #[error("--fund requires SPONSOR_KEY to pay the funding transaction(s)")]
    MissingFundingKey,
    #[error("native amount must be a positive base-10 value with at most 18 decimal places")]
    InvalidAmount,
    #[error("this native-currency operation supports at most {maximum} manifest wallets")]
    WalletLimit { maximum: usize },
    #[error("native-currency arithmetic overflowed")]
    ArithmeticOverflow,
    #[error("funding payer must not also appear in WALLETS_FILE")]
    FundingPayerInManifest,
    #[error("wallet {0} has unsupported account code or delegation; undelegate it before funding")]
    FundingTargetHasCode(Address),
    #[error(
        "a delegated funding target points to an executor whose runtime is not the audited build"
    )]
    FundingExecutorMismatch,
    #[error(
        "the delegated funding executor runtime changed after confirmation; nothing was submitted"
    )]
    FundingExecutorStateChanged,
    #[error("the transaction payer has malformed or non-EIP-7702 account code")]
    InvalidPayerCode,
    #[error("withdrawal recipient has arbitrary contract code")]
    InvalidRecipientCode,
    #[error("the canonical Multicall3 runtime changed after confirmation; nothing was submitted")]
    MulticallStateChanged,
    #[error("wallet {0} executable code changed after confirmation; it was not signed")]
    WalletCodeChanged(Address),
    #[error("withdrawal gas estimate for wallet {0} exceeded its protected buffer")]
    WithdrawalGasUnstable(Address),
    #[error("payer balance is below the current maximum cost of {required_wei} wei")]
    PayerUnderfunded { required_wei: U256 },
    #[error("no wallet has enough balance to withdraw after reserving maximum gas")]
    NothingToWithdraw,
    #[error("transaction broadcast outcome is uncertain for local hash {0}")]
    BroadcastUncertain(B256),
    #[error("RPC rate limiting exhausted the two retries for local hash {0}")]
    RateLimitExhausted(B256),
    #[error("transaction {0} remained pending after its initial submission and two retries")]
    Pending(B256),
    #[error("receipt tracking became uncertain after broadcasting {0}")]
    ReceiptUncertain(B256),
    #[error("transaction reverted in block {block_number}")]
    Reverted { block_number: u64 },
    #[error("native-currency operation finished with {succeeded} succeeded and {failed} failed")]
    PartialFailure { succeeded: usize, failed: usize },
}

struct WithdrawalPlan {
    entry: WalletEntry,
    state: AccountState,
    inputs: SubmissionInputs,
    gas_limit: u64,
    maximum_fees: Eip1559Fees,
    initial_value: U256,
}

struct FundingTargetSnapshot {
    wallet_codes: Vec<Bytes>,
    delegated_executor: Option<(Address, Bytes)>,
}

#[derive(Clone, Copy)]
struct WithdrawalQuote {
    fees: Eip1559Fees,
    maximum_fees: Eip1559Fees,
    gas_limit: u64,
    initial_value: U256,
}

#[derive(Clone, Copy)]
struct FundingSubmission {
    nonce: u64,
    fees: Eip1559Fees,
    maximum_cost: U256,
}

enum TransferValue {
    Fixed(U256),
    Sweep { balance: U256 },
}

impl TransferValue {
    fn at_fee(&self, gas_limit: u64, max_fee_per_gas: U256) -> Result<U256, NativeFundsError> {
        match self {
            Self::Fixed(value) => Ok(*value),
            Self::Sweep { balance } => {
                let reserve = maximum_gas_cost(gas_limit, max_fee_per_gas)?;
                balance
                    .checked_sub(reserve)
                    .filter(|value| *value != U256::ZERO)
                    .ok_or(NativeFundsError::NothingToWithdraw)
            }
        }
    }
}

pub async fn fund(
    config: &AppConfig,
    multi: &MultiWalletConfig,
    sponsor_key: Option<&str>,
    amount: NativeAmount,
) -> Result<(), NativeFundsError> {
    let manifest = load_manifest(multi, funding_wallet_limit(&multi.mode))?;
    let payer =
        WalletSigner::from_private_key(sponsor_key.ok_or(NativeFundsError::MissingFundingKey)?)?;
    let payer_address = payer.identity().address;
    if manifest
        .wallets()
        .iter()
        .any(|wallet| wallet.address() == payer_address)
    {
        return Err(NativeFundsError::FundingPayerInManifest);
    }

    let (gateway, chain, rpc_index) = connect(config).await?;
    let funding_targets = load_funding_target_states(
        config,
        &gateway,
        &chain,
        rpc_index,
        &manifest,
        funding_executor(&multi.mode),
    )
    .await?;
    let multicall_state = rpc_read_retry(config, || {
        gateway.account_state(&chain, rpc_index, MULTICALL3_ADDRESS)
    })
    .await?;
    let total_value = amount
        .wei()
        .checked_mul(U256::from(manifest.len()))
        .ok_or(NativeFundsError::ArithmeticOverflow)?;

    if keccak256(&multicall_state.code) == MULTICALL3_RUNTIME_HASH {
        fund_with_multicall(
            config,
            &gateway,
            &chain,
            rpc_index,
            &payer,
            manifest,
            funding_targets,
            amount,
            total_value,
        )
        .await
    } else {
        if multicall_state.code.is_empty() {
            logging::warn(format!(
                "Canonical Multicall3 is absent on chain {}; using sequential direct funding.",
                chain.chain_id
            ));
        } else {
            logging::warn(format!(
                "Canonical Multicall3 runtime mismatch on chain {}; refusing it and using sequential direct funding.",
                chain.chain_id
            ));
        }
        fund_directly(
            config,
            &gateway,
            &chain,
            rpc_index,
            &payer,
            manifest,
            funding_targets,
            amount,
            total_value,
        )
        .await
    }
}

#[allow(clippy::too_many_lines)]
pub async fn withdraw(
    config: &AppConfig,
    multi: &MultiWalletConfig,
) -> Result<(), NativeFundsError> {
    require_self_funded_withdrawal(multi)?;
    let manifest = load_manifest(multi, MAX_SELF_FUNDED_WALLETS)?;
    let (gateway, chain, rpc_index) = connect(config).await?;
    let recipient_state = rpc_read_retry(config, || {
        gateway.account_state(&chain, rpc_index, multi.recipient)
    })
    .await?;
    report_recipient_code(&recipient_state.code)?;

    let mut plans = Vec::with_capacity(manifest.len());
    let mut skipped = 0_usize;
    for entry in manifest.into_wallets() {
        if entry.address() == multi.recipient {
            skipped += 1;
            logging::warn(format!(
                "Wallet skipped because it is the withdrawal recipient: {}",
                entry.address()
            ));
            continue;
        }
        match prepare_withdrawal_plan(config, &gateway, &chain, rpc_index, entry, multi.recipient)
            .await?
        {
            Some(plan) => plans.push(plan),
            None => skipped += 1,
        }
    }
    if plans.is_empty() {
        return Err(NativeFundsError::NothingToWithdraw);
    }

    let total_balance = checked_sum(plans.iter().map(|plan| plan.state.balance))?;
    let total_initial_value = checked_sum(plans.iter().map(|plan| plan.initial_value))?;
    let total_maximum_gas = plans.iter().try_fold(U256::ZERO, |total, plan| {
        let reserve = maximum_gas_cost(plan.gas_limit, plan.maximum_fees.max_fee_per_gas)?;
        total
            .checked_add(reserve)
            .ok_or(NativeFundsError::ArithmeticOverflow)
    })?;
    logging::section_break();
    logging::info(format!("Network chain ID: {}", chain.chain_id));
    logging::info(format!("Withdrawal recipient: {}", multi.recipient));
    logging::info(format!(
        "Sequential withdrawals: wallets={} | skipped={skipped}",
        plans.len()
    ));
    logging::info(format!("Captured wallet balance: {total_balance} wei"));
    logging::info(format!(
        "Initial sweep value: {total_initial_value} wei | maximum reserved gas: {total_maximum_gas} wei"
    ));
    logging::warn(
        "Unused EIP-1559 fee headroom can remain as wallet dust after a successful sweep.",
    );
    terminal::confirm_native_funds("Withdraw the maximum safe balance from these wallets?")?;

    let refreshed_recipient = rpc_read_retry(config, || {
        gateway.account_state(&chain, rpc_index, multi.recipient)
    })
    .await?;
    if refreshed_recipient.code != recipient_state.code {
        return Err(NativeFundsError::WalletCodeChanged(multi.recipient));
    }

    let mut succeeded = 0_usize;
    let mut failed = skipped;
    for plan in plans {
        let address = plan.entry.address();
        let refreshed = load_wallet_snapshot(config, &gateway, &chain, rpc_index, address).await?;
        if refreshed.0.code != plan.state.code {
            failed += 1;
            logging::warn(NativeFundsError::WalletCodeChanged(address));
            continue;
        }
        let Some(quote) = quote_withdrawal(
            config,
            &gateway,
            &chain,
            rpc_index,
            address,
            refreshed.0.balance,
            refreshed.1.fee_estimate,
            multi.recipient,
        )
        .await?
        else {
            failed += 1;
            continue;
        };
        report_withdrawal_refresh(&plan, &refreshed.0, &refreshed.1, quote);
        match submit_transfer(
            config,
            &gateway,
            &chain,
            rpc_index,
            plan.entry.signer(),
            refreshed.1.pending_nonce,
            multi.recipient,
            Bytes::new(),
            quote.gas_limit,
            quote.fees,
            TransferValue::Sweep {
                balance: refreshed.0.balance,
            },
        )
        .await
        {
            Ok((receipt, value)) => {
                succeeded += 1;
                logging::success(format!(
                    "Wallet {address} withdrew {value} wei: {} in block {}.",
                    receipt.transaction_hash, receipt.block_number
                ));
            }
            Err(error) => {
                failed += 1;
                logging::warn(format!("Wallet {address} withdrawal failed: {error}"));
            }
        }
    }
    logging::info(format!(
        "Sequential withdrawal finished: succeeded={succeeded}, failed={failed}."
    ));
    if failed == 0 {
        Ok(())
    } else {
        Err(NativeFundsError::PartialFailure { succeeded, failed })
    }
}

#[allow(clippy::too_many_arguments)]
async fn fund_with_multicall(
    config: &AppConfig,
    gateway: &ChainGateway,
    chain: &ChainConfig,
    rpc_index: usize,
    payer: &WalletSigner,
    manifest: WalletManifest,
    funding_targets: FundingTargetSnapshot,
    amount: NativeAmount,
    total_value: U256,
) -> Result<(), NativeFundsError> {
    let calldata = encode_multicall_funding(&manifest, amount.wei())?;
    let payer_address = payer.identity().address;
    let (payer_state, inputs) =
        load_wallet_snapshot(config, gateway, chain, rpc_index, payer_address).await?;
    report_payer_code(&payer_state.code)?;
    let estimated_gas = rpc_read_retry(config, || {
        gateway.estimate_transaction(
            chain,
            rpc_index,
            payer_address,
            MULTICALL3_ADDRESS,
            total_value,
            &calldata,
        )
    })
    .await?;
    let gas_limit = buffered_gas(estimated_gas)?;
    let fees = initial_transaction_fees(config.fees, inputs.fee_estimate)?;
    let maximum_fees = maximum_transaction_fees(config.fees, DIRECT_TRANSFER_MAX_ATTEMPTS, fees)?;
    let required = total_value
        .checked_add(maximum_gas_cost(gas_limit, maximum_fees.max_fee_per_gas)?)
        .ok_or(NativeFundsError::ArithmeticOverflow)?;
    ensure_balance(payer_state.balance, required)?;

    report_funding_confirmation(
        chain.chain_id,
        payer_address,
        manifest.len(),
        amount,
        total_value,
        "one atomic Multicall3 transaction",
        estimated_gas,
        gas_limit,
        required,
    );
    terminal::confirm_native_funds("Fund every manifest wallet with this Multicall3 transaction?")?;

    let refreshed_multicall = rpc_read_retry(config, || {
        gateway.account_state(chain, rpc_index, MULTICALL3_ADDRESS)
    })
    .await?;
    if keccak256(&refreshed_multicall.code) != MULTICALL3_RUNTIME_HASH {
        return Err(NativeFundsError::MulticallStateChanged);
    }
    validate_funding_targets_unchanged(
        config,
        gateway,
        chain,
        rpc_index,
        &manifest,
        &funding_targets,
    )
    .await?;
    let (refreshed_state, refreshed_inputs) =
        load_wallet_snapshot(config, gateway, chain, rpc_index, payer_address).await?;
    let refreshed = funding_submission(
        config,
        &refreshed_state,
        &refreshed_inputs,
        total_value,
        gas_limit,
    )?;
    report_funding_refresh(inputs.pending_nonce, required, refreshed);
    let (receipt, _) = submit_transfer(
        config,
        gateway,
        chain,
        rpc_index,
        payer,
        refreshed.nonce,
        MULTICALL3_ADDRESS,
        calldata,
        gas_limit,
        refreshed.fees,
        TransferValue::Fixed(total_value),
    )
    .await?;
    logging::success(format!(
        "Atomic Multicall3 funding confirmed for {} wallets: {} in block {}.",
        manifest.len(),
        receipt.transaction_hash,
        receipt.block_number
    ));
    Ok(())
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn fund_directly(
    config: &AppConfig,
    gateway: &ChainGateway,
    chain: &ChainConfig,
    rpc_index: usize,
    payer: &WalletSigner,
    manifest: WalletManifest,
    funding_targets: FundingTargetSnapshot,
    amount: NativeAmount,
    total_value: U256,
) -> Result<(), NativeFundsError> {
    let payer_address = payer.identity().address;
    let (payer_state, inputs) =
        load_wallet_snapshot(config, gateway, chain, rpc_index, payer_address).await?;
    report_payer_code(&payer_state.code)?;
    let fees = initial_transaction_fees(config.fees, inputs.fee_estimate)?;
    let maximum_fees = maximum_transaction_fees(config.fees, DIRECT_TRANSFER_MAX_ATTEMPTS, fees)?;
    let mut gas_limits = Vec::with_capacity(manifest.len());
    let mut estimated_total_gas = 0_u64;
    let mut buffered_total_gas = 0_u64;
    for wallet in manifest.wallets() {
        let estimate = rpc_read_retry(config, || {
            gateway.estimate_transaction(
                chain,
                rpc_index,
                payer_address,
                wallet.address(),
                amount.wei(),
                &[],
            )
        })
        .await?;
        let gas_limit = buffered_gas(estimate)?;
        estimated_total_gas = estimated_total_gas
            .checked_add(estimate)
            .ok_or(NativeFundsError::ArithmeticOverflow)?;
        buffered_total_gas = buffered_total_gas
            .checked_add(gas_limit)
            .ok_or(NativeFundsError::ArithmeticOverflow)?;
        gas_limits.push(gas_limit);
    }
    let required = total_value
        .checked_add(maximum_gas_cost(
            buffered_total_gas,
            maximum_fees.max_fee_per_gas,
        )?)
        .ok_or(NativeFundsError::ArithmeticOverflow)?;
    ensure_balance(payer_state.balance, required)?;

    report_funding_confirmation(
        chain.chain_id,
        payer_address,
        manifest.len(),
        amount,
        total_value,
        "sequential direct transactions (Multicall3 unavailable)",
        estimated_total_gas,
        buffered_total_gas,
        required,
    );
    terminal::confirm_native_funds("Fund the manifest wallets sequentially?")?;

    validate_funding_targets_unchanged(
        config,
        gateway,
        chain,
        rpc_index,
        &manifest,
        &funding_targets,
    )
    .await?;
    let (refreshed_state, refreshed_inputs) =
        load_wallet_snapshot(config, gateway, chain, rpc_index, payer_address).await?;
    let refreshed = funding_submission(
        config,
        &refreshed_state,
        &refreshed_inputs,
        total_value,
        buffered_total_gas,
    )?;
    report_funding_refresh(inputs.pending_nonce, required, refreshed);

    let mut succeeded = 0_usize;
    let mut failed = 0_usize;
    let mut submission = refreshed;
    for (offset, wallet) in manifest.wallets().iter().enumerate() {
        if offset != 0 {
            let remaining_count = manifest.len() - offset;
            let remaining_value = amount
                .wei()
                .checked_mul(U256::from(remaining_count))
                .ok_or(NativeFundsError::ArithmeticOverflow)?;
            let remaining_gas = gas_limits[offset..]
                .iter()
                .try_fold(0_u64, |total, gas_limit| total.checked_add(*gas_limit))
                .ok_or(NativeFundsError::ArithmeticOverflow)?;
            let payer_snapshot =
                load_wallet_snapshot(config, gateway, chain, rpc_index, payer_address).await?;
            submission = funding_submission(
                config,
                &payer_snapshot.0,
                &payer_snapshot.1,
                remaining_value,
                remaining_gas,
            )?;
            logging::info(format!(
                "Funding submission refreshed: nonce={} | remaining maximum cost={} wei",
                submission.nonce, submission.maximum_cost
            ));
        }
        let gas_limit = gas_limits[offset];
        match submit_transfer(
            config,
            gateway,
            chain,
            rpc_index,
            payer,
            submission.nonce,
            wallet.address(),
            Bytes::new(),
            gas_limit,
            submission.fees,
            TransferValue::Fixed(amount.wei()),
        )
        .await
        {
            Ok((receipt, _)) => {
                succeeded += 1;
                logging::success(format!(
                    "Wallet funded: {} via {} in block {}.",
                    wallet.address(),
                    receipt.transaction_hash,
                    receipt.block_number
                ));
                if offset + 1 < manifest.len() {
                    submission.nonce = submission
                        .nonce
                        .checked_add(1)
                        .ok_or(NativeFundsError::ArithmeticOverflow)?;
                }
            }
            Err(NativeFundsError::Reverted { block_number }) => {
                failed += 1;
                logging::warn(format!(
                    "Funding {} reverted in block {block_number}; continuing with the consumed nonce.",
                    wallet.address()
                ));
                if offset + 1 < manifest.len() {
                    submission.nonce = submission
                        .nonce
                        .checked_add(1)
                        .ok_or(NativeFundsError::ArithmeticOverflow)?;
                }
            }
            Err(NativeFundsError::RateLimitExhausted(_)) => {
                failed += 1;
                logging::warn(format!(
                    "Funding {} exhausted two rate-limit retries; moving to the next wallet without consuming the payer nonce.",
                    wallet.address()
                ));
            }
            Err(error) => return Err(error),
        }
    }
    logging::info(format!(
        "Sequential direct funding finished: succeeded={succeeded}, failed={failed}."
    ));
    if failed == 0 {
        Ok(())
    } else {
        Err(NativeFundsError::PartialFailure { succeeded, failed })
    }
}

async fn prepare_withdrawal_plan(
    config: &AppConfig,
    gateway: &ChainGateway,
    chain: &ChainConfig,
    rpc_index: usize,
    entry: WalletEntry,
    recipient: Address,
) -> Result<Option<WithdrawalPlan>, NativeFundsError> {
    let address = entry.address();
    let (state, inputs) = load_wallet_snapshot(config, gateway, chain, rpc_index, address).await?;
    let Some(quote) = quote_withdrawal(
        config,
        gateway,
        chain,
        rpc_index,
        address,
        state.balance,
        inputs.fee_estimate,
        recipient,
    )
    .await?
    else {
        return Ok(None);
    };
    Ok(Some(WithdrawalPlan {
        entry,
        state,
        inputs,
        gas_limit: quote.gas_limit,
        maximum_fees: quote.maximum_fees,
        initial_value: quote.initial_value,
    }))
}

#[allow(clippy::too_many_arguments)]
async fn quote_withdrawal(
    config: &AppConfig,
    gateway: &ChainGateway,
    chain: &ChainConfig,
    rpc_index: usize,
    address: Address,
    balance: U256,
    fee_estimate: crate::chain::FeeEstimate,
    recipient: Address,
) -> Result<Option<WithdrawalQuote>, NativeFundsError> {
    let fees = initial_transaction_fees(config.fees, fee_estimate)?;
    let maximum_fees = maximum_transaction_fees(config.fees, DIRECT_TRANSFER_MAX_ATTEMPTS, fees)?;
    let probe_value = balance.min(U256::from(1_u8));
    let estimate = match rpc_read_retry(config, || {
        gateway.estimate_transaction(chain, rpc_index, address, recipient, probe_value, &[])
    })
    .await
    {
        Ok(estimate) => estimate,
        Err(NativeFundsError::Chain(ChainError::Rpc { .. })) => {
            logging::warn(format!(
                "Wallet {address} skipped because the recipient rejected its withdrawal estimate."
            ));
            return Ok(None);
        }
        Err(error) => return Err(error),
    };
    let mut gas_limit = buffered_gas(estimate)?;
    let mut maximum_reserve = maximum_gas_cost(gas_limit, maximum_fees.max_fee_per_gas)?;
    if balance <= maximum_reserve {
        logging::warn(format!(
            "Wallet {address} skipped: balance {balance} does not cover maximum gas reserve {maximum_reserve}."
        ));
        return Ok(None);
    }
    let mut initial_value =
        TransferValue::Sweep { balance }.at_fee(gas_limit, fees.max_fee_per_gas)?;
    let mut final_estimate = rpc_read_retry(config, || {
        gateway.estimate_transaction(chain, rpc_index, address, recipient, initial_value, &[])
    })
    .await?;
    if final_estimate > gas_limit {
        gas_limit = buffered_gas(final_estimate)?;
        maximum_reserve = maximum_gas_cost(gas_limit, maximum_fees.max_fee_per_gas)?;
        if balance <= maximum_reserve {
            logging::warn(format!(
                "Wallet {address} skipped: balance {balance} does not cover refreshed maximum gas reserve {maximum_reserve}."
            ));
            return Ok(None);
        }
        initial_value = TransferValue::Sweep { balance }.at_fee(gas_limit, fees.max_fee_per_gas)?;
        final_estimate = rpc_read_retry(config, || {
            gateway.estimate_transaction(chain, rpc_index, address, recipient, initial_value, &[])
        })
        .await?;
        if final_estimate > gas_limit {
            return Err(NativeFundsError::WithdrawalGasUnstable(address));
        }
    }
    Ok(Some(WithdrawalQuote {
        fees,
        maximum_fees,
        gas_limit,
        initial_value,
    }))
}

fn report_withdrawal_refresh(
    plan: &WithdrawalPlan,
    state: &AccountState,
    inputs: &SubmissionInputs,
    quote: WithdrawalQuote,
) {
    if state.balance != plan.state.balance
        || inputs.pending_nonce != plan.inputs.pending_nonce
        || quote.gas_limit != plan.gas_limit
        || quote.maximum_fees != plan.maximum_fees
    {
        logging::info(format!(
            "Withdrawal submission refreshed for {}: nonce={} | balance={} wei | gas limit={}",
            plan.entry.address(),
            inputs.pending_nonce,
            state.balance,
            quote.gas_limit
        ));
    }
}

#[allow(clippy::too_many_arguments)]
async fn submit_transfer(
    config: &AppConfig,
    gateway: &ChainGateway,
    chain: &ChainConfig,
    rpc_index: usize,
    signer: &WalletSigner,
    nonce: u64,
    target: Address,
    calldata: Bytes,
    gas_limit: u64,
    mut fees: Eip1559Fees,
    value: TransferValue,
) -> Result<(TransactionReceipt, U256), NativeFundsError> {
    let replacement = AutomaticFeePolicy::new(10_000, config.fees.replacement_bump_bps)?;
    let mut submitted = Vec::new();
    for attempt in 1..=DIRECT_TRANSFER_MAX_ATTEMPTS {
        let transaction_value = value.at_fee(gas_limit, fees.max_fee_per_gas)?;
        let signed_transaction = sign_eip1559_transaction(
            &Eip1559Transaction {
                chain_id: chain.chain_id,
                nonce,
                max_priority_fee_per_gas: fees.max_priority_fee_per_gas,
                max_fee_per_gas: fees.max_fee_per_gas,
                gas_limit,
                target,
                value: transaction_value,
                calldata: calldata.clone(),
            },
            signer,
        )?;
        let local_hash = signed_transaction.hash();
        logging::info(format!(
            "Submitting transaction: {local_hash} (attempt {attempt}/{DIRECT_TRANSFER_MAX_ATTEMPTS})."
        ));
        match gateway
            .send_raw_transaction(chain, rpc_index, &signed_transaction)
            .await
        {
            Ok(hash) if hash == local_hash => {
                submitted.push((hash, transaction_value));
            }
            Ok(hash) => return Err(NativeFundsError::BroadcastUncertain(hash)),
            Err(ChainError::RateLimited { .. }) if attempt < DIRECT_TRANSFER_MAX_ATTEMPTS => {
                logging::warn("RPC rate limited submission; retrying this wallet sequentially.");
                sleep(retry_delay(config, attempt)).await;
                continue;
            }
            Err(ChainError::RateLimited { .. }) => {
                return if submitted.is_empty() {
                    Err(NativeFundsError::RateLimitExhausted(local_hash))
                } else {
                    Err(NativeFundsError::Pending(
                        submitted.last().map_or(local_hash, |(hash, _)| *hash),
                    ))
                };
            }
            Err(_) => return Err(NativeFundsError::BroadcastUncertain(local_hash)),
        }

        let receipt = wait_for_submitted_receipt(config, gateway, chain, rpc_index, &submitted)
            .await
            .map_err(|_| NativeFundsError::ReceiptUncertain(local_hash))?;
        if let Some(receipt) = receipt {
            if !receipt.is_success {
                return Err(NativeFundsError::Reverted {
                    block_number: receipt.block_number,
                });
            }
            let confirmed_value = submitted
                .iter()
                .find_map(|(hash, value)| (*hash == receipt.transaction_hash).then_some(*value))
                .ok_or(NativeFundsError::BroadcastUncertain(
                    receipt.transaction_hash,
                ))?;
            return Ok((receipt, confirmed_value));
        }
        if attempt < DIRECT_TRANSFER_MAX_ATTEMPTS {
            fees = replacement.replacement(fees)?;
        }
    }
    Err(NativeFundsError::Pending(
        submitted.last().map_or(B256::ZERO, |(hash, _)| *hash),
    ))
}

async fn wait_for_submitted_receipt(
    config: &AppConfig,
    gateway: &ChainGateway,
    chain: &ChainConfig,
    rpc_index: usize,
    submitted: &[(B256, U256)],
) -> Result<Option<TransactionReceipt>, NativeFundsError> {
    let hashes = submitted.iter().map(|(hash, _)| *hash).collect::<Vec<_>>();
    gateway
        .wait_for_any_transaction_receipt(
            chain,
            rpc_index,
            &hashes,
            ReceiptPollingPolicy::from(config.retry),
        )
        .await
        .map(|receipt| receipt.map(|(_, receipt)| receipt))
        .map_err(Into::into)
}

async fn connect(
    config: &AppConfig,
) -> Result<(ChainGateway, ChainConfig, usize), NativeFundsError> {
    let gateway = ChainGateway::new(Duration::from_millis(config.opensea.request_timeout_ms))?;
    let probe = rpc_read_retry(config, || gateway.probe_rpc(&config.rpc_url)).await?;
    let chain = ChainConfig {
        chain_id: probe.chain_id,
        rpc_urls: vec![config.rpc_url.clone()],
    };
    logging::success(format!("RPC connected: chain_id={}", chain.chain_id));
    Ok((gateway, chain, probe.rpc_index))
}

async fn load_wallet_snapshot(
    config: &AppConfig,
    gateway: &ChainGateway,
    chain: &ChainConfig,
    rpc_index: usize,
    wallet: Address,
) -> Result<(AccountState, SubmissionInputs), NativeFundsError> {
    let snapshot =
        rpc_read_retry(config, || gateway.wallet_snapshot(chain, rpc_index, wallet)).await?;
    Ok((snapshot.account_state, snapshot.submission_inputs))
}

async fn load_funding_target_states(
    config: &AppConfig,
    gateway: &ChainGateway,
    chain: &ChainConfig,
    rpc_index: usize,
    manifest: &WalletManifest,
    expected_executor: Option<Address>,
) -> Result<FundingTargetSnapshot, NativeFundsError> {
    let mut wallet_codes = Vec::with_capacity(manifest.len());
    let mut has_delegated_target = false;
    for wallet in manifest.wallets() {
        let state = rpc_read_retry(config, || {
            gateway.account_state(chain, rpc_index, wallet.address())
        })
        .await?;
        has_delegated_target |=
            validate_funding_target_code(wallet.address(), &state.code, expected_executor)?;
        wallet_codes.push(state.code);
    }
    let delegated_executor = if has_delegated_target {
        let executor = expected_executor.ok_or(NativeFundsError::FundingExecutorMismatch)?;
        let state =
            rpc_read_retry(config, || gateway.account_state(chain, rpc_index, executor)).await?;
        if keccak256(&state.code) != AUDITED_EXECUTOR_RUNTIME_HASH {
            return Err(NativeFundsError::FundingExecutorMismatch);
        }
        Some((executor, state.code))
    } else {
        None
    };
    Ok(FundingTargetSnapshot {
        wallet_codes,
        delegated_executor,
    })
}

async fn validate_funding_targets_unchanged(
    config: &AppConfig,
    gateway: &ChainGateway,
    chain: &ChainConfig,
    rpc_index: usize,
    manifest: &WalletManifest,
    original: &FundingTargetSnapshot,
) -> Result<(), NativeFundsError> {
    for (wallet, original_code) in manifest.wallets().iter().zip(&original.wallet_codes) {
        let refreshed = rpc_read_retry(config, || {
            gateway.account_state(chain, rpc_index, wallet.address())
        })
        .await?;
        if refreshed.code != *original_code {
            return Err(NativeFundsError::WalletCodeChanged(wallet.address()));
        }
    }
    if let Some((executor, original_code)) = &original.delegated_executor {
        let refreshed = rpc_read_retry(config, || {
            gateway.account_state(chain, rpc_index, *executor)
        })
        .await?;
        if refreshed.code != *original_code
            || keccak256(&refreshed.code) != AUDITED_EXECUTOR_RUNTIME_HASH
        {
            return Err(NativeFundsError::FundingExecutorStateChanged);
        }
    }
    Ok(())
}

async fn rpc_read_retry<T, F, Fut>(
    config: &AppConfig,
    mut operation: F,
) -> Result<T, NativeFundsError>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, ChainError>>,
{
    for attempt in 1..=DIRECT_TRANSFER_MAX_ATTEMPTS {
        match operation().await {
            Ok(value) => return Ok(value),
            Err(ChainError::RateLimited { .. }) if attempt < DIRECT_TRANSFER_MAX_ATTEMPTS => {
                logging::warn("RPC rate limited the request; retrying sequentially.");
                sleep(retry_delay(config, attempt)).await;
            }
            Err(error) => return Err(error.into()),
        }
    }
    unreachable!("bounded RPC retry loop always returns")
}

fn retry_delay(config: &AppConfig, attempt: u32) -> Duration {
    let multiplier = 1_u64
        .checked_shl(attempt.saturating_sub(1))
        .unwrap_or(u64::MAX);
    Duration::from_millis(
        config
            .retry
            .base_delay_ms
            .saturating_mul(multiplier)
            .min(config.retry.max_delay_ms),
    )
}

fn require_self_funded_withdrawal(multi: &MultiWalletConfig) -> Result<(), NativeFundsError> {
    if matches!(multi.mode, MultiWalletMode::SelfFunded) {
        Ok(())
    } else {
        Err(NativeFundsError::WithdrawSelfFundedOnly)
    }
}

fn funding_wallet_limit(mode: &MultiWalletMode) -> usize {
    match mode {
        MultiWalletMode::SelfFunded => MAX_SELF_FUNDED_WALLETS,
        MultiWalletMode::Sponsored(_) => MAX_SPONSORED_BATCH_SIZE,
    }
}

fn funding_executor(mode: &MultiWalletMode) -> Option<Address> {
    match mode {
        MultiWalletMode::SelfFunded => None,
        MultiWalletMode::Sponsored(sponsored) => Some(sponsored.executor),
    }
}

fn load_manifest(
    multi: &MultiWalletConfig,
    maximum: usize,
) -> Result<WalletManifest, NativeFundsError> {
    let manifest = WalletManifest::load(&multi.manifest_path)?;
    if manifest.len() > maximum {
        return Err(NativeFundsError::WalletLimit { maximum });
    }
    Ok(manifest)
}

fn validate_funding_target_code(
    wallet: Address,
    code: &[u8],
    expected_executor: Option<Address>,
) -> Result<bool, NativeFundsError> {
    let Some(executor) = expected_executor else {
        return if code.is_empty() {
            Ok(false)
        } else {
            Err(NativeFundsError::FundingTargetHasCode(wallet))
        };
    };
    match classify_delegation(code, executor) {
        DelegationState::Clear => Ok(false),
        DelegationState::Expected => Ok(true),
        DelegationState::Unexpected(_) | DelegationState::OtherCode => {
            Err(NativeFundsError::FundingTargetHasCode(wallet))
        }
    }
}

fn report_payer_code(code: &[u8]) -> Result<(), NativeFundsError> {
    match classify_delegation(code, Address::ZERO) {
        DelegationState::Clear => Ok(()),
        DelegationState::Unexpected(delegate) => {
            logging::warn(format!(
                "Funding payer is EIP-7702 delegated to {delegate}; this operation does not alter it."
            ));
            Ok(())
        }
        DelegationState::Expected | DelegationState::OtherCode => {
            Err(NativeFundsError::InvalidPayerCode)
        }
    }
}

fn report_recipient_code(code: &[u8]) -> Result<(), NativeFundsError> {
    match classify_delegation(code, Address::ZERO) {
        DelegationState::Clear => Ok(()),
        DelegationState::Unexpected(delegate) => {
            logging::warn(format!(
                "Withdrawal recipient is EIP-7702 delegated to {delegate}; its delegated receive path must accept native currency."
            ));
            Ok(())
        }
        DelegationState::Expected | DelegationState::OtherCode => {
            Err(NativeFundsError::InvalidRecipientCode)
        }
    }
}

fn funding_submission(
    config: &AppConfig,
    state: &AccountState,
    inputs: &SubmissionInputs,
    value: U256,
    gas_limit: u64,
) -> Result<FundingSubmission, NativeFundsError> {
    report_payer_code(&state.code)?;
    let fees = initial_transaction_fees(config.fees, inputs.fee_estimate)?;
    let maximum_fees = maximum_transaction_fees(config.fees, DIRECT_TRANSFER_MAX_ATTEMPTS, fees)?;
    let maximum_cost = value
        .checked_add(maximum_gas_cost(gas_limit, maximum_fees.max_fee_per_gas)?)
        .ok_or(NativeFundsError::ArithmeticOverflow)?;
    ensure_balance(state.balance, maximum_cost)?;
    Ok(FundingSubmission {
        nonce: inputs.pending_nonce,
        fees,
        maximum_cost,
    })
}

fn report_funding_refresh(original_nonce: u64, original_cost: U256, refreshed: FundingSubmission) {
    if refreshed.nonce != original_nonce || refreshed.maximum_cost != original_cost {
        logging::info(format!(
            "Funding submission refreshed: nonce={} | maximum cost={} wei",
            refreshed.nonce, refreshed.maximum_cost
        ));
    }
}

fn encode_multicall_funding(
    manifest: &WalletManifest,
    amount: U256,
) -> Result<Bytes, NativeFundsError> {
    if amount == U256::ZERO || manifest.is_empty() {
        return Err(NativeFundsError::InvalidAmount);
    }
    let calls = manifest
        .wallets()
        .iter()
        .map(|wallet| Call3Value {
            target: wallet.address(),
            allowFailure: false,
            value: amount,
            callData: Bytes::new(),
        })
        .collect();
    Ok(Bytes::from(aggregate3ValueCall { calls }.abi_encode()))
}

fn buffered_gas(estimate: u64) -> Result<u64, NativeFundsError> {
    if estimate == 0 {
        return Err(NativeFundsError::ArithmeticOverflow);
    }
    let proportional = estimate
        .checked_mul(GAS_BUFFER_BPS)
        .and_then(|value| value.checked_add(GAS_BUFFER_DENOMINATOR - 1))
        .map(|value| value / GAS_BUFFER_DENOMINATOR)
        .ok_or(NativeFundsError::ArithmeticOverflow)?;
    estimate
        .checked_add(MINIMUM_GAS_BUFFER)
        .map(|minimum| proportional.max(minimum))
        .ok_or(NativeFundsError::ArithmeticOverflow)
}

fn maximum_gas_cost(gas_limit: u64, max_fee_per_gas: U256) -> Result<U256, NativeFundsError> {
    U256::from(gas_limit)
        .checked_mul(max_fee_per_gas)
        .ok_or(NativeFundsError::ArithmeticOverflow)
}

fn ensure_balance(balance: U256, required: U256) -> Result<(), NativeFundsError> {
    if balance < required {
        Err(NativeFundsError::PayerUnderfunded {
            required_wei: required,
        })
    } else {
        Ok(())
    }
}

fn checked_sum(mut values: impl Iterator<Item = U256>) -> Result<U256, NativeFundsError> {
    values.try_fold(U256::ZERO, |total, value| {
        total
            .checked_add(value)
            .ok_or(NativeFundsError::ArithmeticOverflow)
    })
}

#[allow(clippy::too_many_arguments)]
fn report_funding_confirmation(
    chain_id: u64,
    payer: Address,
    wallets: usize,
    amount: NativeAmount,
    total_value: U256,
    route: &str,
    estimated_gas: u64,
    gas_limit: u64,
    maximum_cost: U256,
) {
    logging::section_break();
    logging::info(format!("Network chain ID: {chain_id}"));
    logging::info(format!("Funding payer: {payer}"));
    logging::info(format!("Funding route: {route}"));
    logging::info(format!(
        "Wallets: {wallets} | amount each: {amount} native ({}) wei",
        amount.wei()
    ));
    logging::info(format!("Total distributed value: {total_value} wei"));
    logging::info(format!(
        "Gas: estimated={estimated_gas} | buffered={gas_limit} | maximum cost={maximum_cost} wei"
    ));
}

fn parse_native_amount(value: &str) -> Result<U256, NativeFundsError> {
    let (whole, fractional) = value
        .trim()
        .split_once('.')
        .map_or((value.trim(), ""), |parts| parts);
    if whole.is_empty()
        || (value.contains('.') && fractional.is_empty())
        || !whole.bytes().all(|byte| byte.is_ascii_digit())
        || !fractional.bytes().all(|byte| byte.is_ascii_digit())
        || fractional.len() > NATIVE_DECIMALS
    {
        return Err(NativeFundsError::InvalidAmount);
    }
    let scale = U256::from(NATIVE_SCALE);
    let whole = U256::from_str_radix(whole, 10).map_err(|_| NativeFundsError::InvalidAmount)?;
    let mut fractional_digits = fractional.to_owned();
    fractional_digits.extend(std::iter::repeat_n('0', NATIVE_DECIMALS - fractional.len()));
    let fractional = if fractional_digits.is_empty() {
        U256::ZERO
    } else {
        U256::from_str_radix(&fractional_digits, 10).map_err(|_| NativeFundsError::InvalidAmount)?
    };
    let amount = whole
        .checked_mul(scale)
        .and_then(|value| value.checked_add(fractional))
        .filter(|value| *value != U256::ZERO)
        .ok_or(NativeFundsError::InvalidAmount)?;
    Ok(amount)
}

#[cfg(test)]
mod tests {
    use alloy_sol_types::SolCall;

    use super::*;
    use crate::{
        chain::{FeeEstimate, LatestBlock},
        config::{FeesConfig, OpenSeaConfig, RetryConfig, SchedulingConfig},
    };

    const FIRST_KEY: &str = "0x0000000000000000000000000000000000000000000000000000000000000001";
    const SECOND_KEY: &str = "0x0000000000000000000000000000000000000000000000000000000000000002";

    #[test]
    fn parses_and_formats_exact_native_amounts() {
        let amount: NativeAmount = "1.000000000000000001".parse().expect("amount");
        assert_eq!(amount.wei(), U256::from(10_u64.pow(18)) + U256::from(1_u8));
        assert_eq!(amount.to_string(), "1.000000000000000001");
        assert_eq!(
            "0.001".parse::<NativeAmount>().expect("small").wei(),
            U256::from(10_u64.pow(15))
        );
        for invalid in ["0", "-1", "1e18", "1.0000000000000000001", ".1", "1."] {
            assert!(
                invalid.parse::<NativeAmount>().is_err(),
                "accepted {invalid}"
            );
        }
    }

    #[test]
    fn multicall_funding_is_atomic_and_uses_empty_calldata() {
        let manifest = WalletManifest::from_json(&format!(
            r#"{{"version":1,"wallets":[{{"private_key":"{FIRST_KEY}","quantity":1}},{{"private_key":"{SECOND_KEY}","quantity":1}}]}}"#
        ))
        .expect("manifest");
        let calldata = encode_multicall_funding(&manifest, U256::from(7_u8)).expect("calldata");
        assert_eq!(&calldata[..4], aggregate3ValueCall::SELECTOR);
        let decoded = aggregate3ValueCall::abi_decode(&calldata).expect("decode");
        assert_eq!(decoded.calls.len(), 2);
        assert!(decoded.calls.iter().all(|call| !call.allowFailure));
        assert!(
            decoded
                .calls
                .iter()
                .all(|call| call.value == U256::from(7_u8))
        );
        assert!(decoded.calls.iter().all(|call| call.callData.is_empty()));
    }

    #[test]
    fn gas_buffer_and_sweep_reserve_fail_closed() {
        assert_eq!(buffered_gas(21_000).expect("buffer"), 26_000);
        assert!(buffered_gas(0).is_err());
        let value = TransferValue::Sweep {
            balance: U256::from(100_000_u64),
        }
        .at_fee(21_000, U256::from(2_u8))
        .expect("sweep");
        assert_eq!(value, U256::from(58_000_u64));
        assert!(
            TransferValue::Sweep {
                balance: U256::from(42_000_u64)
            }
            .at_fee(21_000, U256::from(2_u8))
            .is_err()
        );
        assert_eq!(DIRECT_TRANSFER_MAX_ATTEMPTS, 3);
    }

    #[test]
    fn funding_submission_accepts_refreshed_nonce_and_higher_fees() {
        let config = automatic_test_config();
        let state = AccountState {
            balance: U256::MAX,
            pending_nonce: 7,
            code: Bytes::new(),
        };
        let original_inputs = submission_inputs(100, 10);
        let mut refreshed_inputs = submission_inputs(101, 10);
        refreshed_inputs.pending_nonce = 8;
        let original = funding_submission(
            &config,
            &state,
            &original_inputs,
            U256::from(1_000_u64),
            21_000,
        )
        .expect("original submission");
        let refreshed = funding_submission(
            &config,
            &state,
            &refreshed_inputs,
            U256::from(1_000_u64),
            21_000,
        )
        .expect("refreshed submission");

        assert_eq!(refreshed.nonce, 8);
        assert!(refreshed.fees.max_fee_per_gas > original.fees.max_fee_per_gas);
        assert!(refreshed.maximum_cost > original.maximum_cost);
    }

    #[test]
    fn funding_targets_allow_only_clear_or_the_audited_mode_executor() {
        let wallet = Address::repeat_byte(0x11);
        let executor = Address::repeat_byte(0x22);
        let other_executor = Address::repeat_byte(0x33);
        let expected_code = crate::sponsored::delegation_designator(executor);
        let other_code = crate::sponsored::delegation_designator(other_executor);

        assert!(!validate_funding_target_code(wallet, &[], None).expect("clear self-funded"));
        assert!(
            !validate_funding_target_code(wallet, &[], Some(executor)).expect("clear sponsored")
        );
        assert!(
            validate_funding_target_code(wallet, &expected_code, Some(executor))
                .expect("expected sponsored delegation")
        );
        assert!(matches!(
            validate_funding_target_code(wallet, &expected_code, None),
            Err(NativeFundsError::FundingTargetHasCode(address)) if address == wallet
        ));
        assert!(matches!(
            validate_funding_target_code(wallet, &other_code, Some(executor)),
            Err(NativeFundsError::FundingTargetHasCode(address)) if address == wallet
        ));
    }

    fn submission_inputs(max_fee: u64, priority_fee: u64) -> SubmissionInputs {
        SubmissionInputs {
            latest_block: LatestBlock {
                timestamp: 1,
                base_fee_per_gas: Some(U256::from(1_u8)),
            },
            pending_nonce: 7,
            fee_estimate: FeeEstimate {
                max_priority_fee_per_gas: U256::from(priority_fee),
                max_fee_per_gas: U256::from(max_fee),
            },
        }
    }

    fn automatic_test_config() -> AppConfig {
        AppConfig {
            opensea: OpenSeaConfig {
                site_url: "https://opensea.io".parse().expect("site URL"),
                graphql_url: "https://gql.opensea.io/graphql"
                    .parse()
                    .expect("GraphQL URL"),
                app_id: "os2-web".into(),
                request_timeout_ms: 1_000,
                eligibility_request_timeout_ms: 1_000,
                max_attempts: 3,
                retry_interval_ms: 250,
                calldata_max_attempts: 40,
            },
            scheduling: SchedulingConfig {
                refresh_interval_seconds: 600,
            },
            retry: RetryConfig {
                max_attempts: 1,
                pending_timeout_seconds: 1,
                base_delay_ms: 50,
                max_delay_ms: 100,
            },
            fees: FeesConfig {
                mode: crate::config::FeeMode::Automatic,
                replacement_bump_bps: 11_250,
            },
            rpc_url: "https://rpc.example.invalid".parse().expect("RPC URL"),
            gas_limit: 300_000,
        }
    }
}
