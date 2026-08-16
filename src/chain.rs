use std::{fmt, time::Duration};

use alloy_primitives::{Address, B256, Bytes, U256, keccak256};
use reqwest::Client;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use thiserror::Error;
use tokio::time::{Instant, sleep};
use url::Url;
use zeroize::Zeroizing;

use crate::{
    config::{ChainConfig, RetryConfig},
    transaction::SignedTransaction,
};

const RPC_RESPONSE_LIMIT: usize = 1024 * 1024;
const RPC_CONTENT_LENGTH_LIMIT: u64 = 1024 * 1024;
const WALLET_SNAPSHOT_MAX_ATTEMPTS: usize = 2;
const EIP7702_PROBE_CALLDATA: &str = "0xc1cd7856";
const EIP7702_PROBE_DELEGATE: &str = "0x1234567890abcdef1234567890abcdef12345678";
const EIP7702_PROBE_ACCOUNT: &str = "0x000000000000000000000000000000000dead123";
const EIP7702_PROBE_DESIGNATOR: &str = "0xef01001234567890abcdef1234567890abcdef12345678";
const EIP7702_PROBE_RUNTIME: &str = concat!(
    "0x6080604052348015600e575f5ffd5b50600436106026575f3560e01c8063c1cd785614602a",
    "575b5f5ffd5b60306044565b604051603b91906064565b60405180910390f35b5f60019050",
    "90565b5f8115159050919050565b605e81604c565b82525050565b5f60208201905060755f",
    "8301846057565b9291505056fea2646970667358221220265103185dec648e9bcac4dd322c",
    "8482f2923aa8ab542d2233f257916b73cd6a64736f6c634300081c0033"
);
const EIP1153_PROBE_ACCOUNT: &str = "0x000000000000000000000000000000000dead124";
const EIP1153_PROBE_RUNTIME: &str = "0x600160005d60005c60005260206000f3";
const ABI_TRUE: &str = "0x0000000000000000000000000000000000000000000000000000000000000001";

#[derive(Debug, Error)]
pub enum ChainError {
    #[error("cannot construct the RPC HTTP client")]
    Client,
    #[error("RPC endpoint {index} is not configured")]
    EndpointNotConfigured { index: usize },
    #[error("RPC endpoint {index} returned an invalid response")]
    InvalidResponse { index: usize },
    #[error("RPC endpoint {index} does not support the required three-read JSON-RPC batch")]
    BatchUnsupported { index: usize },
    #[error("RPC endpoint {index} returned error code {code}")]
    Rpc { index: usize, code: i64 },
    #[error("RPC endpoint {index} rate limited the request")]
    RateLimited { index: usize },
    #[error("wallet nonce changed while RPC account state and fee inputs were being captured")]
    WalletSnapshotChanged,
    #[error("RPC polling timeout exceeds the platform timer range")]
    PollingTimeoutOutOfRange,
    #[error("RPC endpoint does not expose an EIP-1559 base fee")]
    Eip1559Unavailable,
    #[error("RPC quantity overflowed the supported transaction fields")]
    QuantityOverflow,
    #[error("RPC returned a different transaction hash than the locally signed transaction")]
    TransactionHashMismatch,
}

#[derive(Clone)]
pub struct ChainGateway {
    client: Client,
}

impl ChainGateway {
    pub fn new(timeout: Duration) -> Result<Self, ChainError> {
        let client = Client::builder()
            .timeout(timeout)
            .pool_idle_timeout(None)
            .pool_max_idle_per_host(2)
            .tcp_keepalive(Duration::from_mins(1))
            .http2_adaptive_window(true)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| ChainError::Client)?;
        Ok(Self { client })
    }

    pub async fn probe_rpc(&self, rpc_url: &Url) -> Result<ChainProbe, ChainError> {
        let chain_id = self
            .request::<String>(rpc_url, 1, "eth_chainId", Value::Array(vec![]))
            .await
            .and_then(|value| {
                parse_quantity_u64(&value).map_err(|_| ChainError::InvalidResponse { index: 1 })
            })?;
        if chain_id == 0 {
            return Err(ChainError::InvalidResponse { index: 1 });
        }
        Ok(ChainProbe {
            chain_id,
            rpc_index: 1,
        })
    }

    pub async fn eip7702_is_live(
        &self,
        config: &ChainConfig,
        rpc_index: usize,
    ) -> Result<bool, ChainError> {
        let endpoint = endpoint(config, rpc_index)?;
        let result = self
            .request_with_id::<String>(endpoint, rpc_index, 3, "eth_call", eip7702_probe_params())
            .await;
        classify_capability_probe(result)
    }

    pub async fn eip1153_is_live(
        &self,
        config: &ChainConfig,
        rpc_index: usize,
    ) -> Result<bool, ChainError> {
        let endpoint = endpoint(config, rpc_index)?;
        let result = self
            .request_with_id::<String>(endpoint, rpc_index, 4, "eth_call", eip1153_probe_params())
            .await;
        classify_capability_probe(result)
    }

    pub async fn latest_block(
        &self,
        config: &ChainConfig,
        rpc_index: usize,
    ) -> Result<LatestBlock, ChainError> {
        let endpoint = endpoint(config, rpc_index)?;
        let block: RpcBlock = self
            .request(
                endpoint,
                rpc_index,
                "eth_getBlockByNumber",
                json!(["latest", false]),
            )
            .await?;
        let timestamp = parse_quantity_u64(&block.timestamp)
            .map_err(|_| ChainError::InvalidResponse { index: rpc_index })?;
        let base_fee_per_gas = block
            .base_fee_per_gas
            .as_deref()
            .map(parse_quantity_u256)
            .transpose()
            .map_err(|_| ChainError::InvalidResponse { index: rpc_index })?;
        Ok(LatestBlock {
            timestamp,
            base_fee_per_gas,
        })
    }

    pub async fn submission_inputs(
        &self,
        config: &ChainConfig,
        rpc_index: usize,
        wallet: Address,
    ) -> Result<SubmissionInputs, ChainError> {
        let endpoint = endpoint(config, rpc_index)?;
        let requests = [
            JsonRpcRequest {
                jsonrpc: "2.0",
                id: 1,
                method: "eth_getBlockByNumber",
                params: json!(["latest", false]),
            },
            JsonRpcRequest {
                jsonrpc: "2.0",
                id: 2,
                method: "eth_getTransactionCount",
                params: json!([wallet.to_checksum(None), "pending"]),
            },
            JsonRpcRequest {
                jsonrpc: "2.0",
                id: 3,
                method: "eth_maxPriorityFeePerGas",
                params: Value::Array(vec![]),
            },
        ];
        let response = self
            .client
            .post(endpoint.clone())
            .json(&requests)
            .send()
            .await
            .map_err(|_| ChainError::InvalidResponse { index: rpc_index })?;
        if response.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
            return Err(ChainError::RateLimited { index: rpc_index });
        }
        if !response.status().is_success()
            || response
                .content_length()
                .is_some_and(|length| length > RPC_CONTENT_LENGTH_LIMIT)
        {
            return Err(ChainError::InvalidResponse { index: rpc_index });
        }
        let response_body = read_limited_body(response, RPC_RESPONSE_LIMIT)
            .await
            .map_err(|()| ChainError::InvalidResponse { index: rpc_index })?;
        let envelope: Value = serde_json::from_slice(&response_body)
            .map_err(|_| ChainError::InvalidResponse { index: rpc_index })?;
        decode_submission_batch(&envelope, rpc_index)
    }

    pub async fn account_state(
        &self,
        config: &ChainConfig,
        rpc_index: usize,
        wallet: Address,
    ) -> Result<AccountState, ChainError> {
        let endpoint = endpoint(config, rpc_index)?;
        let wallet = wallet.to_checksum(None);
        let requests = [
            JsonRpcRequest {
                jsonrpc: "2.0",
                id: 1,
                method: "eth_getBalance",
                params: json!([wallet, "pending"]),
            },
            JsonRpcRequest {
                jsonrpc: "2.0",
                id: 2,
                method: "eth_getTransactionCount",
                params: json!([wallet, "pending"]),
            },
            JsonRpcRequest {
                jsonrpc: "2.0",
                id: 3,
                method: "eth_getCode",
                params: json!([wallet, "latest"]),
            },
        ];
        let response = self
            .client
            .post(endpoint.clone())
            .json(&requests)
            .send()
            .await
            .map_err(|_| ChainError::InvalidResponse { index: rpc_index })?;
        if response.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
            return Err(ChainError::RateLimited { index: rpc_index });
        }
        if !response.status().is_success()
            || response
                .content_length()
                .is_some_and(|length| length > RPC_CONTENT_LENGTH_LIMIT)
        {
            return Err(ChainError::InvalidResponse { index: rpc_index });
        }
        let response_body = read_limited_body(response, RPC_RESPONSE_LIMIT)
            .await
            .map_err(|()| ChainError::InvalidResponse { index: rpc_index })?;
        let envelope: Value = serde_json::from_slice(&response_body)
            .map_err(|_| ChainError::InvalidResponse { index: rpc_index })?;
        decode_account_state_batch(&envelope, rpc_index)
    }

    pub async fn wallet_snapshot(
        &self,
        config: &ChainConfig,
        rpc_index: usize,
        wallet: Address,
    ) -> Result<WalletSnapshot, ChainError> {
        for attempt in 1..=WALLET_SNAPSHOT_MAX_ATTEMPTS {
            let (account_state, submission_inputs) = tokio::join!(
                self.account_state(config, rpc_index, wallet),
                self.submission_inputs(config, rpc_index, wallet)
            );
            let account_state = account_state?;
            let submission_inputs = submission_inputs?;
            match reconcile_wallet_snapshot(account_state, submission_inputs) {
                Ok(snapshot) => return Ok(snapshot),
                Err(error) if attempt == WALLET_SNAPSHOT_MAX_ATTEMPTS => return Err(error),
                Err(ChainError::WalletSnapshotChanged) => {}
                Err(error) => return Err(error),
            }
        }
        unreachable!("bounded wallet snapshot loop always returns")
    }

    pub async fn wait_for_account_code_hash(
        &self,
        config: &ChainConfig,
        rpc_index: usize,
        check: CodeHashCheck,
    ) -> Result<bool, ChainError> {
        let deadline = Instant::now()
            .checked_add(Duration::from_secs(check.timeout_seconds))
            .ok_or(ChainError::PollingTimeoutOutOfRange)?;
        let mut delay_ms = check.poll_interval_ms.max(50);
        let mut last_error = None;
        let mut received_code = false;
        loop {
            match self
                .account_code(config, rpc_index, check.account, check.block_number)
                .await
            {
                Ok(code) => {
                    received_code = true;
                    if keccak256(&code) == check.expected_hash {
                        return Ok(true);
                    }
                }
                Err(error) => last_error = Some(error),
            }
            let now = Instant::now();
            if now >= deadline {
                return if received_code {
                    Ok(false)
                } else {
                    Err(last_error.unwrap_or(ChainError::InvalidResponse { index: rpc_index }))
                };
            }
            sleep(Duration::from_millis(delay_ms).min(deadline - now)).await;
            delay_ms = delay_ms
                .saturating_mul(2)
                .min(check.max_poll_interval_ms.max(50));
        }
    }

    pub async fn account_code(
        &self,
        config: &ChainConfig,
        rpc_index: usize,
        account: Address,
        block_number: Option<u64>,
    ) -> Result<Bytes, ChainError> {
        let endpoint = endpoint(config, rpc_index)?;
        let block = block_number.map_or_else(|| "latest".into(), |value| format!("0x{value:x}"));
        let code: String = self
            .request(
                endpoint,
                rpc_index,
                "eth_getCode",
                json!([account.to_checksum(None), block]),
            )
            .await?;
        decode_code(&code, rpc_index)
    }

    pub async fn estimate_transaction(
        &self,
        config: &ChainConfig,
        rpc_index: usize,
        sender: Address,
        target: Address,
        value: U256,
        calldata: &[u8],
    ) -> Result<u64, ChainError> {
        let endpoint = endpoint(config, rpc_index)?;
        let estimate: String = self
            .request(
                endpoint,
                rpc_index,
                "eth_estimateGas",
                json!([{
                    "from": sender.to_checksum(None),
                    "to": target.to_checksum(None),
                    "value": format!("{value:#x}"),
                    "input": format!("0x{}", hex::encode(calldata)),
                }]),
            )
            .await?;
        parse_quantity_u64(&estimate).map_err(|_| ChainError::InvalidResponse { index: rpc_index })
    }

    /// Read-only contract call (`eth_call`) against the latest block.
    pub async fn call_contract(
        &self,
        config: &ChainConfig,
        rpc_index: usize,
        target: Address,
        calldata: &[u8],
    ) -> Result<Bytes, ChainError> {
        let endpoint = endpoint(config, rpc_index)?;
        let result: String = self
            .request(
                endpoint,
                rpc_index,
                "eth_call",
                json!([{
                    "to": target.to_checksum(None),
                    "data": format!("0x{}", hex::encode(calldata)),
                }, "latest"]),
            )
            .await?;
        hex::decode(result.strip_prefix("0x").unwrap_or(&result))
            .map(Bytes::from)
            .map_err(|_| ChainError::InvalidResponse { index: rpc_index })
    }

    /// Pending nonce for a wallet (`eth_getTransactionCount`).
    pub async fn transaction_count(
        &self,
        config: &ChainConfig,
        rpc_index: usize,
        wallet: Address,
    ) -> Result<u64, ChainError> {
        let endpoint = endpoint(config, rpc_index)?;
        let count: String = self
            .request(
                endpoint,
                rpc_index,
                "eth_getTransactionCount",
                json!([wallet.to_checksum(None), "pending"]),
            )
            .await?;
        parse_quantity_u64(&count).map_err(|_| ChainError::InvalidResponse { index: rpc_index })
    }

    pub async fn send_raw_transaction(
        &self,
        config: &ChainConfig,
        rpc_index: usize,
        signed: &SignedTransaction,
    ) -> Result<B256, ChainError> {
        let endpoint = endpoint(config, rpc_index)?;
        let encoded = Zeroizing::new(format!("0x{}", hex::encode(signed.raw())));
        let returned_hash: String = self
            .request(
                endpoint,
                rpc_index,
                "eth_sendRawTransaction",
                json!([encoded.as_str()]),
            )
            .await?;
        let returned_hash = returned_hash
            .parse()
            .map_err(|_| ChainError::InvalidResponse { index: rpc_index })?;
        if returned_hash != signed.hash() {
            return Err(ChainError::TransactionHashMismatch);
        }
        Ok(returned_hash)
    }

    pub async fn transaction_receipt(
        &self,
        config: &ChainConfig,
        rpc_index: usize,
        transaction_hash: B256,
    ) -> Result<Option<TransactionReceipt>, ChainError> {
        let endpoint = endpoint(config, rpc_index)?;
        let receipt: Option<RpcReceipt> = self
            .request(
                endpoint,
                rpc_index,
                "eth_getTransactionReceipt",
                json!([transaction_hash.to_string()]),
            )
            .await?;
        receipt
            .map(|receipt| decode_receipt(&receipt, rpc_index, transaction_hash))
            .transpose()
    }

    pub async fn wait_for_any_transaction_receipt(
        &self,
        config: &ChainConfig,
        rpc_index: usize,
        transaction_hashes: &[B256],
        policy: ReceiptPollingPolicy,
    ) -> Result<Option<(usize, TransactionReceipt)>, ChainError> {
        if transaction_hashes.is_empty() {
            return Err(ChainError::InvalidResponse { index: rpc_index });
        }
        let deadline = Instant::now()
            .checked_add(Duration::from_secs(policy.timeout_seconds))
            .ok_or(ChainError::PollingTimeoutOutOfRange)?;
        let mut delay_ms = policy.initial_delay_ms.max(50);
        let mut received_response = false;
        let mut last_rate_limit = None;
        loop {
            for (index, transaction_hash) in transaction_hashes.iter().enumerate() {
                match self
                    .transaction_receipt(config, rpc_index, *transaction_hash)
                    .await
                {
                    Ok(Some(receipt)) => return Ok(Some((index, receipt))),
                    Ok(None) => received_response = true,
                    Err(error @ ChainError::RateLimited { .. }) => {
                        last_rate_limit = Some(error);
                    }
                    Err(error) => return Err(error),
                }
            }
            let now = Instant::now();
            if now >= deadline {
                return if received_response {
                    Ok(None)
                } else {
                    Err(last_rate_limit.unwrap_or(ChainError::InvalidResponse { index: rpc_index }))
                };
            }
            sleep(Duration::from_millis(delay_ms).min(deadline - now)).await;
            delay_ms = delay_ms
                .saturating_mul(2)
                .min(policy.maximum_delay_ms.max(50));
        }
    }

    async fn request<T: DeserializeOwned>(
        &self,
        endpoint: &Url,
        index: usize,
        method: &'static str,
        params: Value,
    ) -> Result<T, ChainError> {
        self.request_with_id(endpoint, index, 1, method, params)
            .await
    }

    async fn request_with_id<T: DeserializeOwned>(
        &self,
        endpoint: &Url,
        index: usize,
        id: u64,
        method: &'static str,
        params: Value,
    ) -> Result<T, ChainError> {
        let response = self
            .client
            .post(endpoint.clone())
            .json(&JsonRpcRequest {
                jsonrpc: "2.0",
                id,
                method,
                params,
            })
            .send()
            .await
            .map_err(|_| ChainError::InvalidResponse { index })?;
        if response.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
            return Err(ChainError::RateLimited { index });
        }
        if !response.status().is_success() {
            return Err(ChainError::InvalidResponse { index });
        }
        if response
            .content_length()
            .is_some_and(|length| length > RPC_CONTENT_LENGTH_LIMIT)
        {
            return Err(ChainError::InvalidResponse { index });
        }
        let response_body = read_limited_body(response, RPC_RESPONSE_LIMIT)
            .await
            .map_err(|()| ChainError::InvalidResponse { index })?;
        let envelope: Value = serde_json::from_slice(&response_body)
            .map_err(|_| ChainError::InvalidResponse { index })?;
        let result = extract_result(&envelope, index, id)?;
        serde_json::from_value(result.clone()).map_err(|_| ChainError::InvalidResponse { index })
    }
}

fn eip7702_probe_params() -> Value {
    let mut overrides = serde_json::Map::with_capacity(2);
    overrides.insert(
        EIP7702_PROBE_DELEGATE.into(),
        json!({"code": EIP7702_PROBE_RUNTIME}),
    );
    overrides.insert(
        EIP7702_PROBE_ACCOUNT.into(),
        json!({"code": EIP7702_PROBE_DESIGNATOR}),
    );
    json!([
        {"data": EIP7702_PROBE_CALLDATA, "to": EIP7702_PROBE_ACCOUNT},
        "pending",
        Value::Object(overrides)
    ])
}

fn eip1153_probe_params() -> Value {
    let mut overrides = serde_json::Map::with_capacity(1);
    overrides.insert(
        EIP1153_PROBE_ACCOUNT.into(),
        json!({"code": EIP1153_PROBE_RUNTIME}),
    );
    json!([
        {"data": "0x", "to": EIP1153_PROBE_ACCOUNT},
        "pending",
        Value::Object(overrides)
    ])
}

fn is_eip7702_probe_success(result: &str) -> bool {
    result == ABI_TRUE
}

fn classify_capability_probe(result: Result<String, ChainError>) -> Result<bool, ChainError> {
    match result {
        Ok(value) => Ok(is_eip7702_probe_success(&value)),
        Err(ChainError::Rpc { .. }) => Ok(false),
        Err(error) => Err(error),
    }
}

async fn read_limited_body(mut response: reqwest::Response, limit: usize) -> Result<Vec<u8>, ()> {
    let capacity = response
        .content_length()
        .and_then(|length| usize::try_from(length).ok())
        .unwrap_or(8 * 1024)
        .min(limit);
    let mut body = Vec::with_capacity(capacity);
    while let Some(chunk) = response.chunk().await.map_err(|_| ())? {
        if chunk.len() > limit.saturating_sub(body.len()) {
            return Err(());
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

impl fmt::Debug for ChainGateway {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ChainGateway")
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainProbe {
    pub chain_id: u64,
    pub rpc_index: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LatestBlock {
    pub timestamp: u64,
    pub base_fee_per_gas: Option<U256>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FeeEstimate {
    pub max_priority_fee_per_gas: U256,
    pub max_fee_per_gas: U256,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SubmissionInputs {
    pub latest_block: LatestBlock,
    pub pending_nonce: u64,
    pub fee_estimate: FeeEstimate,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountState {
    pub balance: U256,
    pub pending_nonce: u64,
    pub code: Bytes,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WalletSnapshot {
    pub account_state: AccountState,
    pub submission_inputs: SubmissionInputs,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CodeHashCheck {
    pub account: Address,
    pub block_number: Option<u64>,
    pub expected_hash: B256,
    pub timeout_seconds: u64,
    pub poll_interval_ms: u64,
    pub max_poll_interval_ms: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReceiptPollingPolicy {
    pub timeout_seconds: u64,
    pub initial_delay_ms: u64,
    pub maximum_delay_ms: u64,
}

impl From<RetryConfig> for ReceiptPollingPolicy {
    fn from(config: RetryConfig) -> Self {
        Self {
            timeout_seconds: config.pending_timeout_seconds,
            initial_delay_ms: config.base_delay_ms,
            maximum_delay_ms: config.max_delay_ms,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransactionReceipt {
    pub transaction_hash: B256,
    pub block_number: u64,
    pub is_success: bool,
    pub contract_address: Option<Address>,
    pub logs: Vec<TransactionLog>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransactionLog {
    pub address: Address,
    pub topics: Vec<B256>,
    pub data: Bytes,
}

#[derive(Serialize)]
struct JsonRpcRequest {
    jsonrpc: &'static str,
    id: u64,
    method: &'static str,
    params: Value,
}

#[derive(Deserialize)]
struct RpcBlock {
    timestamp: String,
    #[serde(rename = "baseFeePerGas")]
    base_fee_per_gas: Option<String>,
}

#[derive(Deserialize)]
struct RpcReceipt {
    #[serde(rename = "transactionHash")]
    transaction_hash: String,
    #[serde(rename = "blockNumber")]
    block_number: String,
    status: String,
    #[serde(rename = "contractAddress")]
    contract_address: Option<String>,
    #[serde(default)]
    logs: Vec<RpcLog>,
}

#[derive(Deserialize)]
struct RpcLog {
    address: String,
    #[serde(default)]
    topics: Vec<String>,
    data: String,
}

fn endpoint(config: &ChainConfig, index: usize) -> Result<&Url, ChainError> {
    index
        .checked_sub(1)
        .and_then(|index| config.rpc_urls.get(index))
        .ok_or(ChainError::EndpointNotConfigured { index })
}

fn extract_result(envelope: &Value, index: usize, expected_id: u64) -> Result<&Value, ChainError> {
    if envelope.get("jsonrpc").and_then(Value::as_str) != Some("2.0")
        || envelope.get("id").and_then(Value::as_u64) != Some(expected_id)
    {
        return Err(ChainError::InvalidResponse { index });
    }
    if let Some(error) = envelope.get("error") {
        let code = error
            .get("code")
            .and_then(Value::as_i64)
            .ok_or(ChainError::InvalidResponse { index })?;
        let message = error.get("message").and_then(Value::as_str).unwrap_or("");
        if is_rate_limit_error(code, message) {
            return Err(ChainError::RateLimited { index });
        }
        return Err(ChainError::Rpc { index, code });
    }
    envelope
        .get("result")
        .ok_or(ChainError::InvalidResponse { index })
}

fn is_rate_limit_error(code: i64, message: &str) -> bool {
    let message = message.to_ascii_lowercase();
    matches!(code, 429 | -32_005)
        || message.contains("rate limit")
        || message.contains("too many requests")
        || message.contains("request limit")
}

fn decode_submission_batch(envelope: &Value, index: usize) -> Result<SubmissionInputs, ChainError> {
    let responses = envelope
        .as_array()
        .filter(|responses| responses.len() == 3)
        .ok_or(ChainError::BatchUnsupported { index })?;
    let mut results: [Option<Value>; 3] = std::array::from_fn(|_| None);
    for response in responses {
        let id = response
            .get("id")
            .and_then(Value::as_u64)
            .filter(|id| (1..=3).contains(id))
            .ok_or(ChainError::BatchUnsupported { index })?;
        let slot = usize::try_from(id - 1).map_err(|_| ChainError::InvalidResponse { index })?;
        if results[slot].is_some() {
            return Err(ChainError::BatchUnsupported { index });
        }
        results[slot] = Some(extract_result(response, index, id)?.clone());
    }

    let block: RpcBlock = serde_json::from_value(
        results[0]
            .take()
            .ok_or(ChainError::BatchUnsupported { index })?,
    )
    .map_err(|_| ChainError::InvalidResponse { index })?;
    let timestamp =
        parse_quantity_u64(&block.timestamp).map_err(|_| ChainError::InvalidResponse { index })?;
    let base_fee_per_gas = block
        .base_fee_per_gas
        .as_deref()
        .ok_or(ChainError::Eip1559Unavailable)
        .and_then(|value| {
            parse_quantity_u256(value).map_err(|_| ChainError::InvalidResponse { index })
        })?;
    let pending_nonce: String = serde_json::from_value(
        results[1]
            .take()
            .ok_or(ChainError::BatchUnsupported { index })?,
    )
    .map_err(|_| ChainError::InvalidResponse { index })?;
    let pending_nonce =
        parse_quantity_u64(&pending_nonce).map_err(|_| ChainError::InvalidResponse { index })?;
    let priority_fee: String = serde_json::from_value(
        results[2]
            .take()
            .ok_or(ChainError::BatchUnsupported { index })?,
    )
    .map_err(|_| ChainError::InvalidResponse { index })?;
    let max_priority_fee_per_gas =
        parse_quantity_u256(&priority_fee).map_err(|_| ChainError::InvalidResponse { index })?;
    let max_fee_per_gas = base_fee_per_gas
        .checked_mul(U256::from(2_u8))
        .and_then(|value| value.checked_add(max_priority_fee_per_gas))
        .ok_or(ChainError::QuantityOverflow)?;

    Ok(SubmissionInputs {
        latest_block: LatestBlock {
            timestamp,
            base_fee_per_gas: Some(base_fee_per_gas),
        },
        pending_nonce,
        fee_estimate: FeeEstimate {
            max_priority_fee_per_gas,
            max_fee_per_gas,
        },
    })
}

fn decode_account_state_batch(envelope: &Value, index: usize) -> Result<AccountState, ChainError> {
    let responses = envelope
        .as_array()
        .filter(|responses| responses.len() == 3)
        .ok_or(ChainError::BatchUnsupported { index })?;
    let mut results: [Option<Value>; 3] = std::array::from_fn(|_| None);
    for response in responses {
        let id = response
            .get("id")
            .and_then(Value::as_u64)
            .filter(|id| (1..=3).contains(id))
            .ok_or(ChainError::BatchUnsupported { index })?;
        let slot = usize::try_from(id - 1).map_err(|_| ChainError::InvalidResponse { index })?;
        if results[slot].is_some() {
            return Err(ChainError::BatchUnsupported { index });
        }
        results[slot] = Some(extract_result(response, index, id)?.clone());
    }

    let balance: String = serde_json::from_value(
        results[0]
            .take()
            .ok_or(ChainError::BatchUnsupported { index })?,
    )
    .map_err(|_| ChainError::InvalidResponse { index })?;
    let pending_nonce: String = serde_json::from_value(
        results[1]
            .take()
            .ok_or(ChainError::BatchUnsupported { index })?,
    )
    .map_err(|_| ChainError::InvalidResponse { index })?;
    let code: String = serde_json::from_value(
        results[2]
            .take()
            .ok_or(ChainError::BatchUnsupported { index })?,
    )
    .map_err(|_| ChainError::InvalidResponse { index })?;
    Ok(AccountState {
        balance: parse_quantity_u256(&balance)
            .map_err(|_| ChainError::InvalidResponse { index })?,
        pending_nonce: parse_quantity_u64(&pending_nonce)
            .map_err(|_| ChainError::InvalidResponse { index })?,
        code: decode_code(&code, index)?,
    })
}

fn decode_code(code: &str, index: usize) -> Result<Bytes, ChainError> {
    let digits = code
        .strip_prefix("0x")
        .filter(|digits| digits.len() % 2 == 0)
        .ok_or(ChainError::InvalidResponse { index })?;
    Ok(Bytes::from(
        hex::decode(digits).map_err(|_| ChainError::InvalidResponse { index })?,
    ))
}

fn decode_receipt(
    receipt: &RpcReceipt,
    index: usize,
    expected_hash: B256,
) -> Result<TransactionReceipt, ChainError> {
    let transaction_hash: B256 = receipt
        .transaction_hash
        .parse()
        .map_err(|_| ChainError::InvalidResponse { index })?;
    if transaction_hash != expected_hash {
        return Err(ChainError::TransactionHashMismatch);
    }
    let block_number = parse_quantity_u64(&receipt.block_number)
        .map_err(|_| ChainError::InvalidResponse { index })?;
    let status =
        parse_quantity_u64(&receipt.status).map_err(|_| ChainError::InvalidResponse { index })?;
    if status > 1 {
        return Err(ChainError::InvalidResponse { index });
    }
    let logs = receipt
        .logs
        .iter()
        .map(|log| decode_log(log, index))
        .collect::<Result<Vec<_>, _>>()?;
    let contract_address = receipt
        .contract_address
        .as_deref()
        .map(str::parse)
        .transpose()
        .map_err(|_| ChainError::InvalidResponse { index })?;
    Ok(TransactionReceipt {
        transaction_hash,
        block_number,
        is_success: status == 1,
        contract_address,
        logs,
    })
}

fn decode_log(log: &RpcLog, index: usize) -> Result<TransactionLog, ChainError> {
    let address = log
        .address
        .parse()
        .map_err(|_| ChainError::InvalidResponse { index })?;
    let topics = log
        .topics
        .iter()
        .map(|topic| {
            topic
                .parse()
                .map_err(|_| ChainError::InvalidResponse { index })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let data = log
        .data
        .strip_prefix("0x")
        .filter(|digits| digits.len() % 2 == 0)
        .ok_or(ChainError::InvalidResponse { index })?;
    let data = hex::decode(data).map_err(|_| ChainError::InvalidResponse { index })?;
    Ok(TransactionLog {
        address,
        topics,
        data: Bytes::from(data),
    })
}

pub fn parse_chain_id(value: &str) -> Result<u64, std::num::ParseIntError> {
    parse_quantity_u64(value)
}

fn parse_quantity_u64(value: &str) -> Result<u64, std::num::ParseIntError> {
    let digits = value.strip_prefix("0x").unwrap_or("");
    if digits.is_empty() || (digits.len() > 1 && digits.starts_with('0')) {
        return u64::from_str_radix("x", 16);
    }
    u64::from_str_radix(digits, 16)
}

fn reconcile_wallet_snapshot(
    account_state: AccountState,
    submission_inputs: SubmissionInputs,
) -> Result<WalletSnapshot, ChainError> {
    if account_state.pending_nonce != submission_inputs.pending_nonce {
        return Err(ChainError::WalletSnapshotChanged);
    }
    Ok(WalletSnapshot {
        account_state,
        submission_inputs,
    })
}

fn parse_quantity_u256(value: &str) -> Result<U256, alloy_primitives::ruint::ParseError> {
    let digits = value.strip_prefix("0x").unwrap_or("");
    if digits.is_empty() || (digits.len() > 1 && digits.starts_with('0')) {
        return U256::from_str_radix("x", 16);
    }
    U256::from_str_radix(digits, 16)
}

#[cfg(test)]
mod tests {
    use alloy_primitives::{B256, Bytes, U256};

    use super::{
        AccountState, ChainError, FeeEstimate, LatestBlock, ReceiptPollingPolicy, RetryConfig,
        RpcReceipt, SubmissionInputs, classify_capability_probe, decode_account_state_batch,
        decode_receipt, decode_submission_batch, eip1153_probe_params, eip7702_probe_params,
        extract_result, is_eip7702_probe_success, reconcile_wallet_snapshot,
    };

    #[test]
    fn rejects_json_rpc_envelopes_with_wrong_version_or_id() {
        let wrong_version = serde_json::json!({"jsonrpc":"1.0","id":1,"result":"0x1"});
        assert!(matches!(
            extract_result(&wrong_version, 1, 1),
            Err(ChainError::InvalidResponse { index: 1 })
        ));

        let wrong_id = serde_json::json!({"jsonrpc":"2.0","id":2,"result":"0x1"});
        assert!(matches!(
            extract_result(&wrong_id, 1, 1),
            Err(ChainError::InvalidResponse { index: 1 })
        ));
    }

    #[test]
    fn wallet_snapshot_requires_one_consistent_pending_nonce() {
        let state = AccountState {
            balance: U256::from(1_u8),
            pending_nonce: 7,
            code: Bytes::new(),
        };
        let inputs = SubmissionInputs {
            latest_block: LatestBlock {
                timestamp: 1,
                base_fee_per_gas: Some(U256::from(1_u8)),
            },
            pending_nonce: 7,
            fee_estimate: FeeEstimate {
                max_priority_fee_per_gas: U256::from(1_u8),
                max_fee_per_gas: U256::from(2_u8),
            },
        };

        assert!(reconcile_wallet_snapshot(state.clone(), inputs).is_ok());
        assert!(matches!(
            reconcile_wallet_snapshot(
                state,
                SubmissionInputs {
                    pending_nonce: 8,
                    ..inputs
                }
            ),
            Err(ChainError::WalletSnapshotChanged)
        ));
    }

    #[test]
    fn receipt_polling_policy_preserves_validated_retry_settings() {
        let retry = RetryConfig {
            max_attempts: 3,
            pending_timeout_seconds: 20,
            base_delay_ms: 250,
            max_delay_ms: 2_000,
        };

        assert_eq!(
            ReceiptPollingPolicy::from(retry),
            ReceiptPollingPolicy {
                timeout_seconds: 20,
                initial_delay_ms: 250,
                maximum_delay_ms: 2_000,
            }
        );
    }

    #[test]
    fn classifies_explicit_json_rpc_rate_limits_for_sequential_fallback() {
        for envelope in [
            serde_json::json!({
                "jsonrpc":"2.0", "id":1,
                "error":{"code":429,"message":"Too Many Requests"}
            }),
            serde_json::json!({
                "jsonrpc":"2.0", "id":1,
                "error":{"code":-32005,"message":"limit exceeded"}
            }),
            serde_json::json!({
                "jsonrpc":"2.0", "id":1,
                "error":{"code":-32000,"message":"rate limit reached"}
            }),
        ] {
            assert!(matches!(
                extract_result(&envelope, 1, 1),
                Err(ChainError::RateLimited { index: 1 })
            ));
        }
    }

    #[test]
    fn builds_and_strictly_decodes_the_eip7702_liveness_probe() {
        let params = eip7702_probe_params();

        assert_eq!(params[0]["data"], "0xc1cd7856");
        assert_eq!(
            params[0]["to"],
            "0x000000000000000000000000000000000dead123"
        );
        assert_eq!(params[1], "pending");
        assert_eq!(
            params[2]["0x000000000000000000000000000000000dead123"]["code"],
            "0xef01001234567890abcdef1234567890abcdef12345678"
        );
        assert_eq!(
            params[2]["0x1234567890abcdef1234567890abcdef12345678"]["code"],
            super::EIP7702_PROBE_RUNTIME
        );
        assert!(is_eip7702_probe_success(
            "0x0000000000000000000000000000000000000000000000000000000000000001"
        ));
        assert!(!is_eip7702_probe_success("0x1"));
        assert!(!is_eip7702_probe_success(
            "0x0000000000000000000000000000000000000000000000000000000000000000"
        ));
    }

    #[test]
    fn builds_the_transient_storage_liveness_probe() {
        let params = eip1153_probe_params();

        assert_eq!(params[0]["data"], "0x");
        assert_eq!(
            params[0]["to"],
            "0x000000000000000000000000000000000dead124"
        );
        assert_eq!(params[1], "pending");
        assert_eq!(
            params[2]["0x000000000000000000000000000000000dead124"]["code"],
            "0x600160005d60005c60005260206000f3"
        );
    }

    #[test]
    fn classifies_rpc_rejection_as_an_unsupported_capability() {
        assert!(
            !classify_capability_probe(Err(ChainError::Rpc {
                index: 1,
                code: -32_602,
            }))
            .expect("unsupported capability")
        );
        assert!(matches!(
            classify_capability_probe(Err(ChainError::InvalidResponse { index: 1 })),
            Err(ChainError::InvalidResponse { index: 1 })
        ));
    }

    #[test]
    fn accepts_null_receipt_result_but_rejects_missing_result() {
        let pending = serde_json::json!({"jsonrpc":"2.0","id":1,"result":null});
        assert!(extract_result(&pending, 1, 1).expect("pending").is_null());
        let missing = serde_json::json!({"jsonrpc":"2.0","id":1});
        assert!(extract_result(&missing, 1, 1).is_err());
    }

    #[test]
    fn matches_out_of_order_submission_batch_responses_by_id() {
        let envelope = serde_json::json!([
            {"jsonrpc":"2.0","id":3,"result":"0xf4240"},
            {"jsonrpc":"2.0","id":1,"result":{"timestamp":"0x64","baseFeePerGas":"0x7a120"}},
            {"jsonrpc":"2.0","id":2,"result":"0x7"}
        ]);

        let inputs = decode_submission_batch(&envelope, 1).expect("batch");
        assert_eq!(inputs.latest_block.timestamp, 100);
        assert_eq!(inputs.pending_nonce, 7);
        assert_eq!(inputs.fee_estimate.max_priority_fee_per_gas, 1_000_000);
        assert_eq!(inputs.fee_estimate.max_fee_per_gas, 2_000_000);
    }

    #[test]
    fn rejects_duplicate_or_missing_submission_batch_responses() {
        let duplicate = serde_json::json!([
            {"jsonrpc":"2.0","id":1,"result":{"timestamp":"0x64","baseFeePerGas":"0x7a120"}},
            {"jsonrpc":"2.0","id":1,"result":"0x7"},
            {"jsonrpc":"2.0","id":3,"result":"0xf4240"}
        ]);
        assert!(matches!(
            decode_submission_batch(&duplicate, 1),
            Err(ChainError::BatchUnsupported { index: 1 })
        ));
    }

    #[test]
    fn decodes_account_state_batch_by_id_and_rejects_bad_code() {
        let envelope = serde_json::json!([
            {"jsonrpc":"2.0","id":3,"result":"0xef01000000000000000000000000000000000000000011"},
            {"jsonrpc":"2.0","id":1,"result":"0x123"},
            {"jsonrpc":"2.0","id":2,"result":"0x7"}
        ]);
        let state = decode_account_state_batch(&envelope, 1).expect("state");
        assert_eq!(state.balance, U256::from(0x123_u64));
        assert_eq!(state.pending_nonce, 7);
        assert_eq!(state.code.len(), 23);

        let invalid = serde_json::json!([
            {"jsonrpc":"2.0","id":1,"result":"0x1"},
            {"jsonrpc":"2.0","id":2,"result":"0x0"},
            {"jsonrpc":"2.0","id":3,"result":"0x1"}
        ]);
        assert!(decode_account_state_batch(&invalid, 1).is_err());
        assert_eq!(Bytes::new().len(), 0);
    }

    #[test]
    fn decodes_contract_address_from_creation_receipt() {
        let hash = B256::repeat_byte(0x11);
        let receipt = RpcReceipt {
            transaction_hash: hash.to_string(),
            block_number: "0x2a".into(),
            status: "0x1".into(),
            contract_address: Some("0x0000000000000000000000000000000000000022".into()),
            logs: Vec::new(),
        };
        let decoded = decode_receipt(&receipt, 1, hash).expect("receipt");

        assert!(decoded.is_success);
        assert_eq!(decoded.block_number, 42);
        assert_eq!(
            decoded.contract_address,
            Some(
                "0x0000000000000000000000000000000000000022"
                    .parse()
                    .expect("address")
            )
        );

        let invalid = RpcReceipt {
            contract_address: Some("not-an-address".into()),
            ..receipt
        };
        assert!(decode_receipt(&invalid, 1, hash).is_err());
    }
}
