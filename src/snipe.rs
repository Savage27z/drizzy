//! Public `SeaDrop` sniper: locally built calldata, pre-signed transactions,
//! multi-RPC blast.
//!
//! This is the fast path merged from `nft-public-mint` (TypeScript) into the
//! Rust CLI. Unlike the `OpenSea` API path (`opensea-mint mint`), it never
//! touches `OpenSea`'s API on the critical path: the `mintPublic` calldata is
//! assembled from on-chain state, every wallet transaction is signed and
//! serialised *before* the stage opens, and at fire time the only work left is
//! writing pre-built JSON bodies to every RPC endpoint in parallel.
//!
//! Allowlist/FCFS stages (`mintSigned`) still need `OpenSea`'s per-wallet
//! signatures, so those go through the existing `mint` command.

use std::{path::PathBuf, time::Duration};

use alloy_primitives::{Address, U256};
use reqwest::StatusCode;
use thiserror::Error;
use tokio::{
    task::JoinHandle,
    time::{Instant, sleep},
};
use url::Url;
use zeroize::Zeroizing;

use crate::{
    blast::{self, BlastError, BlastResult, PreparedBlast},
    chain::{AccountState, ChainError, ChainGateway, TransactionReceipt},
    config::ChainConfig,
    domain::format_countdown,
    logging,
    multi_wallet::WalletManifest,
    seadrop::{self, LocalMintPlan},
    signing::{WalletSigner, WalletSignerError},
    transaction::{Eip1559Transaction, TransactionError, sign_eip1559_transaction},
};

const READ_TIMEOUT: Duration = Duration::from_secs(10);
const RECEIPT_TIMEOUT_SECONDS: u64 = 60;
const DEFAULT_GAS_LIMIT: u64 = 250_000;
const GWEI: u128 = 1_000_000_000;

/// Chain registry — mirrors `nft-public-mint/src/chains.ts`. Everything
/// chain-specific lives here so adding a network is a single entry.
struct ChainProfile {
    key: &'static str,
    chain_id: u64,
    explorer: &'static str,
    alchemy_host: &'static str,
    public_rpcs: &'static [&'static str],
}

const CHAINS: &[ChainProfile] = &[
    ChainProfile {
        key: "ethereum",
        chain_id: 1,
        explorer: "https://etherscan.io",
        alchemy_host: "eth-mainnet.g.alchemy.com",
        public_rpcs: &[
            "https://ethereum-rpc.publicnode.com",
            "https://eth.merkle.io",
            "https://cloudflare-eth.com",
        ],
    },
    ChainProfile {
        key: "base",
        chain_id: 8453,
        explorer: "https://basescan.org",
        alchemy_host: "base-mainnet.g.alchemy.com",
        public_rpcs: &[
            "https://mainnet.base.org",
            "https://base-rpc.publicnode.com",
            // Send-only (rejects eth_chainId/eth_call) but the fastest inclusion
            // path — kept for blasting, never read from.
            "https://mainnet-sequencer.base.org",
        ],
    },
    ChainProfile {
        key: "robinhood",
        chain_id: 4663,
        explorer: "https://robinhoodchain.blockscout.com",
        alchemy_host: "robinhood-mainnet.g.alchemy.com",
        public_rpcs: &[
            "https://rpc.mainnet.chain.robinhood.com",
            "https://sequencer.mainnet.chain.robinhood.com",
        ],
    },
];

const DEFAULT_EXPLORER: &str = "https://basescan.org";

fn resolve_chain(key: &str) -> Option<&'static ChainProfile> {
    CHAINS.iter().find(|profile| profile.key == key)
}

fn chain_by_id(chain_id: u64) -> Option<&'static ChainProfile> {
    CHAINS.iter().find(|profile| profile.chain_id == chain_id)
}

fn explorer_url(chain_id: u64, tx_hash: &str) -> String {
    let base = chain_by_id(chain_id).map_or(DEFAULT_EXPLORER, |profile| profile.explorer);
    format!("{base}/tx/{tx_hash}")
}

#[derive(Debug, Error)]
pub enum SnipeError {
    #[error("invalid collection locator: {0}")]
    InvalidCollection(String),
    #[error("OpenSea slug lookup failed: {0}")]
    SlugLookup(String),
    #[error("invalid RPC endpoint: {0}")]
    InvalidRpc(String),
    #[error("no RPC endpoints configured; pass --rpc, set RPC_URL in .env, or choose --chain")]
    NoRpcEndpoints,
    #[error("no working RPC endpoint after probing {count} candidate(s)")]
    NoWorkingRpc { count: usize },
    #[error("no RPC endpoint on the selected chain ({chain}, id {chain_id})")]
    NoEndpointForChain { chain: String, chain_id: u64 },
    #[error("no wallet keys configured; pass --key or --wallets")]
    NoWallets,
    #[error("invalid mint quantity: {0}")]
    InvalidQuantity(String),
    #[error(
        "collection has no public stage on the SeaDrop singleton; allowlist/FCFS stages need `opensea-mint mint`"
    )]
    NoPublicStage,
    #[error(
        "wallet {address} cannot cover mint value + gas: balance {balance} wei, required {required} wei; highest affordable max fee ≈ {affordable} gwei"
    )]
    Underfunded {
        address: Address,
        balance: U256,
        required: U256,
        affordable: String,
    },
    #[error("invalid gas value: {0}")]
    InvalidGas(String),
    #[error("chain id mismatch: RPCs disagree ({first} vs {second})")]
    ChainMismatch { first: u64, second: u64 },
    #[error(transparent)]
    Chain(#[from] ChainError),
    #[error(transparent)]
    Blast(#[from] BlastError),
    #[error(transparent)]
    Seadrop(#[from] seadrop::SeadropError),
    #[error(transparent)]
    Wallet(#[from] WalletSignerError),
    #[error(transparent)]
    Transaction(#[from] TransactionError),
    #[error(transparent)]
    Manifest(#[from] crate::multi_wallet::WalletManifestError),
}

#[derive(Debug)]
pub struct SnipeOptions {
    pub collection: String,
    pub quantity: Option<u64>,
    pub keys: Vec<Zeroizing<String>>,
    pub wallets_file: Option<PathBuf>,
    /// Optional 0-based subset of manifest wallets to fire.
    pub wallet_indices: Option<Vec<usize>>,
    pub rpc_urls: Vec<String>,
    pub chain: Option<String>,
    pub max_fee_per_gas: Option<U256>,
    pub max_priority_fee_per_gas: Option<U256>,
    pub gas_limit: u64,
    pub early_fire_ms: u64,
    pub fire_now: bool,
    /// Optional channel receiving every progress line (bot streaming).
    pub notify: Option<tokio::sync::mpsc::UnboundedSender<String>>,
}

impl Default for SnipeOptions {
    fn default() -> Self {
        Self {
            collection: String::new(),
            quantity: None,
            keys: Vec::new(),
            wallets_file: None,
            wallet_indices: None,
            rpc_urls: Vec::new(),
            chain: None,
            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
            gas_limit: DEFAULT_GAS_LIMIT,
            early_fire_ms: 0,
            fire_now: false,
            notify: None,
        }
    }
}

/// Parse a decimal gwei string (e.g. `0.05` or `200`) into wei.
pub fn parse_gwei(value: &str) -> Result<U256, SnipeError> {
    let trimmed = value.trim();
    let (whole, fraction) = match trimmed.split_once('.') {
        Some((whole, fraction)) => (whole, fraction),
        None => (trimmed, ""),
    };
    if whole.is_empty() && fraction.is_empty() {
        return Err(SnipeError::InvalidGas(value.to_owned()));
    }
    let whole: u128 = if whole.is_empty() {
        0
    } else {
        whole
            .parse()
            .map_err(|_| SnipeError::InvalidGas(value.to_owned()))?
    };
    let mut fraction = fraction.to_owned();
    if fraction.len() > 9 {
        return Err(SnipeError::InvalidGas(
            "more than 9 decimal places (gwei precision)".to_owned(),
        ));
    }
    while fraction.len() < 9 {
        fraction.push('0');
    }
    let fraction: u128 = if fraction.is_empty() {
        0
    } else {
        fraction
            .parse()
            .map_err(|_| SnipeError::InvalidGas(value.to_owned()))?
    };
    let wei = whole
        .checked_mul(GWEI)
        .and_then(|scaled| scaled.checked_add(fraction))
        .ok_or_else(|| SnipeError::InvalidGas(value.to_owned()))?;
    Ok(U256::from(wei))
}

/// Format wei as a gwei string with up to three decimals.
fn format_gwei(wei: U256) -> String {
    let whole = wei / U256::from(GWEI);
    let fraction = wei % U256::from(GWEI);
    let millis = fraction * U256::from(1_000) / U256::from(GWEI);
    format!("{whole}.{millis:0>3}")
}

/// Resolve a collection locator (address, URL, or slug) to a contract address.
/// Slug lookups hit `OpenSea`'s public v2 collections endpoint; the key is
/// optional and only used when `OPENSEA_API_KEY` is set.
async fn resolve_nft_contract(
    locator: &str,
    client: &reqwest::Client,
) -> Result<Address, SnipeError> {
    let trimmed = locator.trim();
    if trimmed.starts_with("0x") || trimmed.starts_with("0X") {
        return trimmed
            .parse()
            .map_err(|_| SnipeError::InvalidCollection(trimmed.to_owned()));
    }
    if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        let url =
            Url::parse(trimmed).map_err(|_| SnipeError::InvalidCollection(trimmed.to_owned()))?;
        for segment in url.path_segments().into_iter().flatten() {
            if segment.len() == 42
                && (segment.starts_with("0x") || segment.starts_with("0X"))
                && let Ok(address) = segment.parse()
            {
                return Ok(address);
            }
        }
        let slug = url
            .path_segments()
            .into_iter()
            .flatten()
            .last()
            .unwrap_or_default()
            .to_owned();
        return resolve_slug(&slug, client).await;
    }
    resolve_slug(trimmed, client).await
}

async fn resolve_slug(slug: &str, client: &reqwest::Client) -> Result<Address, SnipeError> {
    let mut request = client.get(format!("https://api.opensea.io/api/v2/collections/{slug}"));
    if let Ok(api_key) = std::env::var("OPENSEA_API_KEY")
        && !api_key.trim().is_empty()
    {
        request = request.header("x-api-key", api_key.trim());
    }
    let response = request
        .send()
        .await
        .map_err(|error| SnipeError::SlugLookup(error.to_string()))?;
    match response.status() {
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => {
            return Err(SnipeError::SlugLookup(
                "OpenSea refused the lookup (401/403) — the slug may be misspelled, or it wants an API key"
                    .to_owned(),
            ));
        }
        StatusCode::NOT_FOUND => {
            return Err(SnipeError::SlugLookup(format!(
                "no OpenSea collection called \"{slug}\""
            )));
        }
        StatusCode::TOO_MANY_REQUESTS => {
            return Err(SnipeError::SlugLookup(
                "OpenSea rate-limited the lookup — retry shortly".to_owned(),
            ));
        }
        status if !status.is_success() => {
            return Err(SnipeError::SlugLookup(format!(
                "could not resolve \"{slug}\": {status}"
            )));
        }
        _ => {}
    }
    let json: serde_json::Value = response
        .json()
        .await
        .map_err(|error| SnipeError::SlugLookup(error.to_string()))?;
    let contracts = json
        .get("contracts")
        .and_then(|value| value.as_array())
        .ok_or_else(|| SnipeError::SlugLookup(format!("no contracts listed for \"{slug}\"")))?;
    let first = contracts
        .first()
        .ok_or_else(|| SnipeError::SlugLookup(format!("no contracts listed for \"{slug}\"")))?;
    let address = first
        .get("address")
        .and_then(|value| value.as_str())
        .ok_or_else(|| {
            SnipeError::SlugLookup(format!("malformed contract entry for \"{slug}\""))
        })?;
    address
        .parse()
        .map_err(|_| SnipeError::InvalidCollection(address.to_owned()))
}

/// Endpoints whose host contains "sequencer" are send-only on Base and
/// Robinhood — fastest for inclusion but they reject reads. They stay in the
/// blast list but are moved after read-capable endpoints so reads always use
/// index 0.
fn order_endpoints(working: Vec<(Url, u64)>) -> Vec<(Url, u64)> {
    let (mut reads, mut sends): (Vec<_>, Vec<_>) = working.into_iter().partition(|(url, _)| {
        !url.host_str()
            .is_some_and(|host| host.contains("sequencer"))
    });
    reads.append(&mut sends);
    reads
}

async fn run_probe(
    gateway: &ChainGateway,
    candidates: &[Url],
    expected_chain_id: Option<u64>,
) -> Result<(u64, Vec<Url>), SnipeError> {
    let mut probed: Vec<(Url, u64)> = Vec::new();
    for url in candidates {
        match gateway.probe_rpc(url).await {
            Ok(probe) => probed.push((url.clone(), probe.chain_id)),
            Err(_) => logging::warn(format!("RPC {url} unreachable — dropped")),
        }
    }
    if probed.is_empty() {
        return Err(SnipeError::NoWorkingRpc {
            count: candidates.len(),
        });
    }
    if let Some(expected) = expected_chain_id {
        probed.retain(|(_, chain_id)| *chain_id == expected);
        if probed.is_empty() {
            return Err(SnipeError::NoEndpointForChain {
                chain: chain_by_id(expected)
                    .map_or_else(|| "unknown".to_owned(), |profile| profile.key.to_owned()),
                chain_id: expected,
            });
        }
    }
    let chain_id = probed[0].1;
    if probed.iter().any(|(_, other)| *other != chain_id) {
        return Err(SnipeError::ChainMismatch {
            first: chain_id,
            second: probed
                .iter()
                .find(|(_, other)| *other != chain_id)
                .unwrap()
                .1,
        });
    }
    let ordered = order_endpoints(probed);
    Ok((chain_id, ordered.into_iter().map(|(url, _)| url).collect()))
}

fn validate_rpc_url(url: &Url) -> bool {
    if url.scheme() == "https" {
        return true;
    }
    if url.scheme() == "http"
        && url
            .host_str()
            .is_some_and(|host| host == "localhost" || host == "127.0.0.1" || host == "::1")
    {
        return true;
    }
    false
}

fn resolve_rpc_candidates(options: &SnipeOptions) -> Result<Vec<Url>, SnipeError> {
    let profile = options.chain.as_deref().and_then(resolve_chain);
    let mut urls: Vec<Url> = Vec::new();

    for raw in &options.rpc_urls {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.contains("://") {
            let url =
                Url::parse(trimmed).map_err(|_| SnipeError::InvalidRpc(trimmed.to_owned()))?;
            if !validate_rpc_url(&url) {
                return Err(SnipeError::InvalidRpc(format!(
                    "{trimmed} must use HTTPS, except for an HTTP loopback endpoint"
                )));
            }
            urls.push(url);
        } else if let Some(profile) = profile {
            // Bare Alchemy key — expand against the selected chain.
            let url = format!("https://{}/v2/{trimmed}", profile.alchemy_host);
            let url = Url::parse(&url).map_err(|_| SnipeError::InvalidRpc(trimmed.to_owned()))?;
            urls.push(url);
        } else {
            return Err(SnipeError::InvalidRpc(format!(
                "{trimmed} is not a URL; pass --chain to expand a bare Alchemy key"
            )));
        }
    }

    if urls.is_empty() {
        // .env RPC_URL beats chain defaults (a private RPC is the single
        // biggest factor in winning a contested mint).
        if let Ok(env_rpc) = std::env::var("RPC_URL") {
            let trimmed = env_rpc.trim();
            if !trimmed.is_empty() {
                let url =
                    Url::parse(trimmed).map_err(|_| SnipeError::InvalidRpc(trimmed.to_owned()))?;
                if !validate_rpc_url(&url) {
                    return Err(SnipeError::InvalidRpc(
                        "RPC_URL must use HTTPS, except for an HTTP loopback endpoint".to_owned(),
                    ));
                }
                urls.push(url);
            }
        }
    }
    if urls.is_empty()
        && let Some(profile) = profile
    {
        for rpc in profile.public_rpcs {
            urls.push(Url::parse(rpc).expect("static public RPC URL"));
        }
    }
    if urls.is_empty() {
        return Err(SnipeError::NoRpcEndpoints);
    }
    Ok(urls)
}

fn load_wallets(options: &SnipeOptions) -> Result<Vec<(WalletSigner, u64)>, SnipeError> {
    let mut wallets: Vec<(WalletSigner, u64)> = Vec::new();
    for key in &options.keys {
        let signer = WalletSigner::from_private_key(key)?;
        wallets.push((signer, options.quantity.unwrap_or(1)));
    }
    if let Some(path) = &options.wallets_file {
        let manifest = WalletManifest::load(path)?;
        for entry in manifest.wallets() {
            let quantity = options.quantity.unwrap_or_else(|| entry.quantity());
            wallets.push((entry.signer().clone(), quantity));
        }
    }
    if let Some(indices) = &options.wallet_indices {
        let mut selected = Vec::with_capacity(indices.len());
        for index in indices {
            let wallet = wallets.get(*index).ok_or_else(|| {
                SnipeError::InvalidQuantity(format!(
                    "wallet index {index} out of range ({} wallet(s) available)",
                    wallets.len()
                ))
            })?;
            selected.push(wallet.clone());
        }
        wallets = selected;
    }
    if wallets.is_empty() {
        return Err(SnipeError::NoWallets);
    }
    Ok(wallets)
}

/// Wait until `fire_time_millis` (unix epoch milliseconds), with a countdown
/// while far away and a tight spin-wait for the final milliseconds — the
/// sub-millisecond precision that makes a pre-signed blast land at T-0.
async fn wait_until_fire(fire_time_millis: i64, stage_label: &str) {
    let now = unix_millis();
    let remaining = fire_time_millis - now;
    if remaining <= 0 {
        return;
    }
    logging::info(format!(
        "{stage_label} | firing in {}",
        format_countdown(u64::try_from(remaining / 1000).unwrap_or(0))
    ));

    // Coarse countdown while more than 10s away.
    while fire_time_millis - unix_millis() > 10_000 {
        logging::info(format!(
            "Waiting... {} remaining",
            format_countdown(u64::try_from((fire_time_millis - unix_millis()) / 1000).unwrap_or(0))
        ));
        sleep(Duration::from_secs(1)).await;
    }

    // Precise wait for the last seconds: sleep most of it, then spin.
    let remaining = fire_time_millis - unix_millis();
    if remaining > 100 {
        sleep(Duration::from_millis(
            u64::try_from(remaining - 100).unwrap_or(0),
        ))
        .await;
    }
    while unix_millis() < fire_time_millis {
        std::hint::spin_loop();
    }
    logging::success("FIRING!");
}

fn unix_millis() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| {
            i64::try_from(duration.as_millis()).unwrap_or(i64::MAX)
        })
}

struct PreparedWallet {
    index: usize,
    address: Address,
    blast: PreparedBlast,
}

struct FiredWallet {
    index: usize,
    address: Address,
    handles: Vec<JoinHandle<BlastResult>>,
}

async fn collect_results(
    fired: Vec<FiredWallet>,
) -> (
    Vec<(usize, Address, Vec<BlastResult>)>,
    Vec<(usize, Address, Vec<BlastResult>)>,
) {
    let mut accepted = Vec::new();
    let mut rejected = Vec::new();
    for wallet in fired {
        let mut results = Vec::with_capacity(wallet.handles.len());
        for handle in wallet.handles {
            if let Ok(result) = handle.await {
                results.push(result);
            }
        }
        if blast::is_accepted(&results) {
            accepted.push((wallet.index, wallet.address, results));
        } else {
            rejected.push((wallet.index, wallet.address, results));
        }
    }
    (accepted, rejected)
}

async fn wait_for_receipt(
    gateway: &ChainGateway,
    config: &ChainConfig,
    tx_hash: &str,
) -> Result<Option<TransactionReceipt>, ChainError> {
    let deadline = Instant::now() + Duration::from_secs(RECEIPT_TIMEOUT_SECONDS);
    let mut delay = Duration::from_millis(250);
    loop {
        match tx_hash.parse::<alloy_primitives::B256>() {
            Ok(hash) => match gateway.transaction_receipt(config, 1, hash).await {
                Ok(Some(receipt)) => return Ok(Some(receipt)),
                Ok(None) | Err(ChainError::RateLimited { .. }) => {}
                Err(error) => return Err(error),
            },
            Err(_) => return Ok(None),
        }
        if Instant::now() >= deadline {
            return Ok(None);
        }
        sleep(delay).await;
        delay = (delay * 2).min(Duration::from_secs(2));
    }
}

/// Full local-public snipe flow. Returns `Ok(())` after dispatch + receipt
/// reporting; nothing is ever broadcast before `Fire?`-style confirmation is
/// baked into the CLI (dispatch only happens after an explicit `--fire-now`,
/// a passed stage start, or an auto-detected live stage).
/// Summary of a planned snipe, used by the bot's confirm step.
#[derive(Debug)]
pub struct SnipePreview {
    pub nft_contract: Address,
    pub chain_id: u64,
    pub chain_name: String,
    pub price: U256,
    pub start_time: u64,
    pub end_time: u64,
    pub fee_recipient: Address,
    pub wallet_count: usize,
}

/// Resolve collection + chain + public stage and report what a snipe would
/// do, without signing or broadcasting anything. The bot shows this summary
/// before asking for confirmation.
pub async fn preview(options: &SnipeOptions) -> Result<SnipePreview, SnipeError> {
    let _ = dotenvy::dotenv();
    let read_client = reqwest::Client::new();
    let nft_contract = resolve_nft_contract(&options.collection, &read_client).await?;
    let candidates = resolve_rpc_candidates(options)?;
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
        .ok_or(SnipeError::NoPublicStage)?;
    let wallet_count = load_wallets(options)?.len();
    Ok(SnipePreview {
        nft_contract,
        chain_id,
        chain_name: chain_by_id(chain_id)
            .map_or_else(|| "unknown".to_owned(), |p| p.key.to_owned()),
        price: base.drop.mint_price,
        start_time: base.drop.start_time,
        end_time: base.drop.end_time,
        fee_recipient: base.fee_recipient,
        wallet_count,
    })
}

#[allow(clippy::too_many_lines)]
pub async fn run_snipe(options: SnipeOptions) -> Result<(), SnipeError> {
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
    macro_rules! emit_error {
        ($msg:expr) => {{
            let msg: String = $msg.into();
            logging::error(&msg);
            if let Some(tx) = &notify {
                let _ = tx.send(msg);
            }
        }};
    }

    // Load .env for RPC_URL / OPENSEA_API_KEY without requiring one.
    let _ = dotenvy::dotenv();

    let gas_limit = options.gas_limit.max(21_000);
    let read_client = reqwest::Client::new();
    let nft_contract = resolve_nft_contract(&options.collection, &read_client).await?;
    let candidates = resolve_rpc_candidates(&options)?;

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
    let endpoints = blast::parse_endpoints(&rpc_urls);
    let chain_name = chain_by_id(chain_id).map_or("unknown", |profile| profile.key);

    logging::section_break();
    emit_info!(format!(
        "SNIPE {nft_contract} on {chain_name} (chain id {chain_id})"
    ));
    emit_info!(format!("RPC blast targets: {}", rpc_urls.len()));

    // ── Build the public-stage plan from on-chain data only ──
    let base = seadrop::build_local_mint_plan(&gateway, &config, 1, nft_contract, 1)
        .await?
        .ok_or(SnipeError::NoPublicStage)?;
    let drop = base.drop;

    let wallets = load_wallets(&options)?;
    let plans: Vec<(WalletSigner, u64, LocalMintPlan)> = wallets
        .into_iter()
        .map(|(signer, quantity)| {
            let plan = LocalMintPlan {
                to: base.to,
                data: seadrop::encode_mint_public(nft_contract, base.fee_recipient, quantity),
                value: drop.mint_price * U256::from(quantity),
                drop,
                fee_recipient: base.fee_recipient,
            };
            (signer, quantity, plan)
        })
        .collect();

    emit_info!(format!(
        "SeaDrop: {} | price {} wei × {} wallet(s)",
        base.to,
        drop.mint_price,
        plans.len()
    ));
    emit_info!(format!("Fee recipient: {}", base.fee_recipient));
    emit_info!(format!(
        "Calldata: {} bytes (identical for every wallet)",
        (base.data.len() - 4)
    ));

    // ── Fees: explicit CLI values win; otherwise chain estimate ──
    let first_address = plans[0].0.identity().address;
    let (max_fee_per_gas, max_priority_fee_per_gas) =
        match (options.max_fee_per_gas, options.max_priority_fee_per_gas) {
            (Some(max), Some(priority)) => (max, priority),
            (Some(max), None) => {
                let estimate = gateway
                    .submission_inputs(&config, 1, first_address)
                    .await
                    .map_or_else(
                        |_| U256::from(0),
                        |inputs| inputs.fee_estimate.max_priority_fee_per_gas,
                    );
                (max, estimate)
            }
            (None, Some(priority)) => {
                let base = gateway
                    .latest_block(&config, 1)
                    .await?
                    .base_fee_per_gas
                    .unwrap_or_default();
                (base * U256::from(2) + priority, priority)
            }
            (None, None) => {
                if let Ok(inputs) = gateway.submission_inputs(&config, 1, first_address).await {
                    (
                        inputs.fee_estimate.max_fee_per_gas,
                        inputs.fee_estimate.max_priority_fee_per_gas,
                    )
                } else {
                    let base = gateway
                        .latest_block(&config, 1)
                        .await?
                        .base_fee_per_gas
                        .unwrap_or_default();
                    (base * U256::from(2), U256::from(0))
                }
            }
        };

    emit_info!(format!(
        "Gas: limit {gas_limit} | max fee {} gwei | priority {} gwei",
        format_gwei(max_fee_per_gas),
        format_gwei(max_priority_fee_per_gas)
    ));

    // ── Per-wallet balance + nonce, pre-sign everything ──
    emit_info!("Checking balances and signing...");
    let mut prepared: Vec<PreparedWallet> = Vec::new();
    for (index, (signer, _quantity, plan)) in plans.iter().enumerate() {
        let account: AccountState = gateway
            .account_state(&config, 1, signer.identity().address)
            .await?;
        let required = plan
            .value
            .checked_add(
                U256::from(gas_limit)
                    .checked_mul(max_fee_per_gas)
                    .ok_or_else(|| SnipeError::InvalidGas("gas cost overflow".to_owned()))?,
            )
            .ok_or_else(|| SnipeError::InvalidGas("total cost overflow".to_owned()))?;
        if account.balance < required {
            let affordable = account.balance.saturating_sub(plan.value) / U256::from(gas_limit);
            return Err(SnipeError::Underfunded {
                address: signer.identity().address,
                balance: account.balance,
                required,
                affordable: format_gwei(affordable),
            });
        }

        let transaction = Eip1559Transaction {
            chain_id,
            nonce: account.pending_nonce,
            max_priority_fee_per_gas,
            max_fee_per_gas,
            gas_limit,
            target: plan.to,
            value: plan.value,
            calldata: plan.data.clone(),
        };
        let signed = sign_eip1559_transaction(&transaction, signer)?;
        prepared.push(PreparedWallet {
            index,
            address: signer.identity().address,
            blast: blast::prepare_blast(&signed),
        });
    }
    emit_success!(format!(
        "{} tx(s) signed and serialised — nothing left to compute at fire time",
        prepared.len()
    ));

    // ── Warm sockets ──
    let blast_client = blast::build_client()?;
    blast::warm_connections(&blast_client, &endpoints).await;

    // ── Timing: wait for the stage, then fire pre-built bytes ──
    let stage_start = i64::try_from(drop.start_time)
        .unwrap_or(i64::MAX)
        .saturating_mul(1000);
    let fire_time = stage_start - i64::try_from(options.early_fire_ms).unwrap_or(i64::MAX);
    let now = unix_millis();
    let wait_for_stage = !options.fire_now && fire_time > now;

    if wait_for_stage {
        wait_until_fire(
            fire_time,
            &format!("Mint stage opens at {}", drop.start_time),
        )
        .await;
    } else if options.early_fire_ms > 0 && fire_time > now {
        wait_until_fire(fire_time, "Early fire window").await;
    } else {
        emit_info!("Stage is live (or --fire-now) — dispatching immediately");
    }

    let dispatch_start = Instant::now();
    let mut fired: Vec<FiredWallet> = Vec::new();
    for wallet in &prepared {
        let handles = blast::blast_to_all(&blast_client, &wallet.blast, &endpoints);
        fired.push(FiredWallet {
            index: wallet.index,
            address: wallet.address,
            handles,
        });
    }
    let dispatch_ms = dispatch_start.elapsed().as_millis();
    let since_stage = (unix_millis() - stage_start).max(0);
    emit_success!(format!(
        "DISPATCHED {} tx(s) ({}ms dispatch, +{}ms after stage open)",
        fired.len(),
        dispatch_ms,
        since_stage
    ));

    let (accepted, rejected) = collect_results(fired).await;

    for (index, address, results) in &rejected {
        let reasons = blast::rejection_reasons(results);
        emit_warn!(format!(
            "[W{index}] {address} REJECTED by every RPC — never broadcast"
        ));
        for reason in reasons {
            emit_warn!(format!("    {reason}"));
        }
        if results.iter().any(|r| {
            r.error
                .as_deref()
                .is_some_and(|e| e.to_ascii_lowercase().contains("less than block base fee"))
        }) {
            emit_warn!("    → max fee is under the chain's base fee. Raise it and re-run.");
        }
    }

    if accepted.is_empty() {
        logging::error("NOTHING WAS BROADCAST — no receipts to wait for");
        return Ok(());
    }

    // ── Receipts (only for txs an endpoint actually accepted) ──
    emit_info!("Waiting for receipts...");
    for (index, address, results) in &accepted {
        let tx_hash = results
            .iter()
            .find_map(|r| r.tx_hash.as_ref())
            .map(std::string::ToString::to_string)
            .unwrap_or_default();
        let receipt = if tx_hash.is_empty() {
            None
        } else {
            wait_for_receipt(&gateway, &config, &tx_hash).await?
        };
        match receipt {
            Some(receipt) => {
                let status = if receipt.is_success {
                    "SUCCESS"
                } else {
                    "FAILED"
                };
                if receipt.is_success {
                    emit_success!(format!(
                        "[W{index}] {address} | block {} | {status}",
                        receipt.block_number
                    ));
                } else {
                    emit_error!(format!(
                        "[W{index}] {address} | block {} | {status}",
                        receipt.block_number
                    ));
                }
                emit_info!(format!(
                    "[W{index}] track: {}",
                    explorer_url(chain_id, &tx_hash)
                ));
            }
            None => {
                emit_warn!(format!(
                    "[W{index}] TIMEOUT — check: {}",
                    explorer_url(chain_id, &tx_hash)
                ));
            }
        }
    }

    logging::section_break();
    logging::success("LOCAL PUBLIC MINT COMPLETE");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_gwei_decimal() {
        assert_eq!(parse_gwei("0.05").unwrap(), U256::from(50_000_000u128));
        assert_eq!(parse_gwei("200").unwrap(), U256::from(200_000_000_000u128));
        assert_eq!(parse_gwei("0").unwrap(), U256::from(0u128));
        assert_eq!(
            parse_gwei("1.234567891").unwrap(),
            U256::from(1_234_567_891u128)
        );
    }

    #[test]
    fn rejects_bad_gwei() {
        assert!(parse_gwei("1.0000000000").is_err());
        assert!(parse_gwei("abc").is_err());
        assert!(parse_gwei("").is_err());
    }

    #[test]
    fn formats_gwei() {
        assert_eq!(format_gwei(U256::from(50_000_000u128)), "0.050");
        assert_eq!(format_gwei(U256::from(200_000_000_000u128)), "200.000");
    }

    #[test]
    fn orders_sequencers_last() {
        let base: Url = "https://mainnet.base.org".parse().unwrap();
        let seq: Url = "https://mainnet-sequencer.base.org".parse().unwrap();
        let ordered = order_endpoints(vec![(seq.clone(), 8453), (base.clone(), 8453)]);
        assert_eq!(ordered[0].0, base);
        assert_eq!(ordered[1].0, seq);
    }
}
