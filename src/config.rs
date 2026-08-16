use std::{
    collections::{BTreeMap, HashSet},
    env, fmt,
    path::{Path, PathBuf},
};

use alloy_primitives::{Address, U256};
use thiserror::Error;
use url::Url;
use zeroize::Zeroizing;

use crate::signing::WalletSigner;
use crate::sponsored::sponsored_wallet_gas_limit;

const SITE_URL: &str = "https://opensea.io";
const GRAPHQL_URL: &str = "https://gql.opensea.io/graphql";
const APP_ID: &str = "os2-web";
const KNOWN_SETTINGS: &[&str] = &[
    "WALLET_KEY",
    "WALLETS_FILE",
    "SPONSORED",
    "RECIPIENT_ADDRESS",
    "SPONSOR_KEY",
    "SPONSORED_EXECUTOR_ADDRESS",
    "SPONSORED_OPERATION_DEADLINE_SECONDS",
    "RPC_URL",
    "RPC_URL_BOT",
    "BOT_TOKEN",
    "ALLOWED_CHAT_IDS",
    "FEE_AUTOMATIC",
    "MAX_FEE_PER_GAS_GWEI",
    "MAX_PRIORITY_FEE_PER_GAS_GWEI",
    "REPLACEMENT_BUMP_BPS",
    "GAS_LIMIT",
    "SCHEDULE_REFRESH_INTERVAL_SECONDS",
    "TRANSACTION_MAX_ATTEMPTS",
    "PENDING_TIMEOUT_SECONDS",
    "RECEIPT_POLL_BASE_DELAY_MS",
    "RECEIPT_POLL_MAX_DELAY_MS",
    "OPENSEA_REQUEST_TIMEOUT_MS",
    "ELIGIBILITY_REQUEST_TIMEOUT_MS",
    "OPENSEA_MAX_ATTEMPTS",
    "OPENSEA_RETRY_INTERVAL_MS",
    "OPENSEA_CALLDATA_MAX_ATTEMPTS",
];
const GWEI_IN_WEI: u64 = 1_000_000_000;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("cannot determine the current directory: {0}")]
    CurrentDirectory(#[source] std::io::Error),
    #[error("cannot determine the running executable path: {0}")]
    CurrentExecutable(#[source] std::io::Error),
    #[error("no .env file was found in the current directory or its parents")]
    MissingEnvironmentFile,
    #[error("cannot parse .env configuration at {path}")]
    Parse {
        path: PathBuf,
        #[source]
        source: dotenvy::Error,
    },
    #[error(".env contains the duplicate setting {0}")]
    DuplicateSetting(String),
    #[error(".env contains the unknown setting {0}")]
    UnknownSetting(String),
    #[error(".env is missing the required setting {0}")]
    MissingSetting(&'static str),
    #[error(".env setting {name} is invalid: {reason}")]
    InvalidSetting {
        name: &'static str,
        reason: &'static str,
    },
    #[error("configuration is invalid: {0}")]
    Validation(String),
}

#[derive(Clone)]
pub struct AppConfig {
    pub opensea: OpenSeaConfig,
    pub scheduling: SchedulingConfig,
    pub retry: RetryConfig,
    pub fees: FeesConfig,
    pub rpc_url: Url,
    pub gas_limit: u64,
}

#[derive(Clone)]
pub struct ChainConfig {
    pub chain_id: u64,
    pub rpc_urls: Vec<Url>,
}

#[derive(Clone, Debug)]
pub struct OpenSeaConfig {
    pub site_url: Url,
    pub graphql_url: Url,
    pub app_id: String,
    pub request_timeout_ms: u64,
    pub eligibility_request_timeout_ms: u64,
    pub max_attempts: u32,
    pub retry_interval_ms: u64,
    pub calldata_max_attempts: u32,
}

#[derive(Clone, Copy, Debug)]
pub struct SchedulingConfig {
    pub refresh_interval_seconds: u64,
}

#[derive(Clone, Copy, Debug)]
pub struct RetryConfig {
    pub max_attempts: u32,
    pub pending_timeout_seconds: u64,
    pub base_delay_ms: u64,
    pub max_delay_ms: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FeesConfig {
    pub mode: FeeMode,
    pub replacement_bump_bps: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FeeMode {
    Automatic,
    Manual {
        max_fee_per_gas: U256,
        max_priority_fee_per_gas: U256,
    },
}

impl fmt::Debug for AppConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AppConfig")
            .field("opensea", &self.opensea)
            .field("scheduling", &self.scheduling)
            .field("retry", &self.retry)
            .field("fees", &self.fees)
            .field("rpc_url", &"<redacted>")
            .field("gas_limit", &self.gas_limit)
            .finish()
    }
}

impl fmt::Debug for ChainConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ChainConfig")
            .field("chain_id", &self.chain_id)
            .field("rpc_url_count", &self.rpc_urls.len())
            .finish()
    }
}

pub struct LoadedConfig {
    pub app: AppConfig,
    wallet_key: Option<Zeroizing<String>>,
    multi_wallet: Option<MultiWalletConfig>,
    sponsor_key: Option<Zeroizing<String>>,
    source_path: PathBuf,
}

pub struct DeploymentConfig {
    pub app: AppConfig,
    deployer_key: Zeroizing<String>,
    configured_executor: Option<Address>,
    source_path: PathBuf,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MultiWalletConfig {
    pub manifest_path: PathBuf,
    pub recipient: Address,
    pub mode: MultiWalletMode,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MultiWalletMode {
    SelfFunded,
    Sponsored(SponsoredConfig),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SponsoredConfig {
    pub executor: Address,
    pub wallet_gas_limit: u64,
    pub operation_deadline_seconds: u64,
}

impl LoadedConfig {
    pub fn load() -> Result<Self, ConfigError> {
        let current = env::current_dir().map_err(ConfigError::CurrentDirectory)?;
        let executable = env::current_exe().map_err(ConfigError::CurrentExecutable)?;
        let start = environment_search_start(&current, &executable);
        Self::load_from(&start)
    }

    pub fn load_from(start: &Path) -> Result<Self, ConfigError> {
        let source_path = find_environment_file(start)?;
        let values = parse_environment_file(&source_path)?;
        Self::from_values(values, source_path)
    }

    #[must_use]
    pub fn wallet_key(&self) -> Option<&str> {
        self.wallet_key.as_ref().map(|value| value.as_str())
    }

    #[must_use]
    pub const fn multi_wallet(&self) -> Option<&MultiWalletConfig> {
        self.multi_wallet.as_ref()
    }

    #[must_use]
    pub fn sponsor_key(&self) -> Option<&str> {
        self.sponsor_key.as_ref().map(|value| value.as_str())
    }

    #[must_use]
    pub fn source_path(&self) -> &Path {
        &self.source_path
    }

    fn from_values(
        mut values: BTreeMap<String, String>,
        source_path: PathBuf,
    ) -> Result<Self, ConfigError> {
        validate_known_settings(&values)?;
        let (wallet_key, manifest_setting) = select_wallet_source(&mut values)?;
        let rpc_url = parse_url(&take_required(&mut values, "RPC_URL")?, "RPC_URL")?;
        if !is_allowed_rpc_url(&rpc_url) {
            return Err(invalid(
                "RPC_URL",
                "must use HTTPS, except for an HTTP loopback test endpoint",
            ));
        }
        let fees = parse_fees(&mut values)?;

        let gas_limit = take_required(&mut values, "GAS_LIMIT")?
            .parse()
            .map_err(|_| invalid("GAS_LIMIT", "expected an unsigned integer"))?;
        let config = AppConfig {
            opensea: OpenSeaConfig {
                site_url: Url::parse(SITE_URL).map_err(|_| invalid("RPC_URL", "internal URL"))?,
                graphql_url: Url::parse(GRAPHQL_URL)
                    .map_err(|_| invalid("RPC_URL", "internal URL"))?,
                app_id: APP_ID.into(),
                request_timeout_ms: take_u64_default(
                    &mut values,
                    "OPENSEA_REQUEST_TIMEOUT_MS",
                    10_000,
                )?,
                eligibility_request_timeout_ms: take_u64_default(
                    &mut values,
                    "ELIGIBILITY_REQUEST_TIMEOUT_MS",
                    5_000,
                )?,
                max_attempts: take_u32_default(&mut values, "OPENSEA_MAX_ATTEMPTS", 3)?,
                retry_interval_ms: take_u64_default(&mut values, "OPENSEA_RETRY_INTERVAL_MS", 250)?,
                calldata_max_attempts: take_u32_default(
                    &mut values,
                    "OPENSEA_CALLDATA_MAX_ATTEMPTS",
                    40,
                )?,
            },
            scheduling: SchedulingConfig {
                refresh_interval_seconds: take_u64_default(
                    &mut values,
                    "SCHEDULE_REFRESH_INTERVAL_SECONDS",
                    600,
                )?,
            },
            retry: RetryConfig {
                max_attempts: take_u32_default(&mut values, "TRANSACTION_MAX_ATTEMPTS", 3)?,
                pending_timeout_seconds: take_u64_default(
                    &mut values,
                    "PENDING_TIMEOUT_SECONDS",
                    20,
                )?,
                base_delay_ms: take_u64_default(&mut values, "RECEIPT_POLL_BASE_DELAY_MS", 250)?,
                max_delay_ms: take_u64_default(&mut values, "RECEIPT_POLL_MAX_DELAY_MS", 2_000)?,
            },
            fees,
            rpc_url,
            gas_limit,
        };
        config.validate()?;
        let (multi_wallet, sponsor_key) = if let Some(manifest_setting) = manifest_setting {
            let (multi_wallet, sponsor_key) =
                parse_multi_wallet_config(&mut values, &source_path, manifest_setting, gas_limit)?;
            (Some(multi_wallet), sponsor_key)
        } else {
            reject_multi_wallet_settings(&values)?;
            (None, None)
        };
        Ok(Self {
            app: config,
            wallet_key,
            multi_wallet,
            sponsor_key,
            source_path,
        })
    }
}

fn select_wallet_source(
    values: &mut BTreeMap<String, String>,
) -> Result<(Option<Zeroizing<String>>, Option<String>), ConfigError> {
    let mut wallet_key = values.remove("WALLET_KEY").map(Zeroizing::new);
    let manifest_setting = values.remove("WALLETS_FILE");
    if wallet_key.is_some() && manifest_setting.is_some() {
        let sponsored = values
            .get("SPONSORED")
            .map(|value| parse_bool(value, "SPONSORED"))
            .transpose()?;
        if sponsored == Some(true) {
            wallet_key = None;
        } else {
            return Err(ConfigError::Validation(
                "configure exactly one of WALLET_KEY or WALLETS_FILE unless SPONSORED=true selects WALLETS_FILE"
                    .into(),
            ));
        }
    } else if wallet_key.is_none() && manifest_setting.is_none() {
        return Err(ConfigError::Validation(
            "configure exactly one of WALLET_KEY or WALLETS_FILE".into(),
        ));
    }
    Ok((wallet_key, manifest_setting))
}

impl DeploymentConfig {
    pub fn load() -> Result<Self, ConfigError> {
        let current = env::current_dir().map_err(ConfigError::CurrentDirectory)?;
        let executable = env::current_exe().map_err(ConfigError::CurrentExecutable)?;
        let start = environment_search_start(&current, &executable);
        Self::load_from(&start)
    }

    pub fn load_from(start: &Path) -> Result<Self, ConfigError> {
        let source_path = find_environment_file(start)?;
        let values = parse_environment_file(&source_path)?;
        Self::from_values(values, source_path)
    }

    fn from_values(
        mut values: BTreeMap<String, String>,
        source_path: PathBuf,
    ) -> Result<Self, ConfigError> {
        validate_known_settings(&values)?;
        let deployer_key = take_required(&mut values, "SPONSOR_KEY")?;
        let configured_executor = values
            .remove("SPONSORED_EXECUTOR_ADDRESS")
            .map(|value| parse_address(&value, "SPONSORED_EXECUTOR_ADDRESS"))
            .transpose()?;

        for setting in [
            "WALLET_KEY",
            "WALLETS_FILE",
            "SPONSORED",
            "RECIPIENT_ADDRESS",
            "SPONSORED_OPERATION_DEADLINE_SECONDS",
        ] {
            values.remove(setting);
        }
        values.insert("WALLET_KEY".into(), deployer_key);
        let mut loaded = LoadedConfig::from_values(values, source_path.clone())?;
        let deployer_key = loaded
            .wallet_key
            .take()
            .ok_or(ConfigError::MissingSetting("SPONSOR_KEY"))?;

        Ok(Self {
            app: loaded.app,
            deployer_key,
            configured_executor,
            source_path,
        })
    }

    #[must_use]
    pub fn deployer_key(&self) -> &str {
        self.deployer_key.as_str()
    }

    #[must_use]
    pub const fn configured_executor(&self) -> Option<Address> {
        self.configured_executor
    }

    #[must_use]
    pub fn source_path(&self) -> &Path {
        &self.source_path
    }
}

fn environment_search_start(current: &Path, executable: &Path) -> PathBuf {
    if executable.starts_with(current) {
        executable.parent().unwrap_or(executable).to_path_buf()
    } else {
        current.to_path_buf()
    }
}

fn parse_fees(values: &mut BTreeMap<String, String>) -> Result<FeesConfig, ConfigError> {
    let is_automatic = parse_bool(&take_required(values, "FEE_AUTOMATIC")?, "FEE_AUTOMATIC")?;
    let replacement_bump_bps = take_u32_default(values, "REPLACEMENT_BUMP_BPS", 11_250)?;
    let mode = if is_automatic {
        if values.contains_key("MAX_FEE_PER_GAS_GWEI")
            || values.contains_key("MAX_PRIORITY_FEE_PER_GAS_GWEI")
        {
            return Err(invalid(
                "FEE_AUTOMATIC",
                "remove manual fee settings when automatic fees are enabled",
            ));
        }
        FeeMode::Automatic
    } else {
        FeeMode::Manual {
            max_fee_per_gas: parse_gwei(
                &take_required(values, "MAX_FEE_PER_GAS_GWEI")?,
                "MAX_FEE_PER_GAS_GWEI",
            )?,
            max_priority_fee_per_gas: parse_gwei(
                &take_required(values, "MAX_PRIORITY_FEE_PER_GAS_GWEI")?,
                "MAX_PRIORITY_FEE_PER_GAS_GWEI",
            )?,
        }
    };
    Ok(FeesConfig {
        mode,
        replacement_bump_bps,
    })
}

impl fmt::Debug for LoadedConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LoadedConfig")
            .field("app", &self.app)
            .field("multi_wallet", &self.multi_wallet)
            .field("has_sponsor_key", &self.sponsor_key.is_some())
            .field("source_path", &self.source_path)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for DeploymentConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeploymentConfig")
            .field("app", &self.app)
            .field("configured_executor", &self.configured_executor)
            .field("source_path", &self.source_path)
            .finish_non_exhaustive()
    }
}

impl AppConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        self.validate_opensea()?;
        self.validate_scheduling()?;
        if self.gas_limit == 0 {
            return Err(ConfigError::Validation(
                "GAS_LIMIT must be greater than zero".into(),
            ));
        }
        if !(1..=10).contains(&self.retry.max_attempts)
            || !(1..=86_400).contains(&self.retry.pending_timeout_seconds)
            || !(50..=60_000).contains(&self.retry.base_delay_ms)
            || !(50..=60_000).contains(&self.retry.max_delay_ms)
            || self.retry.base_delay_ms > self.retry.max_delay_ms
        {
            return Err(ConfigError::Validation(
                "transaction retries require 1-10 attempts, a 1-86400 second timeout, and 50-60000 ms polling delays"
                    .into(),
            ));
        }
        if !(10_001..=20_000).contains(&self.fees.replacement_bump_bps) {
            return Err(ConfigError::Validation(
                "REPLACEMENT_BUMP_BPS must be between 10001 and 20000".into(),
            ));
        }
        match self.fees.mode {
            FeeMode::Manual {
                max_fee_per_gas,
                max_priority_fee_per_gas,
            } if max_fee_per_gas == U256::ZERO || max_fee_per_gas < max_priority_fee_per_gas => {
                return Err(ConfigError::Validation(
                    "manual max fee must be nonzero and cover the priority fee".into(),
                ));
            }
            _ => {}
        }
        Ok(())
    }

    fn validate_opensea(&self) -> Result<(), ConfigError> {
        if !is_exact_https_url(&self.opensea.site_url, "opensea.io", "/")
            || !is_exact_https_url(&self.opensea.graphql_url, "gql.opensea.io", "/graphql")
            || self.opensea.app_id != APP_ID
            || !(100..=120_000).contains(&self.opensea.request_timeout_ms)
            || !(100..=120_000).contains(&self.opensea.eligibility_request_timeout_ms)
            || !(1..=10).contains(&self.opensea.max_attempts)
            || !(50..=30_000).contains(&self.opensea.retry_interval_ms)
            || !(1..=1_000).contains(&self.opensea.calldata_max_attempts)
        {
            return Err(ConfigError::Validation(
                "OpenSea transport settings are invalid".into(),
            ));
        }
        Ok(())
    }

    fn validate_scheduling(&self) -> Result<(), ConfigError> {
        if !(10..=86_400).contains(&self.scheduling.refresh_interval_seconds) {
            return Err(ConfigError::Validation(
                "schedule refresh interval is outside the 10-86400 second range".into(),
            ));
        }
        Ok(())
    }
}

fn find_environment_file(start: &Path) -> Result<PathBuf, ConfigError> {
    let start = if start.is_file() {
        start.parent().unwrap_or(start)
    } else {
        start
    };
    start
        .ancestors()
        .map(|directory| directory.join(".env"))
        .find(|candidate| candidate.is_file())
        .ok_or(ConfigError::MissingEnvironmentFile)
}

fn parse_environment_file(path: &Path) -> Result<BTreeMap<String, String>, ConfigError> {
    let iterator = dotenvy::from_path_iter(path).map_err(|source| ConfigError::Parse {
        path: path.to_path_buf(),
        source,
    })?;
    let mut values = BTreeMap::new();
    for item in iterator {
        let (name, value) = item.map_err(|source| ConfigError::Parse {
            path: path.to_path_buf(),
            source,
        })?;
        if values.insert(name.clone(), value).is_some() {
            return Err(ConfigError::DuplicateSetting(name));
        }
    }
    Ok(values)
}

fn validate_known_settings(values: &BTreeMap<String, String>) -> Result<(), ConfigError> {
    let known = KNOWN_SETTINGS.iter().copied().collect::<HashSet<_>>();
    if let Some(name) = values.keys().find(|name| !known.contains(name.as_str())) {
        return Err(ConfigError::UnknownSetting(name.clone()));
    }
    Ok(())
}

fn parse_multi_wallet_config(
    values: &mut BTreeMap<String, String>,
    source_path: &Path,
    manifest_setting: String,
    mint_gas_limit: u64,
) -> Result<(MultiWalletConfig, Option<Zeroizing<String>>), ConfigError> {
    if manifest_setting.trim().is_empty() {
        return Err(invalid("WALLETS_FILE", "expected a nonempty file path"));
    }
    let configured_path = PathBuf::from(manifest_setting);
    let manifest_path = if configured_path.is_absolute() {
        configured_path
    } else {
        source_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(configured_path)
    };
    let is_sponsored = parse_bool(&take_required(values, "SPONSORED")?, "SPONSORED")?;
    let sponsor_key = values.remove("SPONSOR_KEY").map(Zeroizing::new);
    let sponsor_address = sponsor_key
        .as_ref()
        .map(|value| WalletSigner::from_private_key(value.as_str()))
        .transpose()
        .map_err(|_| invalid("SPONSOR_KEY", "expected a valid private key"))?
        .map(|signer| signer.identity().address);
    let recipient = values
        .remove("RECIPIENT_ADDRESS")
        .map(|value| parse_address(&value, "RECIPIENT_ADDRESS"))
        .transpose()?
        .or(sponsor_address)
        .ok_or_else(|| {
            invalid(
                "RECIPIENT_ADDRESS",
                "required when SPONSOR_KEY is not configured",
            )
        })?;

    let mode = if is_sponsored {
        if sponsor_key.is_none() {
            return Err(ConfigError::MissingSetting("SPONSOR_KEY"));
        }
        let sponsored = parse_sponsored_config(values, mint_gas_limit)?;
        if recipient == sponsored.executor {
            return Err(invalid(
                "RECIPIENT_ADDRESS",
                "must differ from SPONSORED_EXECUTOR_ADDRESS",
            ));
        }
        MultiWalletMode::Sponsored(sponsored)
    } else {
        reject_sponsored_settings(values)?;
        MultiWalletMode::SelfFunded
    };

    Ok((
        MultiWalletConfig {
            manifest_path,
            recipient,
            mode,
        },
        sponsor_key,
    ))
}

fn parse_sponsored_config(
    values: &mut BTreeMap<String, String>,
    mint_gas_limit: u64,
) -> Result<SponsoredConfig, ConfigError> {
    let wallet_gas_limit = sponsored_wallet_gas_limit(mint_gas_limit).ok_or_else(|| {
        invalid(
            "GAS_LIMIT",
            "too large to derive the sponsored per-wallet execution envelope",
        )
    })?;
    let operation_deadline_seconds =
        take_u64_default(values, "SPONSORED_OPERATION_DEADLINE_SECONDS", 120)?;
    if !(30..=3_600).contains(&operation_deadline_seconds) {
        return Err(invalid(
            "SPONSORED_OPERATION_DEADLINE_SECONDS",
            "expected 30 through 3600 seconds",
        ));
    }
    let executor = parse_address(
        &take_required(values, "SPONSORED_EXECUTOR_ADDRESS")?,
        "SPONSORED_EXECUTOR_ADDRESS",
    )?;
    Ok(SponsoredConfig {
        executor,
        wallet_gas_limit,
        operation_deadline_seconds,
    })
}

fn reject_multi_wallet_settings(values: &BTreeMap<String, String>) -> Result<(), ConfigError> {
    const SETTINGS: &[&str] = &[
        "SPONSORED",
        "RECIPIENT_ADDRESS",
        "SPONSOR_KEY",
        "SPONSORED_EXECUTOR_ADDRESS",
        "SPONSORED_OPERATION_DEADLINE_SECONDS",
    ];
    if let Some(name) = SETTINGS.iter().find(|name| values.contains_key(**name)) {
        return Err(ConfigError::Validation(format!(
            "{name} requires WALLETS_FILE"
        )));
    }
    Ok(())
}

fn reject_sponsored_settings(values: &BTreeMap<String, String>) -> Result<(), ConfigError> {
    const SETTINGS: &[&str] = &[
        "SPONSORED_EXECUTOR_ADDRESS",
        "SPONSORED_OPERATION_DEADLINE_SECONDS",
    ];
    if let Some(name) = SETTINGS.iter().find(|name| values.contains_key(**name)) {
        return Err(ConfigError::Validation(format!(
            "{name} requires SPONSORED=true"
        )));
    }
    Ok(())
}

fn parse_address(value: &str, name: &'static str) -> Result<Address, ConfigError> {
    let address = value
        .parse()
        .map_err(|_| invalid(name, "expected a 20-byte hex address"))?;
    if address == Address::ZERO {
        return Err(invalid(name, "must not be the zero address"));
    }
    Ok(address)
}

fn take_required(
    values: &mut BTreeMap<String, String>,
    name: &'static str,
) -> Result<String, ConfigError> {
    values
        .remove(name)
        .filter(|value| !value.trim().is_empty())
        .ok_or(ConfigError::MissingSetting(name))
}

fn take_u64_default(
    values: &mut BTreeMap<String, String>,
    name: &'static str,
    default: u64,
) -> Result<u64, ConfigError> {
    values.remove(name).map_or(Ok(default), |value| {
        value
            .parse()
            .map_err(|_| invalid(name, "expected an unsigned integer"))
    })
}

fn take_u32_default(
    values: &mut BTreeMap<String, String>,
    name: &'static str,
    default: u32,
) -> Result<u32, ConfigError> {
    values.remove(name).map_or(Ok(default), |value| {
        value
            .parse()
            .map_err(|_| invalid(name, "expected an unsigned integer"))
    })
}

fn parse_bool(value: &str, name: &'static str) -> Result<bool, ConfigError> {
    match value.trim().to_ascii_lowercase().as_str() {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(invalid(name, "expected true or false")),
    }
}

fn parse_url(value: &str, name: &'static str) -> Result<Url, ConfigError> {
    Url::parse(value).map_err(|_| invalid(name, "expected an absolute URL"))
}

fn parse_gwei(value: &str, name: &'static str) -> Result<U256, ConfigError> {
    let value = value.trim();
    let (whole, fraction) = value.split_once('.').unwrap_or((value, ""));
    if whole.is_empty()
        || !whole.bytes().all(|byte| byte.is_ascii_digit())
        || !fraction.bytes().all(|byte| byte.is_ascii_digit())
        || fraction.len() > 9
    {
        return Err(invalid(
            name,
            "expected a nonnegative gwei value with at most 9 decimals",
        ));
    }
    let whole =
        U256::from_str_radix(whole, 10).map_err(|_| invalid(name, "gwei value is too large"))?;
    let mut fraction_text = fraction.to_owned();
    fraction_text.extend(std::iter::repeat_n('0', 9 - fraction.len()));
    let fraction = if fraction_text.is_empty() {
        U256::ZERO
    } else {
        U256::from_str_radix(&fraction_text, 10)
            .map_err(|_| invalid(name, "gwei value is too large"))?
    };
    whole
        .checked_mul(U256::from(GWEI_IN_WEI))
        .and_then(|value| value.checked_add(fraction))
        .ok_or_else(|| invalid(name, "gwei value is too large"))
}

const fn invalid(name: &'static str, reason: &'static str) -> ConfigError {
    ConfigError::InvalidSetting { name, reason }
}

fn is_allowed_rpc_url(url: &Url) -> bool {
    if url.scheme() == "https" {
        return url.host().is_some();
    }
    if url.scheme() != "http" {
        return false;
    }
    match url.host() {
        Some(url::Host::Domain(host)) => host.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(address)) => address.is_loopback(),
        Some(url::Host::Ipv6(address)) => address.is_loopback(),
        None => false,
    }
}

fn is_exact_https_url(url: &Url, host: &str, path: &str) -> bool {
    url.scheme() == "https"
        && url.host_str() == Some(host)
        && url.port().is_none()
        && url.username().is_empty()
        && url.password().is_none()
        && url.path() == path
        && url.query().is_none()
        && url.fragment().is_none()
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "0x0000000000000000000000000000000000000000000000000000000000000001";

    fn base_values() -> BTreeMap<String, String> {
        BTreeMap::from([
            ("RPC_URL".into(), "https://rpc.example".into()),
            ("FEE_AUTOMATIC".into(), "true".into()),
            ("GAS_LIMIT".into(), "200000".into()),
        ])
    }

    #[test]
    fn unified_env_example_documents_every_known_setting() {
        let documented = include_str!("../.env.example")
            .lines()
            .filter_map(|line| {
                let line = line.trim_start();
                let line = line.strip_prefix('#').unwrap_or(line).trim_start();
                let (name, _) = line.split_once('=')?;
                (!name.is_empty()
                    && name
                        .bytes()
                        .all(|byte| byte.is_ascii_uppercase() || byte == b'_'))
                .then_some(name)
            })
            .collect::<HashSet<_>>();
        let known = KNOWN_SETTINGS.iter().copied().collect::<HashSet<_>>();

        assert_eq!(documented, known);
    }

    #[test]
    fn readme_documents_every_known_setting() {
        let readme = include_str!("../README.md");

        for setting in KNOWN_SETTINGS {
            assert!(
                readme.contains(&format!("`{setting}`")),
                "README is missing {setting}"
            );
        }
    }

    #[test]
    fn readme_documents_configuration_defaults_and_ranges() {
        let readme = include_str!("../README.md");
        let expected_rows = [
            ("TRANSACTION_MAX_ATTEMPTS", &["`3`", "`1-10`"][..]),
            ("PENDING_TIMEOUT_SECONDS", &["`20`", "`1-86400`"][..]),
            (
                "RECEIPT_POLL_BASE_DELAY_MS",
                &["`250`", "`50-60000`"] as &[&str],
            ),
            (
                "RECEIPT_POLL_MAX_DELAY_MS",
                &["`2000`", "`50-60000`"] as &[&str],
            ),
            ("REPLACEMENT_BUMP_BPS", &["`11250`", "`10001-20000`"][..]),
            (
                "SCHEDULE_REFRESH_INTERVAL_SECONDS",
                &["`600`", "`10-86400`"] as &[&str],
            ),
            (
                "OPENSEA_REQUEST_TIMEOUT_MS",
                &["`10000`", "`100-120000`"] as &[&str],
            ),
            (
                "ELIGIBILITY_REQUEST_TIMEOUT_MS",
                &["`5000`", "`100-120000`"] as &[&str],
            ),
            ("OPENSEA_MAX_ATTEMPTS", &["`3`", "`1-10`"][..]),
            (
                "OPENSEA_RETRY_INTERVAL_MS",
                &["`250`", "`50-30000`"] as &[&str],
            ),
            (
                "OPENSEA_CALLDATA_MAX_ATTEMPTS",
                &["`40`", "`1-1000`"] as &[&str],
            ),
            (
                "SPONSORED_OPERATION_DEADLINE_SECONDS",
                &["`120`", "`30-3600`"] as &[&str],
            ),
        ];

        for (setting, expected_values) in expected_rows {
            let row = readme
                .lines()
                .find(|line| line.starts_with(&format!("| `{setting}` |")))
                .unwrap_or_else(|| panic!("README is missing the {setting} table row"));
            for expected in expected_values {
                assert!(
                    row.contains(expected),
                    "README {setting} row is missing {expected}: {row}"
                );
            }
        }
    }

    #[test]
    fn active_env_example_defaults_match_parser_defaults() {
        let mut values = include_str!("../.env.example")
            .lines()
            .filter_map(|line| {
                let line = line.trim();
                (!line.is_empty() && !line.starts_with('#'))
                    .then(|| line.split_once('='))
                    .flatten()
                    .map(|(name, value)| (name.to_owned(), value.to_owned()))
            })
            .collect::<BTreeMap<_, _>>();
        values.insert("WALLET_KEY".into(), KEY.into());
        values.insert("RPC_URL".into(), "https://rpc.example".into());

        let loaded = LoadedConfig::from_values(values, PathBuf::from("C:/mint/.env"))
            .expect("active example defaults");

        assert_eq!(loaded.app.gas_limit, 300_000);
        assert_eq!(loaded.app.scheduling.refresh_interval_seconds, 600);
        assert_eq!(loaded.app.retry.max_attempts, 3);
        assert_eq!(loaded.app.retry.pending_timeout_seconds, 20);
        assert_eq!(loaded.app.retry.base_delay_ms, 250);
        assert_eq!(loaded.app.retry.max_delay_ms, 2_000);
        assert_eq!(loaded.app.fees.replacement_bump_bps, 11_250);
        assert_eq!(loaded.app.opensea.request_timeout_ms, 10_000);
        assert_eq!(loaded.app.opensea.eligibility_request_timeout_ms, 5_000);
        assert_eq!(loaded.app.opensea.max_attempts, 3);
        assert_eq!(loaded.app.opensea.retry_interval_ms, 250);
        assert_eq!(loaded.app.opensea.calldata_max_attempts, 40);
    }

    #[test]
    fn prefers_the_executable_tree_when_it_is_inside_the_launch_directory() {
        let current = Path::new("C:/workspace");
        let executable = Path::new("C:/workspace/opensea-mint-rs/target/release/opensea-mint.exe");
        assert_eq!(
            environment_search_start(current, executable),
            Path::new("C:/workspace/opensea-mint-rs/target/release")
        );

        let external = Path::new("C:/test-bin/opensea-mint.exe");
        assert_eq!(environment_search_start(current, external), current);
    }

    #[test]
    fn parses_fractional_gwei_without_floating_point() {
        assert_eq!(
            parse_gwei("1.25", "MAX_FEE_PER_GAS_GWEI").expect("gwei"),
            U256::from(1_250_000_000_u64)
        );
        assert!(parse_gwei("1.0000000001", "MAX_FEE_PER_GAS_GWEI").is_err());
    }

    #[test]
    fn open_sea_retry_defaults_and_bounds_are_enforced() {
        let mut defaults = base_values();
        defaults.insert("WALLET_KEY".into(), KEY.into());
        let loaded = LoadedConfig::from_values(defaults, PathBuf::from("C:/mint/.env"))
            .expect("default OpenSea retry policy");

        assert_eq!(loaded.app.opensea.max_attempts, 3);
        assert_eq!(loaded.app.opensea.retry_interval_ms, 250);
        assert_eq!(loaded.app.opensea.calldata_max_attempts, 40);

        for (name, value) in [
            ("OPENSEA_REQUEST_TIMEOUT_MS", "99"),
            ("ELIGIBILITY_REQUEST_TIMEOUT_MS", "120001"),
            ("OPENSEA_MAX_ATTEMPTS", "0"),
            ("OPENSEA_RETRY_INTERVAL_MS", "49"),
            ("OPENSEA_CALLDATA_MAX_ATTEMPTS", "1001"),
        ] {
            let mut invalid_values = base_values();
            invalid_values.insert("WALLET_KEY".into(), KEY.into());
            invalid_values.insert(name.into(), value.into());
            assert!(
                LoadedConfig::from_values(invalid_values, PathBuf::from("C:/mint/.env")).is_err(),
                "{name}={value} must be rejected"
            );
        }
    }

    #[test]
    fn transaction_retry_and_fee_bounds_are_enforced() {
        for (name, value) in [
            ("TRANSACTION_MAX_ATTEMPTS", "0"),
            ("TRANSACTION_MAX_ATTEMPTS", "11"),
            ("PENDING_TIMEOUT_SECONDS", "86401"),
            ("RECEIPT_POLL_BASE_DELAY_MS", "49"),
            ("RECEIPT_POLL_MAX_DELAY_MS", "60001"),
            ("REPLACEMENT_BUMP_BPS", "10000"),
            ("REPLACEMENT_BUMP_BPS", "20001"),
        ] {
            let mut invalid_values = base_values();
            invalid_values.insert("WALLET_KEY".into(), KEY.into());
            invalid_values.insert(name.into(), value.into());
            assert!(
                LoadedConfig::from_values(invalid_values, PathBuf::from("C:/mint/.env")).is_err(),
                "{name}={value} must be rejected"
            );
        }

        let mut reversed_delays = base_values();
        reversed_delays.insert("WALLET_KEY".into(), KEY.into());
        reversed_delays.insert("RECEIPT_POLL_BASE_DELAY_MS".into(), "500".into());
        reversed_delays.insert("RECEIPT_POLL_MAX_DELAY_MS".into(), "250".into());
        assert!(LoadedConfig::from_values(reversed_delays, PathBuf::from("C:/mint/.env")).is_err());
    }

    #[test]
    fn loads_self_funded_mode_with_fixed_wallet_limit_and_explicit_recipient() {
        let mut values = base_values();
        values.extend([
            ("WALLETS_FILE".into(), "wallets.json".into()),
            ("SPONSORED".into(), "false".into()),
            (
                "RECIPIENT_ADDRESS".into(),
                "0x0000000000000000000000000000000000000011".into(),
            ),
        ]);
        let loaded = LoadedConfig::from_values(values, PathBuf::from("C:/mint/.env"))
            .expect("multi-wallet config");
        let multi = loaded.multi_wallet().expect("multi config");

        assert_eq!(multi.manifest_path, PathBuf::from("C:/mint/wallets.json"));
        assert_eq!(multi.mode, MultiWalletMode::SelfFunded);
        assert!(loaded.wallet_key().is_none());
    }

    #[test]
    fn sponsor_key_supplies_recipient_without_being_exposed_in_debug() {
        let mut values = base_values();
        values.extend([
            ("WALLETS_FILE".into(), "wallets.json".into()),
            ("SPONSORED".into(), "false".into()),
            ("SPONSOR_KEY".into(), KEY.into()),
        ]);
        let loaded = LoadedConfig::from_values(values, PathBuf::from("C:/mint/.env"))
            .expect("multi-wallet config");
        let expected = WalletSigner::from_private_key(KEY)
            .expect("signer")
            .identity()
            .address;

        assert_eq!(loaded.multi_wallet().expect("multi").recipient, expected);
        assert!(!format!("{loaded:?}").contains(KEY));
    }

    #[test]
    fn deployment_config_uses_sponsor_and_ignores_wallet_mode_selection() {
        let mut values = base_values();
        values.extend([
            ("WALLET_KEY".into(), KEY.into()),
            ("WALLETS_FILE".into(), "wallets.json".into()),
            ("SPONSORED".into(), "true".into()),
            ("SPONSOR_KEY".into(), KEY.into()),
            (
                "SPONSORED_EXECUTOR_ADDRESS".into(),
                "0x0000000000000000000000000000000000000011".into(),
            ),
        ]);
        let loaded = DeploymentConfig::from_values(values, PathBuf::from("C:/mint/.env"))
            .expect("deployment config");

        assert_eq!(loaded.deployer_key(), KEY);
        assert_eq!(
            loaded.configured_executor(),
            Some(
                "0x0000000000000000000000000000000000000011"
                    .parse()
                    .expect("executor")
            )
        );
        assert_eq!(loaded.app.rpc_url.as_str(), "https://rpc.example/");
        assert!(!format!("{loaded:?}").contains(KEY));
    }

    #[test]
    fn deployment_config_requires_a_sponsor_key_and_rejects_unknown_settings() {
        let error = DeploymentConfig::from_values(base_values(), PathBuf::from("C:/mint/.env"))
            .expect_err("missing sponsor key");
        assert!(matches!(error, ConfigError::MissingSetting("SPONSOR_KEY")));

        let mut values = base_values();
        values.insert("SPONSOR_KEY".into(), KEY.into());
        values.insert("SPONSORED_CHAIN_ID".into(), "8453".into());
        let error = DeploymentConfig::from_values(values, PathBuf::from("C:/mint/.env"))
            .expect_err("unknown setting");
        assert!(matches!(error, ConfigError::UnknownSetting(name) if name == "SPONSORED_CHAIN_ID"));
    }

    #[test]
    fn sponsored_mode_requires_nonzero_executor_address() {
        let mut values = base_values();
        values.extend([
            ("WALLETS_FILE".into(), "wallets.json".into()),
            ("SPONSORED".into(), "true".into()),
            ("SPONSOR_KEY".into(), KEY.into()),
            (
                "SPONSORED_EXECUTOR_ADDRESS".into(),
                "0x0000000000000000000000000000000000000011".into(),
            ),
        ]);
        let loaded = LoadedConfig::from_values(values, PathBuf::from("C:/mint/.env"))
            .expect("sponsored config");
        let MultiWalletMode::Sponsored(sponsored) = &loaded.multi_wallet().expect("multi").mode
        else {
            panic!("expected sponsored mode");
        };
        assert_eq!(
            sponsored.executor,
            "0x0000000000000000000000000000000000000011"
                .parse::<Address>()
                .expect("address")
        );
        assert_eq!(sponsored.wallet_gas_limit, 450_000);
        assert_eq!(sponsored.operation_deadline_seconds, 120);
    }

    #[test]
    fn sponsored_manifest_takes_precedence_over_a_stale_single_wallet_key() {
        let mut values = base_values();
        values.extend([
            ("WALLET_KEY".into(), KEY.into()),
            ("WALLETS_FILE".into(), "wallets.json".into()),
            ("SPONSORED".into(), "true".into()),
            ("SPONSOR_KEY".into(), KEY.into()),
            (
                "SPONSORED_EXECUTOR_ADDRESS".into(),
                "0x0000000000000000000000000000000000000011".into(),
            ),
        ]);

        let loaded = LoadedConfig::from_values(values, PathBuf::from("C:/mint/.env"))
            .expect("sponsored manifest config");

        assert!(loaded.wallet_key().is_none());
        assert!(matches!(
            loaded.multi_wallet().expect("multi").mode,
            MultiWalletMode::Sponsored(_)
        ));

        let mut ambiguous = base_values();
        ambiguous.extend([
            ("WALLET_KEY".into(), KEY.into()),
            ("WALLETS_FILE".into(), "wallets.json".into()),
            ("SPONSORED".into(), "false".into()),
            (
                "RECIPIENT_ADDRESS".into(),
                "0x0000000000000000000000000000000000000011".into(),
            ),
        ]);
        assert!(matches!(
            LoadedConfig::from_values(ambiguous, PathBuf::from("C:/mint/.env")),
            Err(ConfigError::Validation(_))
        ));
    }

    #[test]
    fn sponsored_mode_rejects_executor_as_nft_recipient() {
        let executor = "0x0000000000000000000000000000000000000011";
        let mut values = base_values();
        values.extend([
            ("WALLETS_FILE".into(), "wallets.json".into()),
            ("SPONSORED".into(), "true".into()),
            ("SPONSOR_KEY".into(), KEY.into()),
            ("SPONSORED_EXECUTOR_ADDRESS".into(), executor.into()),
            ("RECIPIENT_ADDRESS".into(), executor.into()),
        ]);

        let error = LoadedConfig::from_values(values, PathBuf::from("C:/mint/.env"))
            .expect_err("executor recipient");
        assert!(matches!(
            error,
            ConfigError::InvalidSetting {
                name: "RECIPIENT_ADDRESS",
                ..
            }
        ));
    }

    #[test]
    fn rejects_removed_deployment_gas_and_concurrency_settings() {
        for setting in [
            "SPONSORED_CHAIN_ID",
            "SPONSORED_EXECUTOR_RUNTIME_HASH",
            "SPONSORED_DELEGATION_CODE_HASH",
            "SPONSORED_WALLET_GAS_LIMIT",
            "MULTI_WALLET_CONCURRENCY",
        ] {
            let mut values = base_values();
            values.insert(setting.into(), "1".into());
            let error = LoadedConfig::from_values(values, PathBuf::from("C:/mint/.env"))
                .expect_err("legacy setting must be rejected");
            assert!(
                matches!(&error, ConfigError::UnknownSetting(name) if name == setting),
                "unexpected error for {setting}: {error}"
            );
        }
    }
}
