use std::fs;

use alloy_primitives::{U256, eip191_hash_message};
use opensea_mint::{
    config::{FeeMode, LoadedConfig},
    signing::WalletSigner,
};
use tempfile::tempdir;

const TEST_KEY: &str = "0x0000000000000000000000000000000000000000000000000000000000000001";

fn valid_environment() -> String {
    format!(
        r"WALLET_KEY={TEST_KEY}
RPC_URL=https://rpc.example.invalid
FEE_AUTOMATIC=true
GAS_LIMIT=300000
SCHEDULE_REFRESH_INTERVAL_SECONDS=600
TRANSACTION_MAX_ATTEMPTS=3
PENDING_TIMEOUT_SECONDS=20
RECEIPT_POLL_BASE_DELAY_MS=250
RECEIPT_POLL_MAX_DELAY_MS=2000
REPLACEMENT_BUMP_BPS=11250
"
    )
}

fn load_source(source: &str) -> Result<LoadedConfig, opensea_mint::config::ConfigError> {
    let directory = tempdir().expect("temp directory");
    fs::write(directory.path().join(".env"), source).expect("write .env");
    LoadedConfig::load_from(directory.path())
}

#[test]
fn parses_and_validates_a_complete_env_only_config() {
    let loaded = load_source(&valid_environment()).expect("valid config");

    assert_eq!(loaded.app.rpc_url.as_str(), "https://rpc.example.invalid/");
    assert_eq!(loaded.app.retry.max_attempts, 3);
    assert_eq!(loaded.app.scheduling.refresh_interval_seconds, 600);
    assert!(matches!(loaded.app.fees.mode, FeeMode::Automatic));
    assert_eq!(loaded.wallet_key(), Some(TEST_KEY));
}

#[test]
fn rejects_unknown_settings_insecure_rpc_and_invalid_scheduling() {
    assert!(load_source(&format!("{}UNEXPECTED=true\n", valid_environment())).is_err());
    assert!(
        load_source(
            &valid_environment()
                .replace("https://rpc.example.invalid", "http://rpc.example.invalid")
        )
        .is_err()
    );
    assert!(
        load_source(&valid_environment().replace(
            "SCHEDULE_REFRESH_INTERVAL_SECONDS=600",
            "SCHEDULE_REFRESH_INTERVAL_SECONDS=5"
        ))
        .is_err()
    );
}

#[test]
fn manual_fee_mode_requires_and_parses_both_eip1559_values() {
    let manual = valid_environment().replace(
        "FEE_AUTOMATIC=true",
        "FEE_AUTOMATIC=false\nMAX_FEE_PER_GAS_GWEI=1.25\nMAX_PRIORITY_FEE_PER_GAS_GWEI=0.5",
    );
    let loaded = load_source(&manual).expect("manual config");
    assert_eq!(
        loaded.app.fees.mode,
        FeeMode::Manual {
            max_fee_per_gas: U256::from(1_250_000_000_u64),
            max_priority_fee_per_gas: U256::from(500_000_000_u64),
        }
    );

    let missing = valid_environment().replace("FEE_AUTOMATIC=true", "FEE_AUTOMATIC=false");
    assert!(load_source(&missing).is_err());
}

#[test]
fn rejects_fee_settings_from_the_inactive_mode_and_missing_gas_limit() {
    let automatic_with_manual = valid_environment().replace(
        "FEE_AUTOMATIC=true",
        "FEE_AUTOMATIC=true\nMAX_FEE_PER_GAS_GWEI=1\nMAX_PRIORITY_FEE_PER_GAS_GWEI=0.1",
    );
    assert!(load_source(&automatic_with_manual).is_err());
    assert!(load_source(&valid_environment().replace("GAS_LIMIT=300000\n", "")).is_err());
}

#[test]
fn loaded_configuration_debug_redacts_the_wallet_key() {
    let loaded = load_source(&valid_environment()).expect("config");
    let debug = format!("{loaded:?}");

    assert!(!debug.contains(TEST_KEY));
    assert!(!debug.contains("wallet_key"));
    assert!(!debug.contains("rpc.example.invalid"));
}

#[test]
fn derives_one_wallet_address_and_redacts_debug_output() {
    let signer = WalletSigner::from_private_key(TEST_KEY).expect("valid signer");

    assert_eq!(
        signer.identity().address,
        "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf"
            .parse::<alloy_primitives::Address>()
            .expect("expected address")
    );
    let debug = format!("{signer:?}");
    assert!(debug.contains("WalletIdentity"));
    assert!(!debug.contains(TEST_KEY));
    assert!(!debug.contains("private_key"));
}

#[test]
fn signs_a_personal_message_for_the_configured_wallet() {
    let signer = WalletSigner::from_private_key(TEST_KEY).expect("valid signer");
    let message = b"query-only fixture";
    let signature = signer
        .sign_personal_message(message)
        .expect("personal signature");

    assert_eq!(
        signature
            .recover_address_from_prehash(&eip191_hash_message(message))
            .expect("recover"),
        signer.identity().address
    );
}

#[test]
fn rejects_invalid_single_wallet_keys() {
    assert!(WalletSigner::from_private_key("not-a-key").is_err());
    assert!(WalletSigner::from_private_key("0x00").is_err());
}
