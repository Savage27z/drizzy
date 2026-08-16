use std::{collections::HashSet, fmt, fs, io::Read, path::Path};

use alloy_primitives::{Address, U256};
use serde::Deserialize;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::signing::{WalletSigner, WalletSignerError};

pub const MAX_SELF_FUNDED_WALLETS: usize = 10;

const MANIFEST_VERSION: u32 = 1;
const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Error)]
pub enum WalletManifestError {
    #[error("wallet manifest cannot be inspected")]
    Metadata(#[source] std::io::Error),
    #[error("wallet manifest must be a regular file, not a symbolic link")]
    NotRegularFile,
    #[error("wallet manifest exceeds the 1 MiB input limit")]
    TooLarge,
    #[error("wallet manifest cannot be read")]
    Read(#[source] std::io::Error),
    #[error("wallet manifest is not valid versioned JSON")]
    Json(#[source] serde_json::Error),
    #[error("wallet manifest version is unsupported")]
    UnsupportedVersion,
    #[error("wallet manifest must contain at least one wallet")]
    Empty,
    #[error("wallet entry {index} has a zero quantity")]
    ZeroQuantity { index: usize },
    #[error("wallet entry {index} has an invalid private key")]
    InvalidPrivateKey {
        index: usize,
        #[source]
        source: WalletSignerError,
    },
    #[error("wallet entry {index} derives a duplicate address")]
    DuplicateAddress { index: usize },
    #[error("native-currency funding arithmetic overflowed")]
    FundingOverflow,
    #[error("wallet remains underfunded at the pre-sign check")]
    Underfunded,
}

pub struct WalletManifest {
    wallets: Vec<WalletEntry>,
}

impl WalletManifest {
    pub fn load(path: &Path) -> Result<Self, WalletManifestError> {
        let metadata = fs::symlink_metadata(path).map_err(WalletManifestError::Metadata)?;
        if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
            return Err(WalletManifestError::NotRegularFile);
        }
        if metadata.len() > MAX_MANIFEST_BYTES {
            return Err(WalletManifestError::TooLarge);
        }
        let file = fs::File::open(path).map_err(WalletManifestError::Read)?;
        let opened_metadata = file.metadata().map_err(WalletManifestError::Metadata)?;
        if !opened_metadata.file_type().is_file() || opened_metadata.len() > MAX_MANIFEST_BYTES {
            return Err(if opened_metadata.file_type().is_file() {
                WalletManifestError::TooLarge
            } else {
                WalletManifestError::NotRegularFile
            });
        }
        let mut source = Zeroizing::new(String::new());
        file.take(MAX_MANIFEST_BYTES + 1)
            .read_to_string(&mut source)
            .map_err(WalletManifestError::Read)?;
        if source.len() as u64 > MAX_MANIFEST_BYTES {
            return Err(WalletManifestError::TooLarge);
        }
        Self::from_json(&source)
    }

    pub fn from_json(source: &str) -> Result<Self, WalletManifestError> {
        if source.len() as u64 > MAX_MANIFEST_BYTES {
            return Err(WalletManifestError::TooLarge);
        }
        let raw: RawWalletManifest =
            serde_json::from_str(source).map_err(WalletManifestError::Json)?;
        if raw.version != MANIFEST_VERSION {
            return Err(WalletManifestError::UnsupportedVersion);
        }
        if raw.wallets.is_empty() {
            return Err(WalletManifestError::Empty);
        }

        let mut addresses = HashSet::with_capacity(raw.wallets.len());
        let mut wallets = Vec::with_capacity(raw.wallets.len());
        for (offset, entry) in raw.wallets.into_iter().enumerate() {
            let index = offset + 1;
            if entry.quantity == 0 {
                return Err(WalletManifestError::ZeroQuantity { index });
            }
            let signer = WalletSigner::from_private_key(&entry.private_key)
                .map_err(|source| WalletManifestError::InvalidPrivateKey { index, source })?;
            if !addresses.insert(signer.identity().address) {
                return Err(WalletManifestError::DuplicateAddress { index });
            }
            wallets.push(WalletEntry {
                signer,
                quantity: entry.quantity,
            });
        }
        Ok(Self { wallets })
    }

    #[must_use]
    pub fn wallets(&self) -> &[WalletEntry] {
        &self.wallets
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.wallets.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.wallets.is_empty()
    }

    #[must_use]
    pub fn into_wallets(self) -> Vec<WalletEntry> {
        self.wallets
    }
}

impl fmt::Debug for WalletManifest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WalletManifest")
            .field("wallet_count", &self.wallets.len())
            .finish()
    }
}

pub struct WalletEntry {
    signer: WalletSigner,
    quantity: u64,
}

impl WalletEntry {
    #[must_use]
    pub const fn signer(&self) -> &WalletSigner {
        &self.signer
    }

    #[must_use]
    pub const fn address(&self) -> Address {
        self.signer.identity().address
    }

    #[must_use]
    pub const fn quantity(&self) -> u64 {
        self.quantity
    }
}

impl fmt::Debug for WalletEntry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WalletEntry")
            .field("address", &self.address())
            .field("quantity", &self.quantity)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FundingRequirement {
    pub mint_value: U256,
    pub gas_limit: u64,
    pub max_fee_per_gas: U256,
}

impl FundingRequirement {
    pub fn maximum_native_cost(self) -> Result<U256, WalletManifestError> {
        U256::from(self.gas_limit)
            .checked_mul(self.max_fee_per_gas)
            .and_then(|gas_cost| gas_cost.checked_add(self.mint_value))
            .ok_or(WalletManifestError::FundingOverflow)
    }

    pub fn shortfall(self, balance: U256) -> Result<U256, WalletManifestError> {
        let required = self.maximum_native_cost()?;
        Ok(required.saturating_sub(balance))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawWalletManifest {
    version: u32,
    wallets: Vec<RawWalletEntry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawWalletEntry {
    private_key: Zeroizing<String>,
    quantity: u64,
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::*;

    const FIRST_KEY: &str = "0x0000000000000000000000000000000000000000000000000000000000000001";
    const SECOND_KEY: &str = "0x0000000000000000000000000000000000000000000000000000000000000002";

    #[test]
    fn loads_strict_versioned_wallets_without_exposing_keys() {
        let source = format!(
            r#"{{"version":1,"wallets":[{{"private_key":"{FIRST_KEY}","quantity":2}},{{"private_key":"{SECOND_KEY}","quantity":1}}]}}"#
        );
        let manifest = WalletManifest::from_json(&source).expect("manifest");

        assert_eq!(manifest.len(), 2);
        assert_eq!(manifest.wallets()[0].quantity(), 2);
        let debug = format!("{manifest:?} {:?}", manifest.wallets());
        assert!(!debug.contains(FIRST_KEY));
        assert!(!debug.contains(SECOND_KEY));
    }

    #[test]
    fn rejects_unknown_fields_duplicates_zero_quantity_and_bad_versions() {
        let unknown = format!(
            r#"{{"version":1,"wallets":[{{"private_key":"{FIRST_KEY}","quantity":1,"label":"x"}}]}}"#
        );
        assert!(matches!(
            WalletManifest::from_json(&unknown),
            Err(WalletManifestError::Json(_))
        ));

        let duplicate = format!(
            r#"{{"version":1,"wallets":[{{"private_key":"{FIRST_KEY}","quantity":1}},{{"private_key":"{FIRST_KEY}","quantity":1}}]}}"#
        );
        assert!(matches!(
            WalletManifest::from_json(&duplicate),
            Err(WalletManifestError::DuplicateAddress { index: 2 })
        ));

        let zero =
            format!(r#"{{"version":1,"wallets":[{{"private_key":"{FIRST_KEY}","quantity":0}}]}}"#);
        assert!(matches!(
            WalletManifest::from_json(&zero),
            Err(WalletManifestError::ZeroQuantity { index: 1 })
        ));

        let unsupported = r#"{"version":2,"wallets":[]}"#;
        assert!(matches!(
            WalletManifest::from_json(unsupported),
            Err(WalletManifestError::UnsupportedVersion)
        ));
    }

    #[test]
    fn calculates_maximum_funding_and_shortfall_with_checked_arithmetic() {
        let requirement = FundingRequirement {
            mint_value: U256::from(10_u8),
            gas_limit: 100,
            max_fee_per_gas: U256::from(3_u8),
        };
        assert_eq!(
            requirement.maximum_native_cost().expect("cost"),
            U256::from(310)
        );
        assert_eq!(
            requirement.shortfall(U256::from(250)).expect("shortfall"),
            U256::from(60)
        );
        assert_eq!(
            requirement.shortfall(U256::from(400)).expect("funded"),
            U256::ZERO
        );

        let overflow = FundingRequirement {
            mint_value: U256::MAX,
            gas_limit: 1,
            max_fee_per_gas: U256::ONE,
        };
        assert!(matches!(
            overflow.maximum_native_cost(),
            Err(WalletManifestError::FundingOverflow)
        ));
    }

    #[test]
    fn file_loading_rejects_manifest_data_beyond_the_input_limit() {
        let directory = tempdir().expect("temporary directory");
        let path = directory.path().join("wallets.json");
        let oversized_length = usize::try_from(MAX_MANIFEST_BYTES).expect("manifest limit") + 1;
        fs::write(&path, vec![b' '; oversized_length]).expect("oversized manifest");

        assert!(matches!(
            WalletManifest::load(&path),
            Err(WalletManifestError::TooLarge)
        ));
    }
}
