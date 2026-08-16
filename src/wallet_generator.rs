use std::{
    fmt,
    fs::OpenOptions,
    io::{self, Write},
    path::{Path, PathBuf},
};

use alloy_primitives::Address;
use k256::ecdsa::SigningKey;
use rand_core::OsRng;
use serde::Serialize;
use thiserror::Error;
use zeroize::Zeroizing;

const MANIFEST_VERSION: u32 = 1;
const MAX_MANIFEST_BYTES: usize = 1024 * 1024;
const MINIMUM_GENERATED_ENTRY_BYTES: usize = 100;

#[derive(Debug, Error)]
pub enum WalletGeneratorError {
    #[error("wallet count and quantity must both be greater than zero")]
    InvalidAmount,
    #[error("requested wallet count cannot fit in the 1 MiB manifest limit")]
    TooManyWallets,
    #[error("generated wallet manifest exceeds the 1 MiB input limit")]
    ManifestTooLarge,
    #[error("wallet output path already exists; choose a new path")]
    AlreadyExists,
    #[error("wallet output file cannot be created at {path}")]
    Create {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("wallet output file could not be written completely")]
    Write(#[source] io::Error),
    #[error("generated wallet manifest could not be serialized")]
    Serialize(#[source] serde_json::Error),
}

pub struct GeneratedWalletManifest {
    path: PathBuf,
    addresses: Vec<Address>,
    quantity: u64,
}

impl GeneratedWalletManifest {
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    #[must_use]
    pub fn addresses(&self) -> &[Address] {
        &self.addresses
    }

    #[must_use]
    pub const fn quantity(&self) -> u64 {
        self.quantity
    }
}

impl fmt::Debug for GeneratedWalletManifest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GeneratedWalletManifest")
            .field("path", &self.path)
            .field("wallet_count", &self.addresses.len())
            .field("quantity", &self.quantity)
            .finish()
    }
}

pub fn create_wallet_manifest(
    output: &Path,
    count: usize,
    quantity: u64,
) -> Result<GeneratedWalletManifest, WalletGeneratorError> {
    if count == 0 || quantity == 0 {
        return Err(WalletGeneratorError::InvalidAmount);
    }
    if count > MAX_MANIFEST_BYTES / MINIMUM_GENERATED_ENTRY_BYTES {
        return Err(WalletGeneratorError::TooManyWallets);
    }

    let mut addresses = Vec::with_capacity(count);
    let mut wallets = Vec::with_capacity(count);
    for _ in 0..count {
        let signing_key = SigningKey::random(&mut OsRng);
        addresses.push(Address::from_private_key(&signing_key));
        let private_key = Zeroizing::new(format!("0x{}", hex::encode(signing_key.to_bytes())));
        wallets.push(GeneratedWallet {
            private_key,
            quantity,
        });
    }
    let manifest = GeneratedManifest {
        version: MANIFEST_VERSION,
        wallets,
    };
    let encoded = Zeroizing::new(
        serde_json::to_vec_pretty(&manifest).map_err(WalletGeneratorError::Serialize)?,
    );
    if encoded.len() > MAX_MANIFEST_BYTES {
        return Err(WalletGeneratorError::ManifestTooLarge);
    }

    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    set_private_file_permissions(&mut options);
    let mut file = options.open(output).map_err(|source| {
        if source.kind() == io::ErrorKind::AlreadyExists {
            WalletGeneratorError::AlreadyExists
        } else {
            WalletGeneratorError::Create {
                path: output.to_path_buf(),
                source,
            }
        }
    })?;
    file.write_all(&encoded)
        .map_err(WalletGeneratorError::Write)?;
    file.write_all(b"\n").map_err(WalletGeneratorError::Write)?;
    file.sync_all().map_err(WalletGeneratorError::Write)?;

    Ok(GeneratedWalletManifest {
        path: output.to_path_buf(),
        addresses,
        quantity,
    })
}

#[cfg(unix)]
fn set_private_file_permissions(options: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt;
    options.mode(0o600);
}

#[cfg(not(unix))]
fn set_private_file_permissions(_options: &mut OpenOptions) {}

#[derive(Serialize)]
struct GeneratedManifest {
    version: u32,
    wallets: Vec<GeneratedWallet>,
}

#[derive(Serialize)]
struct GeneratedWallet {
    private_key: Zeroizing<String>,
    quantity: u64,
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::*;
    use crate::multi_wallet::WalletManifest;

    #[test]
    fn creates_parseable_distinct_wallets_with_default_quantity_shape() {
        let directory = tempdir().expect("temp directory");
        let path = directory.path().join("wallets.json");
        let generated = create_wallet_manifest(&path, 3, 1).expect("generated manifest");
        let loaded = WalletManifest::load(&path).expect("load generated manifest");

        assert_eq!(generated.addresses().len(), 3);
        assert_eq!(generated.quantity(), 1);
        assert_eq!(loaded.len(), 3);
        assert!(loaded.wallets().iter().all(|wallet| wallet.quantity() == 1));
        assert_eq!(
            generated.addresses(),
            loaded
                .wallets()
                .iter()
                .map(crate::multi_wallet::WalletEntry::address)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn refuses_zero_amounts_and_existing_output_files() {
        let directory = tempdir().expect("temp directory");
        let path = directory.path().join("wallets.json");
        assert!(matches!(
            create_wallet_manifest(&path, 0, 1),
            Err(WalletGeneratorError::InvalidAmount)
        ));
        create_wallet_manifest(&path, 1, 1).expect("first manifest");
        assert!(matches!(
            create_wallet_manifest(&path, 1, 1),
            Err(WalletGeneratorError::AlreadyExists)
        ));
    }

    #[test]
    fn debug_output_never_contains_generated_private_keys() {
        let directory = tempdir().expect("temp directory");
        let path = directory.path().join("wallets.json");
        let generated = create_wallet_manifest(&path, 1, 2).expect("generated manifest");
        let source = std::fs::read_to_string(&path).expect("manifest source");
        let private_key = source
            .split("\"private_key\": \"")
            .nth(1)
            .and_then(|value| value.split('"').next())
            .expect("private key");
        assert!(!format!("{generated:?}").contains(private_key));
    }
}
