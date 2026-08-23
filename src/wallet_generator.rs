use std::{
    fmt,
    fs::OpenOptions,
    io::{self, Write},
    path::{Path, PathBuf},
};

use alloy_primitives::Address;
use bip32::{DerivationPath, XPrv};
use bip39::Mnemonic;
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroizing;

const MANIFEST_VERSION: u32 = 2;
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
    #[error("generated wallet manifest could not be encrypted: {0}")]
    Encrypt(String),
    #[error("BIP-32 key derivation failed for wallet index {0}")]
    Derivation(u32),
    #[error("invalid mnemonic phrase")]
    InvalidMnemonic,
}

pub struct GeneratedWalletManifest {
    path: PathBuf,
    addresses: Vec<Address>,
    quantity: u64,
    mnemonic: Zeroizing<String>,
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

    #[must_use]
    pub fn mnemonic(&self) -> &str {
        &self.mnemonic
    }
}

impl fmt::Debug for GeneratedWalletManifest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GeneratedWalletManifest")
            .field("path", &self.path)
            .field("wallet_count", &self.addresses.len())
            .field("quantity", &self.quantity)
            .finish_non_exhaustive()
    }
}

fn seed_from_mnemonic(mnemonic: &Mnemonic) -> [u8; 64] {
    mnemonic.to_seed_normalized("")
}

fn derive_wallets_from_seed(
    seed: &[u8; 64],
    count: usize,
    quantity: u64,
) -> Result<(Vec<Address>, Vec<GeneratedWallet>), WalletGeneratorError> {
    let mut addresses = Vec::with_capacity(count);
    let mut wallets = Vec::with_capacity(count);
    for i in 0..count {
        let index = u32::try_from(i).map_err(|_| WalletGeneratorError::TooManyWallets)?;
        let path: DerivationPath = format!("m/44'/60'/0'/0/{index}")
            .parse()
            .map_err(|_| WalletGeneratorError::Derivation(index))?;
        let child_xprv = XPrv::derive_from_path(seed, &path)
            .map_err(|_| WalletGeneratorError::Derivation(index))?;
        let signing_key = child_xprv.private_key().clone();
        addresses.push(Address::from_private_key(&signing_key));
        let private_key = Zeroizing::new(format!("0x{}", hex::encode(signing_key.to_bytes())));
        wallets.push(GeneratedWallet {
            private_key,
            quantity,
        });
    }
    Ok((addresses, wallets))
}

fn write_manifest(
    output: &Path,
    wallets: Vec<GeneratedWallet>,
) -> Result<(), WalletGeneratorError> {
    write_manifest_at(output, wallets, false)
}

/// `overwrite` is only ever `true` for `expand_wallet_manifest`, where the
/// caller has already verified the phrase reproduces every wallet the
/// existing manifest holds before this replaces it — see the prefix check in
/// that function's doc comment. Every other caller keeps the default
/// create-only behavior, so a manifest is never silently replaced.
fn write_manifest_at(
    output: &Path,
    wallets: Vec<GeneratedWallet>,
    overwrite: bool,
) -> Result<(), WalletGeneratorError> {
    let manifest = GeneratedManifest {
        version: MANIFEST_VERSION,
        wallets,
    };
    let plaintext = Zeroizing::new(
        serde_json::to_string_pretty(&manifest).map_err(WalletGeneratorError::Serialize)?,
    );
    if plaintext.len() > MAX_MANIFEST_BYTES {
        return Err(WalletGeneratorError::ManifestTooLarge);
    }
    let encoded = Zeroizing::new(
        match crate::manifest_crypto::passphrase_from_env() {
            Some(passphrase) => crate::manifest_crypto::encrypt(&plaintext, &passphrase)
                .map_err(|error| WalletGeneratorError::Encrypt(error.to_string()))?,
            None => plaintext.to_string(),
        }
        .into_bytes(),
    );

    let mut options = OpenOptions::new();
    if overwrite {
        options.write(true).create(true).truncate(true);
    } else {
        options.write(true).create_new(true);
    }
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
    Ok(())
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

    let mnemonic = Mnemonic::generate_in_with(&mut OsRng, bip39::Language::English, 12)
        .map_err(|_| WalletGeneratorError::InvalidMnemonic)?;
    let mnemonic_phrase = Zeroizing::new(mnemonic.to_string());
    let seed = seed_from_mnemonic(&mnemonic);
    let (addresses, wallets) = derive_wallets_from_seed(&seed, count, quantity)?;
    write_manifest(output, wallets)?;

    Ok(GeneratedWalletManifest {
        path: output.to_path_buf(),
        addresses,
        quantity,
        mnemonic: mnemonic_phrase,
    })
}

pub fn recover_wallet_manifest(
    output: &Path,
    phrase: &str,
    count: usize,
    quantity: u64,
) -> Result<GeneratedWalletManifest, WalletGeneratorError> {
    if count == 0 || quantity == 0 {
        return Err(WalletGeneratorError::InvalidAmount);
    }
    if count > MAX_MANIFEST_BYTES / MINIMUM_GENERATED_ENTRY_BYTES {
        return Err(WalletGeneratorError::TooManyWallets);
    }

    let mnemonic: Mnemonic = phrase
        .parse()
        .map_err(|_| WalletGeneratorError::InvalidMnemonic)?;
    let mnemonic_phrase = Zeroizing::new(mnemonic.to_string());
    let seed = seed_from_mnemonic(&mnemonic);
    let (addresses, wallets) = derive_wallets_from_seed(&seed, count, quantity)?;
    write_manifest(output, wallets)?;

    Ok(GeneratedWalletManifest {
        path: output.to_path_buf(),
        addresses,
        quantity,
        mnemonic: mnemonic_phrase,
    })
}

/// Grow an existing manifest to `count` wallets by re-deriving from the same
/// phrase that produced it and overwriting the file. Every existing wallet's
/// key is unchanged — HD derivation gives wallet `i` the same key regardless
/// of `count`, so this only ever *adds* wallets at the end, never touches the
/// ones already funded.
///
/// The caller is responsible for verifying the phrase actually reproduces the
/// wallets already on disk (e.g. via `addresses_from_mnemonic` against the
/// manifest's current addresses) before calling this — this function itself
/// has no way to check that and will happily overwrite with an unrelated
/// phrase's wallets if asked to.
pub fn expand_wallet_manifest(
    output: &Path,
    phrase: &str,
    count: usize,
    quantity: u64,
) -> Result<GeneratedWalletManifest, WalletGeneratorError> {
    if count == 0 || quantity == 0 {
        return Err(WalletGeneratorError::InvalidAmount);
    }
    if count > MAX_MANIFEST_BYTES / MINIMUM_GENERATED_ENTRY_BYTES {
        return Err(WalletGeneratorError::TooManyWallets);
    }

    let mnemonic: Mnemonic = phrase
        .parse()
        .map_err(|_| WalletGeneratorError::InvalidMnemonic)?;
    let mnemonic_phrase = Zeroizing::new(mnemonic.to_string());
    let seed = seed_from_mnemonic(&mnemonic);
    let (addresses, wallets) = derive_wallets_from_seed(&seed, count, quantity)?;
    write_manifest_at(output, wallets, true)?;

    Ok(GeneratedWalletManifest {
        path: output.to_path_buf(),
        addresses,
        quantity,
        mnemonic: mnemonic_phrase,
    })
}

pub fn addresses_from_mnemonic(
    phrase: &str,
    count: usize,
) -> Result<Vec<Address>, WalletGeneratorError> {
    if count == 0 {
        return Err(WalletGeneratorError::InvalidAmount);
    }
    let mnemonic: Mnemonic = phrase
        .parse()
        .map_err(|_| WalletGeneratorError::InvalidMnemonic)?;
    let seed = seed_from_mnemonic(&mnemonic);
    let mut addresses = Vec::with_capacity(count);
    for i in 0..count {
        let index = u32::try_from(i).map_err(|_| WalletGeneratorError::TooManyWallets)?;
        let path: DerivationPath = format!("m/44'/60'/0'/0/{index}")
            .parse()
            .map_err(|_| WalletGeneratorError::Derivation(index))?;
        let child_xprv = XPrv::derive_from_path(seed, &path)
            .map_err(|_| WalletGeneratorError::Derivation(index))?;
        let signing_key = child_xprv.private_key().clone();
        addresses.push(Address::from_private_key(&signing_key));
    }
    Ok(addresses)
}

#[cfg(unix)]
fn set_private_file_permissions(options: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt;
    options.mode(0o600);
}

#[cfg(not(unix))]
fn set_private_file_permissions(_options: &mut OpenOptions) {}

#[derive(Serialize, Deserialize)]
struct GeneratedManifest {
    version: u32,
    wallets: Vec<GeneratedWallet>,
}

#[derive(Serialize, Deserialize)]
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

    #[test]
    fn mnemonic_is_twelve_words() {
        let directory = tempdir().expect("temp directory");
        let path = directory.path().join("wallets.json");
        let generated = create_wallet_manifest(&path, 2, 1).expect("generated manifest");
        let words: Vec<&str> = generated.mnemonic().split_whitespace().collect();
        assert_eq!(words.len(), 12);
    }

    #[test]
    fn recover_reproduces_same_addresses() {
        let directory = tempdir().expect("temp directory");
        let path = directory.path().join("wallets.json");
        let generated = create_wallet_manifest(&path, 5, 1).expect("generated manifest");
        let phrase = generated.mnemonic().to_owned();

        let recovered_path = directory.path().join("recovered.json");
        let recovered =
            recover_wallet_manifest(&recovered_path, &phrase, 5, 1).expect("recovered manifest");
        assert_eq!(generated.addresses(), recovered.addresses());
    }

    #[test]
    fn recover_with_fewer_wallets_gives_prefix() {
        let directory = tempdir().expect("temp directory");
        let path = directory.path().join("wallets.json");
        let generated = create_wallet_manifest(&path, 10, 1).expect("generated manifest");
        let phrase = generated.mnemonic().to_owned();

        let recovered_path = directory.path().join("recovered.json");
        let recovered =
            recover_wallet_manifest(&recovered_path, &phrase, 3, 1).expect("recovered manifest");
        assert_eq!(&generated.addresses()[..3], recovered.addresses());
    }

    #[test]
    fn expand_grows_a_manifest_in_place_without_changing_existing_wallets() {
        let directory = tempdir().expect("temp directory");
        let path = directory.path().join("wallets.json");
        let generated = create_wallet_manifest(&path, 3, 1).expect("generated manifest");
        let phrase = generated.mnemonic().to_owned();

        let expanded = expand_wallet_manifest(&path, &phrase, 10, 1).expect("expanded manifest");
        assert_eq!(expanded.addresses().len(), 10);
        assert_eq!(&expanded.addresses()[..3], generated.addresses());

        let reloaded = crate::multi_wallet::WalletManifest::load(&path).expect("reloaded manifest");
        assert_eq!(reloaded.len(), 10);
    }

    #[test]
    fn expand_refuses_to_shrink_past_the_manifest_limit() {
        let directory = tempdir().expect("temp directory");
        let path = directory.path().join("wallets.json");
        let generated = create_wallet_manifest(&path, 3, 1).expect("generated manifest");
        let phrase = generated.mnemonic().to_owned();

        assert!(matches!(
            expand_wallet_manifest(&path, &phrase, 0, 1),
            Err(WalletGeneratorError::InvalidAmount)
        ));
    }

    #[test]
    fn addresses_from_mnemonic_matches_generated() {
        let directory = tempdir().expect("temp directory");
        let path = directory.path().join("wallets.json");
        let generated = create_wallet_manifest(&path, 4, 1).expect("generated manifest");
        let phrase = generated.mnemonic().to_owned();

        let addrs = addresses_from_mnemonic(&phrase, 4).expect("addresses");
        assert_eq!(generated.addresses(), &addrs[..]);
    }

    #[test]
    fn invalid_mnemonic_is_rejected() {
        let directory = tempdir().expect("temp directory");
        let path = directory.path().join("wallets.json");
        assert!(matches!(
            recover_wallet_manifest(&path, "not a valid mnemonic phrase at all", 1, 1),
            Err(WalletGeneratorError::InvalidMnemonic)
        ));
    }

    #[test]
    fn debug_output_never_contains_mnemonic() {
        let directory = tempdir().expect("temp directory");
        let path = directory.path().join("wallets.json");
        let generated = create_wallet_manifest(&path, 1, 1).expect("generated manifest");
        let debug = format!("{generated:?}");
        for word in generated.mnemonic().split_whitespace() {
            assert!(
                !debug.contains(word),
                "debug output leaked mnemonic word: {word}"
            );
        }
    }

    #[test]
    fn wallets_match_metamask_derivation_path() {
        let known_phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let addrs = addresses_from_mnemonic(known_phrase, 3).expect("addresses");
        assert_eq!(
            format!("{:?}", addrs[0]).to_lowercase(),
            "0x9858effd232b4033e47d90003d41ec34ecaeda94"
        );
    }
}
