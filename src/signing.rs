use std::fmt;

use alloy_primitives::{Address, B256, Signature, eip191_hash_message};
use k256::ecdsa::SigningKey;
use thiserror::Error;
use zeroize::Zeroizing;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum WalletSignerError {
    #[error("WALLET_KEY does not contain a valid private key")]
    InvalidPrivateKey,
    #[error("wallet signing failed")]
    SigningFailed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WalletIdentity {
    pub address: Address,
}

#[derive(Clone)]
pub struct WalletSigner {
    identity: WalletIdentity,
    signing_key: SigningKey,
}

impl WalletSigner {
    pub fn from_private_key(value: &str) -> Result<Self, WalletSignerError> {
        let key_text = value.strip_prefix("0x").unwrap_or(value);
        let key_bytes = Zeroizing::new(
            hex::decode(key_text).map_err(|_| WalletSignerError::InvalidPrivateKey)?,
        );
        let signing_key =
            SigningKey::from_slice(&key_bytes).map_err(|_| WalletSignerError::InvalidPrivateKey)?;
        Ok(Self {
            identity: WalletIdentity {
                address: Address::from_private_key(&signing_key),
            },
            signing_key,
        })
    }

    #[must_use]
    pub const fn identity(&self) -> WalletIdentity {
        self.identity
    }

    pub fn sign_personal_message(&self, message: &[u8]) -> Result<Signature, WalletSignerError> {
        self.sign_hash(&eip191_hash_message(message))
    }

    pub(crate) fn sign_hash(&self, hash: &B256) -> Result<Signature, WalletSignerError> {
        self.signing_key
            .sign_prehash_recoverable(hash.as_slice())
            .map(Into::into)
            .map_err(|_| WalletSignerError::SigningFailed)
    }
}

impl fmt::Debug for WalletSigner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WalletSigner")
            .field("identity", &self.identity)
            .finish_non_exhaustive()
    }
}
