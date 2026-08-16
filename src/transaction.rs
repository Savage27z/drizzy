use std::fmt;

use alloy_eip7702::SignedAuthorization;
use alloy_primitives::{Address, B256, Bytes, U256, keccak256};
use alloy_rlp::RlpEncodable;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::signing::{WalletSigner, WalletSignerError};

const EIP1559_TRANSACTION_TYPE: u8 = 2;
const EIP7702_TRANSACTION_TYPE: u8 = 4;

#[derive(PartialEq, Eq)]
pub struct Eip1559Transaction {
    pub chain_id: u64,
    pub nonce: u64,
    pub max_priority_fee_per_gas: U256,
    pub max_fee_per_gas: U256,
    pub gas_limit: u64,
    pub target: Address,
    pub value: U256,
    pub calldata: Bytes,
}

#[derive(Clone, PartialEq, Eq)]
pub struct Eip7702Transaction {
    pub chain_id: u64,
    pub nonce: u64,
    pub max_priority_fee_per_gas: U256,
    pub max_fee_per_gas: U256,
    pub gas_limit: u64,
    pub target: Address,
    pub value: U256,
    pub calldata: Bytes,
    pub authorization_list: Vec<SignedAuthorization>,
}

impl fmt::Debug for Eip7702Transaction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Eip7702Transaction")
            .field("chain_id", &self.chain_id)
            .field("nonce", &self.nonce)
            .field("max_priority_fee_per_gas", &self.max_priority_fee_per_gas)
            .field("max_fee_per_gas", &self.max_fee_per_gas)
            .field("gas_limit", &self.gas_limit)
            .field("target", &self.target)
            .field("value", &self.value)
            .field("calldata_bytes", &self.calldata.len())
            .field("authorization_count", &self.authorization_list.len())
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for Eip1559Transaction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Eip1559Transaction")
            .field("chain_id", &self.chain_id)
            .field("nonce", &self.nonce)
            .field("max_priority_fee_per_gas", &self.max_priority_fee_per_gas)
            .field("max_fee_per_gas", &self.max_fee_per_gas)
            .field("gas_limit", &self.gas_limit)
            .field("target", &self.target)
            .field("value", &self.value)
            .field("calldata_bytes", &self.calldata.len())
            .finish_non_exhaustive()
    }
}

pub struct SignedTransaction {
    raw: Zeroizing<Vec<u8>>,
    hash: B256,
}

impl SignedTransaction {
    #[must_use]
    pub const fn hash(&self) -> B256 {
        self.hash
    }

    #[must_use]
    pub fn raw(&self) -> &[u8] {
        &self.raw
    }
}

impl fmt::Debug for SignedTransaction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SignedTransaction")
            .field("hash", &self.hash)
            .field("encoded_bytes", &self.raw.len())
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Error)]
pub enum TransactionError {
    #[error("EIP-1559 fee cap must cover the priority fee")]
    InvalidFees,
    #[error("transaction gas limit must be greater than zero")]
    InvalidGasLimit,
    #[error("transaction target must not be the zero address")]
    InvalidTarget,
    #[error("EIP-7702 transaction must contain at least one authorization")]
    EmptyAuthorizationList,
    #[error(transparent)]
    Signing(#[from] WalletSignerError),
}

pub fn sign_eip7702_transaction(
    transaction: &Eip7702Transaction,
    signer: &WalletSigner,
) -> Result<SignedTransaction, TransactionError> {
    validate_transaction_shape(
        transaction.max_fee_per_gas,
        transaction.max_priority_fee_per_gas,
        transaction.gas_limit,
        transaction.target,
    )?;
    if transaction.authorization_list.is_empty() {
        return Err(TransactionError::EmptyAuthorizationList);
    }

    let unsigned = UnsignedEip7702Payload::from(transaction);
    let mut signing_payload = Zeroizing::new(Vec::with_capacity(unsigned.length_hint() + 1));
    signing_payload.push(EIP7702_TRANSACTION_TYPE);
    signing_payload.extend(alloy_rlp::encode(&unsigned));
    let signature = signer.sign_hash(&keccak256(&signing_payload))?;

    let signed_payload = SignedEip7702Payload {
        chain_id: transaction.chain_id,
        nonce: transaction.nonce,
        max_priority_fee_per_gas: transaction.max_priority_fee_per_gas,
        max_fee_per_gas: transaction.max_fee_per_gas,
        gas_limit: transaction.gas_limit,
        target: transaction.target,
        value: transaction.value,
        calldata: transaction.calldata.clone(),
        access_list: Vec::new(),
        authorization_list: transaction.authorization_list.clone(),
        signature_y_parity: signature.v(),
        signature_r: signature.r(),
        signature_s: signature.s(),
    };
    let mut raw = Zeroizing::new(Vec::with_capacity(signing_payload.len() + 128));
    raw.push(EIP7702_TRANSACTION_TYPE);
    raw.extend(alloy_rlp::encode(signed_payload));
    let hash = keccak256(&raw);
    Ok(SignedTransaction { raw, hash })
}

pub fn sign_eip1559_transaction(
    transaction: &Eip1559Transaction,
    signer: &WalletSigner,
) -> Result<SignedTransaction, TransactionError> {
    validate_transaction_shape(
        transaction.max_fee_per_gas,
        transaction.max_priority_fee_per_gas,
        transaction.gas_limit,
        transaction.target,
    )?;

    let unsigned = UnsignedPayload::from(transaction);
    let mut signing_payload = Zeroizing::new(Vec::with_capacity(unsigned.length_hint() + 1));
    signing_payload.push(EIP1559_TRANSACTION_TYPE);
    signing_payload.extend(alloy_rlp::encode(&unsigned));
    let signing_hash = keccak256(&signing_payload);
    let signature = signer.sign_hash(&signing_hash)?;

    let signed_payload = SignedPayload {
        chain_id: transaction.chain_id,
        nonce: transaction.nonce,
        max_priority_fee_per_gas: transaction.max_priority_fee_per_gas,
        max_fee_per_gas: transaction.max_fee_per_gas,
        gas_limit: transaction.gas_limit,
        target: transaction.target,
        value: transaction.value,
        calldata: transaction.calldata.clone(),
        access_list: Vec::new(),
        signature_y_parity: signature.v(),
        signature_r: signature.r(),
        signature_s: signature.s(),
    };
    let mut raw = Zeroizing::new(Vec::with_capacity(signing_payload.len() + 68));
    raw.push(EIP1559_TRANSACTION_TYPE);
    raw.extend(alloy_rlp::encode(signed_payload));
    let hash = keccak256(&raw);
    Ok(SignedTransaction { raw, hash })
}

fn validate_transaction_shape(
    max_fee_per_gas: U256,
    max_priority_fee_per_gas: U256,
    gas_limit: u64,
    target: Address,
) -> Result<(), TransactionError> {
    validate_fee_and_gas_shape(max_fee_per_gas, max_priority_fee_per_gas, gas_limit)?;
    if target == Address::ZERO {
        return Err(TransactionError::InvalidTarget);
    }
    Ok(())
}

fn validate_fee_and_gas_shape(
    max_fee_per_gas: U256,
    max_priority_fee_per_gas: U256,
    gas_limit: u64,
) -> Result<(), TransactionError> {
    if max_fee_per_gas < max_priority_fee_per_gas {
        return Err(TransactionError::InvalidFees);
    }
    if gas_limit == 0 {
        return Err(TransactionError::InvalidGasLimit);
    }
    Ok(())
}

#[derive(Clone, RlpEncodable)]
struct AccessListEntry {
    address: Address,
    storage_keys: Vec<B256>,
}

#[derive(RlpEncodable)]
struct UnsignedPayload {
    chain_id: u64,
    nonce: u64,
    max_priority_fee_per_gas: U256,
    max_fee_per_gas: U256,
    gas_limit: u64,
    target: Address,
    value: U256,
    calldata: Bytes,
    access_list: Vec<AccessListEntry>,
}

impl UnsignedPayload {
    fn length_hint(&self) -> usize {
        self.calldata.len() + 160
    }
}

impl From<&Eip1559Transaction> for UnsignedPayload {
    fn from(transaction: &Eip1559Transaction) -> Self {
        Self {
            chain_id: transaction.chain_id,
            nonce: transaction.nonce,
            max_priority_fee_per_gas: transaction.max_priority_fee_per_gas,
            max_fee_per_gas: transaction.max_fee_per_gas,
            gas_limit: transaction.gas_limit,
            target: transaction.target,
            value: transaction.value,
            calldata: transaction.calldata.clone(),
            access_list: Vec::new(),
        }
    }
}

#[derive(RlpEncodable)]
struct SignedPayload {
    chain_id: u64,
    nonce: u64,
    max_priority_fee_per_gas: U256,
    max_fee_per_gas: U256,
    gas_limit: u64,
    target: Address,
    value: U256,
    calldata: Bytes,
    access_list: Vec<AccessListEntry>,
    signature_y_parity: bool,
    signature_r: U256,
    signature_s: U256,
}

#[derive(RlpEncodable)]
struct UnsignedEip7702Payload {
    chain_id: u64,
    nonce: u64,
    max_priority_fee_per_gas: U256,
    max_fee_per_gas: U256,
    gas_limit: u64,
    target: Address,
    value: U256,
    calldata: Bytes,
    access_list: Vec<AccessListEntry>,
    authorization_list: Vec<SignedAuthorization>,
}

impl UnsignedEip7702Payload {
    fn length_hint(&self) -> usize {
        self.calldata.len() + self.authorization_list.len().saturating_mul(128) + 192
    }
}

impl From<&Eip7702Transaction> for UnsignedEip7702Payload {
    fn from(transaction: &Eip7702Transaction) -> Self {
        Self {
            chain_id: transaction.chain_id,
            nonce: transaction.nonce,
            max_priority_fee_per_gas: transaction.max_priority_fee_per_gas,
            max_fee_per_gas: transaction.max_fee_per_gas,
            gas_limit: transaction.gas_limit,
            target: transaction.target,
            value: transaction.value,
            calldata: transaction.calldata.clone(),
            access_list: Vec::new(),
            authorization_list: transaction.authorization_list.clone(),
        }
    }
}

#[derive(RlpEncodable)]
struct SignedEip7702Payload {
    chain_id: u64,
    nonce: u64,
    max_priority_fee_per_gas: U256,
    max_fee_per_gas: U256,
    gas_limit: u64,
    target: Address,
    value: U256,
    calldata: Bytes,
    access_list: Vec<AccessListEntry>,
    authorization_list: Vec<SignedAuthorization>,
    signature_y_parity: bool,
    signature_r: U256,
    signature_s: U256,
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_eip7702::Authorization;

    #[test]
    fn signs_only_type_two_transactions_and_redacts_raw_bytes() {
        let signer = WalletSigner::from_private_key(
            "0x0000000000000000000000000000000000000000000000000000000000000001",
        )
        .expect("signer");
        let transaction = Eip1559Transaction {
            chain_id: 8453,
            nonce: 7,
            max_priority_fee_per_gas: U256::from(1_000_000_u64),
            max_fee_per_gas: U256::from(2_000_000_u64),
            gas_limit: 200_000,
            target: "0x00005EA00Ac477B1030CE78506496e8C2dE24bf5"
                .parse()
                .expect("target"),
            value: U256::ZERO,
            calldata: Bytes::from_static(&[0x4b, 0x61, 0xcd, 0x6f]),
        };
        let signed_transaction = sign_eip1559_transaction(&transaction, &signer).expect("signed");

        assert_eq!(signed_transaction.raw()[0], EIP1559_TRANSACTION_TYPE);
        assert_eq!(
            format!("0x{}", hex::encode(signed_transaction.raw())),
            "0x02f86f82210507830f4240831e848083030d409400005ea00ac477b1030ce78506496e8c2de24bf580844b61cd6fc080a06f00fac4260eb7a02fa6c5109aec3d5efd5519fb011545e89656d44d15e338e9a02d52209fbaa995756a8a83106ae5c0a01b8e3025e14dbddd8ed8bb7480007c62"
        );
        assert_eq!(
            signed_transaction.hash(),
            keccak256(signed_transaction.raw())
        );
        let debug = format!("{signed_transaction:?}");
        assert!(!debug.contains(&hex::encode(signed_transaction.raw())));
    }

    #[test]
    fn signs_type_four_transaction_with_recoverable_authorization() {
        let sponsor = WalletSigner::from_private_key(
            "0x0000000000000000000000000000000000000000000000000000000000000001",
        )
        .expect("sponsor");
        let wallet = WalletSigner::from_private_key(
            "0x0000000000000000000000000000000000000000000000000000000000000002",
        )
        .expect("wallet");
        let authorization = Authorization {
            chain_id: U256::from(8453_u64),
            address: "0x0000000000000000000000000000000000000011"
                .parse()
                .expect("delegate"),
            nonce: 3,
        };
        let authorization_signature = wallet
            .sign_hash(&authorization.signature_hash())
            .expect("authorization signature");
        let signed_authorization = authorization.into_signed(authorization_signature);
        assert_eq!(
            signed_authorization.recover_authority().expect("authority"),
            wallet.identity().address
        );

        let transaction = Eip7702Transaction {
            chain_id: 8453,
            nonce: 9,
            max_priority_fee_per_gas: U256::from(1_000_000_u64),
            max_fee_per_gas: U256::from(2_000_000_u64),
            gas_limit: 500_000,
            target: "0x0000000000000000000000000000000000000011"
                .parse()
                .expect("dispatcher"),
            value: U256::from(10_u64),
            calldata: Bytes::from_static(&[0xff, 0x71, 0x29, 0x23]),
            authorization_list: vec![signed_authorization],
        };
        let signed = sign_eip7702_transaction(&transaction, &sponsor).expect("signed");

        assert_eq!(signed.raw()[0], EIP7702_TRANSACTION_TYPE);
        assert_eq!(signed.hash(), keccak256(signed.raw()));
        let debug = format!("{signed:?}");
        assert!(!debug.contains(&hex::encode(signed.raw())));
    }

    #[test]
    fn rejects_type_four_transaction_without_authorization() {
        let signer = WalletSigner::from_private_key(
            "0x0000000000000000000000000000000000000000000000000000000000000001",
        )
        .expect("signer");
        let transaction = Eip7702Transaction {
            chain_id: 8453,
            nonce: 0,
            max_priority_fee_per_gas: U256::ZERO,
            max_fee_per_gas: U256::from(1_u64),
            gas_limit: 21_000,
            target: Address::repeat_byte(0x11),
            value: U256::ZERO,
            calldata: Bytes::new(),
            authorization_list: Vec::new(),
        };

        assert!(matches!(
            sign_eip7702_transaction(&transaction, &signer),
            Err(TransactionError::EmptyAuthorizationList)
        ));
    }
}
