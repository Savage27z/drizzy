use alloy_eip7702::{Authorization, SignedAuthorization};
use alloy_primitives::{Address, B256, Bytes, U256, aliases::U48, b256, keccak256};
use alloy_sol_types::{SolCall, SolValue, sol};
use thiserror::Error;

use crate::signing::{WalletSigner, WalletSignerError};

pub const MAX_SPONSORED_BATCH_SIZE: usize = 25;
pub const MAX_MINT_CALLDATA_SIZE: usize = 16_384;
pub const POST_MINT_GAS_RESERVE: u64 = 25_000;
pub const SPONSORED_WALLET_GAS_OVERHEAD: u64 = 250_000;
pub const EIP7702_DELEGATION_PREFIX: [u8; 3] = [0xef, 0x01, 0x00];
pub const AUDITED_EXECUTOR_RUNTIME_HASH: B256 =
    b256!("81a86fa2c51be4ed2e09e88256a792e20464184b657f49797d79c6eb90f63d60");
const OUTER_TRANSACTION_INTRINSIC_GAS: u64 = 21_000;
const AUTHORIZATION_INTRINSIC_GAS: u64 = 25_000;
const DISPATCHER_BASE_GAS_RESERVE: u64 = 100_000;
const PER_OPERATION_DISPATCH_GAS_RESERVE: u64 = 30_000;
const FINAL_BATCH_GAS_RESERVE: u64 = 50_000;
const EXECUTE_BATCH_FIXED_CALLDATA_BYTES: u64 = 100;
const MAX_ENCODED_OPERATION_BYTES: u64 = 16_832;

const DOMAIN_TYPE: &str =
    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)";
const OPERATION_TYPE: &str = "SponsoredMint(address sponsor,bytes32 batchId,uint256 index,address dispatcher,address wallet,address mintTarget,bytes32 mintCalldataHash,uint256 mintValue,uint256 expectedUnits,uint64 mintGasLimit,uint64 walletGasLimit,address nftContract,address recipient,uint48 deadline)";
const DOMAIN_NAME: &str = "OSNM-Z Sponsored Mint";
const DOMAIN_VERSION: &str = "2";
const MAX_UINT48: u64 = (1_u64 << 48) - 1;

#[must_use]
pub const fn sponsored_wallet_gas_limit(mint_gas_limit: u64) -> Option<u64> {
    mint_gas_limit.checked_add(SPONSORED_WALLET_GAS_OVERHEAD)
}

sol! {
    #[derive(Debug, PartialEq, Eq)]
    struct ContractMintOperation {
        address wallet;
        address mintTarget;
        address nftContract;
        address recipient;
        uint256 mintValue;
        uint256 expectedUnits;
        uint64 mintGasLimit;
        uint64 walletGasLimit;
        uint48 deadline;
        bytes mintCalldata;
        bytes32 signatureR;
        bytes32 signatureYParityAndS;
    }

    #[derive(Debug, PartialEq, Eq)]
    function executeBatch(bytes32 batchId, ContractMintOperation[] operations) external;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SponsoredMintOperation {
    pub wallet: Address,
    pub mint_target: Address,
    pub nft_contract: Address,
    pub recipient: Address,
    pub mint_value: U256,
    pub expected_units: U256,
    pub mint_gas_limit: u64,
    pub wallet_gas_limit: u64,
    pub deadline: u64,
    pub mint_calldata: Bytes,
    pub signature_r: B256,
    pub signature_y_parity_and_s: B256,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnsignedSponsoredMintOperation {
    pub wallet: Address,
    pub mint_target: Address,
    pub nft_contract: Address,
    pub recipient: Address,
    pub mint_value: U256,
    pub expected_units: U256,
    pub mint_gas_limit: u64,
    pub wallet_gas_limit: u64,
    pub deadline: u64,
    pub mint_calldata: Bytes,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SponsoredMintError {
    #[error("sponsored batches must contain between 1 and 25 operations")]
    InvalidBatchSize,
    #[error("chain ID must not be zero")]
    InvalidChainId,
    #[error("batch ID must not be zero")]
    InvalidBatchId,
    #[error("sponsor and dispatcher must not be zero addresses")]
    InvalidExecutionAddress,
    #[error("operation contains a zero address")]
    ZeroAddress,
    #[error("recipient must differ from the delegated wallet")]
    RecipientEqualsWallet,
    #[error("mint calldata must contain a selector and be at most 16384 bytes")]
    InvalidMintCalldata,
    #[error("expected mint units must be greater than zero")]
    InvalidExpectedUnits,
    #[error("wallet gas limit must cover mint gas plus the 25000 gas post-mint reserve")]
    InvalidGasLimits,
    #[error("mint target and NFT contract must differ from the wallet and dispatcher")]
    ExecutorTarget,
    #[error("operation deadline exceeds uint48")]
    InvalidDeadline,
    #[error("sponsored outer gas calculation overflowed")]
    GasOverflow,
    #[error("signature recovery did not produce the expected wallet")]
    SignatureMismatch,
    #[error(transparent)]
    Signing(#[from] WalletSignerError),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DelegationState {
    Clear,
    Expected,
    Unexpected(Address),
    OtherCode,
}

impl SponsoredMintOperation {
    #[must_use]
    pub fn unsigned(operation: UnsignedSponsoredMintOperation) -> Self {
        Self {
            wallet: operation.wallet,
            mint_target: operation.mint_target,
            nft_contract: operation.nft_contract,
            recipient: operation.recipient,
            mint_value: operation.mint_value,
            expected_units: operation.expected_units,
            mint_gas_limit: operation.mint_gas_limit,
            wallet_gas_limit: operation.wallet_gas_limit,
            deadline: operation.deadline,
            mint_calldata: operation.mint_calldata,
            signature_r: B256::ZERO,
            signature_y_parity_and_s: B256::ZERO,
        }
    }

    pub fn validate(&self, dispatcher: Address) -> Result<(), SponsoredMintError> {
        if self.wallet == Address::ZERO
            || self.mint_target == Address::ZERO
            || self.nft_contract == Address::ZERO
            || self.recipient == Address::ZERO
        {
            return Err(SponsoredMintError::ZeroAddress);
        }
        if self.recipient == self.wallet {
            return Err(SponsoredMintError::RecipientEqualsWallet);
        }
        if !(4..=MAX_MINT_CALLDATA_SIZE).contains(&self.mint_calldata.len()) {
            return Err(SponsoredMintError::InvalidMintCalldata);
        }
        if self.expected_units == U256::ZERO {
            return Err(SponsoredMintError::InvalidExpectedUnits);
        }
        let required_wallet_gas = self
            .mint_gas_limit
            .checked_add(POST_MINT_GAS_RESERVE)
            .ok_or(SponsoredMintError::InvalidGasLimits)?;
        if self.mint_gas_limit == 0 || self.wallet_gas_limit < required_wallet_gas {
            return Err(SponsoredMintError::InvalidGasLimits);
        }
        if self.mint_target == self.wallet
            || self.mint_target == dispatcher
            || self.nft_contract == self.wallet
            || self.nft_contract == dispatcher
        {
            return Err(SponsoredMintError::ExecutorTarget);
        }
        if self.deadline > MAX_UINT48 {
            return Err(SponsoredMintError::InvalidDeadline);
        }
        Ok(())
    }

    fn contract_value(&self) -> ContractMintOperation {
        ContractMintOperation {
            wallet: self.wallet,
            mintTarget: self.mint_target,
            nftContract: self.nft_contract,
            recipient: self.recipient,
            mintValue: self.mint_value,
            expectedUnits: self.expected_units,
            mintGasLimit: self.mint_gas_limit,
            walletGasLimit: self.wallet_gas_limit,
            deadline: U48::from(self.deadline),
            mintCalldata: self.mint_calldata.clone(),
            signatureR: self.signature_r,
            signatureYParityAndS: self.signature_y_parity_and_s,
        }
    }
}

pub fn operation_digest(
    chain_id: u64,
    dispatcher: Address,
    sponsor: Address,
    batch_id: B256,
    index: usize,
    operation: &SponsoredMintOperation,
) -> Result<B256, SponsoredMintError> {
    validate_batch_identity(chain_id, dispatcher, sponsor, batch_id)?;
    operation.validate(dispatcher)?;

    let domain_separator = keccak256(
        (
            keccak256(DOMAIN_TYPE),
            keccak256(DOMAIN_NAME),
            keccak256(DOMAIN_VERSION),
            U256::from(chain_id),
            operation.wallet,
        )
            .abi_encode(),
    );
    let struct_hash = keccak256(
        (
            keccak256(OPERATION_TYPE),
            sponsor,
            batch_id,
            U256::from(index),
            dispatcher,
            operation.wallet,
            operation.mint_target,
            keccak256(&operation.mint_calldata),
            operation.mint_value,
            operation.expected_units,
            U256::from(operation.mint_gas_limit),
            U256::from(operation.wallet_gas_limit),
            operation.nft_contract,
            operation.recipient,
            U256::from(operation.deadline),
        )
            .abi_encode(),
    );
    let mut eip712_message = [0_u8; 66];
    eip712_message[..2].copy_from_slice(&[0x19, 0x01]);
    eip712_message[2..34].copy_from_slice(domain_separator.as_slice());
    eip712_message[34..].copy_from_slice(struct_hash.as_slice());
    Ok(keccak256(eip712_message))
}

pub fn sign_operation(
    chain_id: u64,
    dispatcher: Address,
    sponsor: Address,
    batch_id: B256,
    index: usize,
    operation: &mut SponsoredMintOperation,
    signer: &WalletSigner,
) -> Result<(), SponsoredMintError> {
    if signer.identity().address != operation.wallet {
        return Err(SponsoredMintError::SignatureMismatch);
    }
    let digest = operation_digest(chain_id, dispatcher, sponsor, batch_id, index, operation)?;
    let signature = signer.sign_hash(&digest)?;
    operation.signature_r = B256::from(signature.r().to_be_bytes::<32>());

    let y_parity: U256 = U256::from(u8::from(signature.v())) << 255;
    let compact_s: U256 = signature.s() | y_parity;
    operation.signature_y_parity_and_s = B256::from(compact_s.to_be_bytes::<32>());
    Ok(())
}

pub fn sign_delegation(
    chain_id: u64,
    delegate: Address,
    authorization_nonce: u64,
    signer: &WalletSigner,
) -> Result<SignedAuthorization, SponsoredMintError> {
    if chain_id == 0 {
        return Err(SponsoredMintError::InvalidChainId);
    }
    let authorization = Authorization {
        chain_id: U256::from(chain_id),
        address: delegate,
        nonce: authorization_nonce,
    };
    let signature = signer.sign_hash(&authorization.signature_hash())?;
    let signed_authorization = authorization.into_signed(signature);
    if signed_authorization.recover_authority().ok() != Some(signer.identity().address) {
        return Err(SponsoredMintError::SignatureMismatch);
    }
    Ok(signed_authorization)
}

#[must_use]
pub fn delegation_designator(delegate: Address) -> Bytes {
    let mut code = Vec::with_capacity(EIP7702_DELEGATION_PREFIX.len() + Address::len_bytes());
    code.extend_from_slice(&EIP7702_DELEGATION_PREFIX);
    code.extend_from_slice(delegate.as_slice());
    Bytes::from(code)
}

#[must_use]
pub fn classify_delegation(code: &[u8], expected_delegate: Address) -> DelegationState {
    if code.is_empty() {
        return DelegationState::Clear;
    }
    if code.len() == EIP7702_DELEGATION_PREFIX.len() + Address::len_bytes()
        && code.starts_with(&EIP7702_DELEGATION_PREFIX)
    {
        let delegate = Address::from_slice(&code[EIP7702_DELEGATION_PREFIX.len()..]);
        if delegate == expected_delegate {
            DelegationState::Expected
        } else {
            DelegationState::Unexpected(delegate)
        }
    } else {
        DelegationState::OtherCode
    }
}

pub fn encode_execute_batch(
    chain_id: u64,
    dispatcher: Address,
    sponsor: Address,
    batch_id: B256,
    operations: &[SponsoredMintOperation],
) -> Result<Bytes, SponsoredMintError> {
    validate_batch_identity(chain_id, dispatcher, sponsor, batch_id)?;
    if operations.is_empty() || operations.len() > MAX_SPONSORED_BATCH_SIZE {
        return Err(SponsoredMintError::InvalidBatchSize);
    }

    let mut contract_operations = Vec::with_capacity(operations.len());
    for operation in operations {
        operation.validate(dispatcher)?;
        contract_operations.push(operation.contract_value());
    }
    let calldata = executeBatchCall {
        batchId: batch_id,
        operations: contract_operations,
    }
    .abi_encode();
    Ok(Bytes::from(calldata))
}

pub fn sponsored_outer_gas_limit(
    calldata: &[u8],
    operations: &[SponsoredMintOperation],
) -> Result<u64, SponsoredMintError> {
    if operations.is_empty() || operations.len() > MAX_SPONSORED_BATCH_SIZE {
        return Err(SponsoredMintError::InvalidBatchSize);
    }
    let calldata_gas = calldata.iter().try_fold(0_u64, |total, byte| {
        total.checked_add(if *byte == 0 { 4 } else { 16 })
    });
    sponsored_outer_gas_limit_for_calldata_gas(
        calldata_gas.ok_or(SponsoredMintError::GasOverflow)?,
        operations,
    )
}

pub fn sponsored_outer_gas_limit_upper_bound(
    calldata_length: usize,
    operations: &[SponsoredMintOperation],
) -> Result<u64, SponsoredMintError> {
    let calldata_gas = u64::try_from(calldata_length)
        .ok()
        .and_then(|length| length.checked_mul(16))
        .ok_or(SponsoredMintError::GasOverflow)?;
    sponsored_outer_gas_limit_for_calldata_gas(calldata_gas, operations)
}

pub fn sponsored_setup_gas_limit(
    wallet_gas_limit: u64,
    operation_count: usize,
) -> Result<u64, SponsoredMintError> {
    if operation_count == 0 || operation_count > MAX_SPONSORED_BATCH_SIZE {
        return Err(SponsoredMintError::InvalidBatchSize);
    }
    let count = u64::try_from(operation_count).map_err(|_| SponsoredMintError::GasOverflow)?;
    let calldata_length = count
        .checked_mul(MAX_ENCODED_OPERATION_BYTES)
        .and_then(|value| value.checked_add(EXECUTE_BATCH_FIXED_CALLDATA_BYTES))
        .ok_or(SponsoredMintError::GasOverflow)?;
    let calldata_gas = calldata_length
        .checked_mul(16)
        .ok_or(SponsoredMintError::GasOverflow)?;
    let operations = std::iter::repeat_n(wallet_gas_limit, operation_count);
    sponsored_outer_gas_limit_for_wallet_limits(calldata_gas, operations, operation_count)
}

fn sponsored_outer_gas_limit_for_calldata_gas(
    calldata_gas: u64,
    operations: &[SponsoredMintOperation],
) -> Result<u64, SponsoredMintError> {
    if operations.is_empty() || operations.len() > MAX_SPONSORED_BATCH_SIZE {
        return Err(SponsoredMintError::InvalidBatchSize);
    }
    sponsored_outer_gas_limit_for_wallet_limits(
        calldata_gas,
        operations
            .iter()
            .map(|operation| operation.wallet_gas_limit),
        operations.len(),
    )
}

fn sponsored_outer_gas_limit_for_wallet_limits(
    calldata_gas: u64,
    wallet_gas_limits: impl IntoIterator<Item = u64>,
    operation_count: usize,
) -> Result<u64, SponsoredMintError> {
    let authorization_gas = u64::try_from(operation_count)
        .ok()
        .and_then(|count| count.checked_mul(AUTHORIZATION_INTRINSIC_GAS));
    let mut gas_limit = OUTER_TRANSACTION_INTRINSIC_GAS
        .checked_add(calldata_gas)
        .and_then(|value| value.checked_add(authorization_gas?))
        .and_then(|value| value.checked_add(DISPATCHER_BASE_GAS_RESERVE))
        .and_then(|value| value.checked_add(FINAL_BATCH_GAS_RESERVE))
        .ok_or(SponsoredMintError::GasOverflow)?;
    for wallet_gas_limit in wallet_gas_limits {
        let eip150_buffer = wallet_gas_limit
            .checked_add(62)
            .ok_or(SponsoredMintError::GasOverflow)?
            / 63;
        gas_limit = gas_limit
            .checked_add(wallet_gas_limit)
            .and_then(|value| value.checked_add(eip150_buffer))
            .and_then(|value| value.checked_add(PER_OPERATION_DISPATCH_GAS_RESERVE))
            .ok_or(SponsoredMintError::GasOverflow)?;
    }
    Ok(gas_limit)
}

fn validate_batch_identity(
    chain_id: u64,
    dispatcher: Address,
    sponsor: Address,
    batch_id: B256,
) -> Result<(), SponsoredMintError> {
    if chain_id == 0 {
        return Err(SponsoredMintError::InvalidChainId);
    }
    if dispatcher == Address::ZERO || sponsor == Address::ZERO {
        return Err(SponsoredMintError::InvalidExecutionAddress);
    }
    if batch_id == B256::ZERO {
        return Err(SponsoredMintError::InvalidBatchId);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_sol_types::SolCall;

    const PRIVATE_KEY: &str = "0x0000000000000000000000000000000000000000000000000000000000000001";

    fn addresses() -> (Address, Address, Address, Address) {
        (
            "0x0000000000000000000000000000000000000011"
                .parse()
                .expect("dispatcher"),
            "0x0000000000000000000000000000000000000022"
                .parse()
                .expect("sponsor"),
            "0x0000000000000000000000000000000000000033"
                .parse()
                .expect("mint target"),
            "0x0000000000000000000000000000000000000044"
                .parse()
                .expect("NFT"),
        )
    }

    fn operation(wallet: Address) -> SponsoredMintOperation {
        let (_, _, mint_target, nft_contract) = addresses();
        SponsoredMintOperation::unsigned(UnsignedSponsoredMintOperation {
            wallet,
            mint_target,
            nft_contract,
            recipient: "0x0000000000000000000000000000000000000055"
                .parse()
                .expect("recipient"),
            mint_value: U256::from(10_u64),
            expected_units: U256::from(2_u64),
            mint_gas_limit: 100_000,
            wallet_gas_limit: 125_000,
            deadline: 2_000_000_000,
            mint_calldata: Bytes::from_static(&[0x12, 0x34, 0x56, 0x78]),
        })
    }

    #[test]
    fn signs_operation_and_binds_sponsor_batch_index_and_dispatcher() {
        let signer = WalletSigner::from_private_key(PRIVATE_KEY).expect("signer");
        let (dispatcher, sponsor, _, _) = addresses();
        let batch_id = B256::repeat_byte(0x77);
        let mut operation = operation(signer.identity().address);
        let unsigned_digest =
            operation_digest(8453, dispatcher, sponsor, batch_id, 0, &operation).expect("digest");
        assert_eq!(
            unsigned_digest,
            "0xd2c1e6ec11ca71ea4d734a0b4af5745555e4f1711ae503cafab3aba1697cee82"
                .parse::<B256>()
                .expect("independent Solidity ABI digest fixture")
        );

        sign_operation(
            8453,
            dispatcher,
            sponsor,
            batch_id,
            0,
            &mut operation,
            &signer,
        )
        .expect("signed");
        assert_ne!(operation.signature_r, B256::ZERO);
        assert_ne!(operation.signature_y_parity_and_s, B256::ZERO);
        assert_eq!(
            unsigned_digest,
            operation_digest(8453, dispatcher, sponsor, batch_id, 0, &operation)
                .expect("digest ignores signature")
        );
        assert_ne!(
            unsigned_digest,
            operation_digest(8453, dispatcher, sponsor, batch_id, 1, &operation)
                .expect("changed index")
        );
    }

    #[test]
    fn encodes_exact_wallet_funded_execute_batch_shape() {
        let signer = WalletSigner::from_private_key(PRIVATE_KEY).expect("signer");
        let (dispatcher, sponsor, _, _) = addresses();
        let batch_id = B256::repeat_byte(0x77);
        let operation = operation(signer.identity().address);
        let calldata = encode_execute_batch(
            8453,
            dispatcher,
            sponsor,
            batch_id,
            std::slice::from_ref(&operation),
        )
        .expect("batch");

        assert_eq!(&calldata[..4], executeBatchCall::SELECTOR);
        let decoded = executeBatchCall::abi_decode(&calldata).expect("decode");
        assert_eq!(decoded.batchId, batch_id);
        assert_eq!(decoded.operations, vec![operation.contract_value()]);
        let gas_limit = sponsored_outer_gas_limit(&calldata, &[operation]).expect("outer gas");
        assert!(gas_limit > 125_000);
    }

    #[test]
    fn final_signed_calldata_reprices_the_outer_gas_budget() {
        let signer = WalletSigner::from_private_key(PRIVATE_KEY).expect("signer");
        let (dispatcher, sponsor, _, _) = addresses();
        let batch_id = B256::repeat_byte(0x77);
        let mut operation = operation(signer.identity().address);
        operation.deadline = 0;

        let provisional_calldata = encode_execute_batch(
            8453,
            dispatcher,
            sponsor,
            batch_id,
            std::slice::from_ref(&operation),
        )
        .expect("provisional batch");
        let provisional_gas =
            sponsored_outer_gas_limit(&provisional_calldata, std::slice::from_ref(&operation))
                .expect("provisional gas");

        operation.deadline = 2_000_000_000;
        sign_operation(
            8453,
            dispatcher,
            sponsor,
            batch_id,
            0,
            &mut operation,
            &signer,
        )
        .expect("signed operation");
        let final_calldata = encode_execute_batch(
            8453,
            dispatcher,
            sponsor,
            batch_id,
            std::slice::from_ref(&operation),
        )
        .expect("final batch");
        let final_gas =
            sponsored_outer_gas_limit(&final_calldata, std::slice::from_ref(&operation))
                .expect("final gas");
        let upper_bound = sponsored_outer_gas_limit_upper_bound(
            provisional_calldata.len(),
            std::slice::from_ref(&operation),
        )
        .expect("upper bound");

        assert!(final_gas > provisional_gas);
        assert!(upper_bound >= final_gas);
    }

    #[test]
    fn setup_gas_limit_bounds_maximum_allowed_operation_calldata() {
        let signer = WalletSigner::from_private_key(PRIVATE_KEY).expect("signer");
        let (dispatcher, sponsor, _, _) = addresses();
        let batch_id = B256::repeat_byte(0x77);
        let mut operation = operation(signer.identity().address);
        operation.mint_calldata = Bytes::from(vec![0xff; MAX_MINT_CALLDATA_SIZE]);
        let calldata = encode_execute_batch(
            8453,
            dispatcher,
            sponsor,
            batch_id,
            std::slice::from_ref(&operation),
        )
        .expect("batch");
        let actual_upper =
            sponsored_outer_gas_limit_upper_bound(calldata.len(), std::slice::from_ref(&operation))
                .expect("actual upper bound");
        let setup_upper =
            sponsored_setup_gas_limit(operation.wallet_gas_limit, 1).expect("setup upper bound");

        assert!(setup_upper >= actual_upper);
    }

    #[test]
    fn delegation_signature_recovers_for_delegation_and_revocation() {
        let signer = WalletSigner::from_private_key(PRIVATE_KEY).expect("signer");
        let (dispatcher, _, _, _) = addresses();
        let delegation = sign_delegation(8453, dispatcher, 7, &signer).expect("delegation");
        let revocation = sign_delegation(8453, Address::ZERO, 8, &signer).expect("revocation");

        assert_eq!(
            delegation.recover_authority().expect("authority"),
            signer.identity().address
        );
        assert_eq!(delegation.address, dispatcher);
        assert_eq!(revocation.address, Address::ZERO);
    }

    #[test]
    fn classifies_only_exact_eip7702_designators() {
        let (dispatcher, sponsor, _, _) = addresses();
        let expected = delegation_designator(dispatcher);
        let other = delegation_designator(sponsor);

        assert_eq!(classify_delegation(&[], dispatcher), DelegationState::Clear);
        assert_eq!(
            classify_delegation(&expected, dispatcher),
            DelegationState::Expected
        );
        assert_eq!(
            classify_delegation(&other, dispatcher),
            DelegationState::Unexpected(sponsor)
        );
        assert_eq!(
            classify_delegation(&[0xef, 0x01, 0x00], dispatcher),
            DelegationState::OtherCode
        );
    }

    #[test]
    fn exposes_one_chain_independent_audited_executor_runtime() {
        assert_ne!(AUDITED_EXECUTOR_RUNTIME_HASH, B256::ZERO);
    }

    #[test]
    fn derives_the_wallet_envelope_from_each_wallet_mint_limit() {
        assert_eq!(sponsored_wallet_gas_limit(300_000), Some(550_000));
        assert_eq!(sponsored_wallet_gas_limit(u64::MAX), None);
    }

    #[test]
    fn rejects_contract_invalid_shapes_before_signing() {
        let signer = WalletSigner::from_private_key(PRIVATE_KEY).expect("signer");
        let (dispatcher, sponsor, _, _) = addresses();
        let batch_id = B256::repeat_byte(0x77);
        let mut invalid = operation(signer.identity().address);
        invalid.wallet_gas_limit = invalid.mint_gas_limit + POST_MINT_GAS_RESERVE - 1;

        assert_eq!(
            invalid.validate(dispatcher),
            Err(SponsoredMintError::InvalidGasLimits)
        );
        assert_eq!(
            encode_execute_batch(8453, dispatcher, sponsor, batch_id, &[]),
            Err(SponsoredMintError::InvalidBatchSize)
        );
    }
}
