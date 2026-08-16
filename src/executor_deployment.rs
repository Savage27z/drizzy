use alloy_primitives::{Address, B256, Bytes, U256, address, b256, hex, keccak256};
use thiserror::Error;

const CREATION_CODE_HEX: &str = include_str!("../contracts/SponsoredMintExecutor.creation.hex");
const EXECUTOR_SALT_DOMAIN: &[u8] = b"opensea-mint/SponsoredMintExecutor/v1";
const DEPLOYMENT_GAS_BUFFER_BPS: u64 = 12_000;
const BASIS_POINTS: u64 = 10_000;

pub const DETERMINISTIC_FACTORY_ADDRESS: Address =
    address!("4e59b44847b379578588920cA78FbF26c0B4956C");
pub const DETERMINISTIC_FACTORY_RUNTIME: [u8; 69] = hex!(
    "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe03601600081602082378035828234f58015156039578182fd5b8082525050506014600cf3"
);
pub const AUDITED_EXECUTOR_CREATION_HASH: B256 =
    b256!("6bcc55c2a44c46d8a3b24f71cef400d0fc38b611f6ec38acaaee24d71470bf4f");

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum ExecutorDeploymentError {
    #[error("the embedded executor creation artifact is malformed")]
    InvalidCreationArtifact,
    #[error("the embedded executor creation artifact does not match the audited build")]
    CreationArtifactMismatch,
    #[error("executor deployment gas calculation overflowed")]
    GasOverflow,
    #[error("executor deployment cost calculation overflowed")]
    CostOverflow,
}

pub fn audited_executor_creation_code() -> Result<Bytes, ExecutorDeploymentError> {
    let digits = CREATION_CODE_HEX
        .trim()
        .strip_prefix("0x")
        .filter(|digits| !digits.is_empty() && digits.len() % 2 == 0)
        .ok_or(ExecutorDeploymentError::InvalidCreationArtifact)?;
    let code = Bytes::from(
        hex::decode(digits).map_err(|_| ExecutorDeploymentError::InvalidCreationArtifact)?,
    );
    if keccak256(&code) != AUDITED_EXECUTOR_CREATION_HASH {
        return Err(ExecutorDeploymentError::CreationArtifactMismatch);
    }
    Ok(code)
}

#[must_use]
pub fn deterministic_executor_salt(sponsor: Address) -> B256 {
    let mut material = Vec::with_capacity(EXECUTOR_SALT_DOMAIN.len() + sponsor.len());
    material.extend_from_slice(EXECUTOR_SALT_DOMAIN);
    material.extend_from_slice(sponsor.as_slice());
    keccak256(material)
}

#[must_use]
pub fn predicted_executor_address(sponsor: Address) -> Address {
    DETERMINISTIC_FACTORY_ADDRESS.create2(
        deterministic_executor_salt(sponsor),
        AUDITED_EXECUTOR_CREATION_HASH,
    )
}

#[must_use]
pub fn deterministic_deployment_calldata(sponsor: Address, creation_code: &[u8]) -> Bytes {
    let salt = deterministic_executor_salt(sponsor);
    let mut calldata = Vec::with_capacity(32 + creation_code.len());
    calldata.extend_from_slice(salt.as_slice());
    calldata.extend_from_slice(creation_code);
    Bytes::from(calldata)
}

pub fn buffered_deployment_gas(estimate: u64) -> Result<u64, ExecutorDeploymentError> {
    if estimate == 0 {
        return Err(ExecutorDeploymentError::GasOverflow);
    }
    estimate
        .checked_mul(DEPLOYMENT_GAS_BUFFER_BPS)
        .and_then(|scaled| scaled.checked_add(BASIS_POINTS - 1))
        .map(|scaled| scaled / BASIS_POINTS)
        .ok_or(ExecutorDeploymentError::GasOverflow)
}

pub fn maximum_deployment_cost(
    gas_limit: u64,
    max_fee_per_gas: U256,
) -> Result<U256, ExecutorDeploymentError> {
    U256::from(gas_limit)
        .checked_mul(max_fee_per_gas)
        .ok_or(ExecutorDeploymentError::CostOverflow)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_creation_artifact_matches_the_audited_build() {
        let creation = audited_executor_creation_code().expect("creation code");
        assert_eq!(creation.len(), 9_449);
        assert_eq!(keccak256(&creation), AUDITED_EXECUTOR_CREATION_HASH);
    }

    #[test]
    fn predicts_per_sponsor_cross_chain_address_and_encodes_factory_call() {
        let sponsor: Address = "0xb20a608c624ca5003905aa834de7156c68b2e1d0"
            .parse()
            .expect("sponsor");
        let other_sponsor = Address::repeat_byte(0x22);
        let creation = audited_executor_creation_code().expect("creation code");
        let address = predicted_executor_address(sponsor);

        assert_eq!(
            address,
            "0x384791Def6b0f850A275e00113Fa103B9C5B25AF"
                .parse::<Address>()
                .expect("independently calculated address")
        );
        assert_ne!(address, predicted_executor_address(other_sponsor));
        let calldata = deterministic_deployment_calldata(sponsor, &creation);
        assert_eq!(
            &calldata[..32],
            deterministic_executor_salt(sponsor).as_slice()
        );
        assert_eq!(&calldata[32..], creation.as_ref());
    }

    #[test]
    fn verifies_the_canonical_factory_and_buffers_estimated_gas() {
        assert_eq!(DETERMINISTIC_FACTORY_RUNTIME.len(), 69);
        assert_eq!(buffered_deployment_gas(100_001).expect("gas"), 120_002);
        assert!(buffered_deployment_gas(0).is_err());
        assert!(buffered_deployment_gas(u64::MAX).is_err());
    }

    #[test]
    fn calculates_checked_maximum_cost() {
        assert_eq!(
            maximum_deployment_cost(200_000, U256::from(2_u64)).expect("cost"),
            U256::from(400_000_u64)
        );
        assert!(maximum_deployment_cost(u64::MAX, U256::MAX).is_err());
    }
}
