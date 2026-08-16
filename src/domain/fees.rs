use alloy_primitives::U256;
use thiserror::Error;

const BASIS_POINTS: u32 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Eip1559Fees {
    pub max_fee_per_gas: U256,
    pub max_priority_fee_per_gas: U256,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AutomaticFeePolicy {
    multiplier_bps: u32,
    replacement_bump_bps: u32,
}

impl AutomaticFeePolicy {
    pub fn new(multiplier_bps: u32, replacement_bump_bps: u32) -> Result<Self, FeeError> {
        if multiplier_bps < BASIS_POINTS || replacement_bump_bps <= BASIS_POINTS {
            return Err(FeeError::InvalidMultiplier);
        }
        Ok(Self {
            multiplier_bps,
            replacement_bump_bps,
        })
    }

    pub fn initial(self, estimate: Eip1559Fees) -> Result<Eip1559Fees, FeeError> {
        multiply_fees(estimate, self.multiplier_bps)
    }

    pub fn replacement(self, pending: Eip1559Fees) -> Result<Eip1559Fees, FeeError> {
        multiply_fees(pending, self.replacement_bump_bps)
    }
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum FeeError {
    #[error("fee multipliers must not reduce fees and replacements must increase them")]
    InvalidMultiplier,
    #[error("fee calculation overflowed")]
    Overflow,
}

fn multiply_fees(fees: Eip1559Fees, basis_points: u32) -> Result<Eip1559Fees, FeeError> {
    Ok(Eip1559Fees {
        max_fee_per_gas: multiply_ceil(fees.max_fee_per_gas, basis_points)?,
        max_priority_fee_per_gas: multiply_ceil(fees.max_priority_fee_per_gas, basis_points)?,
    })
}

fn multiply_ceil(value: U256, basis_points: u32) -> Result<U256, FeeError> {
    let numerator = value
        .checked_mul(U256::from(basis_points))
        .and_then(|scaled| scaled.checked_add(U256::from(BASIS_POINTS - 1)))
        .ok_or(FeeError::Overflow)?;
    Ok(numerator / U256::from(BASIS_POINTS))
}
