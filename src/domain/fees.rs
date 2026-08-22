use alloy_primitives::U256;
use thiserror::Error;

const BASIS_POINTS: u32 = 10_000;
/// The protocol caps how fast the base fee itself can rise: at most 12.5%
/// (1/8) per block (EIP-1559). `max_fee_per_gas` only needs headroom above
/// `max_priority_fee_per_gas` to outrun *that* growth — it is a ceiling that
/// is never actually paid past `base_fee + priority_fee`, so escalating it at
/// the same (often much higher, user-configured) rate used to win the tip
/// race just inflates the wallet balance a wallet must reserve, for no real
/// benefit. Capping the buffer's growth here keeps every replacement fully
/// safe (it can never fall behind the real base fee) while avoiding that
/// waste whenever `replacement_bump_bps` is configured more aggressively
/// than the protocol's own base-fee ceiling requires.
const MAX_BASE_FEE_GROWTH_BPS: u32 = 11_250;

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
        // The tip (max_priority_fee_per_gas) is what actually has to win the
        // inclusion race, so it escalates at the full configured rate.
        let max_priority_fee_per_gas =
            multiply_ceil(pending.max_priority_fee_per_gas, self.replacement_bump_bps)?;
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
