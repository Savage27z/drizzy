use crate::{
    chain::FeeEstimate,
    config::{FeeMode, FeesConfig},
    domain::{AutomaticFeePolicy, Eip1559Fees, FeeError},
};

const AUTOMATIC_FEE_MULTIPLIER_BPS: u32 = 12_500;

pub(crate) fn initial_transaction_fees(
    config: FeesConfig,
    estimate: FeeEstimate,
) -> Result<Eip1559Fees, FeeError> {
    match config.mode {
        FeeMode::Automatic => {
            AutomaticFeePolicy::new(AUTOMATIC_FEE_MULTIPLIER_BPS, config.replacement_bump_bps)?
                .initial(Eip1559Fees {
                    max_fee_per_gas: estimate.max_fee_per_gas,
                    max_priority_fee_per_gas: estimate.max_priority_fee_per_gas,
                })
        }
        FeeMode::Manual {
            max_fee_per_gas,
            max_priority_fee_per_gas,
        } => Ok(Eip1559Fees {
            max_fee_per_gas,
            max_priority_fee_per_gas,
        }),
    }
}

pub(crate) fn maximum_transaction_fees(
    config: FeesConfig,
    maximum_attempts: u32,
    mut fees: Eip1559Fees,
) -> Result<Eip1559Fees, FeeError> {
    let replacement = AutomaticFeePolicy::new(10_000, config.replacement_bump_bps)?;
    for _ in 1..maximum_attempts {
        fees = replacement.replacement(fees)?;
    }
    Ok(fees)
}

#[cfg(test)]
mod tests {
    use alloy_primitives::U256;

    use super::*;

    #[test]
    fn applies_one_shared_initial_and_replacement_fee_policy() {
        let config = FeesConfig {
            mode: FeeMode::Automatic,
            replacement_bump_bps: 11_250,
        };
        let initial = initial_transaction_fees(
            config,
            FeeEstimate {
                max_fee_per_gas: U256::from(100_u64),
                max_priority_fee_per_gas: U256::from(8_u64),
            },
        )
        .expect("initial fees");
        assert_eq!(initial.max_fee_per_gas, U256::from(125_u64));
        assert_eq!(initial.max_priority_fee_per_gas, U256::from(10_u64));

        let maximum = maximum_transaction_fees(config, 3, initial).expect("maximum fees");
        assert_eq!(maximum.max_fee_per_gas, U256::from(159_u64));
        assert_eq!(maximum.max_priority_fee_per_gas, U256::from(14_u64));
    }

    #[test]
    fn manual_fees_ignore_rpc_estimates() {
        let config = FeesConfig {
            mode: FeeMode::Manual {
                max_fee_per_gas: U256::from(50_u64),
                max_priority_fee_per_gas: U256::from(5_u64),
            },
            replacement_bump_bps: 11_250,
        };
        let fees = initial_transaction_fees(
            config,
            FeeEstimate {
                max_fee_per_gas: U256::MAX,
                max_priority_fee_per_gas: U256::MAX,
            },
        )
        .expect("manual fees");
        assert_eq!(fees.max_fee_per_gas, U256::from(50_u64));
        assert_eq!(fees.max_priority_fee_per_gas, U256::from(5_u64));
    }
}
