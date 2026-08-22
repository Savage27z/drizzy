use crate::{
    chain::FeeEstimate,
    config::{FeeMode, FeesConfig},
    domain::{AutomaticFeePolicy, Eip1559Fees, FeeError},
};

pub(crate) fn initial_transaction_fees(
    config: FeesConfig,
    estimate: FeeEstimate,
) -> Result<Eip1559Fees, FeeError> {
    match config.mode {
        FeeMode::Automatic => {
            AutomaticFeePolicy::new(config.initial_multiplier_bps, config.replacement_bump_bps)?
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
            initial_multiplier_bps: 12_500,
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

        // At the default 11_250 bps bump — exactly the protocol's own
        // per-block base-fee growth cap — the buffer cap never kicks in, so
        // this only differs from a flat "multiply everything" scheme by
        // integer-rounding noise (161 vs. a flat-multiply's 159).
        let maximum = maximum_transaction_fees(config, 3, initial).expect("maximum fees");
        assert_eq!(maximum.max_fee_per_gas, U256::from(161_u64));
        assert_eq!(maximum.max_priority_fee_per_gas, U256::from(14_u64));
    }

    #[test]
    fn caps_max_fee_buffer_growth_when_replacement_bump_outpaces_base_fee() {
        // A user who wants an aggressive 50%-per-attempt tip bump to win a
        // hot mint's inclusion race (replacement_bump_bps: 15_000) still only
        // needs the max_fee buffer to grow at the protocol's actual base-fee
        // ceiling (12.5%/block) — not the same 50%. Confirm the tip escalates
        // fully while the reserved buffer grows far more slowly.
        let config = FeesConfig {
            mode: FeeMode::Automatic,
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
