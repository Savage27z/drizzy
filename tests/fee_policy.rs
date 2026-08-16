use alloy_primitives::U256;
use opensea_mint::domain::{AutomaticFeePolicy, Eip1559Fees};

#[test]
fn automatic_policy_applies_fee_multiplier_and_replacement_bump() {
    let policy = AutomaticFeePolicy::new(12_500, 11_250).expect("policy");
    let estimate = Eip1559Fees {
        max_fee_per_gas: U256::from(100),
        max_priority_fee_per_gas: U256::from(4),
    };

    let initial = policy.initial(estimate).expect("initial fees");
    assert_eq!(initial.max_fee_per_gas, U256::from(125));
    assert_eq!(initial.max_priority_fee_per_gas, U256::from(5));
    assert_eq!(
        policy
            .replacement(initial)
            .expect("replacement")
            .max_fee_per_gas,
        U256::from(141)
    );
}
