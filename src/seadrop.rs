//! On-chain `SeaDrop` public-mint plan builder.
//!
//! A public stage is unsigned: `SeaDrop.mintPublic()` takes only the drop's own
//! parameters, so the whole transaction can be assembled from on-chain reads.
//! That removes `OpenSea`'s access token, its expiry, its rate limits, and — the
//! part that actually matters for first-come-first-served — the ~1s API
//! round-trip from the critical path, because every transaction can be signed
//! before the stage even opens.
//!
//! Ported from the `nft-public-mint` TypeScript sniper
//! (`src/seadrop-public.ts`), merged into the Rust CLI.

use alloy_primitives::{Address, Bytes, U256, keccak256};
use alloy_sol_types::SolValue;
use thiserror::Error;

use crate::chain::{ChainError, ChainGateway};
use crate::config::ChainConfig;

/// `OpenSea`'s canonical `SeaDrop` singleton used by their hosted drops.
const SEADROP_ADDRESS: &str = "0x00005ea00ac477b1030ce78506496e8c2de24bf5";

/// `OpenSea`'s standard fee collector — the usual allowed recipient on their
/// drops. Only used when a drop leaves the recipient list empty and
/// unrestricted, since `SeaDrop` rejects the zero address outright.
const OPENSEA_FEE_RECIPIENT: &str = "0x0000a26b00c1f0df003000390027140000faa719";

const GET_PUBLIC_DROP: &str = "getPublicDrop(address)";
const GET_ALLOWED_FEE_RECIPIENTS: &str = "getAllowedFeeRecipients(address)";
const MINT_PUBLIC: &str = "mintPublic(address,address,address,uint256)";

#[derive(Debug, Error)]
pub enum SeadropError {
    #[error("SeaDrop on-chain read failed: {0}")]
    Chain(#[from] ChainError),
    #[error("SeaDrop returned malformed public-drop data")]
    MalformedPublicDrop,
    #[error("SeaDrop returned malformed fee-recipient data")]
    MalformedFeeRecipients,
}

/// The `getPublicDrop` mapping entry for one NFT contract.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicDrop {
    pub mint_price: U256,
    pub start_time: u64,
    pub end_time: u64,
    pub max_total_mintable_by_wallet: u16,
    pub fee_bps: u16,
    pub restrict_fee_recipients: bool,
}

/// Everything needed to sign and dispatch a public mint for one wallet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalMintPlan {
    /// Always the `SeaDrop` singleton.
    pub to: Address,
    /// Calldata for `mintPublic` — identical for every wallet when quantities
    /// match, because `minterIfNotPayer` is the zero address ("credit caller").
    pub data: Bytes,
    /// `mintPrice × quantity`, exactly what `SeaDrop` expects.
    pub value: U256,
    pub drop: PublicDrop,
    pub fee_recipient: Address,
}

fn seadrop_address() -> Address {
    SEADROP_ADDRESS.parse().expect("static seadrop address")
}

fn opensea_fee_recipient() -> Address {
    OPENSEA_FEE_RECIPIENT
        .parse()
        .expect("static fee recipient address")
}

fn selector(signature: &str) -> [u8; 4] {
    keccak256(signature.as_bytes())[..4]
        .try_into()
        .expect("keccak256 output is at least 4 bytes")
}

fn encode_call(signature: &str, args: &[u8]) -> Bytes {
    let mut calldata = Vec::with_capacity(4 + args.len());
    calldata.extend_from_slice(&selector(signature));
    calldata.extend_from_slice(args);
    Bytes::from(calldata)
}

/// `mintPublic(nftContract, feeRecipient, address(0), quantity)` — the zero
/// `minterIfNotPayer` credits the caller, keeping calldata identical across
/// wallets.
#[must_use]
pub fn encode_mint_public(nft_contract: Address, fee_recipient: Address, quantity: u64) -> Bytes {
    let args = (
        nft_contract,
        fee_recipient,
        Address::ZERO,
        U256::from(quantity),
    )
        .abi_encode();
    encode_call(MINT_PUBLIC, &args)
}

/// Read the public drop for `nft_contract`. Returns `None` when the contract
/// has no public drop on the `SeaDrop` singleton — either it is not a `SeaDrop`
/// collection at all, or it uses a newer variant that keeps drop config on the
/// token contract itself.
///
/// # Panics
///
/// Panics only if the `SeaDrop` singleton or the drop tuple decodes to an
/// impossible shape (guarded by a length check before any slicing).
pub async fn fetch_public_drop(
    gateway: &ChainGateway,
    config: &ChainConfig,
    rpc_index: usize,
    nft_contract: Address,
) -> Result<Option<PublicDrop>, SeadropError> {
    let args = nft_contract.abi_encode();
    let result = gateway
        .call_contract(
            config,
            rpc_index,
            seadrop_address(),
            &encode_call(GET_PUBLIC_DROP, &args),
        )
        .await?;

    let words = result.as_ref();
    if words.len() < 6 * 32 {
        return Ok(None);
    }
    let mint_price = U256::from_be_slice(&words[0..32]);
    // uint48 is right-aligned in its 32-byte word: value occupies the last 6
    // bytes, so reading the last 8 bytes as a u64 gives 2 zero + 6 value.
    let start_time = u64::from_be_bytes(words[56..64].try_into().expect("word1 tail is 8 bytes"));
    let end_time = u64::from_be_bytes(words[88..96].try_into().expect("word2 tail is 8 bytes"));
    let max_total_mintable_by_wallet =
        u16::from_be_bytes(words[126..128].try_into().expect("word3 tail is 2 bytes"));
    let fee_bps = u16::from_be_bytes(words[158..160].try_into().expect("word4 tail is 2 bytes"));
    let restrict_fee_recipients = words[191] != 0;

    let drop = PublicDrop {
        mint_price,
        start_time,
        end_time,
        max_total_mintable_by_wallet,
        fee_bps,
        restrict_fee_recipients,
    };
    // An unset mapping entry decodes to all zeros rather than reverting.
    if drop.start_time == 0 && drop.end_time == 0 && drop.max_total_mintable_by_wallet == 0 {
        return Ok(None);
    }
    Ok(Some(drop))
}

/// `SeaDrop` reverts on a zero fee recipient, and on a disallowed one when the
/// drop restricts them — so this has to come from the chain, not a guess.
pub async fn resolve_fee_recipient(
    gateway: &ChainGateway,
    config: &ChainConfig,
    rpc_index: usize,
    nft_contract: Address,
    restricted: bool,
) -> Result<Option<(Address, &'static str)>, SeadropError> {
    let args = nft_contract.abi_encode();
    let result = gateway
        .call_contract(
            config,
            rpc_index,
            seadrop_address(),
            &encode_call(GET_ALLOWED_FEE_RECIPIENTS, &args),
        )
        .await?;

    let allowed: Vec<Address> = match Vec::<Address>::abi_decode(result.as_ref()) {
        Ok(allowed) => allowed,
        Err(_) => return Err(SeadropError::MalformedFeeRecipients),
    };

    if let Some(first) = allowed.first() {
        return Ok(Some((*first, "allowed fee recipient on-chain")));
    }
    if restricted {
        // Nothing allowed and the drop enforces the list — a public mint cannot
        // be constructed at all, locally or otherwise.
        return Ok(None);
    }
    Ok(Some((
        opensea_fee_recipient(),
        "OpenSea default (drop does not restrict)",
    )))
}

/// Build the full local mint plan for `nft_contract` × `quantity`, or `None`
/// when no public stage exists.
pub async fn build_local_mint_plan(
    gateway: &ChainGateway,
    config: &ChainConfig,
    rpc_index: usize,
    nft_contract: Address,
    quantity: u64,
) -> Result<Option<LocalMintPlan>, SeadropError> {
    let Some(drop) = fetch_public_drop(gateway, config, rpc_index, nft_contract).await? else {
        return Ok(None);
    };
    let Some((fee_recipient, _source)) = resolve_fee_recipient(
        gateway,
        config,
        rpc_index,
        nft_contract,
        drop.restrict_fee_recipients,
    )
    .await?
    else {
        return Ok(None);
    };

    Ok(Some(LocalMintPlan {
        to: seadrop_address(),
        data: encode_mint_public(nft_contract, fee_recipient, quantity),
        value: drop.mint_price * U256::from(quantity),
        drop,
        fee_recipient,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    // 6-word ABI tuple from getPublicDrop:
    // (uint80 mintPrice, uint48 startTime, uint48 endTime, uint16 maxTotal,
    //  uint16 feeBps, bool restrictFeeRecipients)
    fn drop_payload(
        mint_price: u128,
        start_time: u64,
        end_time: u64,
        max_total: u16,
        fee_bps: u16,
        restrict: bool,
    ) -> Bytes {
        let mut words = Vec::with_capacity(6 * 32);
        for (value, width) in [
            (mint_price, 80usize),
            (start_time as u128, 48),
            (end_time as u128, 48),
            (max_total as u128, 16),
            (fee_bps as u128, 16),
            (restrict as u128, 8),
        ] {
            let mut word = vec![0u8; 32];
            let value_bytes = value.to_be_bytes();
            let start = 32 - width / 8;
            word[start..].copy_from_slice(&value_bytes[value_bytes.len() - width / 8..]);
            words.extend_from_slice(&word);
        }
        Bytes::from(words)
    }

    #[test]
    fn decodes_public_drop_tuple() {
        let payload = drop_payload(
            5_600_000_000_000_000,
            1_785_542_400,
            1_788_220_800,
            10,
            250,
            true,
        );
        let result = Bytes::from(payload);

        let words = result.as_ref();
        assert!(words.len() >= 6 * 32);
        let mint_price = U256::from_be_slice(&words[0..32]);
        assert_eq!(mint_price, U256::from(5_600_000_000_000_000u128));
        let start_time = u64::from_be_bytes(words[56..64].try_into().unwrap());
        assert_eq!(start_time, 1_785_542_400);
        let end_time = u64::from_be_bytes(words[88..96].try_into().unwrap());
        assert_eq!(end_time, 1_788_220_800);
        let max_total = u16::from_be_bytes(words[126..128].try_into().unwrap());
        assert_eq!(max_total, 10);
        let fee_bps = u16::from_be_bytes(words[158..160].try_into().unwrap());
        assert_eq!(fee_bps, 250);
        assert!(words[191] != 0);
    }

    #[test]
    fn mint_public_calldata_matches_expected_shape() {
        let nft: Address = "0x0000000000000000000000000000000000000001"
            .parse()
            .unwrap();
        let fee: Address = "0x0000000000000000000000000000000000000002"
            .parse()
            .unwrap();
        let data = encode_mint_public(nft, fee, 1);

        let selector = &data[..4];
        let expected_selector =
            keccak256(b"mintPublic(address,address,address,uint256)")[..4].to_vec();
        assert_eq!(selector, expected_selector.as_slice());
        assert_eq!(data.len(), 4 + 4 * 32);
    }

    #[test]
    fn selector_matches_keccak_prefix() {
        let expected: Vec<u8> = keccak256(b"getPublicDrop(address)")[..4].to_vec();
        assert_eq!(selector(GET_PUBLIC_DROP), expected.as_slice());
    }
}
