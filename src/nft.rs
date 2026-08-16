use alloy_primitives::{Address, B256, Bytes, U256, keccak256};
use alloy_sol_types::SolValue;
use thiserror::Error;

use crate::chain::TransactionReceipt;

const ERC721_TRANSFER_SELECTOR: [u8; 4] = [0x42, 0x84, 0x2e, 0x0e];
const ERC1155_TRANSFER_SELECTOR: [u8; 4] = [0xf2, 0x42, 0x43, 0x2a];
const MAX_RECEIPT_MINT_ITEMS: usize = 1_024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MintedAsset {
    Erc721 { token_id: U256 },
    Erc1155 { token_id: U256, units: U256 },
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum NftError {
    #[error("mint receipt did not contain the exact requested NFT units")]
    MintReceiptMismatch,
    #[error("mint receipt contained malformed NFT transfer data")]
    MalformedTransferLog,
    #[error("mint receipt contained too many NFT transfer items")]
    TooManyTransferItems,
    #[error("NFT transfer arithmetic overflowed")]
    TransferOverflow,
}

pub fn extract_minted_assets(
    receipt: &TransactionReceipt,
    nft_contract: Address,
    wallet: Address,
    drop_kind: &str,
    expected_token_id: u64,
    expected_units: u64,
) -> Result<Vec<MintedAsset>, NftError> {
    let erc721_topic = keccak256("Transfer(address,address,uint256)");
    let erc1155_single_topic = keccak256("TransferSingle(address,address,address,uint256,uint256)");
    let erc1155_batch_topic =
        keccak256("TransferBatch(address,address,address,uint256[],uint256[])");
    let mut assets = Vec::new();

    for log in receipt
        .logs
        .iter()
        .filter(|log| log.address == nft_contract)
    {
        let Some(topic) = log.topics.first() else {
            continue;
        };
        if drop_kind == "Erc721SeaDropV1" && *topic == erc721_topic {
            if log.topics.len() != 4
                || topic_address(log.topics[1])? != Address::ZERO
                || topic_address(log.topics[2])? != wallet
                || !log.data.is_empty()
            {
                continue;
            }
            assets.push(MintedAsset::Erc721 {
                token_id: U256::from_be_slice(log.topics[3].as_slice()),
            });
        } else if drop_kind == "Erc1155SeaDropV2" && *topic == erc1155_single_topic {
            if log.topics.len() != 4
                || topic_address(log.topics[2])? != Address::ZERO
                || topic_address(log.topics[3])? != wallet
            {
                continue;
            }
            let (token_id, units) = decode_single_data(&log.data)?;
            assets.push(MintedAsset::Erc1155 { token_id, units });
        } else if drop_kind == "Erc1155SeaDropV2" && *topic == erc1155_batch_topic {
            if log.topics.len() != 4
                || topic_address(log.topics[2])? != Address::ZERO
                || topic_address(log.topics[3])? != wallet
            {
                continue;
            }
            for (token_id, units) in decode_batch_data(&log.data)? {
                assets.push(MintedAsset::Erc1155 { token_id, units });
            }
        }
        if assets.len() > MAX_RECEIPT_MINT_ITEMS {
            return Err(NftError::TooManyTransferItems);
        }
    }

    validate_minted_assets(&assets, drop_kind, expected_token_id, expected_units)?;
    if drop_kind == "Erc1155SeaDropV2" {
        return Ok(vec![MintedAsset::Erc1155 {
            token_id: U256::from(expected_token_id),
            units: U256::from(expected_units),
        }]);
    }
    Ok(assets)
}

#[must_use]
pub fn encode_safe_transfer(asset: &MintedAsset, from: Address, recipient: Address) -> Bytes {
    let mut calldata = Vec::new();
    match asset {
        MintedAsset::Erc721 { token_id } => {
            calldata.extend_from_slice(&ERC721_TRANSFER_SELECTOR);
            calldata.extend((from, recipient, *token_id).abi_encode());
        }
        MintedAsset::Erc1155 { token_id, units } => {
            calldata.extend_from_slice(&ERC1155_TRANSFER_SELECTOR);
            calldata.extend((from, recipient, *token_id, *units, Bytes::new()).abi_encode());
        }
    }
    Bytes::from(calldata)
}

fn validate_minted_assets(
    assets: &[MintedAsset],
    drop_kind: &str,
    expected_token_id: u64,
    expected_units: u64,
) -> Result<(), NftError> {
    let expected_token_id = U256::from(expected_token_id);
    let observed_units = assets.iter().try_fold(U256::ZERO, |total, asset| {
        let units = match asset {
            MintedAsset::Erc721 { .. } => U256::ONE,
            MintedAsset::Erc1155 { token_id, units } if *token_id == expected_token_id => *units,
            MintedAsset::Erc1155 { .. } => return Err(NftError::MintReceiptMismatch),
        };
        if units == U256::ZERO {
            return Err(NftError::MintReceiptMismatch);
        }
        total.checked_add(units).ok_or(NftError::TransferOverflow)
    })?;
    if !matches!(drop_kind, "Erc721SeaDropV1" | "Erc1155SeaDropV2")
        || observed_units != U256::from(expected_units)
        || assets.is_empty()
    {
        return Err(NftError::MintReceiptMismatch);
    }
    Ok(())
}

fn topic_address(topic: B256) -> Result<Address, NftError> {
    if topic[..12] != [0_u8; 12] {
        return Err(NftError::MalformedTransferLog);
    }
    Ok(Address::from_slice(&topic[12..]))
}

fn decode_single_data(data: &[u8]) -> Result<(U256, U256), NftError> {
    if data.len() != 64 {
        return Err(NftError::MalformedTransferLog);
    }
    Ok((
        U256::from_be_slice(&data[..32]),
        U256::from_be_slice(&data[32..]),
    ))
}

fn decode_batch_data(data: &[u8]) -> Result<Vec<(U256, U256)>, NftError> {
    if data.len() < 128 || !data.len().is_multiple_of(32) {
        return Err(NftError::MalformedTransferLog);
    }
    let ids_offset = word_usize(data, 0)?;
    let units_offset = word_usize(data, 1)?;
    if ids_offset != 64 {
        return Err(NftError::MalformedTransferLog);
    }
    let ids = decode_u256_array(data, ids_offset)?;
    let expected_units_offset = ids
        .len()
        .checked_mul(32)
        .and_then(|bytes| 96_usize.checked_add(bytes))
        .ok_or(NftError::MalformedTransferLog)?;
    if units_offset != expected_units_offset {
        return Err(NftError::MalformedTransferLog);
    }
    let units = decode_u256_array(data, units_offset)?;
    let expected_length = units
        .len()
        .checked_mul(32)
        .and_then(|bytes| units_offset.checked_add(32 + bytes))
        .ok_or(NftError::MalformedTransferLog)?;
    if ids.is_empty() || ids.len() != units.len() || data.len() != expected_length {
        return Err(NftError::MalformedTransferLog);
    }
    Ok(ids.into_iter().zip(units).collect())
}

fn decode_u256_array(data: &[u8], offset: usize) -> Result<Vec<U256>, NftError> {
    let count = word_usize_at(data, offset)?;
    if count > MAX_RECEIPT_MINT_ITEMS {
        return Err(NftError::TooManyTransferItems);
    }
    let start = offset
        .checked_add(32)
        .ok_or(NftError::MalformedTransferLog)?;
    let end = count
        .checked_mul(32)
        .and_then(|bytes| start.checked_add(bytes))
        .filter(|end| *end <= data.len())
        .ok_or(NftError::MalformedTransferLog)?;
    Ok(data[start..end]
        .chunks_exact(32)
        .map(U256::from_be_slice)
        .collect())
}

fn word_usize(data: &[u8], index: usize) -> Result<usize, NftError> {
    index
        .checked_mul(32)
        .ok_or(NftError::MalformedTransferLog)
        .and_then(|offset| word_usize_at(data, offset))
}

fn word_usize_at(data: &[u8], offset: usize) -> Result<usize, NftError> {
    let end = offset
        .checked_add(32)
        .ok_or(NftError::MalformedTransferLog)?;
    let word = data
        .get(offset..end)
        .ok_or(NftError::MalformedTransferLog)?;
    if word[..24] != [0_u8; 24] {
        return Err(NftError::MalformedTransferLog);
    }
    let bytes: [u8; 8] = word[24..]
        .try_into()
        .map_err(|_| NftError::MalformedTransferLog)?;
    usize::try_from(u64::from_be_bytes(bytes)).map_err(|_| NftError::MalformedTransferLog)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::TransactionLog;

    fn topic_address_value(address: Address) -> B256 {
        let mut value = [0_u8; 32];
        value[12..].copy_from_slice(address.as_slice());
        B256::from(value)
    }

    #[test]
    fn extracts_only_exact_erc721_safe_mints() {
        let wallet = Address::repeat_byte(0x11);
        let nft = Address::repeat_byte(0x22);
        let receipt = TransactionReceipt {
            transaction_hash: B256::repeat_byte(1),
            block_number: 10,
            is_success: true,
            contract_address: None,
            logs: vec![TransactionLog {
                address: nft,
                topics: vec![
                    keccak256("Transfer(address,address,uint256)"),
                    B256::ZERO,
                    topic_address_value(wallet),
                    B256::from(U256::from(7).to_be_bytes::<32>()),
                ],
                data: Bytes::new(),
            }],
        };
        assert_eq!(
            extract_minted_assets(&receipt, nft, wallet, "Erc721SeaDropV1", 0, 1).expect("mint"),
            vec![MintedAsset::Erc721 {
                token_id: U256::from(7)
            }]
        );
    }

    #[test]
    fn encodes_standard_safe_transfer_selectors() {
        let from = Address::repeat_byte(1);
        let recipient = Address::repeat_byte(2);
        let erc721 = encode_safe_transfer(
            &MintedAsset::Erc721 {
                token_id: U256::from(9),
            },
            from,
            recipient,
        );
        assert_eq!(&erc721[..4], &ERC721_TRANSFER_SELECTOR);
        let erc1155 = encode_safe_transfer(
            &MintedAsset::Erc1155 {
                token_id: U256::from(9),
                units: U256::from(3),
            },
            from,
            recipient,
        );
        assert_eq!(&erc1155[..4], &ERC1155_TRANSFER_SELECTOR);
    }

    #[test]
    fn decodes_canonical_erc1155_batch_mints_and_rejects_wrong_units() {
        let wallet = Address::repeat_byte(0x11);
        let nft = Address::repeat_byte(0x22);
        let mut data = vec![0_u8; 192];
        data[31] = 64;
        data[63] = 128;
        data[95] = 1;
        data[127] = 7;
        data[159] = 1;
        data[191] = 3;
        let receipt = TransactionReceipt {
            transaction_hash: B256::repeat_byte(1),
            block_number: 10,
            is_success: true,
            contract_address: None,
            logs: vec![TransactionLog {
                address: nft,
                topics: vec![
                    keccak256("TransferBatch(address,address,address,uint256[],uint256[])"),
                    topic_address_value(Address::repeat_byte(3)),
                    B256::ZERO,
                    topic_address_value(wallet),
                ],
                data: Bytes::from(data),
            }],
        };
        assert_eq!(
            extract_minted_assets(&receipt, nft, wallet, "Erc1155SeaDropV2", 7, 3).expect("mint"),
            vec![MintedAsset::Erc1155 {
                token_id: U256::from(7),
                units: U256::from(3)
            }]
        );
        assert_eq!(
            extract_minted_assets(&receipt, nft, wallet, "Erc1155SeaDropV2", 7, 2),
            Err(NftError::MintReceiptMismatch)
        );
    }

    #[test]
    fn rejects_noncanonical_erc1155_batch_offsets() {
        let mut data = vec![0_u8; 128];
        data[31] = 0x40;
        data[63] = 0x40;
        data[95] = 1;
        data[127] = 7;
        assert_eq!(
            decode_batch_data(&data),
            Err(NftError::MalformedTransferLog)
        );
    }
}
