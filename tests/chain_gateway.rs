use std::time::Duration;

use opensea_mint::chain::{ChainGateway, parse_chain_id};

#[test]
fn parses_canonical_hex_chain_ids() {
    assert_eq!(parse_chain_id("0x1").expect("mainnet"), 1);
    assert_eq!(parse_chain_id("0x2105").expect("base"), 8453);
    assert!(parse_chain_id("8453").is_err());
    assert!(parse_chain_id("0x").is_err());
}

#[test]
fn gateway_debug_does_not_expose_endpoint_configuration() {
    let gateway = ChainGateway::new(Duration::from_secs(1)).expect("client");
    let debug = format!("{gateway:?}");

    assert!(debug.contains("ChainGateway"));
    assert!(!debug.contains("http"));
}
