//! Multi-RPC fire-and-forget dispatch ("blast").
//!
//! Ported from the `nft-public-mint` TypeScript sniper
//! (`src/rpc-blast.ts`). Every transaction is signed and serialised *before*
//! the stage opens; at fire time the only work left is writing pre-built JSON
//! bodies to sockets. Dispatch is sub-millisecond per wallet and every RPC is
//! hit in parallel, so the fastest endpoint wins the race to the mempool.

use std::time::Duration;

use alloy_primitives::B256;
use reqwest::Client;
use serde_json::json;
use thiserror::Error;
use tokio::task::JoinHandle;
use url::Url;

use crate::transaction::SignedTransaction;

#[derive(Clone, Debug)]
pub struct RpcEndpoint {
    pub url: Url,
    pub label: String,
}

#[derive(Debug)]
pub struct PreparedBlast {
    pub tx_hash: B256,
    pub body: String,
}

#[derive(Debug)]
pub struct BlastResult {
    pub label: String,
    pub tx_hash: Option<B256>,
    pub error: Option<String>,
}

#[derive(Debug, Error)]
pub enum BlastError {
    #[error("cannot construct the RPC HTTP client")]
    Client,
}

/// Same connection tuning as the read gateway: keep-alive sockets with no idle
/// timeout and adaptive HTTP/2 windows, so a warm connection never pays a
/// handshake at fire time.
pub fn build_client() -> Result<Client, BlastError> {
    Client::builder()
        .timeout(Duration::from_secs(15))
        .pool_idle_timeout(None)
        .pool_max_idle_per_host(2)
        .tcp_keepalive(Duration::from_mins(1))
        .http2_adaptive_window(true)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|_| BlastError::Client)
}

fn label_from_url(url: &Url) -> String {
    url.host_str()
        .map_or_else(|| url.as_str().to_owned(), ToOwned::to_owned)
}

/// Build the endpoint list with human labels for logging.
#[must_use]
pub fn parse_endpoints(rpc_urls: &[Url]) -> Vec<RpcEndpoint> {
    rpc_urls
        .iter()
        .map(|url| RpcEndpoint {
            url: url.clone(),
            label: label_from_url(url),
        })
        .collect()
}

/// Call this BEFORE the fire moment (after signing) — does all compute work
/// upfront. The JSON body is identical for every endpoint, so it is built once
/// and reused.
#[must_use]
pub fn prepare_blast(signed: &SignedTransaction) -> PreparedBlast {
    PreparedBlast {
        tx_hash: signed.hash(),
        body: json!({
            "jsonrpc": "2.0",
            "method": "eth_sendRawTransaction",
            "params": [format!("0x{}", hex::encode(signed.raw()))],
            "id": 1,
        })
        .to_string(),
    }
}

/// Pre-establish TCP/TLS to every RPC so the first real request doesn't pay
/// for a handshake. Some endpoints (Base's sequencer, for one) only accept
/// send methods, so we warm with `eth_sendRawTransaction` and ignore the
/// error — the handshake is the point, not the response.
pub async fn warm_connections(client: &Client, endpoints: &[RpcEndpoint]) {
    let futures = endpoints.iter().map(|endpoint| {
        let client = client.clone();
        let url = endpoint.url.clone();
        async move {
            let _ = client
                .post(url)
                .json(&json!({
                    "jsonrpc": "2.0",
                    "method": "eth_sendRawTransaction",
                    "params": ["0x00"],
                    "id": 1,
                }))
                .send()
                .await;
        }
    });
    futures_join_all(futures).await;
}

/// Blast a prepared raw tx to all RPC endpoints simultaneously — fire and
/// forget. Each endpoint runs in its own task, so dispatch returns as soon as
/// the requests are initiated (sub-ms). Results are collected by awaiting the
/// returned handles afterwards, off the critical path.
#[must_use]
pub fn blast_to_all(
    client: &Client,
    prepared: &PreparedBlast,
    endpoints: &[RpcEndpoint],
) -> Vec<JoinHandle<BlastResult>> {
    let body = prepared.body.clone();
    let expected_hash = prepared.tx_hash;

    endpoints
        .iter()
        .map(|endpoint| {
            let client = client.clone();
            let url = endpoint.url.clone();
            let label = endpoint.label.clone();
            let body = body.clone();
            tokio::spawn(async move {
                let response = client.post(url).body(body).send().await;
                match response {
                    Ok(response) => match response.json::<serde_json::Value>().await {
                        Ok(json) => {
                            if let Some(result) = json.get("result").and_then(|v| v.as_str()) {
                                let tx_hash = result
                                    .parse()
                                    .ok()
                                    .filter(|hash: &B256| *hash == expected_hash);
                                return BlastResult {
                                    label,
                                    tx_hash,
                                    error: None,
                                };
                            }
                            let error = json
                                .get("error")
                                .and_then(|v| v.get("message"))
                                .and_then(|v| v.as_str())
                                .unwrap_or("unknown RPC error")
                                .to_owned();
                            BlastResult {
                                label,
                                tx_hash: None,
                                error: Some(error),
                            }
                        }
                        Err(error) => BlastResult {
                            label,
                            tx_hash: None,
                            error: Some(error.to_string()),
                        },
                    },
                    Err(error) => BlastResult {
                        label,
                        tx_hash: None,
                        error: Some(error.to_string()),
                    },
                }
            })
        })
        .collect()
}

/// Is this response a successful acceptance? A tx is "accepted" if any
/// endpoint returned its hash, or if every endpoint already knew it
/// (`already known` — someone else raced the same nonce, usually a duplicate
/// blast or a replacement from an earlier run).
#[must_use]
pub fn is_accepted(results: &[BlastResult]) -> bool {
    results
        .iter()
        .any(|r| r.tx_hash.is_some() || r.error.as_deref().is_some_and(is_already_known))
}

fn is_already_known(error: &str) -> bool {
    let lower = error.to_ascii_lowercase();
    lower.contains("already known") || lower.contains("already exists")
}

/// Distinct rejection reasons across all endpoints, for reporting.
#[must_use]
pub fn rejection_reasons(results: &[BlastResult]) -> Vec<&str> {
    let mut reasons: Vec<&str> = Vec::new();
    for result in results {
        if result.tx_hash.is_none()
            && let Some(error) = result.error.as_deref()
            && !reasons.contains(&error)
        {
            reasons.push(error);
        }
    }
    reasons
}

async fn futures_join_all<F, T>(futures: impl IntoIterator<Item = F>)
where
    F: std::future::Future<Output = T>,
{
    let futures: Vec<_> = futures.into_iter().collect();
    for future in futures {
        future.await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_use_hostname() {
        let url: Url = "https://mainnet.base.org".parse().unwrap();
        assert_eq!(label_from_url(&url), "mainnet.base.org");
    }

    #[test]
    fn already_known_detection() {
        assert!(is_already_known(
            "nonce too low - transaction already known"
        ));
        assert!(!is_already_known("insufficient funds for gas"));
    }
}
