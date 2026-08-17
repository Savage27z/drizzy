//! Multi-RPC fire-and-forget dispatch ("blast").
//!
//! Ported from the `nft-public-mint` TypeScript sniper
//! (`src/rpc-blast.ts`). Every transaction is signed and serialised *before*
//! the stage opens; at fire time the only work left is writing pre-built JSON
//! bodies to sockets. Dispatch is sub-millisecond per wallet and every RPC is
//! hit in parallel, so the fastest endpoint wins the race to the mempool.

use std::time::Duration;

use alloy_primitives::B256;
use reqwest::{Client, header::CONTENT_TYPE};
use serde_json::json;
use thiserror::Error;
use tokio::{task::JoinHandle, time::Instant};
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
    /// Round-trip time from dispatch to this endpoint's reply. The whole point
    /// of blasting is that the fastest endpoint wins, so recording which one
    /// actually did turns endpoint choice into a measurement instead of a guess.
    pub latency_ms: u128,
}

#[derive(Debug, Error)]
pub enum BlastError {
    #[error("cannot construct the RPC HTTP client")]
    Client,
}

/// Idle sockets retained per RPC host. A 50-wallet manifest dispatches 50
/// concurrent sends to each endpoint, and a pool that only retains a couple of
/// connections forces the rest to open new ones at the worst possible moment —
/// during the fire. Sized to cover a large manifest with headroom.
pub const POOL_MAX_IDLE_PER_HOST: usize = 64;

/// Same connection tuning as the read gateway: keep-alive sockets with no idle
/// timeout and adaptive HTTP/2 windows, so a warm connection never pays a
/// handshake at fire time.
pub fn build_client() -> Result<Client, BlastError> {
    Client::builder()
        .timeout(Duration::from_secs(15))
        .pool_idle_timeout(None)
        .pool_max_idle_per_host(POOL_MAX_IDLE_PER_HOST)
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

/// Capped well under the client timeout: a single unresponsive endpoint must
/// never delay the fire moment, and a handshake that has not completed by then
/// would not have been useful anyway.
const WARM_TIMEOUT: Duration = Duration::from_secs(3);

/// Pre-establish TCP/TLS to every RPC so the first real request doesn't pay
/// for a handshake. Some endpoints (Base's sequencer, for one) only accept
/// send methods, so we warm with `eth_sendRawTransaction` and ignore the
/// error — the handshake is the point, not the response. Every endpoint is
/// warmed concurrently: serialising them made arming scale with the slowest RPC.
pub async fn warm_connections(client: &Client, endpoints: &[RpcEndpoint]) {
    let handles: Vec<JoinHandle<()>> = endpoints
        .iter()
        .map(|endpoint| {
            let client = client.clone();
            let url = endpoint.url.clone();
            tokio::spawn(async move {
                let _ = tokio::time::timeout(
                    WARM_TIMEOUT,
                    client
                        .post(url)
                        .json(&json!({
                            "jsonrpc": "2.0",
                            "method": "eth_sendRawTransaction",
                            "params": ["0x00"],
                            "id": 1,
                        }))
                        .send(),
                )
                .await;
            })
        })
        .collect();
    for handle in handles {
        let _ = handle.await;
    }
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
                let started = Instant::now();
                // `body()` sets no Content-Type. Geth/reth reject a JSON-RPC
                // POST without `application/json` with HTTP 415, so the header
                // is mandatory here — `json()` sets it for us elsewhere, this
                // is the one call site that serialises ahead of time.
                let response = client
                    .post(url)
                    .header(CONTENT_TYPE, "application/json")
                    .body(body)
                    .send()
                    .await;
                match response {
                    Ok(response) => {
                        let status = response.status();
                        match response.json::<serde_json::Value>().await {
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
                                        latency_ms: started.elapsed().as_millis(),
                                    };
                                }
                                let error = json
                                    .get("error")
                                    .and_then(|v| v.get("message"))
                                    .and_then(|v| v.as_str())
                                    .map_or_else(
                                        || format!("unknown RPC error (HTTP {status})"),
                                        ToOwned::to_owned,
                                    );
                                BlastResult {
                                    label,
                                    tx_hash: None,
                                    error: Some(error),
                                    latency_ms: started.elapsed().as_millis(),
                                }
                            }
                            // A transport-level rejection (415, 429, 5xx) sends
                            // a non-JSON body; surface the status rather than a
                            // bare "expected value at line 1" decode error.
                            Err(error) => BlastResult {
                                label,
                                tx_hash: None,
                                error: Some(if status.is_success() {
                                    error.to_string()
                                } else {
                                    format!("HTTP {status}")
                                }),
                                latency_ms: started.elapsed().as_millis(),
                            },
                        }
                    }
                    Err(error) => BlastResult {
                        label,
                        tx_hash: None,
                        error: Some(error.to_string()),
                        latency_ms: started.elapsed().as_millis(),
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

/// The endpoint that accepted this transaction fastest, with its round-trip
/// time. `None` when no endpoint accepted it.
#[must_use]
pub fn winning_endpoint(results: &[BlastResult]) -> Option<(&str, u128)> {
    results
        .iter()
        .filter(|result| result.tx_hash.is_some())
        .min_by_key(|result| result.latency_ms)
        .map(|result| (result.label.as_str(), result.latency_ms))
}

/// Per-endpoint acceptance counts and mean latency across a whole run, sorted
/// fastest first. This is what turns "which RPC should I use?" from a guess
/// into a number.
#[must_use]
pub fn endpoint_scoreboard(runs: &[&[BlastResult]]) -> Vec<EndpointStats> {
    let mut stats: Vec<EndpointStats> = Vec::new();
    for results in runs {
        for result in *results {
            let index =
                if let Some(index) = stats.iter().position(|entry| entry.label == result.label) {
                    index
                } else {
                    stats.push(EndpointStats {
                        label: result.label.clone(),
                        accepted: 0,
                        attempts: 0,
                        total_latency_ms: 0,
                    });
                    stats.len() - 1
                };
            let entry = &mut stats[index];
            entry.attempts += 1;
            entry.total_latency_ms += result.latency_ms;
            if result.tx_hash.is_some() {
                entry.accepted += 1;
            }
        }
    }
    stats.sort_by_key(EndpointStats::mean_latency_ms);
    stats
}

#[derive(Clone, Debug)]
pub struct EndpointStats {
    pub label: String,
    pub accepted: usize,
    pub attempts: usize,
    pub total_latency_ms: u128,
}

impl EndpointStats {
    #[must_use]
    pub fn mean_latency_ms(&self) -> u128 {
        if self.attempts == 0 {
            return 0;
        }
        self.total_latency_ms / self.attempts as u128
    }
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

    fn result(label: &str, accepted: bool, latency_ms: u128) -> BlastResult {
        BlastResult {
            label: label.to_owned(),
            tx_hash: accepted.then_some(B256::ZERO),
            error: (!accepted).then(|| "rejected".to_owned()),
            latency_ms,
        }
    }

    #[test]
    fn winner_is_the_fastest_accepting_endpoint() {
        let results = vec![
            result("slow.example", true, 400),
            result("fast.example", true, 120),
            // A rejection must never win, however fast it answered.
            result("instant-reject.example", false, 5),
        ];
        assert_eq!(
            winning_endpoint(&results),
            Some(("fast.example", 120)),
            "the fastest *accepting* endpoint wins"
        );
    }

    #[test]
    fn winner_is_none_when_every_endpoint_rejected() {
        let results = vec![
            result("a.example", false, 10),
            result("b.example", false, 20),
        ];
        assert_eq!(winning_endpoint(&results), None);
    }

    #[test]
    fn scoreboard_aggregates_across_wallets_and_sorts_by_latency() {
        let wallet_one = vec![
            result("slow.example", true, 300),
            result("fast.example", true, 100),
        ];
        let wallet_two = vec![
            result("slow.example", true, 500),
            result("fast.example", false, 200),
        ];
        let runs: Vec<&[BlastResult]> = vec![&wallet_one, &wallet_two];
        let board = endpoint_scoreboard(&runs);

        assert_eq!(board.len(), 2);
        assert_eq!(board[0].label, "fast.example", "fastest mean sorts first");
        assert_eq!(board[0].mean_latency_ms(), 150);
        assert_eq!(board[0].accepted, 1);
        assert_eq!(board[0].attempts, 2);
        assert_eq!(board[1].label, "slow.example");
        assert_eq!(board[1].mean_latency_ms(), 400);
        assert_eq!(board[1].accepted, 2);
    }

    /// Accept one request on loopback, return the raw head, and reply with a
    /// canned JSON-RPC result.
    async fn capture_one_request(listener: tokio::net::TcpListener, reply: &'static str) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (mut socket, _) = listener.accept().await.expect("accept");
        let mut buffer = vec![0u8; 8192];
        let read = socket.read(&mut buffer).await.expect("read");
        let request = String::from_utf8_lossy(&buffer[..read]).into_owned();
        let response = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{reply}",
            reply.len()
        );
        let _ = socket.write_all(response.as_bytes()).await;
        let _ = socket.flush().await;
        request
    }

    /// Geth and reth answer a JSON-RPC POST that lacks `Content-Type:
    /// application/json` with HTTP 415, which would silently sink the entire
    /// blast. The body is serialised ahead of fire time rather than via
    /// `RequestBuilder::json`, so the header has to be set explicitly.
    #[tokio::test]
    async fn blast_sends_json_content_type() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url: Url = format!("http://{}", listener.local_addr().unwrap())
            .parse()
            .unwrap();
        let server = tokio::spawn(capture_one_request(
            listener,
            r#"{"jsonrpc":"2.0","id":1,"result":"0x00"}"#,
        ));

        let prepared = PreparedBlast {
            tx_hash: B256::ZERO,
            body:
                r#"{"jsonrpc":"2.0","method":"eth_sendRawTransaction","params":["0xdead"],"id":1}"#
                    .to_owned(),
        };
        let endpoints = parse_endpoints(&[url]);
        for handle in blast_to_all(&build_client().unwrap(), &prepared, &endpoints) {
            let _ = handle.await;
        }

        let request = server.await.expect("server task");
        let lowered = request.to_ascii_lowercase();
        assert!(
            lowered.contains("content-type: application/json"),
            "blast must declare a JSON content type, got:\n{request}"
        );
        assert!(request.contains("eth_sendRawTransaction"));
    }

    /// A rejection that is not JSON (a 415 or 429 error page) must report the
    /// status rather than a bare serde decode error.
    #[tokio::test]
    async fn non_json_rejection_reports_http_status() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url: Url = format!("http://{}", listener.local_addr().unwrap())
            .parse()
            .unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept");
            let mut buffer = vec![0u8; 8192];
            let _ = socket.read(&mut buffer).await;
            let body = "invalid content type, only application/json is supported";
            let response = format!(
                "HTTP/1.1 415 Unsupported Media Type\r\ncontent-type: text/plain\r\ncontent-length: {}\r\n\r\n{body}",
                body.len()
            );
            let _ = socket.write_all(response.as_bytes()).await;
            let _ = socket.flush().await;
        });

        let prepared = PreparedBlast {
            tx_hash: B256::ZERO,
            body: "{}".to_owned(),
        };
        let endpoints = parse_endpoints(&[url]);
        let mut results = Vec::new();
        for handle in blast_to_all(&build_client().unwrap(), &prepared, &endpoints) {
            results.push(handle.await.unwrap());
        }
        let _ = server.await;

        assert!(!is_accepted(&results));
        assert_eq!(
            rejection_reasons(&results),
            vec!["HTTP 415 Unsupported Media Type"]
        );
    }
}
