use std::{
    collections::{HashMap, HashSet},
    fmt::{self, Write as _},
    future::Future,
    sync::Arc,
    time::Duration,
};

use alloy_primitives::{Address, Bytes, U256};
use reqwest::{
    Client, StatusCode,
    cookie::Jar,
    header::{ACCEPT, ORIGIN, REFERER},
};
use serde::{Deserialize, Deserializer, Serialize, de::DeserializeOwned};
use thiserror::Error;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use tokio::time::sleep;
use url::Url;
use zeroize::Zeroizing;

use crate::{
    config::OpenSeaConfig,
    logging,
    signing::{WalletSigner, WalletSignerError},
};

pub const CAPTURE_REVISION: &str = "capture-2026-08-11-dpl_Dv8XfW34avbfTknamurzVCSXqnJe";
const ELIGIBILITY_PERSISTED_QUERY_HASH: &str =
    "e1b54354df0d26d39c6b81429bd5e5d37749eaa4bdc027f987128f8c1e7d2308";
const CONNECTED_ACCOUNT_HINT_COOKIE: &str = "connected-account-server-hint";

const SIWE_STATEMENT: &str = "Click to sign in and accept the OpenSea Terms of Service (https://opensea.io/tos) and Privacy Policy (https://opensea.io/privacy).";
const NONCE_RESPONSE_LIMIT: usize = 4 * 1024;
const AUTH_RESPONSE_LIMIT: usize = 64 * 1024;
const GRAPHQL_RESPONSE_LIMIT: usize = 2 * 1024 * 1024;
const GRAPHQL_CONTENT_LENGTH_LIMIT: u64 = 2 * 1024 * 1024;

/*
 * Keeps generated alias queries and responses below the existing 2 MiB transport boundary.
 */
pub const MAX_MINT_ACTIONS_PER_GRAPHQL_REQUEST: usize = 250;

const COLLECTION_QUERY: &str = r"
query MintCollectionMetadata($slug: String!) {
  collectionBySlug(slug: $slug) {
    __typename
    ... on Collection {
      slug
      address
      chain { identifier networkId }
      drop {
        __typename
        identifier { contractAddress chain { identifier } }
        stages {
          __typename
          stageType
          stageIndex
          startTime
          endTime
          maxTotalMintableByWallet
          ... on Erc1155SeaDropV2Stage {
            fromTokenId
            toTokenId
            maxTotalMintableByWalletPerToken
          }
        }
      }
    }
  }
}
";

const COLLECTION_SEARCH_QUERY: &str = r"
query MintCollectionSearch($query: String!) {
  collectionsByQuery(query: $query, limit: 50) {
    __typename
    slug
    address
    chain { identifier networkId }
  }
}
";

const MINT_ACTION_QUERY: &str = r"
query MintActionTimelineQuery(
  $address: Address!
  $fromAssets: [AssetQuantityInput!]!
  $toAssets: [AssetQuantityInput!]!
  $recipient: Address
) {
  swap(
    address: $address
    fromAssets: $fromAssets
    toAssets: $toAssets
    recipient: $recipient
    action: MINT
  ) {
    actions {
      __typename
      ... on TransactionAction {
        transactionSubmissionData {
          to
          data
          value
          chain { networkId identifier }
        }
      }
    }
    errors { __typename }
  }
}
";

const ELIGIBILITY_QUERY: &str = r"
query DropEligibilityQuery($collectionSlug: String!, $address: Address!) {
  dropBySlug(slug: $collectionSlug) {
    __typename
    ... on Erc721SeaDropV1 {
      minterQuantityMinted(minter: $address)
    }
    stages {
      __typename
      stageType
      stageIndex
      isEligible
      eligibleMinterAddress
      maxTotalMintableByWallet
      eligibleMaxTotalMintableByWallet
      eligiblePrice {
        usd
        token {
          unit
          symbol
          contractAddress
          chain { identifier }
        }
      }
      ... on Erc1155SeaDropV2Stage {
        fromTokenId
        toTokenId
        maxTotalMintableByWalletPerToken
        eligibleMaxTotalMintableByWalletPerToken
      }
    }
  }
}
";

#[derive(Debug, Error)]
pub enum OpenSeaError {
    #[error("cannot construct an isolated OpenSea HTTP client")]
    Client,
    #[error("the OpenSea collection locator is invalid")]
    InvalidCollectionLocator,
    #[error("the contract address matches more than one OpenSea collection on the RPC chain")]
    AmbiguousCollectionLocator,
    #[error("OpenSea authentication nonce response is incompatible with the verified capture")]
    InvalidNonceResponse,
    #[error("OpenSea SIWE authentication failed with HTTP status {0}")]
    Authentication(u16),
    #[error("OpenSea SIWE verification did not establish the configured wallet session")]
    AuthenticationSessionMismatch,
    #[error("OpenSea request failed before a compatible response was received")]
    Transport,
    #[error("OpenSea returned HTTP status {0}")]
    Http(u16),
    #[error("OpenSea rate limited the query")]
    RateLimited,
    #[error("OpenSea rejected this account for trading operations")]
    AccountCannotTrade,
    #[error("OpenSea did not recognize the authenticated wallet session")]
    AuthenticationRequired,
    #[error("OpenSea private GraphQL response drifted from the verified capture")]
    Compatibility,
    #[error("OpenSea collection was not found")]
    CollectionNotFound,
    #[error(
        "OpenSea collection is on chain {collection_chain_id}, but RPC_URL is connected to chain {rpc_chain_id}"
    )]
    CollectionChainMismatch {
        collection_chain_id: u64,
        rpc_chain_id: u64,
    },
    #[error("the collection is not an OpenSea-hosted SeaDrop")]
    DropNotFound,
    #[error("OpenSea returned an invalid address, integer, or calldata field")]
    InvalidProtocolValue,
    #[error("wallet must authenticate before wallet-specific OpenSea queries")]
    SessionRequired,
    #[error("OpenSea reported that the drop is not currently accepting mints")]
    MintStageNotOpen,
    #[error("OpenSea reported that the wallet is ineligible for the active mint stage")]
    MintWalletIneligible,
    #[error("OpenSea reported that the requested mint exceeds an allocation or supply limit")]
    MintLimitExceeded,
    #[error("OpenSea reported insufficient wallet funds for the mint action")]
    MintInsufficientFunds,
    #[error("OpenSea rejected the mint action")]
    MintActionRejected,
    #[error("OpenSea returned a mint action that failed local validation: {reason}")]
    UnsafeMintAction { reason: &'static str },
    #[error(transparent)]
    Signing(#[from] WalletSignerError),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CollectionMetadata {
    pub slug: String,
    pub address: Address,
    pub chain_identifier: String,
    pub network_id: u64,
    pub drop_kind: String,
    pub drop_address: Address,
    pub stages: Vec<StageMetadata>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StageMetadata {
    pub kind: String,
    pub stage_type: String,
    pub stage_index: u32,
    pub start_time: Option<String>,
    pub end_time: Option<String>,
    pub max_total_mintable_by_wallet: Option<u64>,
    pub max_total_mintable_by_wallet_per_token: Option<u64>,
    pub token_range: Option<(u64, u64)>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EligibilitySnapshot {
    pub drop_kind: String,
    pub minter_quantity_minted: Option<u64>,
    pub stages: Vec<StageEligibility>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StageEligibility {
    pub kind: String,
    pub stage_type: String,
    pub stage_index: u32,
    pub is_eligible: Option<bool>,
    pub eligible_minter_relation: Option<EligibleMinterRelation>,
    pub max_total_mintable_by_wallet: Option<u64>,
    pub eligible_max_total_mintable_by_wallet: Option<u64>,
    pub token_range: Option<(u64, u64)>,
    pub max_total_mintable_by_wallet_per_token: Option<u64>,
    pub eligible_max_total_mintable_by_wallet_per_token: Option<u64>,
    pub eligible_native_price_wei: Option<U256>,
    pub eligible_price_chain_identifier: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EligibleMinterRelation {
    ActiveWallet,
    LinkedWallet,
}

#[derive(Clone, PartialEq, Eq)]
pub struct MintTransactionAction {
    pub target: Address,
    pub chain_identifier: String,
    pub network_id: u64,
    pub value: U256,
    pub calldata: Bytes,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MintActionRequest {
    pub wallet: Address,
    pub token_id: String,
    pub quantity: u64,
}

impl fmt::Debug for MintTransactionAction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MintTransactionAction")
            .field("target", &self.target)
            .field("chain_identifier", &self.chain_identifier)
            .field("network_id", &self.network_id)
            .field("value", &self.value)
            .field("calldata_bytes", &self.calldata.len())
            .finish_non_exhaustive()
    }
}

pub struct WalletOpenSeaClient {
    client: Client,
    cookie_jar: Arc<Jar>,
    site_url: Url,
    graphql_url: Url,
    app_id: String,
    eligibility_timeout: Duration,
    max_attempts: u32,
    retry_interval_ms: u64,
    is_authenticated: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CollectionLocator {
    Slug(String),
    Contract(Address),
}

impl WalletOpenSeaClient {
    pub fn new(config: &OpenSeaConfig) -> Result<Self, OpenSeaError> {
        let cookie_jar = Arc::new(Jar::default());
        let client = Client::builder()
            .timeout(Duration::from_millis(config.request_timeout_ms))
            .pool_idle_timeout(None)
            .pool_max_idle_per_host(4)
            .tcp_keepalive(Duration::from_mins(1))
            .http2_adaptive_window(true)
            .cookie_provider(Arc::clone(&cookie_jar))
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!("opensea-mint/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|_| OpenSeaError::Client)?;
        Ok(Self {
            client,
            cookie_jar,
            site_url: config.site_url.clone(),
            graphql_url: config.graphql_url.clone(),
            app_id: config.app_id.clone(),
            eligibility_timeout: Duration::from_millis(config.eligibility_request_timeout_ms),
            max_attempts: config.max_attempts,
            retry_interval_ms: config.retry_interval_ms,
            is_authenticated: false,
        })
    }

    pub async fn collection_metadata(
        &self,
        slug: &str,
    ) -> Result<CollectionMetadata, OpenSeaError> {
        self.retry_request("collection metadata", || {
            self.collection_metadata_once(slug)
        })
        .await
    }

    async fn collection_metadata_once(
        &self,
        slug: &str,
    ) -> Result<CollectionMetadata, OpenSeaError> {
        validate_slug(slug)?;
        let variables = CollectionVariables { slug };
        let data: CollectionQueryData = self
            .graphql("MintCollectionMetadata", COLLECTION_QUERY, &variables, slug)
            .await?;
        decode_collection(data, slug)
    }

    pub async fn resolve_collection(
        &self,
        locator: &CollectionLocator,
        expected_chain_id: u64,
    ) -> Result<CollectionMetadata, OpenSeaError> {
        match locator {
            CollectionLocator::Slug(slug) => {
                let metadata = self.collection_metadata(slug).await?;
                validate_collection_chain(&metadata, expected_chain_id)?;
                Ok(metadata)
            }
            CollectionLocator::Contract(address) => {
                let address_text = address.to_checksum(None);
                let variables = CollectionSearchVariables {
                    query: &address_text,
                };
                let data: CollectionSearchData = self
                    .retry_request("collection search", || {
                        self.graphql(
                            "MintCollectionSearch",
                            COLLECTION_SEARCH_QUERY,
                            &variables,
                            "search",
                        )
                    })
                    .await?;
                let slug = matching_collection_slug(data, *address, expected_chain_id)?;
                let metadata = self.collection_metadata(&slug).await?;
                if metadata.address != *address {
                    return Err(OpenSeaError::Compatibility);
                }
                validate_collection_chain(&metadata, expected_chain_id)?;
                Ok(metadata)
            }
        }
    }

    pub async fn authenticate(
        &mut self,
        signer: &WalletSigner,
        wallet: Address,
        chain_id: u64,
        slug: &str,
    ) -> Result<(), OpenSeaError> {
        for attempt in 1..=self.max_attempts {
            match self.authenticate_once(signer, wallet, chain_id, slug).await {
                Ok(()) => return Ok(()),
                Err(error) if is_retryable_request_error(&error) && attempt < self.max_attempts => {
                    let delay = self.retry_delay();
                    report_request_retry(
                        "wallet authentication",
                        attempt,
                        self.max_attempts,
                        delay,
                    );
                    sleep(delay).await;
                }
                Err(error) => return Err(error),
            }
        }
        unreachable!("bounded authentication retry loop always returns")
    }

    async fn authenticate_once(
        &mut self,
        signer: &WalletSigner,
        wallet: Address,
        chain_id: u64,
        slug: &str,
    ) -> Result<(), OpenSeaError> {
        self.is_authenticated = false;
        if chain_id == 0 {
            return Err(OpenSeaError::InvalidProtocolValue);
        }
        if signer.identity().address != wallet {
            return Err(OpenSeaError::InvalidProtocolValue);
        }
        validate_slug(slug)?;
        let collection_url = self.collection_url(slug)?;
        self.set_connected_account_hint(wallet)?;
        let nonce = self.request_nonce(&collection_url).await?;
        let issued_at = OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .map_err(|_| OpenSeaError::Compatibility)?;
        let address = wallet.to_checksum(None);
        let domain = self
            .site_url
            .host_str()
            .ok_or(OpenSeaError::Compatibility)?;
        let uri = collection_url.as_str();
        let message = Zeroizing::new(create_siwe_message(
            domain, &address, uri, chain_id, &nonce, &issued_at,
        ));
        let signature = signer.sign_personal_message(message.as_bytes())?;
        let signature = Zeroizing::new(signature.to_string());
        let parsed = ParsedSiweMessage {
            domain,
            address: &address,
            statement: SIWE_STATEMENT,
            uri,
            version: "1",
            chain_id: chain_id.to_string(),
            nonce: &nonce,
            issued_at: &issued_at,
            account_type: "Ethereum",
        };
        let body = VerifyRequest {
            message: parsed,
            signature: &signature,
            chain_arch: "EVM",
        };
        let url = self
            .site_url
            .join("/__api/auth/siwe/verify")
            .map_err(|_| OpenSeaError::Compatibility)?;
        let response = self
            .client
            .post(url)
            .header(ORIGIN, self.origin()?)
            .header(REFERER, collection_url.as_str())
            .json(&body)
            .send()
            .await
            .map_err(|_| OpenSeaError::Transport)?;
        if !response.status().is_success() {
            return Err(OpenSeaError::Authentication(response.status().as_u16()));
        }
        let response_body = Zeroizing::new(
            read_limited_body(response, AUTH_RESPONSE_LIMIT)
                .await
                .map_err(map_protocol_body_error)?,
        );
        validate_authentication_response(&response_body, wallet)?;
        self.is_authenticated = true;
        Ok(())
    }

    pub async fn eligibility(
        &self,
        slug: &str,
        wallet: Address,
    ) -> Result<EligibilitySnapshot, OpenSeaError> {
        self.retry_request("wallet eligibility", || self.eligibility_once(slug, wallet))
            .await
    }

    async fn eligibility_once(
        &self,
        slug: &str,
        wallet: Address,
    ) -> Result<EligibilitySnapshot, OpenSeaError> {
        self.require_session()?;
        let referer = self.collection_url(slug)?;
        let url = build_eligibility_request_url(&self.graphql_url, &self.app_id, slug, wallet)?;
        let response = self
            .client
            .get(url)
            .header(ACCEPT, "application/json")
            .header(ORIGIN, self.origin()?)
            .header(REFERER, referer.as_str())
            .timeout(self.eligibility_timeout)
            .send()
            .await
            .map_err(|_| OpenSeaError::Transport)?;
        validate_http_response(&response)?;
        let response_body = Zeroizing::new(
            read_limited_body(response, GRAPHQL_RESPONSE_LIMIT)
                .await
                .map_err(map_protocol_body_error)?,
        );
        let envelope: GraphQlEnvelope<EligibilityQueryData> =
            serde_json::from_slice(&response_body).map_err(|_| OpenSeaError::Compatibility)?;
        if is_persisted_query_retryable(&envelope.errors) {
            let address = format!("{wallet:#x}");
            let variables = EligibilityVariables {
                address: &address,
                collection_slug: slug,
            };
            let data: EligibilityQueryData = self
                .graphql("DropEligibilityQuery", ELIGIBILITY_QUERY, &variables, slug)
                .await?;
            return decode_eligibility(data, wallet);
        }
        let data = decode_graphql_envelope(envelope)?;
        decode_eligibility(data, wallet)
    }

    pub async fn mint_transaction_action(
        &self,
        collection: &CollectionMetadata,
        expected_stage: &StageMetadata,
        wallet: Address,
        token_id: &str,
        quantity: u64,
        expected_chain_id: u64,
    ) -> Result<MintTransactionAction, OpenSeaError> {
        let decoded = self
            .mint_action(collection, wallet, token_id, quantity)
            .await?;
        validate_mint_transaction(
            decoded,
            collection,
            wallet,
            &expected_stage.stage_type,
            expected_stage.stage_index,
            quantity,
            expected_chain_id,
        )
    }

    pub async fn mint_transaction_actions(
        &self,
        collection: &CollectionMetadata,
        expected_stage: &StageMetadata,
        requests: &[MintActionRequest],
        expected_chain_id: u64,
    ) -> Result<Vec<MintTransactionAction>, OpenSeaError> {
        self.require_session()?;
        let (query, variables) = build_mint_action_batch_request(collection, requests)?;
        let data: MintActionBatchQueryData = self
            .graphql(
                "BatchMintActionTimelineQuery",
                &query,
                &variables,
                &collection.slug,
            )
            .await?;
        decode_mint_action_batch(
            data,
            collection,
            expected_stage,
            requests,
            expected_chain_id,
        )
    }

    async fn mint_action(
        &self,
        collection: &CollectionMetadata,
        wallet: Address,
        token_id: &str,
        quantity: u64,
    ) -> Result<DecodedMintAction, OpenSeaError> {
        self.require_session()?;
        if quantity == 0
            || token_id.is_empty()
            || !token_id.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(OpenSeaError::InvalidProtocolValue);
        }
        let address = wallet.to_checksum(None);
        let contract = collection.drop_address.to_checksum(None);
        let native_currency = Address::ZERO.to_checksum(None);
        let from_assets = [AssetQuantityInput {
            asset: AssetInput {
                contract_address: &native_currency,
                chain: &collection.chain_identifier,
                token_id: None,
            },
            quantity: None,
        }];
        let quantity = quantity.to_string();
        let to_assets = [AssetQuantityInput {
            asset: AssetInput {
                contract_address: &contract,
                chain: &collection.chain_identifier,
                token_id: Some(token_id),
            },
            quantity: Some(&quantity),
        }];
        let variables = MintActionVariables {
            address: &address,
            from_assets: &from_assets,
            to_assets: &to_assets,
            recipient: None,
        };
        let data: MintActionQueryData = self
            .graphql(
                "MintActionTimelineQuery",
                MINT_ACTION_QUERY,
                &variables,
                &collection.slug,
            )
            .await?;
        decode_mint_action(data)
    }

    async fn request_nonce(&self, referer: &Url) -> Result<Zeroizing<String>, OpenSeaError> {
        let url = self
            .site_url
            .join("/__api/auth/siwe/nonce")
            .map_err(|_| OpenSeaError::Compatibility)?;
        let response = self
            .client
            .post(url)
            .header(ORIGIN, self.origin()?)
            .header(REFERER, referer.as_str())
            .send()
            .await
            .map_err(|_| OpenSeaError::Transport)?;
        if !response.status().is_success() {
            return Err(OpenSeaError::Authentication(response.status().as_u16()));
        }
        let response_body = Zeroizing::new(
            read_limited_body(response, NONCE_RESPONSE_LIMIT)
                .await
                .map_err(|error| match error {
                    BodyReadError::Transport => OpenSeaError::Transport,
                    BodyReadError::LimitExceeded => OpenSeaError::InvalidNonceResponse,
                })?,
        );
        let response: NonceResponse = serde_json::from_slice(&response_body)
            .map_err(|_| OpenSeaError::InvalidNonceResponse)?;
        let nonce = Zeroizing::new(response.nonce);
        if !(8..=256).contains(&nonce.len())
            || !nonce.bytes().all(|byte| byte.is_ascii_alphanumeric())
        {
            return Err(OpenSeaError::InvalidNonceResponse);
        }
        Ok(nonce)
    }

    async fn graphql<T, V>(
        &self,
        operation_name: &str,
        query: &str,
        variables: &V,
        slug: &str,
    ) -> Result<T, OpenSeaError>
    where
        T: DeserializeOwned,
        V: Serialize + ?Sized,
    {
        let referer = self.collection_url(slug)?;
        let request = GraphQlRequest {
            operation_name,
            query,
            variables,
        };
        let request_builder = self
            .client
            .post(self.graphql_url.clone())
            .header(ACCEPT, "application/json")
            .header("x-app-id", &self.app_id)
            .header(ORIGIN, self.origin()?)
            .header(REFERER, referer.as_str())
            .json(&request);
        let response = request_builder
            .send()
            .await
            .map_err(|_| OpenSeaError::Transport)?;
        validate_http_response(&response)?;
        let response_body = Zeroizing::new(
            read_limited_body(response, GRAPHQL_RESPONSE_LIMIT)
                .await
                .map_err(map_protocol_body_error)?,
        );
        let envelope: GraphQlEnvelope<T> =
            serde_json::from_slice(&response_body).map_err(|_| OpenSeaError::Compatibility)?;
        decode_graphql_envelope(envelope)
    }

    async fn retry_request<T, F, Fut>(
        &self,
        operation: &'static str,
        mut request: F,
    ) -> Result<T, OpenSeaError>
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = Result<T, OpenSeaError>>,
    {
        for attempt in 1..=self.max_attempts {
            match request().await {
                Ok(value) => return Ok(value),
                Err(error) if is_retryable_request_error(&error) && attempt < self.max_attempts => {
                    let delay = self.retry_delay();
                    report_request_retry(operation, attempt, self.max_attempts, delay);
                    sleep(delay).await;
                }
                Err(error) => return Err(error),
            }
        }
        unreachable!("bounded OpenSea retry loop always returns")
    }

    fn retry_delay(&self) -> Duration {
        Duration::from_millis(self.retry_interval_ms)
    }

    fn collection_url(&self, slug: &str) -> Result<Url, OpenSeaError> {
        validate_slug(slug)?;
        self.site_url
            .join(&format!("/collection/{slug}/overview"))
            .map_err(|_| OpenSeaError::InvalidCollectionLocator)
    }

    fn origin(&self) -> Result<String, OpenSeaError> {
        if self.site_url.cannot_be_a_base() {
            return Err(OpenSeaError::Compatibility);
        }
        Ok(self.site_url.origin().ascii_serialization())
    }

    fn set_connected_account_hint(&self, wallet: Address) -> Result<(), OpenSeaError> {
        let cookie = connected_account_hint_cookie(&self.site_url, wallet)?;
        self.cookie_jar.add_cookie_str(&cookie, &self.site_url);
        Ok(())
    }

    fn require_session(&self) -> Result<(), OpenSeaError> {
        if self.is_authenticated {
            Ok(())
        } else {
            Err(OpenSeaError::SessionRequired)
        }
    }
}

fn validate_collection_chain(
    metadata: &CollectionMetadata,
    expected_chain_id: u64,
) -> Result<(), OpenSeaError> {
    if metadata.network_id == expected_chain_id {
        Ok(())
    } else {
        Err(OpenSeaError::CollectionChainMismatch {
            collection_chain_id: metadata.network_id,
            rpc_chain_id: expected_chain_id,
        })
    }
}

fn is_retryable_request_error(error: &OpenSeaError) -> bool {
    matches!(
        error,
        OpenSeaError::Transport
            | OpenSeaError::RateLimited
            | OpenSeaError::Authentication(408 | 409 | 425 | 429 | 500..=599)
            | OpenSeaError::Http(408 | 409 | 425 | 429 | 500..=599)
    )
}

fn report_request_retry(operation: &str, attempt: u32, maximum_attempts: u32, delay: Duration) {
    logging::warn(format!(
        "OpenSea {operation} attempt {attempt}/{maximum_attempts} failed transiently; retrying in {} ms.",
        delay.as_millis()
    ));
}

fn connected_account_hint_cookie(site_url: &Url, wallet: Address) -> Result<String, OpenSeaError> {
    let domain = site_url.host_str().ok_or(OpenSeaError::Compatibility)?;
    let address = format!("{wallet:#x}");
    Ok(format!(
        "{CONNECTED_ACCOUNT_HINT_COOKIE}={address}; Domain={domain}; Path=/; Secure; SameSite=Lax"
    ))
}

impl fmt::Debug for WalletOpenSeaClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WalletOpenSeaClient")
            .field("site_url", &self.site_url)
            .field("graphql_url", &self.graphql_url)
            .field("is_authenticated", &self.is_authenticated)
            .finish_non_exhaustive()
    }
}

pub fn parse_collection_locator(locator: &str) -> Result<CollectionLocator, OpenSeaError> {
    let locator = locator.trim();
    if locator.starts_with("0x") && locator.len() == 42 {
        let address = locator
            .parse()
            .map_err(|_| OpenSeaError::InvalidCollectionLocator)?;
        return Ok(CollectionLocator::Contract(address));
    }
    if validate_slug(locator).is_ok() {
        return Ok(CollectionLocator::Slug(locator.to_owned()));
    }
    let url = Url::parse(locator).map_err(|_| OpenSeaError::InvalidCollectionLocator)?;
    if url.scheme() != "https" || url.host_str() != Some("opensea.io") {
        return Err(OpenSeaError::InvalidCollectionLocator);
    }
    let segments = url
        .path_segments()
        .ok_or(OpenSeaError::InvalidCollectionLocator)?
        .collect::<Vec<_>>();
    if segments.first() != Some(&"collection") {
        return Err(OpenSeaError::InvalidCollectionLocator);
    }
    let slug = segments
        .get(1)
        .copied()
        .ok_or(OpenSeaError::InvalidCollectionLocator)?;
    validate_slug(slug)?;
    Ok(CollectionLocator::Slug(slug.to_owned()))
}

fn validate_slug(slug: &str) -> Result<(), OpenSeaError> {
    if slug.is_empty()
        || slug.len() > 200
        || !slug
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(OpenSeaError::InvalidCollectionLocator);
    }
    Ok(())
}

fn create_siwe_message(
    domain: &str,
    address: &str,
    uri: &str,
    chain_id: u64,
    nonce: &str,
    issued_at: &str,
) -> String {
    format!(
        "{domain} wants you to sign in with your Ethereum account:\n{address}\n\n{SIWE_STATEMENT}\n\nURI: {uri}\nVersion: 1\nChain ID: {chain_id}\nNonce: {nonce}\nIssued At: {issued_at}"
    )
}

fn validate_http_response(response: &reqwest::Response) -> Result<(), OpenSeaError> {
    let status = response.status();
    if status == StatusCode::UNAUTHORIZED {
        return Err(OpenSeaError::AuthenticationRequired);
    }
    if status == StatusCode::TOO_MANY_REQUESTS {
        return Err(OpenSeaError::RateLimited);
    }
    if !status.is_success() {
        return Err(OpenSeaError::Http(status.as_u16()));
    }
    if response
        .content_length()
        .is_some_and(|length| length > GRAPHQL_CONTENT_LENGTH_LIMIT)
    {
        return Err(OpenSeaError::Compatibility);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BodyReadError {
    Transport,
    LimitExceeded,
}

async fn read_limited_body(
    mut response: reqwest::Response,
    limit: usize,
) -> Result<Vec<u8>, BodyReadError> {
    let capacity = response
        .content_length()
        .and_then(|length| usize::try_from(length).ok())
        .unwrap_or(8 * 1024)
        .min(limit);
    let mut body = Vec::with_capacity(capacity);
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| BodyReadError::Transport)?
    {
        if chunk.len() > limit.saturating_sub(body.len()) {
            return Err(BodyReadError::LimitExceeded);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn map_protocol_body_error(error: BodyReadError) -> OpenSeaError {
    match error {
        BodyReadError::Transport => OpenSeaError::Transport,
        BodyReadError::LimitExceeded => OpenSeaError::Compatibility,
    }
}

fn classify_graphql_errors(errors: &[GraphQlError]) -> OpenSeaError {
    for error in errors {
        let message = error.message.to_ascii_lowercase();
        let code = error
            .extensions
            .as_ref()
            .and_then(|extensions| extensions.code.as_deref())
            .unwrap_or_default()
            .to_ascii_uppercase();
        if message.contains("can not perform trading operations")
            || message.contains("cannot perform trading operations")
        {
            return OpenSeaError::AccountCannotTrade;
        }
        if message.contains("not authenticated")
            || message.contains("authentication")
            || code == "UNAUTHENTICATED"
            || code == "UNAUTHORIZED"
        {
            return OpenSeaError::AuthenticationRequired;
        }
        if message.contains("rate limit")
            || matches!(code.as_str(), "RATE_LIMITED" | "TOO_MANY_REQUESTS")
        {
            return OpenSeaError::RateLimited;
        }
    }
    OpenSeaError::Compatibility
}

fn decode_graphql_envelope<T>(envelope: GraphQlEnvelope<T>) -> Result<T, OpenSeaError> {
    if !envelope.errors.is_empty() {
        return Err(classify_graphql_errors(&envelope.errors));
    }
    if let Some(error) = envelope
        .extensions
        .and_then(|extensions| extensions.auth)
        .and_then(|auth| auth.error)
    {
        if let Some(message) = error.message {
            let error = GraphQlError {
                message,
                extensions: None,
            };
            let classified = classify_graphql_errors(std::slice::from_ref(&error));
            if !matches!(classified, OpenSeaError::Compatibility) {
                return Err(classified);
            }
        }
        return Err(OpenSeaError::AuthenticationRequired);
    }
    envelope.data.ok_or(OpenSeaError::Compatibility)
}

fn is_persisted_query_retryable(errors: &[GraphQlError]) -> bool {
    errors.iter().any(|error| {
        matches!(
            error.message.as_str(),
            "PersistedQueryNotFound" | "PersistedQueryNotSupported" | "PersistedQueryIdInvalid"
        ) || error.extensions.as_ref().is_some_and(|extensions| {
            matches!(
                extensions.code.as_deref(),
                Some(
                    "PERSISTED_QUERY_NOT_FOUND"
                        | "PERSISTED_QUERY_NOT_SUPPORTED"
                        | "PERSISTED_QUERY_ID_INVALID"
                )
            )
        })
    })
}

fn decode_collection(
    data: CollectionQueryData,
    requested_slug: &str,
) -> Result<CollectionMetadata, OpenSeaError> {
    let collection = data
        .collection_by_slug
        .ok_or(OpenSeaError::CollectionNotFound)?;
    if collection.kind != "Collection" {
        return Err(OpenSeaError::CollectionNotFound);
    }
    let slug = collection.slug.ok_or(OpenSeaError::Compatibility)?;
    validate_slug(&slug)?;
    if slug != requested_slug {
        return Err(OpenSeaError::Compatibility);
    }
    let address = parse_address(collection.address.as_deref())?;
    let chain = collection.chain.ok_or(OpenSeaError::Compatibility)?;
    let network_id = parse_network_id(chain.network_id.as_ref())?;
    let chain_identifier = chain.identifier;
    let drop = collection.drop.ok_or(OpenSeaError::DropNotFound)?;
    if !matches!(drop.kind.as_str(), "Erc721SeaDropV1" | "Erc1155SeaDropV2") {
        return Err(OpenSeaError::DropNotFound);
    }
    let identifier = drop.identifier.ok_or(OpenSeaError::Compatibility)?;
    if identifier.chain.identifier != chain_identifier {
        return Err(OpenSeaError::Compatibility);
    }
    let drop_address = parse_address(Some(&identifier.contract_address))?;
    if address == Address::ZERO || drop_address != address {
        return Err(OpenSeaError::Compatibility);
    }
    let mut stage_keys = HashSet::new();
    let mut stages = Vec::with_capacity(drop.stages.len());
    for stage in drop.stages {
        validate_stage_identity(&drop.kind, &stage.kind, &stage.stage_type)?;
        validate_stage_time_window(stage.start_time.as_deref(), stage.end_time.as_deref())?;
        let token_range = decode_token_range(stage.from_token_id, stage.to_token_id)?;
        match drop.kind.as_str() {
            "Erc721SeaDropV1"
                if token_range.is_some()
                    || stage.max_total_mintable_by_wallet_per_token.is_some() =>
            {
                return Err(OpenSeaError::Compatibility);
            }
            "Erc1155SeaDropV2" if token_range.is_none() => {
                return Err(OpenSeaError::Compatibility);
            }
            _ => {}
        }
        if !stage_keys.insert((stage.stage_index, token_range)) {
            return Err(OpenSeaError::Compatibility);
        }
        stages.push(StageMetadata {
            kind: stage.kind,
            stage_type: stage.stage_type,
            stage_index: stage.stage_index,
            start_time: stage.start_time,
            end_time: stage.end_time,
            max_total_mintable_by_wallet: stage.max_total_mintable_by_wallet,
            max_total_mintable_by_wallet_per_token: stage.max_total_mintable_by_wallet_per_token,
            token_range,
        });
    }
    validate_metadata_stage_groups(&stages)?;
    Ok(CollectionMetadata {
        slug,
        address,
        chain_identifier,
        network_id,
        drop_kind: drop.kind,
        drop_address,
        stages,
    })
}

fn decode_eligibility(
    data: EligibilityQueryData,
    wallet: Address,
) -> Result<EligibilitySnapshot, OpenSeaError> {
    let drop = data.drop_by_slug.ok_or(OpenSeaError::DropNotFound)?;
    if !matches!(drop.kind.as_str(), "Erc721SeaDropV1" | "Erc1155SeaDropV2") {
        return Err(OpenSeaError::DropNotFound);
    }
    let mut stage_keys = HashSet::new();
    let mut stages = Vec::with_capacity(drop.stages.len());
    for stage in drop.stages {
        validate_stage_identity(&drop.kind, &stage.kind, &stage.stage_type)?;
        let eligible_minter_relation = stage
            .eligible_minter_address
            .as_deref()
            .map(|address| {
                parse_address(Some(address)).map(|address| {
                    if address == wallet {
                        EligibleMinterRelation::ActiveWallet
                    } else {
                        EligibleMinterRelation::LinkedWallet
                    }
                })
            })
            .transpose()?;
        let token_range = decode_token_range(stage.from_token_id, stage.to_token_id)?;
        match drop.kind.as_str() {
            "Erc721SeaDropV1"
                if token_range.is_some()
                    || stage.max_total_mintable_by_wallet_per_token.is_some()
                    || stage
                        .eligible_max_total_mintable_by_wallet_per_token
                        .is_some() =>
            {
                return Err(OpenSeaError::Compatibility);
            }
            "Erc1155SeaDropV2" if token_range.is_none() => {
                return Err(OpenSeaError::Compatibility);
            }
            _ => {}
        }
        if !stage_keys.insert((stage.stage_index, token_range)) {
            return Err(OpenSeaError::Compatibility);
        }
        stages.push(StageEligibility {
            kind: stage.kind,
            stage_type: stage.stage_type,
            stage_index: stage.stage_index,
            is_eligible: stage.is_eligible,
            eligible_minter_relation,
            max_total_mintable_by_wallet: stage.max_total_mintable_by_wallet,
            eligible_max_total_mintable_by_wallet: stage.eligible_max_total_mintable_by_wallet,
            token_range,
            max_total_mintable_by_wallet_per_token: stage.max_total_mintable_by_wallet_per_token,
            eligible_max_total_mintable_by_wallet_per_token: stage
                .eligible_max_total_mintable_by_wallet_per_token,
            eligible_native_price_wei: stage
                .eligible_price
                .as_ref()
                .map(decode_native_price)
                .transpose()?
                .map(|price| price.0),
            eligible_price_chain_identifier: stage
                .eligible_price
                .map(|price| price.token.chain.identifier),
        });
    }
    validate_eligibility_stage_groups(&stages)?;
    if drop.kind == "Erc1155SeaDropV2" && drop.minter_quantity_minted.is_some() {
        return Err(OpenSeaError::Compatibility);
    }
    Ok(EligibilitySnapshot {
        drop_kind: drop.kind,
        minter_quantity_minted: drop.minter_quantity_minted,
        stages,
    })
}

fn build_eligibility_request_url(
    graphql_url: &Url,
    app_id: &str,
    slug: &str,
    wallet: Address,
) -> Result<Url, OpenSeaError> {
    validate_slug(slug)?;
    let address = format!("{wallet:#x}");
    let variables = EligibilityVariables {
        address: &address,
        collection_slug: slug,
    };
    let variables = serde_json::to_string(&variables).map_err(|_| OpenSeaError::Compatibility)?;
    let extensions = serde_json::json!({
        "persistedQuery": {
            "sha256Hash": ELIGIBILITY_PERSISTED_QUERY_HASH,
            "version": 1
        }
    })
    .to_string();
    let mut url = graphql_url.clone();
    url.query_pairs_mut()
        .append_pair("app_id", app_id)
        .append_pair("operationName", "DropEligibilityQuery")
        .append_pair("variables", &variables)
        .append_pair("extensions", &extensions);
    Ok(url)
}

struct DecodedMintAction {
    action_types: Vec<String>,
    error_types: Vec<String>,
    transactions: Vec<MintTransactionAction>,
}

fn validate_mint_transaction(
    decoded: DecodedMintAction,
    collection: &CollectionMetadata,
    expected_wallet: Address,
    expected_stage_type: &str,
    expected_stage_index: u32,
    expected_quantity: u64,
    expected_chain_id: u64,
) -> Result<MintTransactionAction, OpenSeaError> {
    if let Some(error) = classify_mint_action_errors(&decoded.error_types) {
        return Err(error);
    }
    if decoded.action_types.as_slice() != ["MintAction"] {
        return Err(reject_unsafe_mint_action("unexpected action sequence"));
    }
    if decoded.transactions.len() != 1 {
        return Err(reject_unsafe_mint_action(
            "expected exactly one transaction action",
        ));
    }
    let transaction = decoded
        .transactions
        .into_iter()
        .next()
        .ok_or_else(|| reject_unsafe_mint_action("missing transaction action"))?;
    if transaction.target == Address::ZERO {
        return Err(reject_unsafe_mint_action("zero transaction target"));
    }
    if transaction.network_id != expected_chain_id {
        return Err(reject_unsafe_mint_action("network ID mismatch"));
    }
    if transaction.calldata.len() < 4 {
        return Err(reject_unsafe_mint_action(
            "calldata is shorter than a selector",
        ));
    }
    validate_stage_calldata(
        collection,
        expected_wallet,
        expected_stage_type,
        expected_stage_index,
        expected_quantity,
        &transaction.calldata,
    )?;
    Ok(transaction)
}

fn classify_mint_action_errors(error_types: &[String]) -> Option<OpenSeaError> {
    if error_types
        .iter()
        .any(|error| error == "MinterNotEligibleForActiveDropStageError")
    {
        return Some(OpenSeaError::MintWalletIneligible);
    }
    if error_types.iter().any(|error| {
        matches!(
            error.as_str(),
            "MintQuantityMoreThanAllocatedForMinterError"
                | "InsufficientMintsRemainingError"
                | "UnableToFulfillQuantityError"
        )
    }) {
        return Some(OpenSeaError::MintLimitExceeded);
    }
    if error_types
        .iter()
        .any(|error| error == "InsufficientFundError")
    {
        return Some(OpenSeaError::MintInsufficientFunds);
    }
    if error_types
        .iter()
        .any(|error| error == "TradingDisabledError")
    {
        return Some(OpenSeaError::AccountCannotTrade);
    }
    if error_types.iter().any(|error| error == "DropNotFoundError") {
        return Some(OpenSeaError::DropNotFound);
    }
    if error_types
        .iter()
        .any(|error| error == "DropNotMintingError")
    {
        return Some(OpenSeaError::MintStageNotOpen);
    }
    (!error_types.is_empty()).then_some(OpenSeaError::MintActionRejected)
}

fn validate_stage_calldata(
    collection: &CollectionMetadata,
    expected_wallet: Address,
    expected_stage_type: &str,
    expected_stage_index: u32,
    expected_quantity: u64,
    calldata: &[u8],
) -> Result<(), OpenSeaError> {
    if collection.drop_kind != "Erc721SeaDropV1" {
        return Ok(());
    }
    let nft_contract = decode_abi_address(calldata, 0)?;
    let minter_if_not_payer = decode_abi_address(calldata, 2)?;
    let quantity = decode_abi_u64(calldata, 3)?;
    if nft_contract != collection.address {
        return Err(reject_unsafe_mint_action("NFT contract mismatch"));
    }
    /*
     * SeaDrop uses zero for `minterIfNotPayer` when the transaction sender is the minter.
     */
    if minter_if_not_payer != Address::ZERO && minter_if_not_payer != expected_wallet {
        return Err(reject_unsafe_mint_action("minter mismatch"));
    }
    if quantity != expected_quantity {
        return Err(reject_unsafe_mint_action("mint quantity mismatch"));
    }
    let expected_selector = match expected_stage_type {
        "PUBLIC_SALE" => [0x16, 0x1a, 0xc2, 0x1f],
        "SIGNED_PRESALE" => [0x4b, 0x61, 0xcd, 0x6f],
        "MERKLE_PRESALE" => [0x43, 0x00, 0xa4, 0xe6],
        _ => return Err(OpenSeaError::Compatibility),
    };
    if calldata.get(..4) != Some(expected_selector.as_slice()) {
        return Err(reject_unsafe_mint_action("mint selector mismatch"));
    }
    if expected_stage_type == "PUBLIC_SALE" {
        if expected_stage_index != 0 {
            return Err(OpenSeaError::Compatibility);
        }
    } else if decode_abi_u64(calldata, 8)? != u64::from(expected_stage_index) {
        return Err(reject_unsafe_mint_action("mint stage index mismatch"));
    }
    Ok(())
}

fn decode_abi_address(calldata: &[u8], word_index: usize) -> Result<Address, OpenSeaError> {
    let word = abi_word(calldata, word_index)?;
    if word[..12] != [0_u8; 12] {
        return Err(reject_unsafe_mint_action(
            "address ABI word is not canonical",
        ));
    }
    Ok(Address::from_slice(&word[12..]))
}

fn decode_abi_u64(calldata: &[u8], word_index: usize) -> Result<u64, OpenSeaError> {
    let word = abi_word(calldata, word_index)?;
    if word[..24] != [0_u8; 24] {
        return Err(reject_unsafe_mint_action("integer ABI word exceeds u64"));
    }
    let bytes: [u8; 8] = word[24..]
        .try_into()
        .map_err(|_| reject_unsafe_mint_action("integer ABI word has an invalid length"))?;
    Ok(u64::from_be_bytes(bytes))
}

fn abi_word(calldata: &[u8], word_index: usize) -> Result<&[u8], OpenSeaError> {
    let start = word_index
        .checked_mul(32)
        .and_then(|offset| offset.checked_add(4))
        .ok_or_else(|| reject_unsafe_mint_action("calldata ABI offset overflow"))?;
    let end = start
        .checked_add(32)
        .ok_or_else(|| reject_unsafe_mint_action("calldata ABI end overflow"))?;
    calldata
        .get(start..end)
        .ok_or_else(|| reject_unsafe_mint_action("calldata is missing a required ABI word"))
}

fn validate_authentication_response(
    response_body: &[u8],
    wallet: Address,
) -> Result<(), OpenSeaError> {
    let response: AuthenticationResponse =
        serde_json::from_slice(response_body).map_err(|_| OpenSeaError::Compatibility)?;
    let authenticated_address = parse_address(Some(&response.user.address))?;
    if authenticated_address != wallet {
        return Err(OpenSeaError::AuthenticationSessionMismatch);
    }
    Ok(())
}

fn decode_mint_action(data: MintActionQueryData) -> Result<DecodedMintAction, OpenSeaError> {
    let swap = data.swap.ok_or(OpenSeaError::Compatibility)?;
    let mut action_types = Vec::with_capacity(swap.actions.len());
    let mut transactions = Vec::new();
    for action in swap.actions {
        action_types.push(action.kind.clone());
        if let Some(transaction) = action.transaction_submission_data {
            transactions.push(decode_transaction(transaction)?);
        }
    }
    Ok(DecodedMintAction {
        action_types,
        error_types: swap.errors.into_iter().map(|error| error.kind).collect(),
        transactions,
    })
}

fn build_mint_action_batch_request(
    collection: &CollectionMetadata,
    requests: &[MintActionRequest],
) -> Result<(String, serde_json::Value), OpenSeaError> {
    if requests.is_empty() || requests.len() > MAX_MINT_ACTIONS_PER_GRAPHQL_REQUEST {
        return Err(OpenSeaError::InvalidProtocolValue);
    }

    let mut wallets = HashSet::with_capacity(requests.len());
    let mut query = String::from(
        "query BatchMintActionTimelineQuery($fromAssets: [AssetQuantityInput!]!, $recipient: Address",
    );
    let mut variables = serde_json::Map::new();
    variables.insert(
        "fromAssets".into(),
        serde_json::json!([{
            "asset": {
                "contractAddress": Address::ZERO.to_checksum(None),
                "chain": &collection.chain_identifier,
            }
        }]),
    );
    variables.insert("recipient".into(), serde_json::Value::Null);

    for (index, request) in requests.iter().enumerate() {
        if request.wallet == Address::ZERO
            || request.quantity == 0
            || request.token_id.is_empty()
            || !request.token_id.bytes().all(|byte| byte.is_ascii_digit())
            || !wallets.insert(request.wallet)
        {
            return Err(OpenSeaError::InvalidProtocolValue);
        }
        write!(
            &mut query,
            ", $address{index}: Address!, $toAssets{index}: [AssetQuantityInput!]!"
        )
        .map_err(|_| OpenSeaError::Compatibility)?;
        variables.insert(
            format!("address{index}"),
            serde_json::Value::String(request.wallet.to_checksum(None)),
        );
        variables.insert(
            format!("toAssets{index}"),
            serde_json::json!([{
                "asset": {
                    "contractAddress": collection.drop_address.to_checksum(None),
                    "chain": &collection.chain_identifier,
                    "tokenId": &request.token_id,
                },
                "quantity": request.quantity.to_string(),
            }]),
        );
    }

    query.push_str(") {");
    for index in 0..requests.len() {
        write!(
            &mut query,
            " wallet{index}: swap(address: $address{index}, fromAssets: $fromAssets, toAssets: $toAssets{index}, recipient: $recipient, action: MINT) {{ actions {{ __typename ... on TransactionAction {{ transactionSubmissionData {{ to data value chain {{ networkId identifier }} }} }} }} errors {{ __typename }} }}"
        )
        .map_err(|_| OpenSeaError::Compatibility)?;
    }
    query.push_str(" }");
    Ok((query, serde_json::Value::Object(variables)))
}

fn decode_mint_action_batch(
    mut data: MintActionBatchQueryData,
    collection: &CollectionMetadata,
    expected_stage: &StageMetadata,
    requests: &[MintActionRequest],
    expected_chain_id: u64,
) -> Result<Vec<MintTransactionAction>, OpenSeaError> {
    if data.swaps.len() != requests.len() {
        return Err(OpenSeaError::Compatibility);
    }
    let mut transactions = Vec::with_capacity(requests.len());
    for (index, request) in requests.iter().enumerate() {
        let swap = data
            .swaps
            .remove(&format!("wallet{index}"))
            .flatten()
            .ok_or(OpenSeaError::Compatibility)?;
        let decoded = decode_mint_action(MintActionQueryData { swap: Some(swap) })?;
        let transaction = validate_mint_transaction(
            decoded,
            collection,
            request.wallet,
            &expected_stage.stage_type,
            expected_stage.stage_index,
            request.quantity,
            expected_chain_id,
        )?;
        transactions.push(transaction);
    }
    Ok(transactions)
}

fn decode_transaction(
    transaction: TransactionSubmissionData,
) -> Result<MintTransactionAction, OpenSeaError> {
    let target = parse_address(Some(&transaction.to))
        .map_err(|_| reject_invalid_mint_action("invalid transaction target"))?;
    let data = transaction
        .data
        .strip_prefix("0x")
        .ok_or_else(|| reject_invalid_mint_action("calldata is not 0x-prefixed"))?;
    if data.len() % 2 != 0 {
        return Err(reject_invalid_mint_action("calldata has an odd hex length"));
    }
    let decoded =
        hex::decode(data).map_err(|_| reject_invalid_mint_action("calldata is not valid hex"))?;
    let value = transaction
        .value
        .map_or_else(|| "0".to_owned(), ScalarString::into_string);
    let value =
        parse_u256(&value).map_err(|_| reject_invalid_mint_action("invalid transaction value"))?;
    let network_id = transaction
        .chain
        .network_id
        .try_into_u64()
        .map_err(|_| reject_invalid_mint_action("invalid transaction network ID"))?;
    Ok(MintTransactionAction {
        target,
        chain_identifier: transaction.chain.identifier,
        network_id,
        value,
        calldata: Bytes::from(decoded),
    })
}

fn reject_unsafe_mint_action(reason: &'static str) -> OpenSeaError {
    OpenSeaError::UnsafeMintAction { reason }
}

fn reject_invalid_mint_action(reason: &'static str) -> OpenSeaError {
    logging::warn(format!(
        "OpenSea mint action could not be decoded: {reason}."
    ));
    OpenSeaError::InvalidProtocolValue
}

fn parse_address(value: Option<&str>) -> Result<Address, OpenSeaError> {
    value
        .ok_or(OpenSeaError::InvalidProtocolValue)?
        .parse()
        .map_err(|_| OpenSeaError::InvalidProtocolValue)
}

fn matching_collection_slug(
    data: CollectionSearchData,
    address: Address,
    expected_chain_id: u64,
) -> Result<String, OpenSeaError> {
    let mut matching = Vec::new();
    for result in data.collections_by_query {
        let Some(result_address) = result.address.as_deref() else {
            continue;
        };
        if result.kind != "Collection" || parse_address(Some(result_address))? != address {
            continue;
        }
        let chain = result.chain.ok_or(OpenSeaError::Compatibility)?;
        if parse_network_id(chain.network_id.as_ref())? != expected_chain_id {
            continue;
        }
        let slug = result.slug.ok_or(OpenSeaError::Compatibility)?;
        validate_slug(&slug)?;
        matching.push(slug);
    }
    matching.sort_unstable();
    matching.dedup();
    if matching.len() > 1 {
        return Err(OpenSeaError::AmbiguousCollectionLocator);
    }
    matching.pop().ok_or(OpenSeaError::CollectionNotFound)
}

fn parse_u256(value: &str) -> Result<U256, OpenSeaError> {
    if let Some(value) = value.strip_prefix("0x") {
        U256::from_str_radix(value, 16).map_err(|_| OpenSeaError::InvalidProtocolValue)
    } else {
        U256::from_str_radix(value, 10).map_err(|_| OpenSeaError::InvalidProtocolValue)
    }
}

fn decode_native_price(price: &EligiblePriceResponse) -> Result<(U256, String), OpenSeaError> {
    if parse_address(Some(&price.token.contract_address))? != Address::ZERO
        || price.token.symbol.trim().is_empty()
        || price.token.chain.identifier.trim().is_empty()
    {
        return Err(OpenSeaError::Compatibility);
    }
    Ok((
        parse_decimal_native_unit(&price.token.unit.to_string())?,
        price.token.chain.identifier.clone(),
    ))
}

fn parse_decimal_native_unit(value: &str) -> Result<U256, OpenSeaError> {
    let (mantissa, exponent) =
        value
            .split_once(['e', 'E'])
            .map_or(Ok((value, 0_i32)), |(mantissa, exponent)| {
                exponent
                    .parse::<i32>()
                    .map(|exponent| (mantissa, exponent))
                    .map_err(|_| OpenSeaError::InvalidProtocolValue)
            })?;
    if mantissa.starts_with('-') || exponent.unsigned_abs() > 255 {
        return Err(OpenSeaError::InvalidProtocolValue);
    }
    let (whole, fraction) = mantissa.split_once('.').unwrap_or((mantissa, ""));
    if whole.is_empty()
        || !whole.bytes().all(|byte| byte.is_ascii_digit())
        || !fraction.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(OpenSeaError::InvalidProtocolValue);
    }
    let digits = format!("{whole}{fraction}");
    let coefficient =
        U256::from_str_radix(&digits, 10).map_err(|_| OpenSeaError::InvalidProtocolValue)?;
    let fractional_digits =
        i32::try_from(fraction.len()).map_err(|_| OpenSeaError::InvalidProtocolValue)?;
    let scale = 18_i32
        .checked_add(exponent)
        .and_then(|scale| scale.checked_sub(fractional_digits))
        .ok_or(OpenSeaError::InvalidProtocolValue)?;
    if scale >= 0 {
        let factor = checked_power_of_ten(scale.unsigned_abs())?;
        coefficient
            .checked_mul(factor)
            .ok_or(OpenSeaError::InvalidProtocolValue)
    } else {
        let divisor = checked_power_of_ten(scale.unsigned_abs())?;
        if coefficient % divisor != U256::ZERO {
            return Err(OpenSeaError::InvalidProtocolValue);
        }
        Ok(coefficient / divisor)
    }
}

fn checked_power_of_ten(exponent: u32) -> Result<U256, OpenSeaError> {
    (0..exponent).try_fold(U256::ONE, |value, _| {
        value
            .checked_mul(U256::from(10_u8))
            .ok_or(OpenSeaError::InvalidProtocolValue)
    })
}

fn parse_network_id(value: Option<&ScalarString>) -> Result<u64, OpenSeaError> {
    match value {
        Some(ScalarString::String(value)) => value
            .parse()
            .map_err(|_| OpenSeaError::InvalidProtocolValue),
        Some(ScalarString::Unsigned(value)) => Ok(*value),
        None => Err(OpenSeaError::Compatibility),
    }
}

fn decode_token_range(
    from_token_id: Option<u64>,
    to_token_id: Option<u64>,
) -> Result<Option<(u64, u64)>, OpenSeaError> {
    match (from_token_id, to_token_id) {
        (None, None) => Ok(None),
        (Some(from), Some(to)) if from <= to => Ok(Some((from, to))),
        _ => Err(OpenSeaError::Compatibility),
    }
}

fn validate_stage_identity(
    drop_kind: &str,
    stage_kind: &str,
    stage_type: &str,
) -> Result<(), OpenSeaError> {
    let expected_stage_kind = match drop_kind {
        "Erc721SeaDropV1" => "Erc721SeaDropV1Stage",
        "Erc1155SeaDropV2" => "Erc1155SeaDropV2Stage",
        _ => return Err(OpenSeaError::Compatibility),
    };
    if stage_kind != expected_stage_kind
        || !matches!(
            stage_type,
            "PUBLIC_SALE" | "SIGNED_PRESALE" | "MERKLE_PRESALE"
        )
    {
        return Err(OpenSeaError::Compatibility);
    }
    Ok(())
}

fn validate_stage_time_window(
    start_time: Option<&str>,
    end_time: Option<&str>,
) -> Result<(), OpenSeaError> {
    let starts_at = start_time.map(parse_stage_time).transpose()?.unwrap_or(0);
    let ends_at = end_time.map(parse_stage_time).transpose()?;
    if ends_at.is_some_and(|end| end <= starts_at) {
        return Err(OpenSeaError::Compatibility);
    }
    Ok(())
}

fn parse_stage_time(value: &str) -> Result<u64, OpenSeaError> {
    let timestamp = OffsetDateTime::parse(value, &Rfc3339)
        .map_err(|_| OpenSeaError::Compatibility)?
        .unix_timestamp();
    u64::try_from(timestamp).map_err(|_| OpenSeaError::Compatibility)
}

fn validate_metadata_stage_groups(stages: &[StageMetadata]) -> Result<(), OpenSeaError> {
    for (index, stage) in stages.iter().enumerate() {
        for sibling in stages.iter().skip(index + 1) {
            if stage.stage_index != sibling.stage_index {
                continue;
            }
            if stage.kind != sibling.kind
                || stage.stage_type != sibling.stage_type
                || stage.start_time != sibling.start_time
                || stage.end_time != sibling.end_time
                || stage.max_total_mintable_by_wallet != sibling.max_total_mintable_by_wallet
                || token_ranges_overlap(stage.token_range, sibling.token_range)
            {
                return Err(OpenSeaError::Compatibility);
            }
        }
    }
    Ok(())
}

fn validate_eligibility_stage_groups(stages: &[StageEligibility]) -> Result<(), OpenSeaError> {
    for (index, stage) in stages.iter().enumerate() {
        for sibling in stages.iter().skip(index + 1) {
            if stage.stage_index != sibling.stage_index {
                continue;
            }
            if stage.kind != sibling.kind
                || stage.stage_type != sibling.stage_type
                || stage.max_total_mintable_by_wallet != sibling.max_total_mintable_by_wallet
                || token_ranges_overlap(stage.token_range, sibling.token_range)
            {
                return Err(OpenSeaError::Compatibility);
            }
        }
    }
    Ok(())
}

fn token_ranges_overlap(left: Option<(u64, u64)>, right: Option<(u64, u64)>) -> bool {
    match (left, right) {
        (Some((left_from, left_to)), Some((right_from, right_to))) => {
            left_from <= right_to && right_from <= left_to
        }
        _ => true,
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GraphQlRequest<'a, V: ?Sized> {
    operation_name: &'a str,
    query: &'a str,
    variables: &'a V,
}

#[derive(Deserialize)]
struct GraphQlEnvelope<T> {
    data: Option<T>,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    errors: Vec<GraphQlError>,
    extensions: Option<GraphQlResponseExtensions>,
}

#[derive(Deserialize)]
struct GraphQlError {
    #[serde(default)]
    message: String,
    extensions: Option<GraphQlErrorExtensions>,
}

#[derive(Deserialize)]
struct GraphQlErrorExtensions {
    code: Option<String>,
}

#[derive(Deserialize)]
struct GraphQlResponseExtensions {
    auth: Option<GraphQlAuthExtension>,
}

#[derive(Deserialize)]
struct GraphQlAuthExtension {
    error: Option<GraphQlAuthError>,
}

#[derive(Deserialize)]
struct GraphQlAuthError {
    message: Option<String>,
}

#[derive(Deserialize)]
struct NonceResponse {
    nonce: String,
}

#[derive(Deserialize)]
struct AuthenticationResponse {
    user: AuthenticationUser,
}

#[derive(Deserialize)]
struct AuthenticationUser {
    address: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct VerifyRequest<'a> {
    message: ParsedSiweMessage<'a>,
    signature: &'a str,
    chain_arch: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ParsedSiweMessage<'a> {
    domain: &'a str,
    address: &'a str,
    statement: &'static str,
    uri: &'a str,
    version: &'static str,
    chain_id: String,
    nonce: &'a str,
    issued_at: &'a str,
    account_type: &'static str,
}

#[derive(Serialize)]
struct CollectionVariables<'a> {
    slug: &'a str,
}

#[derive(Deserialize)]
struct CollectionQueryData {
    #[serde(rename = "collectionBySlug")]
    collection_by_slug: Option<CollectionResult>,
}

#[derive(Deserialize)]
struct CollectionResult {
    #[serde(rename = "__typename")]
    kind: String,
    slug: Option<String>,
    address: Option<String>,
    chain: Option<ChainIdentifier>,
    drop: Option<DropMetadataResponse>,
}

#[derive(Deserialize)]
struct DropMetadataResponse {
    #[serde(rename = "__typename")]
    kind: String,
    identifier: Option<DropIdentifier>,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    stages: Vec<StageMetadataResponse>,
}

#[derive(Deserialize)]
struct DropIdentifier {
    #[serde(rename = "contractAddress")]
    contract_address: String,
    chain: ChainIdentifier,
}

#[derive(Deserialize)]
struct ChainIdentifier {
    identifier: String,
    #[serde(rename = "networkId")]
    network_id: Option<ScalarString>,
}

#[derive(Serialize)]
struct CollectionSearchVariables<'a> {
    query: &'a str,
}

#[derive(Deserialize)]
struct CollectionSearchData {
    #[serde(
        rename = "collectionsByQuery",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    collections_by_query: Vec<CollectionSearchResult>,
}

#[derive(Deserialize)]
struct CollectionSearchResult {
    #[serde(rename = "__typename")]
    kind: String,
    slug: Option<String>,
    address: Option<String>,
    chain: Option<ChainIdentifier>,
}

#[derive(Deserialize)]
struct StageMetadataResponse {
    #[serde(rename = "__typename")]
    kind: String,
    #[serde(rename = "stageType")]
    stage_type: String,
    #[serde(rename = "stageIndex", deserialize_with = "deserialize_u32")]
    stage_index: u32,
    #[serde(rename = "startTime")]
    start_time: Option<String>,
    #[serde(rename = "endTime")]
    end_time: Option<String>,
    #[serde(
        rename = "maxTotalMintableByWallet",
        default,
        deserialize_with = "deserialize_optional_u64"
    )]
    max_total_mintable_by_wallet: Option<u64>,
    #[serde(
        rename = "maxTotalMintableByWalletPerToken",
        default,
        deserialize_with = "deserialize_optional_u64"
    )]
    max_total_mintable_by_wallet_per_token: Option<u64>,
    #[serde(
        rename = "fromTokenId",
        default,
        deserialize_with = "deserialize_optional_u64"
    )]
    from_token_id: Option<u64>,
    #[serde(
        rename = "toTokenId",
        default,
        deserialize_with = "deserialize_optional_u64"
    )]
    to_token_id: Option<u64>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EligibilityVariables<'a> {
    address: &'a str,
    collection_slug: &'a str,
}

#[derive(Deserialize)]
struct EligibilityQueryData {
    #[serde(rename = "dropBySlug")]
    drop_by_slug: Option<EligibilityDropResponse>,
}

#[derive(Deserialize)]
struct EligibilityDropResponse {
    #[serde(rename = "__typename")]
    kind: String,
    #[serde(
        rename = "minterQuantityMinted",
        default,
        deserialize_with = "deserialize_optional_u64"
    )]
    minter_quantity_minted: Option<u64>,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    stages: Vec<StageEligibilityResponse>,
}

#[derive(Deserialize)]
struct StageEligibilityResponse {
    #[serde(rename = "__typename")]
    kind: String,
    #[serde(rename = "stageType")]
    stage_type: String,
    #[serde(rename = "stageIndex", deserialize_with = "deserialize_u32")]
    stage_index: u32,
    #[serde(rename = "isEligible")]
    is_eligible: Option<bool>,
    #[serde(rename = "eligibleMinterAddress")]
    eligible_minter_address: Option<String>,
    #[serde(
        rename = "maxTotalMintableByWallet",
        default,
        deserialize_with = "deserialize_optional_u64"
    )]
    max_total_mintable_by_wallet: Option<u64>,
    #[serde(
        rename = "eligibleMaxTotalMintableByWallet",
        default,
        deserialize_with = "deserialize_optional_u64"
    )]
    eligible_max_total_mintable_by_wallet: Option<u64>,
    #[serde(rename = "eligiblePrice")]
    eligible_price: Option<EligiblePriceResponse>,
    #[serde(
        rename = "fromTokenId",
        default,
        deserialize_with = "deserialize_optional_u64"
    )]
    from_token_id: Option<u64>,
    #[serde(
        rename = "toTokenId",
        default,
        deserialize_with = "deserialize_optional_u64"
    )]
    to_token_id: Option<u64>,
    #[serde(
        rename = "maxTotalMintableByWalletPerToken",
        default,
        deserialize_with = "deserialize_optional_u64"
    )]
    max_total_mintable_by_wallet_per_token: Option<u64>,
    #[serde(
        rename = "eligibleMaxTotalMintableByWalletPerToken",
        default,
        deserialize_with = "deserialize_optional_u64"
    )]
    eligible_max_total_mintable_by_wallet_per_token: Option<u64>,
}

#[derive(Deserialize)]
struct EligiblePriceResponse {
    token: EligibleTokenPriceResponse,
}

#[derive(Deserialize)]
struct EligibleTokenPriceResponse {
    unit: serde_json::Number,
    symbol: String,
    #[serde(rename = "contractAddress")]
    contract_address: String,
    chain: EligiblePriceChainResponse,
}

#[derive(Deserialize)]
struct EligiblePriceChainResponse {
    identifier: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MintActionVariables<'a> {
    address: &'a str,
    from_assets: &'a [AssetQuantityInput<'a>],
    to_assets: &'a [AssetQuantityInput<'a>],
    recipient: Option<&'a str>,
}

#[derive(Serialize)]
struct AssetQuantityInput<'a> {
    asset: AssetInput<'a>,
    #[serde(skip_serializing_if = "Option::is_none")]
    quantity: Option<&'a str>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AssetInput<'a> {
    contract_address: &'a str,
    chain: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    token_id: Option<&'a str>,
}

#[derive(Deserialize)]
struct MintActionQueryData {
    swap: Option<SwapResponse>,
}

#[derive(Deserialize)]
struct MintActionBatchQueryData {
    #[serde(flatten)]
    swaps: HashMap<String, Option<SwapResponse>>,
}

#[derive(Deserialize)]
struct SwapResponse {
    #[serde(default, deserialize_with = "deserialize_null_default")]
    actions: Vec<ActionResponse>,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    errors: Vec<ActionErrorResponse>,
}

#[derive(Deserialize)]
struct ActionResponse {
    #[serde(rename = "__typename")]
    kind: String,
    #[serde(rename = "transactionSubmissionData")]
    transaction_submission_data: Option<TransactionSubmissionData>,
}

#[derive(Deserialize)]
struct ActionErrorResponse {
    #[serde(rename = "__typename")]
    kind: String,
}

#[derive(Deserialize)]
struct TransactionSubmissionData {
    to: String,
    data: String,
    value: Option<ScalarString>,
    chain: TransactionChain,
}

#[derive(Deserialize)]
struct TransactionChain {
    #[serde(rename = "networkId")]
    network_id: ScalarString,
    identifier: String,
}

fn deserialize_null_default<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de> + Default,
{
    Ok(Option::<T>::deserialize(deserializer)?.unwrap_or_default())
}

fn deserialize_optional_u64<'de, D>(deserializer: D) -> Result<Option<u64>, D::Error>
where
    D: Deserializer<'de>,
{
    Option::<ScalarString>::deserialize(deserializer)?
        .map(ScalarString::try_into_u64)
        .transpose()
        .map_err(serde::de::Error::custom)
}

fn deserialize_u32<'de, D>(deserializer: D) -> Result<u32, D::Error>
where
    D: Deserializer<'de>,
{
    let value = ScalarString::deserialize(deserializer)?
        .try_into_u64()
        .map_err(serde::de::Error::custom)?;
    u32::try_from(value).map_err(serde::de::Error::custom)
}

#[derive(Deserialize)]
#[serde(untagged)]
enum ScalarString {
    String(String),
    Unsigned(u64),
}

impl ScalarString {
    fn try_into_u64(self) -> Result<u64, &'static str> {
        match self {
            Self::String(value) => value.parse().map_err(|_| "invalid unsigned integer"),
            Self::Unsigned(value) => Ok(value),
        }
    }

    fn into_string(self) -> String {
        match self {
            Self::String(value) => value,
            Self::Unsigned(value) => value.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use reqwest::cookie::CookieStore;

    use super::*;

    #[test]
    fn converts_captured_native_price_numbers_to_exact_wei() {
        assert_eq!(
            parse_decimal_native_unit("0.125").expect("decimal"),
            U256::from(125_000_000_000_000_000_u64)
        );
        assert_eq!(
            parse_decimal_native_unit("1e-9").expect("exponent"),
            U256::from(1_000_000_000_u64)
        );
        assert!(parse_decimal_native_unit("0.0000000000000000001").is_err());
        assert!(parse_decimal_native_unit("-1").is_err());
    }

    #[test]
    fn parses_collection_locator_without_accepting_other_hosts() {
        assert_eq!(
            parse_collection_locator("https://opensea.io/collection/test-collection-zun/overview")
                .expect("valid locator"),
            CollectionLocator::Slug("test-collection-zun".into())
        );
        assert!(parse_collection_locator("https://example.com/collection/test").is_err());
        assert!(parse_collection_locator("../test").is_err());
    }

    #[test]
    fn contract_search_requires_an_exact_address_and_rpc_chain_match() {
        let address = "0x90a76eca33e635ebb260a699ef9ee65d02335ed9"
            .parse()
            .expect("address");
        let data: CollectionSearchData = serde_json::from_value(serde_json::json!({
            "collectionsByQuery": [
                {
                    "__typename": "Collection",
                    "slug": "wrong-chain",
                    "address": "0x90a76eca33e635ebb260a699ef9ee65d02335ed9",
                    "chain": { "identifier": "ethereum", "networkId": 1 }
                },
                {
                    "__typename": "Collection",
                    "slug": "fixture",
                    "address": "0x90a76eca33e635ebb260a699ef9ee65d02335ed9",
                    "chain": { "identifier": "base", "networkId": "8453" }
                },
                {
                    "__typename": "Collection",
                    "slug": "no-contract",
                    "address": null,
                    "chain": { "identifier": "base", "networkId": 8453 }
                }
            ]
        }))
        .expect("captured search shape");

        assert_eq!(
            matching_collection_slug(data, address, 8453).expect("exact result"),
            "fixture"
        );
    }

    #[test]
    fn creates_captured_siwe_message_exactly() {
        let message = create_siwe_message(
            "opensea.io",
            "0xA0Cf798816D4b9b9866b5330EEa46a18382f251e",
            "https://opensea.io/collection/test-collection-zun/overview",
            8453,
            "foobarbaz",
            "2026-08-12T00:00:00Z",
        );
        assert!(
            message
                .starts_with("opensea.io wants you to sign in with your Ethereum account:\n0xA0Cf")
        );
        assert!(message.contains("\nChain ID: 8453\nNonce: foobarbaz\n"));
        assert!(!message.contains("Signature"));
    }

    #[test]
    fn classifies_known_graphql_failures_without_returning_raw_text() {
        let errors = [GraphQlError {
            message: "Account can not perform trading operations: secret trace".into(),
            extensions: None,
        }];
        assert!(matches!(
            classify_graphql_errors(&errors),
            OpenSeaError::AccountCannotTrade
        ));
        assert_eq!(
            classify_graphql_errors(&errors).to_string(),
            "OpenSea rejected this account for trading operations"
        );
    }

    #[test]
    fn classifies_graphql_codes_and_captured_auth_extensions() {
        let rate_limited = [GraphQlError {
            message: String::new(),
            extensions: Some(GraphQlErrorExtensions {
                code: Some("TOO_MANY_REQUESTS".into()),
            }),
        }];
        assert!(matches!(
            classify_graphql_errors(&rate_limited),
            OpenSeaError::RateLimited
        ));

        let envelope: GraphQlEnvelope<EligibilityQueryData> =
            serde_json::from_value(serde_json::json!({
                "data": null,
                "extensions": {
                    "auth": {
                        "error": {
                            "message": "Unauthorized",
                            "classification": "AUTHENTICATION",
                            "errorType": "SESSION_EXPIRED"
                        }
                    }
                }
            }))
            .expect("captured auth extension");
        assert!(matches!(
            decode_graphql_envelope(envelope),
            Err(OpenSeaError::AuthenticationRequired)
        ));
    }

    #[test]
    fn recognizes_every_captured_persisted_query_retry_signal() {
        for message in [
            "PersistedQueryNotFound",
            "PersistedQueryNotSupported",
            "PersistedQueryIdInvalid",
        ] {
            assert!(is_persisted_query_retryable(&[GraphQlError {
                message: message.into(),
                extensions: None,
            }]));
        }
        for code in [
            "PERSISTED_QUERY_NOT_FOUND",
            "PERSISTED_QUERY_NOT_SUPPORTED",
            "PERSISTED_QUERY_ID_INVALID",
        ] {
            assert!(is_persisted_query_retryable(&[GraphQlError {
                message: String::new(),
                extensions: Some(GraphQlErrorExtensions {
                    code: Some(code.into()),
                }),
            }]));
        }
        assert!(!is_persisted_query_retryable(&[GraphQlError {
            message: "Unrelated failure".into(),
            extensions: None,
        }]));
    }

    #[test]
    fn retries_only_transient_request_failures() {
        for error in [
            OpenSeaError::Transport,
            OpenSeaError::RateLimited,
            OpenSeaError::Http(408),
            OpenSeaError::Http(429),
            OpenSeaError::Http(503),
            OpenSeaError::Authentication(425),
        ] {
            assert!(is_retryable_request_error(&error), "{error}");
        }

        for error in [
            OpenSeaError::Compatibility,
            OpenSeaError::InvalidNonceResponse,
            OpenSeaError::AuthenticationSessionMismatch,
            OpenSeaError::MintWalletIneligible,
            OpenSeaError::UnsafeMintAction { reason: "test" },
        ] {
            assert!(!is_retryable_request_error(&error), "{error}");
        }
    }

    #[test]
    fn distinguishes_retryable_body_transport_failures_from_protocol_limits() {
        assert!(matches!(
            map_protocol_body_error(BodyReadError::Transport),
            OpenSeaError::Transport
        ));
        assert!(matches!(
            map_protocol_body_error(BodyReadError::LimitExceeded),
            OpenSeaError::Compatibility
        ));
    }

    #[test]
    fn builds_the_captured_persisted_eligibility_request() {
        let wallet: Address = "0x0e1730aab680245971603f9edeaa0c85ebeaaaaa"
            .parse()
            .expect("wallet");
        let url = build_eligibility_request_url(
            &Url::parse("https://gql.opensea.io/graphql").expect("GraphQL URL"),
            "os2-web",
            "test-collection-zun",
            wallet,
        )
        .expect("eligibility URL");
        let query = url
            .query_pairs()
            .into_owned()
            .collect::<std::collections::HashMap<_, _>>();

        assert_eq!(query.get("app_id").map(String::as_str), Some("os2-web"));
        assert_eq!(
            query.get("operationName").map(String::as_str),
            Some("DropEligibilityQuery")
        );
        let variables: serde_json::Value = serde_json::from_str(
            query
                .get("variables")
                .expect("serialized eligibility variables"),
        )
        .expect("variables JSON");
        assert_eq!(
            variables["address"],
            "0x0e1730aab680245971603f9edeaa0c85ebeaaaaa"
        );
        assert_eq!(variables["collectionSlug"], "test-collection-zun");
        let extensions: serde_json::Value = serde_json::from_str(
            query
                .get("extensions")
                .expect("serialized persisted-query extension"),
        )
        .expect("extensions JSON");
        assert_eq!(extensions["persistedQuery"]["version"], 1);
        assert_eq!(
            extensions["persistedQuery"]["sha256Hash"],
            ELIGIBILITY_PERSISTED_QUERY_HASH
        );
    }

    #[test]
    fn scopes_the_connected_account_hint_to_the_graphql_subdomain() {
        let wallet: Address = "0x0e1730aab680245971603f9edeaa0c85ebeaaaaa"
            .parse()
            .expect("wallet");
        let site_url = Url::parse("https://opensea.io").expect("site URL");
        let graphql_url = Url::parse("https://gql.opensea.io/graphql").expect("GraphQL URL");
        let cookie = connected_account_hint_cookie(&site_url, wallet).expect("hint cookie");
        let jar = Jar::default();
        jar.add_cookie_str(&cookie, &site_url);
        let graphql_cookies = jar
            .cookies(&graphql_url)
            .expect("GraphQL cookie header")
            .to_str()
            .expect("ASCII cookie header")
            .to_owned();

        assert!(
            graphql_cookies.contains(
                "connected-account-server-hint=0x0e1730aab680245971603f9edeaa0c85ebeaaaaa"
            )
        );
    }

    #[test]
    fn decodes_the_captured_eligible_wallet_response() {
        let wallet: Address = "0x0e1730aab680245971603f9edeaa0c85ebeaaaaa"
            .parse()
            .expect("wallet");
        let envelope: GraphQlEnvelope<EligibilityQueryData> =
            serde_json::from_value(serde_json::json!({
                "data": {
                    "dropBySlug": {
                        "__typename": "Erc721SeaDropV1",
                        "minterQuantityMinted": null,
                        "stages": [
                            {
                                "stageType": "SIGNED_PRESALE",
                                "stageIndex": 1,
                                "isEligible": true,
                                "eligibleMinterAddress": "0x0e1730aab680245971603f9edeaa0c85ebeaaaaa",
                                "maxTotalMintableByWallet": 1000,
                                "eligibleMaxTotalMintableByWallet": 1000,
                                "eligiblePrice": {
                                    "usd": 0.0,
                                    "token": {
                                        "unit": 0.0,
                                        "symbol": "ETH",
                                        "contractAddress": "0x0000000000000000000000000000000000000000",
                                        "chain": {
                                            "identifier": "base",
                                            "__typename": "Chain"
                                        },
                                        "__typename": "TokenPrice"
                                    },
                                    "__typename": "Price"
                                },
                                "__typename": "Erc721SeaDropV1Stage"
                            },
                            {
                                "stageType": "PUBLIC_SALE",
                                "stageIndex": 0,
                                "isEligible": true,
                                "eligibleMinterAddress": "0x0e1730aab680245971603f9edeaa0c85ebeaaaaa",
                                "maxTotalMintableByWallet": 1000,
                                "eligibleMaxTotalMintableByWallet": 2000,
                                "eligiblePrice": {
                                    "usd": 0.0,
                                    "token": {
                                        "unit": 0.0,
                                        "symbol": "ETH",
                                        "contractAddress": "0x0000000000000000000000000000000000000000",
                                        "chain": {
                                            "identifier": "base",
                                            "__typename": "Chain"
                                        },
                                        "__typename": "TokenPrice"
                                    },
                                    "__typename": "Price"
                                },
                                "__typename": "Erc721SeaDropV1Stage"
                            }
                        ]
                    }
                },
                "extensions": { "debugInfo": { "additionalInformation": {} } }
            }))
            .expect("persisted eligibility response");
        let snapshot = decode_eligibility(envelope.data.expect("response data"), wallet)
            .expect("eligibility snapshot");

        assert_eq!(snapshot.stages.len(), 2);
        assert_eq!(snapshot.stages[0].is_eligible, Some(true));
        assert_eq!(
            snapshot.stages[0].eligible_minter_relation,
            Some(EligibleMinterRelation::ActiveWallet)
        );
        assert_eq!(snapshot.stages[0].max_total_mintable_by_wallet, Some(1000));
        assert_eq!(
            snapshot.stages[0].eligible_max_total_mintable_by_wallet,
            Some(1000)
        );
    }

    #[test]
    fn accepts_additive_fields_and_decimal_string_eligibility_scalars() {
        let wallet: Address = "0x0e1730aab680245971603f9edeaa0c85ebeaaaaa"
            .parse()
            .expect("wallet");
        let envelope: GraphQlEnvelope<EligibilityQueryData> =
            serde_json::from_value(serde_json::json!({
                "data": {
                    "dropBySlug": {
                        "__typename": "Erc1155SeaDropV2",
                        "futureDropField": { "ignored": true },
                        "stages": [{
                            "__typename": "Erc1155SeaDropV2Stage",
                            "stageType": "SIGNED_PRESALE",
                            "stageIndex": "1",
                            "isEligible": true,
                            "eligibleMinterAddress": "0x0e1730aab680245971603f9edeaa0c85ebeaaaaa",
                            "maxTotalMintableByWallet": "1000",
                            "eligibleMaxTotalMintableByWallet": "25",
                            "fromTokenId": "10",
                            "toTokenId": "12",
                            "maxTotalMintableByWalletPerToken": "5",
                            "eligibleMaxTotalMintableByWalletPerToken": "7",
                            "futureStageField": [1, 2, 3]
                        }]
                    },
                    "futureRootField": "ignored"
                },
                "errors": null,
                "extensions": { "debugInfo": { "trace": "ignored" } },
                "futureEnvelopeField": true
            }))
            .expect("forward-compatible response");
        let snapshot = decode_eligibility(
            decode_graphql_envelope(envelope).expect("GraphQL data"),
            wallet,
        )
        .expect("eligibility snapshot");

        assert_eq!(snapshot.stages[0].stage_index, 1);
        assert_eq!(snapshot.stages[0].token_range, Some((10, 12)));
        assert_eq!(
            snapshot.stages[0].eligible_max_total_mintable_by_wallet,
            Some(25)
        );
        assert_eq!(
            snapshot.stages[0].eligible_max_total_mintable_by_wallet_per_token,
            Some(7)
        );
    }

    #[test]
    fn accepts_only_one_normal_mint_action_on_the_expected_chain() {
        let response: MintActionQueryData = serde_json::from_value(serde_json::json!({
            "swap": {
                "actions": [{
                    "__typename": "MintAction",
                    "futureActionField": { "ignored": true },
                    "transactionSubmissionData": {
                        "to": "0x00005EA00Ac477B1030CE78506496e8C2dE24bf5",
                        "data": erc721_calldata("4b61cd6f"),
                        "value": "0",
                        "chain": {
                            "networkId": "8453",
                            "identifier": "base-alias",
                            "futureChainField": 1
                        },
                        "futureTransactionField": "ignored"
                    }
                }],
                "errors": null,
                "futureSwapField": ["ignored"]
            }
        }))
        .expect("captured response");
        let collection = collection_fixture();
        let transaction = validate_mint_transaction(
            decode_mint_action(response).expect("decode"),
            &collection,
            wallet_fixture(),
            "SIGNED_PRESALE",
            1,
            1,
            8453,
        )
        .expect("safe action");

        assert_eq!(transaction.network_id, 8453);
        assert_eq!(transaction.chain_identifier, "base-alias");
        assert_eq!(
            transaction.calldata.get(..4),
            Some([0x4b, 0x61, 0xcd, 0x6f].as_slice())
        );
    }

    #[test]
    fn reports_collection_and_rpc_chain_mismatch_explicitly() {
        let collection = collection_fixture();
        assert!(validate_collection_chain(&collection, 8453).is_ok());
        assert!(matches!(
            validate_collection_chain(&collection, 4663),
            Err(OpenSeaError::CollectionChainMismatch {
                collection_chain_id: 8453,
                rpc_chain_id: 4663
            })
        ));
    }

    #[test]
    fn builds_one_aliased_mint_query_with_wallet_specific_inputs() {
        let requests = [
            MintActionRequest {
                wallet: "0x0e1730aab680245971603f9edeaa0c85ebeaaaaa"
                    .parse()
                    .expect("wallet"),
                token_id: "0".into(),
                quantity: 1,
            },
            MintActionRequest {
                wallet: "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"
                    .parse()
                    .expect("wallet"),
                token_id: "0".into(),
                quantity: 2,
            },
        ];
        let (query, variables) =
            build_mint_action_batch_request(&collection_fixture(), &requests).expect("batch");

        assert!(query.contains("wallet0: swap(address: $address0"));
        assert!(query.contains("wallet1: swap(address: $address1"));
        assert_eq!(
            variables["toAssets1"][0]["quantity"],
            serde_json::Value::String("2".into())
        );
        assert!(!query.contains("0e1730aa"));
    }

    #[test]
    fn batch_decoder_preserves_order_and_binds_every_quantity() {
        let requests = [
            MintActionRequest {
                wallet: "0x0e1730aab680245971603f9edeaa0c85ebeaaaaa"
                    .parse()
                    .expect("wallet"),
                token_id: "0".into(),
                quantity: 1,
            },
            MintActionRequest {
                wallet: "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"
                    .parse()
                    .expect("wallet"),
                token_id: "0".into(),
                quantity: 2,
            },
        ];
        let response: MintActionBatchQueryData = serde_json::from_value(serde_json::json!({
            "wallet1": mint_action_response("4b61cd6f", 2, requests[1].wallet),
            "wallet0": mint_action_response("4b61cd6f", 1, requests[0].wallet),
        }))
        .expect("batch response");
        let stage = StageMetadata {
            kind: "Erc721SeaDropV1Stage".into(),
            stage_type: "SIGNED_PRESALE".into(),
            stage_index: 1,
            start_time: None,
            end_time: None,
            max_total_mintable_by_wallet: Some(10),
            max_total_mintable_by_wallet_per_token: None,
            token_range: None,
        };

        let transactions =
            decode_mint_action_batch(response, &collection_fixture(), &stage, &requests, 8453)
                .expect("safe batch");
        assert_eq!(transactions.len(), 2);
        assert!(
            validate_stage_calldata(
                &collection_fixture(),
                requests[1].wallet,
                "SIGNED_PRESALE",
                1,
                2,
                &transactions[1].calldata,
            )
            .is_ok()
        );
    }

    #[test]
    fn rejects_mint_calldata_for_a_different_erc721_stage_type() {
        let response: MintActionQueryData = serde_json::from_value(serde_json::json!({
            "swap": {
                "actions": [{
                    "__typename": "MintAction",
                    "transactionSubmissionData": {
                        "to": "0x00005EA00Ac477B1030CE78506496e8C2dE24bf5",
                        "data": erc721_calldata("4b61cd6f"),
                        "value": "0",
                        "chain": { "networkId": "8453", "identifier": "base" }
                    }
                }],
                "errors": []
            }
        }))
        .expect("captured response");
        let error = validate_mint_transaction(
            decode_mint_action(response).expect("decode"),
            &collection_fixture(),
            wallet_fixture(),
            "PUBLIC_SALE",
            0,
            1,
            8453,
        )
        .expect_err("signed-presale calldata cannot authorize a public-sale job");

        assert!(matches!(error, OpenSeaError::UnsafeMintAction { .. }));
    }

    #[test]
    fn rejects_erc721_calldata_for_a_different_nft_contract() {
        let mut calldata = hex::decode(
            erc721_calldata("4b61cd6f")
                .strip_prefix("0x")
                .expect("hex prefix"),
        )
        .expect("calldata");
        calldata[4..36].fill(0);
        calldata[35] = 1;
        let error = validate_stage_calldata(
            &collection_fixture(),
            wallet_fixture(),
            "SIGNED_PRESALE",
            1,
            1,
            &calldata,
        )
        .expect_err("calldata must name the discovered collection contract");

        assert!(matches!(error, OpenSeaError::UnsafeMintAction { .. }));
    }

    #[test]
    fn rejects_erc721_calldata_for_a_different_minter() {
        let calldata = hex::decode(
            erc721_calldata("4b61cd6f")
                .strip_prefix("0x")
                .expect("hex prefix"),
        )
        .expect("calldata");
        let other_wallet = "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"
            .parse()
            .expect("wallet");

        assert!(matches!(
            validate_stage_calldata(
                &collection_fixture(),
                other_wallet,
                "SIGNED_PRESALE",
                1,
                1,
                &calldata,
            ),
            Err(OpenSeaError::UnsafeMintAction { .. })
        ));
    }

    #[test]
    fn accepts_zero_minter_if_not_payer_for_the_calling_wallet() {
        let mut calldata = hex::decode(
            erc721_calldata("4b61cd6f")
                .strip_prefix("0x")
                .expect("hex prefix"),
        )
        .expect("calldata");
        calldata[4 + 2 * 32..4 + 3 * 32].fill(0);

        validate_stage_calldata(
            &collection_fixture(),
            wallet_fixture(),
            "SIGNED_PRESALE",
            1,
            1,
            &calldata,
        )
        .expect("zero minter-if-not-payer binds the mint to msg.sender");
    }

    #[test]
    fn binds_erc721_calldata_to_stage_and_quantity() {
        let calldata = hex::decode(
            erc721_calldata("4b61cd6f")
                .strip_prefix("0x")
                .expect("hex prefix"),
        )
        .expect("calldata");
        assert!(matches!(
            validate_stage_calldata(
                &collection_fixture(),
                wallet_fixture(),
                "SIGNED_PRESALE",
                2,
                1,
                &calldata,
            ),
            Err(OpenSeaError::UnsafeMintAction { .. })
        ));
        assert!(matches!(
            validate_stage_calldata(
                &collection_fixture(),
                wallet_fixture(),
                "SIGNED_PRESALE",
                1,
                2,
                &calldata,
            ),
            Err(OpenSeaError::UnsafeMintAction { .. })
        ));
    }

    #[test]
    fn authentication_response_must_match_the_configured_wallet() {
        let wallet: Address = "0x90a76eca33e635ebb260a699ef9ee65d02335ed9"
            .parse()
            .expect("wallet");
        validate_authentication_response(
            br#"{"user":{"address":"0x90a76eca33e635ebb260a699ef9ee65d02335ed9"}}"#,
            wallet,
        )
        .expect("matching wallet");

        let error = validate_authentication_response(
            br#"{"user":{"address":"0x0000000000000000000000000000000000000001"}}"#,
            wallet,
        )
        .expect_err("mismatched wallet session");
        assert!(matches!(error, OpenSeaError::AuthenticationSessionMismatch));
    }

    #[test]
    fn rejects_action_errors_without_returning_a_transaction() {
        let response: MintActionQueryData = serde_json::from_value(serde_json::json!({
            "swap": {
                "actions": [],
                "errors": [{"__typename": "NotEligible"}]
            }
        }))
        .expect("captured response");
        let error = validate_mint_transaction(
            decode_mint_action(response).expect("decode"),
            &collection_fixture(),
            wallet_fixture(),
            "SIGNED_PRESALE",
            1,
            1,
            8453,
        )
        .expect_err("action error must stop execution");

        assert!(matches!(error, OpenSeaError::MintActionRejected));
    }

    #[test]
    fn classifies_captured_mint_eligibility_errors_for_retry_policy() {
        let classify = |error: &str| classify_mint_action_errors(&[error.to_owned()]);

        assert!(matches!(
            classify("DropNotMintingError"),
            Some(OpenSeaError::MintStageNotOpen)
        ));
        assert!(matches!(
            classify("MinterNotEligibleForActiveDropStageError"),
            Some(OpenSeaError::MintWalletIneligible)
        ));
        assert!(matches!(
            classify("MintQuantityMoreThanAllocatedForMinterError"),
            Some(OpenSeaError::MintLimitExceeded)
        ));
        assert!(matches!(
            classify("InsufficientMintsRemainingError"),
            Some(OpenSeaError::MintLimitExceeded)
        ));
        assert!(matches!(
            classify("UnableToFulfillQuantityError"),
            Some(OpenSeaError::MintLimitExceeded)
        ));
        assert!(matches!(
            classify("InsufficientFundError"),
            Some(OpenSeaError::MintInsufficientFunds)
        ));
        assert!(matches!(
            classify("TradingDisabledError"),
            Some(OpenSeaError::AccountCannotTrade)
        ));
        assert!(matches!(
            classify("DropNotFoundError"),
            Some(OpenSeaError::DropNotFound)
        ));
        assert!(matches!(
            classify("UnknownMintError"),
            Some(OpenSeaError::MintActionRejected)
        ));
        assert!(classify_mint_action_errors(&[]).is_none());
    }

    #[test]
    fn fails_closed_for_every_transaction_error_typename_in_the_capture() {
        let captured_transaction_errors = [
            "CollectionNotFoundError",
            "CreatorFeesOverrideNotAllowedError",
            "CreatorFeesRoyaltyRegistryChainNotSupportedError",
            "CreatorFeesTooHighError",
            "CreatorFeesTooManyFeesError",
            "CrossChainPayerNotAllowedForDropError",
            "DropNotFoundError",
            "DropNotMintingError",
            "DropPublishError",
            "EstimateGasFailureError",
            "InsufficientFundError",
            "InsufficientMintsRemainingError",
            "InvalidAssetIdentifierError",
            "InvalidOfferIncrementError",
            "InvalidOrderSignatureError",
            "InvalidPaymentAssetError",
            "MintQuantityMoreThanAllocatedForMinterError",
            "MinterNotEligibleForActiveDropStageError",
            "NoTraitItemsFoundError",
            "OrderChainMismatchError",
            "OrderFinalizedError",
            "OrderLeverageBalanceRatioError",
            "OrderLeverageUserZeroBalanceError",
            "OrderNotFound",
            "OrderNotVendableError",
            "OrderPriceChangeError",
            "OrderProtocolMismatchError",
            "OrderProviderError",
            "OrderUnknownError",
            "SwapProvidersUnavailableError",
            "TradingDisabledError",
            "TraitMismatchError",
            "TransferLockedError",
            "UnableToFulfillQuantityError",
            "UnsupportedOrderCriteriaError",
            "UnsupportedSwapError",
        ];

        for error in captured_transaction_errors {
            assert!(
                classify_mint_action_errors(&[error.to_owned()]).is_some(),
                "captured transaction error was not rejected: {error}"
            );
        }
    }

    #[test]
    fn rejects_a_user_operation_action_without_decoding_its_calls() {
        let response: MintActionQueryData = serde_json::from_value(serde_json::json!({
            "swap": {
                "actions": [{"__typename": "UserOpAction"}],
                "errors": []
            }
        }))
        .expect("captured response shape");
        let error = validate_mint_transaction(
            decode_mint_action(response).expect("decode"),
            &collection_fixture(),
            wallet_fixture(),
            "SIGNED_PRESALE",
            1,
            1,
            8453,
        )
        .expect_err("user operations are never executable");

        assert!(matches!(error, OpenSeaError::UnsafeMintAction { .. }));
    }

    #[test]
    fn rejects_collection_slug_drift_and_duplicate_stage_indices() {
        let drift: CollectionQueryData = serde_json::from_value(collection_response(
            "different-slug",
            &[collection_stage(0)],
        ))
        .expect("response");
        assert!(matches!(
            decode_collection(drift, "fixture"),
            Err(OpenSeaError::Compatibility)
        ));

        let duplicate: CollectionQueryData = serde_json::from_value(collection_response(
            "fixture",
            &[collection_stage(0), collection_stage(0)],
        ))
        .expect("response");
        assert!(matches!(
            decode_collection(duplicate, "fixture"),
            Err(OpenSeaError::Compatibility)
        ));
    }

    #[test]
    fn decodes_the_captured_erc1155_per_token_limit() {
        let response: CollectionQueryData = serde_json::from_value(serde_json::json!({
            "collectionBySlug": {
                "__typename": "Collection",
                "slug": "fixture",
                "address": "0x90a76eca33e635ebb260a699ef9ee65d02335ed9",
                "chain": { "identifier": "base", "networkId": 8453 },
                "drop": {
                    "__typename": "Erc1155SeaDropV2",
                    "identifier": {
                        "contractAddress": "0x90a76eca33e635ebb260a699ef9ee65d02335ed9",
                        "chain": { "identifier": "base" }
                    },
                    "stages": [
                        {
                            "__typename": "Erc1155SeaDropV2Stage",
                            "stageType": "MERKLE_PRESALE",
                            "stageIndex": 2,
                            "startTime": "2026-08-12T00:00:00Z",
                            "endTime": null,
                            "maxTotalMintableByWallet": 10,
                            "maxTotalMintableByWalletPerToken": 3,
                            "fromTokenId": 7,
                            "toTokenId": 9
                        },
                        {
                            "__typename": "Erc1155SeaDropV2Stage",
                            "stageType": "MERKLE_PRESALE",
                            "stageIndex": 2,
                            "startTime": "2026-08-12T00:00:00Z",
                            "endTime": null,
                            "maxTotalMintableByWallet": 10,
                            "maxTotalMintableByWalletPerToken": 4,
                            "fromTokenId": 10,
                            "toTokenId": 12
                        }
                    ]
                }
            }
        }))
        .expect("response");

        let collection = decode_collection(response, "fixture").expect("ERC-1155 collection");
        assert_eq!(collection.stages[0].token_range, Some((7, 9)));
        assert_eq!(
            collection.stages[0].max_total_mintable_by_wallet_per_token,
            Some(3)
        );
        assert_eq!(collection.stages[1].stage_index, 2);
        assert_eq!(collection.stages[1].token_range, Some((10, 12)));
    }

    #[test]
    fn rejects_overlapping_erc1155_ranges_in_one_stage_index() {
        let first = StageMetadata {
            kind: "Erc1155SeaDropV2Stage".into(),
            stage_type: "PUBLIC_SALE".into(),
            stage_index: 2,
            start_time: Some("2026-08-12T00:00:00Z".into()),
            end_time: None,
            max_total_mintable_by_wallet: Some(10),
            max_total_mintable_by_wallet_per_token: Some(3),
            token_range: Some((7, 9)),
        };
        let mut overlapping = first.clone();
        overlapping.token_range = Some((9, 12));

        assert!(matches!(
            validate_metadata_stage_groups(&[first, overlapping]),
            Err(OpenSeaError::Compatibility)
        ));
    }

    fn collection_response(slug: &str, stages: &[serde_json::Value]) -> serde_json::Value {
        serde_json::json!({
            "collectionBySlug": {
                "__typename": "Collection",
                "slug": slug,
                "address": "0x90a76eca33e635ebb260a699ef9ee65d02335ed9",
                "chain": { "identifier": "base", "networkId": 8453 },
                "drop": {
                    "__typename": "Erc721SeaDropV1",
                    "identifier": {
                        "contractAddress": "0x90a76eca33e635ebb260a699ef9ee65d02335ed9",
                        "chain": { "identifier": "base" }
                    },
                    "stages": stages
                }
            }
        })
    }

    fn collection_stage(stage_index: u32) -> serde_json::Value {
        serde_json::json!({
            "__typename": "Erc721SeaDropV1Stage",
            "stageType": "PUBLIC_SALE",
            "stageIndex": stage_index,
            "startTime": "2026-08-12T00:00:00Z",
            "endTime": null,
            "maxTotalMintableByWallet": 1,
            "maxTotalMintableByWalletPerToken": null,
            "fromTokenId": null,
            "toTokenId": null
        })
    }

    fn collection_fixture() -> CollectionMetadata {
        CollectionMetadata {
            slug: "fixture".into(),
            address: "0x90a76eca33e635ebb260a699ef9ee65d02335ed9"
                .parse()
                .expect("address"),
            chain_identifier: "base".into(),
            network_id: 8453,
            drop_kind: "Erc721SeaDropV1".into(),
            drop_address: "0x90a76eca33e635ebb260a699ef9ee65d02335ed9"
                .parse()
                .expect("address"),
            stages: Vec::new(),
        }
    }

    fn wallet_fixture() -> Address {
        "0x0e1730aab680245971603f9edeaa0c85ebeaaaaa"
            .parse()
            .expect("wallet")
    }

    fn erc721_calldata(selector: &str) -> String {
        erc721_calldata_with_quantity(selector, 1)
    }

    fn erc721_calldata_with_quantity(selector: &str, quantity: u64) -> String {
        erc721_calldata_for_wallet(selector, quantity, wallet_fixture())
    }

    fn erc721_calldata_for_wallet(selector: &str, quantity: u64, wallet: Address) -> String {
        let mut calldata = hex::decode(selector).expect("selector");
        calldata.resize(4 + 9 * 32, 0);
        let nft_contract =
            hex::decode("90a76eca33e635ebb260a699ef9ee65d02335ed9").expect("collection address");
        calldata[16..36].copy_from_slice(&nft_contract);
        calldata[4 + 2 * 32 + 12..4 + 3 * 32].copy_from_slice(wallet.as_slice());
        calldata[4 + 3 * 32..4 + 4 * 32].copy_from_slice(&U256::from(quantity).to_be_bytes::<32>());
        calldata[4 + 9 * 32 - 1] = 1;
        format!("0x{}", hex::encode(calldata))
    }

    fn mint_action_response(selector: &str, quantity: u64, wallet: Address) -> serde_json::Value {
        serde_json::json!({
            "actions": [{
                "__typename": "MintAction",
                "transactionSubmissionData": {
                    "to": "0x00005EA00Ac477B1030CE78506496e8C2dE24bf5",
                    "data": erc721_calldata_for_wallet(selector, quantity, wallet),
                    "value": "0",
                    "chain": { "networkId": 8453, "identifier": "base" }
                }
            }],
            "errors": []
        })
    }
}
