//! Telegram bot control surface for the `SeaDrop` sniper.
//!
//! Raw long-polling (`getUpdates`) — no webhook, no framework dependency on
//! top of the existing `reqwest/serde_json/tokio` stack.
//!
//! Security model:
//! - Allowlisted: every chat id must be in `ALLOWED_CHAT_IDS`.
//! - **Per-chat isolation.** Each allowed chat owns a separate manifest at
//!   `WALLETS_DIR/<chat_id>.json`. Allowlisting is not a tenancy model on its
//!   own: with one shared manifest, any allowed user could list, spend, or
//!   overwrite every other user's wallets, so every wallet read, write,
//!   preview, fire, and sweep is keyed by chat id.
//! - Private keys never appear in chat. Wallets are generated server-side via
//!   `/start`, or imported from a `wallets.json` upload — which is refused
//!   when a manifest already exists, so an import cannot destroy funded keys.
//! - `/withdraw` sweeps a chat's wallets to an address it nominates. A bot that
//!   generates wallets must offer an exit, or funds are stranded.
//! - The fire path runs in a background task; progress streams to the chat.

use std::{
    collections::{HashMap, HashSet},
    env,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use alloy_primitives::{Address, U256};
use serde_json::{Value, json};
use thiserror::Error;
use tokio::{
    sync::{Mutex, mpsc},
    time::sleep,
};

use crate::{
    assistant, logging, manifest_crypto,
    multi_wallet::WalletManifest,
    signing::WalletSigner,
    snipe::{self, SnipeOptions},
    sponsored_snipe::{self, SponsoredSnipeOptions},
    sweep, wallet_generator,
};

#[allow(unused_imports)]
use std::fmt::Write as _;

const API_BASE: &str = "https://api.telegram.org/bot";
const POLL_TIMEOUT_SECONDS: u64 = 25;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(70);
/// Relative to the image's `WORKDIR` (`/data`), so this lands on the mounted
/// volume by default.
const DEFAULT_WALLETS_DIR: &str = "wallets";
/// Ceiling on wallets one chat may generate, so a shared bot cannot be used to
/// fill the volume or stage an unbounded spend.
const MAX_WALLETS_PER_USER: usize = 50;
/// Roughly a minute of tolerance for a rolling redeploy's old container to
/// finish draining before this instance declares the token contended.
const CONFLICT_MAX_ATTEMPTS: u32 = 12;
const CONFLICT_RETRY_DELAY: Duration = Duration::from_secs(5);

#[derive(Debug, Error)]
pub enum BotError {
    #[error("BOT_TOKEN is not set — create one with @BotFather and add it to .env")]
    MissingToken,
    #[error(
        "ALLOWED_CHAT_IDS is not set — comma-separated numeric chat ids (find yours with @userinfobot)"
    )]
    MissingAllowedChats,
    #[error("ALLOWED_CHAT_IDS contains no valid chat ids")]
    NoAllowedChats,
    #[error("invalid ALLOWED_CHAT_IDS entry: {0}")]
    InvalidChatId(String),
    #[error("Telegram API error: {0}")]
    TelegramApi(String),
    #[error("Telegram request failed: {0}")]
    Telegram(String),
    #[error("cannot construct the Telegram HTTP client")]
    Http,
    #[error(transparent)]
    Snipe(#[from] snipe::SnipeError),
}

/// One step of the interactive snipe wizard.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Step {
    Collection,
    Chain,
    Quantity,
    /// Only reached when the bot has a sponsor configured — self-funded is
    /// otherwise the only option and this step is skipped entirely.
    Funding,
    Confirm,
}

/// Who pays gas: every wallet its own (unchanged default), or one sponsor
/// wallet for the whole batch via EIP-7702 delegation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Funding {
    SelfFunded,
    Sponsored,
}

#[derive(Clone, Debug)]
struct Wizard {
    step: Step,
    collection: String,
    chain: Option<String>,
    quantity: u64,
    wallets: Option<Vec<usize>>,
    funding: Funding,
    max_fee_per_gas: Option<U256>,
    max_priority_fee_per_gas: Option<U256>,
    early_fire_ms: u64,
}

impl Wizard {
    fn new() -> Self {
        Self {
            step: Step::Collection,
            collection: String::new(),
            chain: None,
            quantity: 1,
            wallets: None,
            funding: Funding::SelfFunded,
            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
            early_fire_ms: 0,
        }
    }
}

/// The operator's own gas-paying wallet and the executor it's wired to.
/// Global, not per-chat — see the module doc comment on the trust model this
/// assumes: every allowed chat can spend this wallet's gas.
struct SponsorContext {
    signer: WalletSigner,
    executor: Address,
    recipient: Address,
    mint_gas_limit: u64,
    operation_deadline_seconds: u64,
}

struct Bot {
    http: reqwest::Client,
    token: String,
    allowed: Vec<i64>,
    /// Directory holding one manifest per chat. A single shared file would let
    /// any allowed user spend, list, or overwrite everyone else's wallets.
    wallets_dir: PathBuf,
    wizards: Mutex<HashMap<i64, Wizard>>,
    active: Mutex<HashMap<i64, usize>>,
    /// Chats that have been asked how many wallets to generate and whose next
    /// plain message is that count.
    awaiting_wallet_count: Mutex<HashSet<i64>>,
    awaiting_recovery: Mutex<HashSet<i64>>,
    /// Chats mid-"add more wallets": the target *total* wallet count they
    /// picked, waiting on their recovery phrase next. The phrase is verified
    /// against the existing manifest's addresses before anything is
    /// overwritten — see `handle_wallet_expansion_phrase`.
    awaiting_wallet_expansion: Mutex<HashMap<i64, usize>>,
    /// `None` unless `SPONSOR_KEY`, `SPONSORED_EXECUTOR_ADDRESS`, and
    /// `RECIPIENT_ADDRESS` are all configured — sponsored mode is simply not
    /// offered in the wizard until then.
    sponsor: Option<SponsorContext>,
}

impl Bot {
    fn new(
        token: String,
        allowed: Vec<i64>,
        wallets_dir: PathBuf,
        sponsor: Option<SponsorContext>,
    ) -> Result<Self, BotError> {
        let http = reqwest::Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .build()
            .map_err(|_| BotError::Http)?;
        Ok(Self {
            http,
            token,
            allowed,
            wallets_dir,
            wizards: Mutex::new(HashMap::new()),
            active: Mutex::new(HashMap::new()),
            awaiting_wallet_count: Mutex::new(HashSet::new()),
            awaiting_recovery: Mutex::new(HashSet::new()),
            awaiting_wallet_expansion: Mutex::new(HashMap::new()),
            sponsor,
        })
    }

    /// Manifest path for one chat. `chat_id` is an integer straight from
    /// Telegram, so it cannot contain path separators or traverse out of the
    /// directory — no sanitising is required, and none should be inferred as
    /// safe for any caller-supplied string.
    fn manifest_path(&self, chat_id: i64) -> PathBuf {
        self.wallets_dir.join(format!("{chat_id}.json"))
    }

    fn has_manifest(&self, chat_id: i64) -> bool {
        self.manifest_path(chat_id).is_file()
    }

    fn is_allowed(&self, chat_id: i64) -> bool {
        self.allowed.contains(&chat_id)
    }

    /// `reqwest::Error` renders as `... for url (https://api.telegram.org/bot<TOKEN>/...)`,
    /// so every transport error would otherwise print the bot token into the
    /// logs. Railway retains deploy logs, so scrub it before it is ever
    /// formatted.
    fn redact(&self, error: &reqwest::Error) -> String {
        error.to_string().replace(self.token.as_str(), "<redacted>")
    }

    async fn api(&self, method: &str, params: Value) -> Result<Value, BotError> {
        let url = format!("{API_BASE}{}/{}", self.token, method);
        let response = self
            .http
            .post(&url)
            .json(&params)
            .send()
            .await
            .map_err(|error| BotError::Telegram(self.redact(&error)))?;
        let value: Value = response
            .json()
            .await
            .map_err(|error| BotError::Telegram(self.redact(&error)))?;
        if value.get("ok").and_then(Value::as_bool) != Some(true) {
            let description = value
                .get("description")
                .and_then(Value::as_str)
                .unwrap_or("unknown error");
            return Err(BotError::TelegramApi(format!("{method}: {description}")));
        }
        Ok(value.get("result").cloned().unwrap_or(Value::Null))
    }

    /// Telegram rejects any message over 4096 characters, so a 50-wallet
    /// listing would be dropped rather than truncated. Split on line
    /// boundaries where possible and send the pieces in order.
    async fn send(&self, chat_id: i64, text: &str) -> Result<(), BotError> {
        for chunk in split_message(text) {
            self.api(
                "sendMessage",
                json!({
                    "chat_id": chat_id,
                    "text": chunk,
                    "parse_mode": "Markdown",
                    "disable_web_page_preview": true,
                }),
            )
            .await?;
        }
        Ok(())
    }

    async fn send_keyboard(
        &self,
        chat_id: i64,
        text: &str,
        rows: &[&[(&str, &str)]],
    ) -> Result<(), BotError> {
        let keyboard: Vec<Vec<Value>> = rows
            .iter()
            .map(|row| {
                row.iter()
                    .map(|(label, data)| json!({"text": label, "callback_data": data}))
                    .collect()
            })
            .collect();
        self.api(
            "sendMessage",
            json!({
                "chat_id": chat_id,
                "text": text,
                "parse_mode": "Markdown",
                "disable_web_page_preview": true,
                "reply_markup": {"inline_keyboard": keyboard},
            }),
        )
        .await?;
        Ok(())
    }

    async fn get_updates(&self, offset: i64) -> Result<Vec<Value>, BotError> {
        let result = self
            .api(
                "getUpdates",
                json!({
                    "timeout": POLL_TIMEOUT_SECONDS,
                    "offset": offset,
                    "allowed_updates": ["message", "callback_query"],
                }),
            )
            .await?;
        Ok(result.as_array().cloned().unwrap_or_default())
    }

    async fn download_file(&self, file_path: &str, destination: &Path) -> Result<(), BotError> {
        let url = format!("{API_BASE}{}/{}", self.token, file_path);
        let bytes = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|error| BotError::Telegram(self.redact(&error)))?
            .bytes()
            .await
            .map_err(|error| BotError::Telegram(self.redact(&error)))?;
        std::fs::write(destination, bytes).map_err(|error| {
            BotError::Telegram(format!("cannot write {}: {error}", destination.display()))
        })
    }

    fn load_manifest(&self, chat_id: i64) -> Result<Vec<(usize, Address, u64)>, String> {
        let manifest = WalletManifest::load(&self.manifest_path(chat_id))
            .map_err(|error| error.to_string())?;
        Ok(manifest
            .wallets()
            .iter()
            .enumerate()
            .map(|(index, entry)| (index, entry.address(), entry.quantity()))
            .collect())
    }
}

/// `None` unless every required sponsor setting is present and valid.
/// Deliberately non-fatal on a missing or bad setting — the bot still runs
/// self-funded-only rather than refusing to start, since sponsored mode is
/// additive. Mirrors the CLI's own `SPONSOR_KEY` / `SPONSORED_EXECUTOR_ADDRESS`
/// / `SPONSORED_OPERATION_DEADLINE_SECONDS` semantics from `config.rs` so the
/// same `.env` values work in both places.
fn load_sponsor_context() -> Option<SponsorContext> {
    let sponsor_key = env::var("SPONSOR_KEY").ok()?;
    let signer = match WalletSigner::from_private_key(sponsor_key.trim()) {
        Ok(signer) => signer,
        Err(error) => {
            logging::warn(format!(
                "SPONSOR_KEY is set but invalid — sponsored mode disabled: {error}"
            ));
            return None;
        }
    };
    let Ok(executor_raw) = env::var("SPONSORED_EXECUTOR_ADDRESS") else {
        logging::warn(
            "SPONSOR_KEY is set but SPONSORED_EXECUTOR_ADDRESS is not — sponsored mode disabled.",
        );
        return None;
    };
    let Ok(executor) = executor_raw.trim().parse::<Address>() else {
        logging::warn(
            "SPONSORED_EXECUTOR_ADDRESS is not a valid address — sponsored mode disabled.",
        );
        return None;
    };
    let Ok(recipient_raw) = env::var("RECIPIENT_ADDRESS") else {
        logging::warn("SPONSOR_KEY is set but RECIPIENT_ADDRESS is not — sponsored mode disabled.");
        return None;
    };
    let Ok(recipient) = recipient_raw.trim().parse::<Address>() else {
        logging::warn("RECIPIENT_ADDRESS is not a valid address — sponsored mode disabled.");
        return None;
    };
    if recipient == executor {
        logging::warn(
            "RECIPIENT_ADDRESS must differ from SPONSORED_EXECUTOR_ADDRESS — sponsored mode disabled.",
        );
        return None;
    }
    let mint_gas_limit = env::var("GAS_LIMIT")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(250_000);
    let operation_deadline_seconds = env::var("SPONSORED_OPERATION_DEADLINE_SECONDS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(120);
    if !(30..=3_600).contains(&operation_deadline_seconds) {
        logging::warn(
            "SPONSORED_OPERATION_DEADLINE_SECONDS must be 30-3600 — sponsored mode disabled.",
        );
        return None;
    }
    Some(SponsorContext {
        signer,
        executor,
        recipient,
        mint_gas_limit,
        operation_deadline_seconds,
    })
}

pub async fn run_bot() -> Result<(), BotError> {
    let _ = dotenvy::dotenv();

    let token = env::var("BOT_TOKEN").map_err(|_| BotError::MissingToken)?;
    if token.trim().is_empty() {
        return Err(BotError::MissingToken);
    }
    let allowed_raw = env::var("ALLOWED_CHAT_IDS").map_err(|_| BotError::MissingAllowedChats)?;
    let mut allowed = Vec::new();
    for entry in allowed_raw.split(',') {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        let chat_id = entry
            .parse::<i64>()
            .map_err(|_| BotError::InvalidChatId(entry.to_owned()))?;
        if !allowed.contains(&chat_id) {
            allowed.push(chat_id);
        }
    }
    if allowed.is_empty() {
        return Err(BotError::NoAllowedChats);
    }
    // Each chat gets its own manifest. WALLETS_FILE named a single shared file,
    // which in a multi-user bot would let any allowed chat spend or overwrite
    // everyone else's wallets — so it is deliberately not honoured here, and
    // its presence is called out rather than silently ignored.
    if env::var("WALLETS_FILE").is_ok() {
        logging::warn(
            "WALLETS_FILE is ignored by the bot — wallets are per-chat under WALLETS_DIR",
        );
    }
    let wallets_dir =
        env::var("WALLETS_DIR").map_or_else(|_| PathBuf::from(DEFAULT_WALLETS_DIR), PathBuf::from);
    std::fs::create_dir_all(&wallets_dir).map_err(|error| {
        BotError::Telegram(format!(
            "cannot create wallets directory {}: {error}",
            wallets_dir.display()
        ))
    })?;

    prepare_encryption_at_rest(&wallets_dir)?;

    let sponsor = load_sponsor_context();
    if sponsor.is_some() {
        logging::info(
            "Sponsored mode available — SPONSOR_KEY, SPONSORED_EXECUTOR_ADDRESS, and RECIPIENT_ADDRESS are all configured.",
        );
    }

    let bot = Arc::new(Bot::new(token, allowed, wallets_dir, sponsor)?);

    let me = bot.api("getMe", json!({})).await?;
    let username = me.get("username").and_then(Value::as_str).unwrap_or("?");
    logging::section_break();
    logging::success(format!(
        "Telegram bot @{username} online — owner chat(s): {:?}",
        bot.allowed
    ));
    logging::info(format!(
        "Per-chat wallet manifests: {}",
        bot.wallets_dir.display()
    ));
    logging::info("Waiting for updates...");
    logging::section_break();

    let mut offset: i64 = 0;
    let mut conflicts: u32 = 0;
    loop {
        match bot.get_updates(offset).await {
            Ok(updates) => {
                conflicts = 0;
                for update in updates {
                    if let Some(update_id) = update.get("update_id").and_then(Value::as_i64) {
                        offset = update_id + 1;
                    }
                    handle_update(&bot, update).await;
                }
            }
            // A rolling redeploy briefly runs the old and new container at
            // once, and the loser sees 409 Conflict. Exiting Ok here would
            // report success to the platform and leave no bot polling at all,
            // so wait for the predecessor to drain and only give up — loudly,
            // with a failing exit code — if it never does.
            Err(BotError::TelegramApi(error)) if error.contains("Conflict") => {
                conflicts += 1;
                if conflicts > CONFLICT_MAX_ATTEMPTS {
                    logging::error(
                        "another bot instance is still polling with this token — stop it first",
                    );
                    return Err(BotError::TelegramApi(error));
                }
                logging::warn(format!(
                    "another instance is polling this token — retrying in {}s ({conflicts}/{CONFLICT_MAX_ATTEMPTS})",
                    CONFLICT_RETRY_DELAY.as_secs()
                ));
                sleep(CONFLICT_RETRY_DELAY).await;
            }
            Err(error) => {
                conflicts = 0;
                logging::warn(format!("getUpdates failed: {error} — retrying in 3s"));
                sleep(Duration::from_secs(3)).await;
            }
        }
    }
}

async fn handle_update(bot: &Arc<Bot>, update: Value) {
    if let Some(callback) = update.get("callback_query") {
        let message = callback.get("message");
        let chat_id = message
            .and_then(|m| m.get("chat"))
            .and_then(|c| c.get("id"))
            .and_then(Value::as_i64)
            .unwrap_or(0);
        let callback_id = callback
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let data = callback
            .get("data")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let _ = bot
            .api(
                "answerCallbackQuery",
                json!({"callback_query_id": callback_id}),
            )
            .await;
        if bot.is_allowed(chat_id) {
            handle_callback(bot, chat_id, &data).await;
        }
        return;
    }

    let Some(message) = update.get("message") else {
        return;
    };
    let chat_id = message
        .get("chat")
        .and_then(|c| c.get("id"))
        .and_then(Value::as_i64)
        .unwrap_or(0);
    if !bot.is_allowed(chat_id) {
        logging::warn(format!("ignoring message from unauthorized chat {chat_id}"));
        return;
    }
    if let Some(text) = message.get("text").and_then(Value::as_str) {
        handle_text(bot, chat_id, text).await;
    } else if message.get("document").is_some() {
        handle_document(bot, chat_id, message).await;
    }
}

const HELP: &str = "\
*Drizzy — NFT Mint Sniper*\n\n\
/start — Main menu\n\
/snipe — New snipe\n\
/wallets — View addresses\n\
/withdraw `<address>` — Withdraw funds\n\
/recover — Restore from recovery phrase\n\
/status — Active snipes\n\
/cancel — Cancel current operation\n\
/help — Commands\n\n\
_You can also paste an OpenSea link or contract address directly._";

async fn handle_text(bot: &Arc<Bot>, chat_id: i64, text: &str) {
    let trimmed = text.trim();
    if let Some(command) = trimmed.strip_prefix('/') {
        let command = command.split_whitespace().next().unwrap_or_default();
        match command {
            "start" => {
                start_onboarding(bot, chat_id).await;
            }
            "help" => {
                let _ = bot.send(chat_id, HELP).await;
            }
            "wallets" => {
                let _ = list_wallets(bot, chat_id).await;
            }
            "withdraw" => {
                let argument = trimmed.split_whitespace().nth(1).unwrap_or_default();
                handle_withdraw(bot, chat_id, argument).await;
            }
            "snipe" => {
                let mut wizards = bot.wizards.lock().await;
                wizards.insert(chat_id, Wizard::new());
                drop(wizards);
                let _ = bot
                    .send(
                        chat_id,
                        "Send the collection — an OpenSea link, slug, or contract address.\n\n/cancel to abort.",
                    )
                    .await;
            }
            "recover" => {
                start_recovery(bot, chat_id).await;
            }
            "cancel" => {
                bot.wizards.lock().await.remove(&chat_id);
                bot.awaiting_recovery.lock().await.remove(&chat_id);
                bot.awaiting_wallet_expansion.lock().await.remove(&chat_id);
                let _ = bot.send(chat_id, "Wizard cancelled.").await;
            }
            "status" => {
                let active = bot.active.lock().await.get(&chat_id).copied().unwrap_or(0);
                let _ = bot.send(chat_id, &format!("Active snipes: {active}")).await;
            }
            _ => {
                let _ = bot.send(chat_id, "Unknown command — /help").await;
            }
        }
        return;
    }

    if bot.awaiting_recovery.lock().await.contains(&chat_id) {
        handle_recovery_phrase(bot, chat_id, trimmed).await;
        return;
    }

    if bot
        .awaiting_wallet_expansion
        .lock()
        .await
        .contains_key(&chat_id)
    {
        handle_wallet_expansion_phrase(bot, chat_id, trimmed).await;
        return;
    }

    if bot.awaiting_wallet_count.lock().await.contains(&chat_id) {
        create_wallets_from_text(bot, chat_id, trimmed).await;
        return;
    }

    // With a wizard running, plain text is always an answer to the current
    // step — a link pasted mid-flow is the collection, not a new snipe.
    if bot.wizards.lock().await.contains_key(&chat_id) {
        advance_wizard(bot, chat_id, trimmed).await;
        return;
    }

    if looks_like_collection(trimmed) {
        start_from_locator(bot, chat_id, trimmed).await;
        return;
    }

    if assistant::is_enabled() {
        handle_natural_language(bot, chat_id, trimmed).await;
        return;
    }

    advance_wizard(bot, chat_id, trimmed).await;
}

/// Route free text through the model and stage whatever it proposes. The
/// proposal lands on the normal confirm screen — this changes how the wizard
/// gets filled in, never whether a human approves the spend.
async fn handle_natural_language(bot: &Arc<Bot>, chat_id: i64, text: &str) {
    let wallets_available = bot
        .load_manifest(chat_id)
        .map_or(0, |wallets| wallets.len());

    let reply = match assistant::interpret(text, wallets_available).await {
        Ok(reply) => reply,
        Err(error) => {
            let _ = bot.send(chat_id, &format!("Error: {error}")).await;
            return;
        }
    };

    let proposal = match reply {
        assistant::Reply::Text(message) => {
            let _ = bot.send(chat_id, &message).await;
            return;
        }
        assistant::Reply::Propose(proposal) => proposal,
    };

    // Map the proposal onto a wizard. A wallet count becomes the leading N
    // manifest indices; unset stays "all", which the confirm screen spells out.
    let mut wizard = Wizard::new();
    wizard.collection.clone_from(&proposal.collection);
    wizard.chain.clone_from(&proposal.chain);
    wizard.quantity = proposal.quantity.unwrap_or(1);
    wizard.early_fire_ms = proposal.early_fire_ms.unwrap_or(0);
    // A proposed count becomes the leading N manifest indices, clamped to what
    // the manifest actually holds — an unclamped count would fail late with
    // "wallet index N out of range" instead of staging what exists. Zero is
    // meaningless and is treated as unset ("all") rather than as an empty
    // selection, which would fail with "no wallets configured".
    wizard.wallets = proposal.wallet_count.and_then(|count| {
        let requested = usize::try_from(count).unwrap_or(usize::MAX);
        let usable = requested.min(wallets_available);
        (usable > 0).then(|| (0..usable).collect())
    });

    // Without a chain there is nothing to preview against, so fall back to the
    // button rather than guessing one.
    if wizard.chain.is_none() {
        wizard.step = Step::Chain;
        bot.wizards.lock().await.insert(chat_id, wizard);
        let _ = bot
            .send_keyboard(
                chat_id,
                &format!("{}\n\nWhich chain?", proposal.interpretation),
                &[&[
                    ("Base", "chain:base"),
                    ("Ethereum", "chain:ethereum"),
                    ("Robinhood", "chain:robinhood"),
                    ("Ink", "chain:ink"),
                ]],
            )
            .await;
        return;
    }

    wizard.step = Step::Confirm;
    bot.wizards.lock().await.insert(chat_id, wizard.clone());
    let _ = bot.send(chat_id, &proposal.interpretation).await;
    show_confirm(bot, chat_id, &wizard).await;
}

/// Seal any manifests left plaintext by an earlier deployment. Done once at
/// startup rather than lazily on read, so the conversion is bounded, visible in
/// the logs, and never races a snipe. A failure here is fatal: continuing would
/// silently leave keys in plaintext while the logs claimed otherwise.
fn prepare_encryption_at_rest(wallets_dir: &Path) -> Result<(), BotError> {
    if !manifest_crypto::is_enabled() {
        logging::warn(format!(
            "{} is not set — wallet manifests are stored in plaintext",
            manifest_crypto::PASSPHRASE_ENV
        ));
        return Ok(());
    }
    match manifest_crypto::migrate_directory(wallets_dir) {
        Ok(0) => {
            logging::info("Wallet manifests are encrypted at rest.");
            Ok(())
        }
        Ok(count) => {
            logging::success(format!(
                "Encrypted {count} plaintext wallet manifest(s) at rest."
            ));
            Ok(())
        }
        Err(error) => {
            logging::error(format!("Cannot encrypt existing manifests: {error}"));
            Err(BotError::Telegram(error.to_string()))
        }
    }
}

/// First run for a chat: offer to create wallets. Never offers to regenerate
/// over an existing manifest — those wallets may hold funds, and the
/// generator refuses to overwrite anyway.
async fn start_onboarding(bot: &Arc<Bot>, chat_id: i64) {
    if bot.has_manifest(chat_id) {
        send_main_menu(bot, chat_id).await;
        return;
    }

    bot.awaiting_wallet_count.lock().await.insert(chat_id);
    let _ = bot
        .send_keyboard(
            chat_id,
            &format!(
                "*Drizzy — NFT Mint Sniper*\n\n\
                 Set up your wallets to get started. Each wallet is unique to this \
                 chat and secured with a 12-word recovery phrase.\n\n\
                 Select wallet count (1–{MAX_WALLETS_PER_USER}):"
            ),
            &[
                &[("3", "wallets:3"), ("5", "wallets:5"), ("10", "wallets:10")],
                &[("Recover Existing", "menu:recover")],
            ],
        )
        .await;
}

async fn send_main_menu(bot: &Arc<Bot>, chat_id: i64) {
    let wallet_count = match crate::multi_wallet::WalletManifest::load(&bot.manifest_path(chat_id))
    {
        Ok(manifest) => manifest.len(),
        Err(_) => 0,
    };
    let _ = bot
        .send_keyboard(
            chat_id,
            &format!(
                "*Drizzy — NFT Mint Sniper*\n\n\
                 Wallets: {wallet_count}\n\n\
                 _Ethereum | Base | Robinhood Chain | Ink_"
            ),
            &[
                &[("Snipe", "menu:snipe"), ("Wallets", "menu:wallets")],
                &[("+ Add Wallets", "menu:addwallets")],
                &[("Withdraw", "menu:withdraw"), ("Status", "menu:status")],
                &[("Help", "menu:help")],
            ],
        )
        .await;
}

/// Parse a typed wallet count and create the manifest.
async fn create_wallets_from_text(bot: &Arc<Bot>, chat_id: i64, text: &str) {
    match text.trim().parse::<usize>() {
        Ok(count) => create_wallets(bot, chat_id, count).await,
        Err(_) => {
            let _ = bot
                .send(
                    chat_id,
                    &format!("Send a number between 1 and {MAX_WALLETS_PER_USER}, or /cancel."),
                )
                .await;
        }
    }
}

async fn create_wallets(bot: &Arc<Bot>, chat_id: i64, count: usize) {
    if count == 0 || count > MAX_WALLETS_PER_USER {
        let _ = bot
            .send(
                chat_id,
                &format!("Pick a number between 1 and {MAX_WALLETS_PER_USER}."),
            )
            .await;
        return;
    }

    bot.awaiting_wallet_count.lock().await.remove(&chat_id);

    let path = bot.manifest_path(chat_id);
    match wallet_generator::create_wallet_manifest(&path, count, 1) {
        Ok(manifest) => {
            let _ = bot
                .send(
                    chat_id,
                    &format!(
                        "*Recovery Phrase*\n\n\
                         `{}`\n\n\
                         Save these 12 words offline. This is the only time they will be displayed. \
                         Use /recover to restore wallets from this phrase.",
                        manifest.mnemonic()
                    ),
                )
                .await;
            let mut lines = format!("*{count} wallet(s) created.*\n\n");
            for (index, address) in manifest.addresses().iter().enumerate() {
                let _ = writeln!(lines, "`{index}` — `{address}`");
            }
            lines.push_str(
                "\nFund each address with the mint price + gas. \
                 Then use /snipe or paste an OpenSea link to begin.",
            );
            let _ = bot.send(chat_id, &lines).await;
        }
        Err(error) => {
            let _ = bot
                .send(chat_id, &format!("Could not create wallets: {error}"))
                .await;
        }
    }
}

async fn start_recovery(bot: &Arc<Bot>, chat_id: i64) {
    if bot.has_manifest(chat_id) {
        let _ = bot
            .send(
                chat_id,
                "Wallets already exist. Run /withdraw first, then /start to set up new ones.",
            )
            .await;
        return;
    }
    bot.awaiting_recovery.lock().await.insert(chat_id);
    let _ = bot
        .send(
            chat_id,
            "Send your 12-word recovery phrase. Wallets will be re-derived in the original order.\n\n\
             /cancel to abort.",
        )
        .await;
}

async fn handle_recovery_phrase(bot: &Arc<Bot>, chat_id: i64, text: &str) {
    bot.awaiting_recovery.lock().await.remove(&chat_id);

    let words: Vec<&str> = text.split_whitespace().collect();
    if !matches!(words.len(), 12 | 15 | 18 | 21 | 24) {
        let _ = bot
            .send(
                chat_id,
                &format!(
                    "Expected 12 or 24 words, got {}. Send your full recovery phrase separated by spaces, or /cancel.",
                    words.len()
                ),
            )
            .await;
        bot.awaiting_recovery.lock().await.insert(chat_id);
        return;
    }

    let phrase = words.join(" ");
    let count = 5;
    let path = bot.manifest_path(chat_id);

    match wallet_generator::recover_wallet_manifest(&path, &phrase, count, 1) {
        Ok(manifest) => {
            let mut lines = format!("*{count} wallet(s) recovered.*\n\n");
            for (index, address) in manifest.addresses().iter().enumerate() {
                let _ = writeln!(lines, "`{index}` — `{address}`");
            }
            lines.push_str(
                "\nVerify these match your previous addresses. Use /snipe or paste an OpenSea link to begin.",
            );
            let _ = bot.send(chat_id, &lines).await;
        }
        Err(wallet_generator::WalletGeneratorError::InvalidMnemonic) => {
            let _ = bot
                .send(
                    chat_id,
                    "Invalid recovery phrase. Check spelling — every word must be from the BIP-39 English word list.",
                )
                .await;
        }
        Err(error) => {
            let _ = bot
                .send(chat_id, &format!("Recovery failed: {error}"))
                .await;
        }
    }
}

/// "+ Add Wallets" entry point: offer a few target totals above the current
/// count, computed from the existing manifest so the buttons are always
/// "more than you have now" rather than a fixed list that might be smaller.
async fn start_add_wallets(bot: &Arc<Bot>, chat_id: i64) {
    let Ok(manifest) = crate::multi_wallet::WalletManifest::load(&bot.manifest_path(chat_id))
    else {
        let _ = bot
            .send(chat_id, "You have no wallets yet — /start to create some.")
            .await;
        return;
    };
    let current = manifest.len();
    if current >= MAX_WALLETS_PER_USER {
        let _ = bot
            .send(
                chat_id,
                &format!("You're already at the {MAX_WALLETS_PER_USER}-wallet limit."),
            )
            .await;
        return;
    }

    let targets = [current + 2, current + 5, current + 10];
    let buttons: Vec<(String, String)> = targets
        .into_iter()
        .filter(|&target| target <= MAX_WALLETS_PER_USER)
        .map(|target| (format!("{target} total"), format!("addwallets:{target}")))
        .collect();
    let row: Vec<(&str, &str)> = buttons
        .iter()
        .map(|(label, data)| (label.as_str(), data.as_str()))
        .collect();
    let _ = bot
        .send_keyboard(
            chat_id,
            &format!(
                "You have {current} wallet(s). Grow to how many total? \
                 (existing wallets and their keys are never changed)"
            ),
            &[&row],
        )
        .await;
}

/// User picked a target total — now we need the recovery phrase before we
/// can derive the new wallets and safely overwrite the manifest.
async fn begin_wallet_expansion(bot: &Arc<Bot>, chat_id: i64, target: usize) {
    let Ok(manifest) = crate::multi_wallet::WalletManifest::load(&bot.manifest_path(chat_id))
    else {
        let _ = bot
            .send(chat_id, "You have no wallets yet — /start to create some.")
            .await;
        return;
    };
    let current = manifest.len();
    if target <= current || target > MAX_WALLETS_PER_USER {
        let _ = bot
            .send(
                chat_id,
                &format!(
                    "Target must be more than your current {current} and at most {MAX_WALLETS_PER_USER}."
                ),
            )
            .await;
        return;
    }
    bot.awaiting_wallet_expansion
        .lock()
        .await
        .insert(chat_id, target);
    let _ = bot
        .send(
            chat_id,
            "Send the 12-word recovery phrase you were shown when these wallets were created.\n\n\
             It's checked against your existing wallets first — nothing is touched if it doesn't match.\n\n\
             /cancel to abort.",
        )
        .await;
}

/// Verifies the phrase actually reproduces the existing wallets before
/// calling `expand_wallet_manifest`, which has no way to check that itself
/// and would otherwise happily overwrite the manifest with an unrelated
/// phrase's wallets.
async fn handle_wallet_expansion_phrase(bot: &Arc<Bot>, chat_id: i64, text: &str) {
    let Some(target) = bot.awaiting_wallet_expansion.lock().await.remove(&chat_id) else {
        return;
    };

    let words: Vec<&str> = text.split_whitespace().collect();
    if !matches!(words.len(), 12 | 15 | 18 | 21 | 24) {
        let _ = bot
            .send(
                chat_id,
                &format!(
                    "Expected 12 or 24 words, got {}. Send your full recovery phrase separated by spaces, or /cancel.",
                    words.len()
                ),
            )
            .await;
        bot.awaiting_wallet_expansion
            .lock()
            .await
            .insert(chat_id, target);
        return;
    }
    let phrase = words.join(" ");

    let path = bot.manifest_path(chat_id);
    let existing = match crate::multi_wallet::WalletManifest::load(&path) {
        Ok(manifest) => manifest,
        Err(error) => {
            let _ = bot
                .send(
                    chat_id,
                    &format!("Cannot read your current wallets: {error}"),
                )
                .await;
            return;
        }
    };
    let current_addresses: Vec<_> = existing
        .wallets()
        .iter()
        .map(crate::multi_wallet::WalletEntry::address)
        .collect();

    match wallet_generator::addresses_from_mnemonic(&phrase, current_addresses.len()) {
        Ok(derived) if derived == current_addresses => {}
        Ok(_) => {
            let _ = bot
                .send(
                    chat_id,
                    "That phrase doesn't match your existing wallets — refusing to overwrite. \
                     Double-check the words, or /cancel.",
                )
                .await;
            return;
        }
        Err(wallet_generator::WalletGeneratorError::InvalidMnemonic) => {
            let _ = bot
                .send(
                    chat_id,
                    "Invalid recovery phrase. Check spelling — every word must be from the BIP-39 English word list.",
                )
                .await;
            return;
        }
        Err(error) => {
            let _ = bot
                .send(chat_id, &format!("Verification failed: {error}"))
                .await;
            return;
        }
    }

    match wallet_generator::expand_wallet_manifest(&path, &phrase, target, 1) {
        Ok(manifest) => {
            let mut lines = format!(
                "*Grown to {target} wallet(s).* Existing wallets are unchanged; new ones:\n\n"
            );
            for (index, address) in manifest
                .addresses()
                .iter()
                .enumerate()
                .skip(current_addresses.len())
            {
                let _ = writeln!(lines, "`{index}` — `{address}`");
            }
            lines.push_str("\nUse /wallets to see the full list.");
            let _ = bot.send(chat_id, &lines).await;
        }
        Err(error) => {
            let _ = bot
                .send(chat_id, &format!("Could not grow the manifest: {error}"))
                .await;
        }
    }
}

/// Sweep every wallet in the caller's manifest to a nominated address.
async fn handle_withdraw(bot: &Arc<Bot>, chat_id: i64, argument: &str) {
    if !bot.has_manifest(chat_id) {
        let _ = bot
            .send(chat_id, "You have no wallets yet — /start to create some.")
            .await;
        return;
    }
    if argument.is_empty() {
        let _ = bot
            .send(
                chat_id,
                "Send the destination: `/withdraw 0xYourAddress`\n\nEvery wallet is swept to that address.",
            )
            .await;
        return;
    }
    let destination = match sweep::parse_destination(argument) {
        Ok(destination) => destination,
        Err(error) => {
            let _ = bot.send(chat_id, &format!("Error: {error}")).await;
            return;
        }
    };

    // Sweeping needs a chain, and there is no wizard context here. Default to
    // the chain the bot is most used on and let the user override explicitly.
    let chain = env::var("WITHDRAW_CHAIN").unwrap_or_else(|_| "base".to_owned());

    let (tx, mut rx) = mpsc::unbounded_channel::<String>();
    let options = sweep::SweepOptions {
        wallets_file: bot.manifest_path(chat_id),
        destination,
        chain: chain.clone(),
        rpc_urls: env_rpc_urls(),
        notify: Some(tx),
    };

    let _ = bot
        .send(
            chat_id,
            &format!("Sweeping all wallets to `{destination}` on {chain}..."),
        )
        .await;

    let forwarder_bot = bot.clone();
    let forwarder = tokio::spawn(async move {
        while let Some(line) = rx.recv().await {
            let _ = forwarder_bot.send(chat_id, &line).await;
        }
    });

    let result_bot = bot.clone();
    tokio::spawn(async move {
        let summary = match sweep::sweep(options).await {
            Ok(report) => format!(
                "Swept {} of {} wallet(s) — {} wei total.",
                report.swept_count(),
                report.outcomes.len(),
                report.total_sent()
            ),
            Err(error) => format!("Sweep failed: {error}"),
        };
        let _ = forwarder.await;
        let _ = result_bot.send(chat_id, &summary).await;
    });
}

/// List only the caller's own wallets. Paths are never shown — they encode
/// other users' chat ids, and a user has no use for a server-side path.
async fn list_wallets(bot: &Arc<Bot>, chat_id: i64) -> Result<(), BotError> {
    match bot.load_manifest(chat_id) {
        Ok(wallets) if wallets.is_empty() => {
            bot.send(
                chat_id,
                "Your manifest exists but holds no wallets. Send /start to create some.",
            )
            .await
        }
        Ok(wallets) => {
            let mut lines = format!("*Wallets ({})*\n\n", wallets.len());
            for (index, address, quantity) in wallets {
                let _ = writeln!(lines, "`{index}` — `{address}` (qty {quantity})");
            }
            bot.send(chat_id, &lines).await
        }
        Err(_) => {
            bot.send(
                chat_id,
                "You have no wallets yet.\n\nSend /start to create some.",
            )
            .await
        }
    }
}

async fn handle_document(bot: &Arc<Bot>, chat_id: i64, message: &Value) {
    let Some(document) = message.get("document") else {
        return;
    };
    let file_name = document
        .get("file_name")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let file_id = document
        .get("file_id")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if !file_name.to_ascii_lowercase().ends_with(".json") {
        let _ = bot
            .send(
                chat_id,
                "📎 Send a wallets.json file (keys are never read back to chat).",
            )
            .await;
        return;
    }
    let file = match bot.api("getFile", json!({"file_id": file_id})).await {
        Ok(file) => file,
        Err(error) => {
            let _ = bot
                .send(chat_id, &format!("Could not fetch file: {error}"))
                .await;
            return;
        }
    };
    let Some(file_path) = file.get("file_path").and_then(Value::as_str) else {
        let _ = bot.send(chat_id, "Telegram returned no file path.").await;
        return;
    };
    // Import into the caller's own manifest, and never over funded wallets —
    // an upload used to overwrite one shared file, so any user could destroy
    // everyone else's keys with a single message and no confirmation.
    let destination = bot.manifest_path(chat_id);
    if destination.exists() {
        let _ = bot
            .send(
                chat_id,
                "You already have wallets. Importing would overwrite them and any funds they hold.\n\nSweep them out with /withdraw first, then re-import.",
            )
            .await;
        return;
    }
    if let Err(error) = bot.download_file(file_path, &destination).await {
        let _ = bot
            .send(chat_id, &format!("Could not save file: {error}"))
            .await;
        return;
    }
    // The upload arrives as plaintext. Seal it immediately so an imported
    // manifest is protected exactly like a generated one.
    if manifest_crypto::is_enabled()
        && let Ok(plaintext) = std::fs::read_to_string(&destination)
        && !manifest_crypto::is_encrypted(&plaintext)
        && let Err(error) = manifest_crypto::write_manifest(&destination, &plaintext)
    {
        let _ = bot
            .send(chat_id, &format!("Could not encrypt the import: {error}"))
            .await;
        return;
    }
    match bot.load_manifest(chat_id) {
        Ok(wallets) if wallets.is_empty() => {
            let _ = bot
                .send(chat_id, "The file parsed but contains no wallets.")
                .await;
        }
        Ok(wallets) => {
            let mut lines = format!("*{} wallet(s) imported.*\n\n", wallets.len());
            for (index, address, quantity) in wallets {
                let _ = writeln!(lines, "`{index}` — `{address}` (qty {quantity})");
            }
            let _ = bot.send(chat_id, &lines).await;
        }
        Err(error) => {
            let _ = bot
                .send(chat_id, &format!("Invalid wallets.json: {error}"))
                .await;
        }
    }
}

#[allow(clippy::too_many_lines)]
async fn handle_callback(bot: &Arc<Bot>, chat_id: i64, data: &str) {
    match data {
        "menu:snipe" => {
            let mut wizards = bot.wizards.lock().await;
            wizards.insert(chat_id, Wizard::new());
            drop(wizards);
            let _ = bot
                .send(
                    chat_id,
                    "Send the collection — an OpenSea link, slug, or contract address.\n\n/cancel to abort.",
                )
                .await;
            return;
        }
        "menu:wallets" => {
            let _ = list_wallets(bot, chat_id).await;
            return;
        }
        "menu:withdraw" => {
            let _ = bot
                .send(chat_id, "Send /withdraw `<address>` to sweep all wallets.")
                .await;
            return;
        }
        "menu:status" => {
            let active = bot.active.lock().await.get(&chat_id).copied().unwrap_or(0);
            let _ = bot.send(chat_id, &format!("Active snipes: {active}")).await;
            return;
        }
        "menu:help" => {
            let _ = bot.send(chat_id, HELP).await;
            return;
        }
        "menu:recover" => {
            start_recovery(bot, chat_id).await;
            return;
        }
        "menu:addwallets" => {
            start_add_wallets(bot, chat_id).await;
            return;
        }
        _ => {}
    }
    if let Some(count) = data.strip_prefix("addwallets:") {
        if let Ok(count) = count.parse::<usize>() {
            begin_wallet_expansion(bot, chat_id, count).await;
        }
        return;
    }
    if let Some(chain) = data.strip_prefix("chain:") {
        let mut wizards = bot.wizards.lock().await;
        if let Some(wizard) = wizards.get_mut(&chat_id)
            && wizard.step == Step::Chain
        {
            wizard.chain = Some(chain.to_owned());
            wizard.step = Step::Quantity;
        }
        drop(wizards);
        let _ = bot
            .send(chat_id, "Quantity per wallet? Send a number (default 1).")
            .await;
        return;
    }
    if let Some(count) = data.strip_prefix("wallets:") {
        if let Ok(count) = count.parse::<usize>() {
            create_wallets(bot, chat_id, count).await;
        }
        return;
    }
    if let Some(mode) = data.strip_prefix("fund:") {
        let mut wizards = bot.wizards.lock().await;
        let updated = if let Some(wizard) = wizards.get_mut(&chat_id)
            && wizard.step == Step::Funding
        {
            wizard.funding = if mode == "sponsor" {
                Funding::Sponsored
            } else {
                Funding::SelfFunded
            };
            wizard.step = Step::Confirm;
            Some(wizard.clone())
        } else {
            None
        };
        drop(wizards);
        if let Some(wizard) = updated {
            show_confirm(bot, chat_id, &wizard).await;
        }
        return;
    }
    match data {
        // Take the wizard out and hand it to the fire path. Removing it first
        // and having `fire_snipe` look it up again means the lookup always
        // misses — pressing FIRE silently does nothing.
        "fire:yes" => {
            let wizard = bot.wizards.lock().await.remove(&chat_id);
            match wizard {
                Some(wizard) => fire_snipe(bot, chat_id, wizard).await,
                None => {
                    let _ = bot
                        .send(chat_id, "No snipe staged — send /snipe or paste a link.")
                        .await;
                }
            }
        }
        "fire:no" => {
            bot.wizards.lock().await.remove(&chat_id);
            let _ = bot
                .send(chat_id, "Cancelled — nothing was signed or broadcast.")
                .await;
        }
        _ => {}
    }
}

#[allow(clippy::too_many_lines)]
async fn advance_wizard(bot: &Arc<Bot>, chat_id: i64, text: &str) {
    let Some(mut wizard) = bot.wizards.lock().await.get(&chat_id).cloned() else {
        let _ = bot
            .send(chat_id, "No wizard active — send /snipe to start one.")
            .await;
        return;
    };

    match wizard.step {
        Step::Collection => {
            wizard.collection = text.trim().to_owned();
            wizard.step = Step::Chain;
            *bot.wizards
                .lock()
                .await
                .get_mut(&chat_id)
                .expect("wizard exists") = wizard;
            let _ = bot
                .send_keyboard(
                    chat_id,
                    "Which chain?",
                    &[&[
                        ("Base", "chain:base"),
                        ("Ethereum", "chain:ethereum"),
                        ("Robinhood", "chain:robinhood"),
                        ("Ink", "chain:ink"),
                    ]],
                )
                .await;
        }
        // Quantity is the last question with a free answer — wallets (all),
        // gas (auto), and early-fire (0) are fixed defaults now rather than
        // separate prompts, so a snipe only ever asks collection, chain,
        // quantity, and (when configured) funding mode before confirm.
        Step::Quantity => match text.parse::<u64>() {
            Ok(quantity) if quantity > 0 => {
                wizard.quantity = quantity;
                if bot.sponsor.is_some() {
                    wizard.step = Step::Funding;
                    *bot.wizards
                        .lock()
                        .await
                        .get_mut(&chat_id)
                        .expect("wizard exists") = wizard;
                    let _ = bot
                        .send_keyboard(
                            chat_id,
                            "Who pays gas?",
                            &[&[
                                ("Self-funded (each wallet)", "fund:self"),
                                ("Sponsored (one wallet, all gas)", "fund:sponsor"),
                            ]],
                        )
                        .await;
                } else {
                    wizard.step = Step::Confirm;
                    *bot.wizards
                        .lock()
                        .await
                        .get_mut(&chat_id)
                        .expect("wizard exists") = wizard.clone();
                    show_confirm(bot, chat_id, &wizard).await;
                }
            }
            _ => {
                let _ = bot
                    .send(chat_id, "Send a positive integer for quantity.")
                    .await;
            }
        },
        Step::Funding => {
            let _ = bot.send(chat_id, "Use the buttons above.").await;
        }
        Step::Confirm => {
            let _ = bot
                .send(
                    chat_id,
                    "Wizard already at confirm — press FIRE or send /cancel.",
                )
                .await;
        }
        Step::Chain => {
            let _ = bot.send(chat_id, "Use the chain buttons above.").await;
        }
    }
}

/// Does this message look like a collection locator rather than chatter? The
/// snipe path already accepts an address, an `OpenSea` URL, or a slug, so this
/// only has to recognise the first two — a bare word is far more likely to be
/// conversation than a slug, and guessing wrong would hijack the message.
fn looks_like_collection(text: &str) -> bool {
    let trimmed = text.trim();
    if trimmed.len() == 42
        && let Some(body) = trimmed.strip_prefix("0x")
    {
        return body.chars().all(|c| c.is_ascii_hexdigit());
    }
    let lowered = trimmed.to_ascii_lowercase();
    (lowered.starts_with("https://") || lowered.starts_with("http://"))
        && lowered.contains("opensea.io")
        && !trimmed.contains(char::is_whitespace)
}

/// `OpenSea` item and asset URLs carry the chain as a path segment
/// (`/assets/base/0x…`, `/item/ethereum/0x…`). Lifting it saves the user a
/// button press; collection-slug URLs carry no chain, so those still ask.
fn infer_chain_from_url(text: &str) -> Option<String> {
    let lowered = text.trim().to_ascii_lowercase();
    let segments: Vec<&str> = lowered
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect();
    let marker = segments
        .iter()
        .position(|segment| *segment == "assets" || *segment == "item")?;
    let candidate = segments.get(marker + 1)?;
    match *candidate {
        "ethereum" | "eth" | "mainnet" => Some("ethereum".to_owned()),
        "base" => Some("base".to_owned()),
        "robinhood" => Some("robinhood".to_owned()),
        "ink" => Some("ink".to_owned()),
        _ => None,
    }
}

/// Entry point for a pasted link or address with no wizard running: stage the
/// collection, lift the chain from the URL when it is there, and hand straight
/// off to the quantity step so the flow is paste → confirm rather than
/// `/snipe` → paste → confirm.
async fn start_from_locator(bot: &Arc<Bot>, chat_id: i64, locator: &str) {
    let mut wizard = Wizard::new();
    wizard.collection = locator.trim().to_owned();

    if let Some(chain) = infer_chain_from_url(locator) {
        wizard.chain = Some(chain.clone());
        wizard.step = Step::Quantity;
        bot.wizards.lock().await.insert(chat_id, wizard);
        let _ = bot
            .send(
                chat_id,
                &format!(
                    "Staged `{}` on {chain}.\n\nQuantity per wallet? Send a number (default 1).\n\n/cancel to abort.",
                    locator.trim()
                ),
            )
            .await;
    } else {
        wizard.step = Step::Chain;
        bot.wizards.lock().await.insert(chat_id, wizard);
        let _ = bot
            .send_keyboard(
                chat_id,
                &format!("Staged `{}`.\n\nWhich chain?", locator.trim()),
                &[&[
                    ("Base", "chain:base"),
                    ("Ethereum", "chain:ethereum"),
                    ("Robinhood", "chain:robinhood"),
                    ("Ink", "chain:ink"),
                ]],
            )
            .await;
    }
}

fn gas_label(wizard: &Wizard) -> String {
    match (wizard.max_fee_per_gas, wizard.max_priority_fee_per_gas) {
        (Some(max), Some(priority)) => format!(
            "max {} / priority {} gwei",
            format_gwei(max),
            format_gwei(priority)
        ),
        (Some(max), None) => format!("max {} gwei / priority auto", format_gwei(max)),
        (None, Some(priority)) => format!("max auto / priority {} gwei", format_gwei(priority)),
        (None, None) => "auto (chain estimate)".to_owned(),
    }
}

fn wallet_label(wizard: &Wizard, wallet_count: usize) -> String {
    match &wizard.wallets {
        Some(indices) if !indices.is_empty() => {
            format!("{} wallet(s) — indices {:?}", indices.len(), indices)
        }
        _ => format!("{wallet_count} wallet(s) — all"),
    }
}

fn stage_status(start_time: u64) -> &'static str {
    let now = i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs()),
    )
    .unwrap_or(i64::MAX);
    if i64::try_from(start_time).unwrap_or(i64::MAX) <= now {
        "Live"
    } else {
        "Scheduled"
    }
}

async fn show_confirm(bot: &Arc<Bot>, chat_id: i64, wizard: &Wizard) {
    match wizard.funding {
        Funding::SelfFunded => show_confirm_self_funded(bot, chat_id, wizard).await,
        Funding::Sponsored => show_confirm_sponsored(bot, chat_id, wizard).await,
    }
}

async fn show_confirm_self_funded(bot: &Arc<Bot>, chat_id: i64, wizard: &Wizard) {
    let chain = wizard.chain.clone().unwrap_or_default();
    let options = SnipeOptions {
        collection: wizard.collection.clone(),
        quantity: Some(wizard.quantity),
        keys: Vec::new(),
        wallets_file: Some(bot.manifest_path(chat_id)),
        wallet_indices: wizard.wallets.clone(),
        rpc_urls: env_rpc_urls(),
        chain: Some(chain.clone()),
        max_fee_per_gas: wizard.max_fee_per_gas,
        max_priority_fee_per_gas: wizard.max_priority_fee_per_gas,
        gas_limit: 250_000,
        early_fire_ms: wizard.early_fire_ms,
        fire_now: false,
        max_total_spend_wei: snipe::default_spend_cap(),
        notify: None,
    };

    match snipe::preview(&options).await {
        Ok(preview) => {
            let summary = format!(
                "*Snipe Preview* — {}\n\n\
                 Contract: `{}`\n\
                 Chain: {}\n\
                 Price: {} wei ({:.4} ETH)\n\
                 Wallets: {}\n\
                 Funding: self-funded (each wallet pays its own gas)\n\
                 Gas: {}\n\
                 Early fire: {} ms\n\n\
                 Confirm?",
                stage_status(preview.start_time),
                preview.nft_contract,
                preview.chain_name,
                preview.price,
                eth_from_wei(preview.price),
                wallet_label(wizard, preview.wallet_count),
                gas_label(wizard),
                wizard.early_fire_ms,
            );
            let _ = bot
                .send_keyboard(
                    chat_id,
                    &summary,
                    &[&[("FIRE", "fire:yes"), ("Cancel", "fire:no")]],
                )
                .await;
        }
        Err(error) => {
            bot.wizards.lock().await.remove(&chat_id);
            let _ = bot
                .send(
                    chat_id,
                    &format!("Cannot preview this snipe: {error}\n\nSend /snipe to try again."),
                )
                .await;
        }
    }
}

async fn show_confirm_sponsored(bot: &Arc<Bot>, chat_id: i64, wizard: &Wizard) {
    let Some(options) = sponsored_options(bot, chat_id, wizard, None) else {
        bot.wizards.lock().await.remove(&chat_id);
        let _ = bot
            .send(
                chat_id,
                "Sponsored mode is no longer configured — send /snipe to try again.",
            )
            .await;
        return;
    };

    match sponsored_snipe::preview(&options).await {
        Ok(preview) => {
            let summary = format!(
                "*Sponsored Snipe Preview* — {}\n\n\
                 Contract: `{}`\n\
                 Chain: {}\n\
                 Price: {} wei ({:.4} ETH)\n\
                 Wallets: {}\n\
                 Funding: sponsored — `{}` pays all gas\n\
                 NFT recipient: `{}`\n\
                 Gas: {}\n\
                 Early fire: {} ms\n\n\
                 Confirm?",
                stage_status(preview.start_time),
                preview.nft_contract,
                preview.chain_name,
                preview.price,
                eth_from_wei(preview.price),
                wallet_label(wizard, preview.wallet_count),
                preview.sponsor,
                preview.recipient,
                gas_label(wizard),
                wizard.early_fire_ms,
            );
            let _ = bot
                .send_keyboard(
                    chat_id,
                    &summary,
                    &[&[("FIRE", "fire:yes"), ("Cancel", "fire:no")]],
                )
                .await;
        }
        Err(error) => {
            bot.wizards.lock().await.remove(&chat_id);
            let _ = bot
                .send(
                    chat_id,
                    &format!(
                        "Cannot preview this sponsored snipe: {error}\n\nSend /snipe to try again."
                    ),
                )
                .await;
        }
    }
}

/// Builds `SponsoredSnipeOptions` from the wizard + bot's sponsor config.
/// `None` if sponsored mode isn't (or is no longer) configured — checked
/// again here rather than trusting the wizard state, since the bot's env
/// could theoretically change between steps in a long-lived process.
fn sponsored_options(
    bot: &Arc<Bot>,
    chat_id: i64,
    wizard: &Wizard,
    notify: Option<mpsc::UnboundedSender<String>>,
) -> Option<SponsoredSnipeOptions> {
    let sponsor = bot.sponsor.as_ref()?;
    Some(SponsoredSnipeOptions {
        collection: wizard.collection.clone(),
        quantity: Some(wizard.quantity),
        wallets_file: bot.manifest_path(chat_id),
        wallet_indices: wizard.wallets.clone(),
        rpc_urls: env_rpc_urls(),
        chain: wizard.chain.clone(),
        sponsor: sponsor.signer.clone(),
        executor: sponsor.executor,
        recipient: sponsor.recipient,
        mint_gas_limit: sponsor.mint_gas_limit,
        operation_deadline_seconds: sponsor.operation_deadline_seconds,
        max_fee_per_gas: wizard.max_fee_per_gas,
        max_priority_fee_per_gas: wizard.max_priority_fee_per_gas,
        early_fire_ms: wizard.early_fire_ms,
        fire_now: false,
        notify,
    })
}

async fn fire_snipe(bot: &Arc<Bot>, chat_id: i64, wizard: Wizard) {
    match wizard.funding {
        Funding::SelfFunded => fire_snipe_self_funded(bot, chat_id, wizard).await,
        Funding::Sponsored => fire_snipe_sponsored(bot, chat_id, wizard).await,
    }
}

async fn fire_snipe_self_funded(bot: &Arc<Bot>, chat_id: i64, wizard: Wizard) {
    let Some(chain) = wizard.chain.clone() else {
        let _ = bot
            .send(chat_id, "No chain selected — send /snipe to start again.")
            .await;
        return;
    };

    let (tx, mut rx) = mpsc::unbounded_channel::<String>();
    let options = SnipeOptions {
        collection: wizard.collection.clone(),
        quantity: Some(wizard.quantity),
        keys: Vec::new(),
        wallets_file: Some(bot.manifest_path(chat_id)),
        wallet_indices: wizard.wallets.clone(),
        rpc_urls: env_rpc_urls(),
        chain: Some(chain),
        max_fee_per_gas: wizard.max_fee_per_gas,
        max_priority_fee_per_gas: wizard.max_priority_fee_per_gas,
        gas_limit: 250_000,
        early_fire_ms: wizard.early_fire_ms,
        fire_now: false,
        max_total_spend_wei: snipe::default_spend_cap(),
        notify: Some(tx),
    };

    {
        let mut active = bot.active.lock().await;
        *active.entry(chat_id).or_insert(0) += 1;
    }

    let bot_clone = bot.clone();
    let forwarder = tokio::spawn(async move {
        while let Some(line) = rx.recv().await {
            let _ = bot_clone.send(chat_id, &line).await;
        }
    });

    let bot_clone = bot.clone();
    tokio::spawn(async move {
        let _ = bot_clone
            .send(
                chat_id,
                "Arming snipe. Signing transactions — progress will stream here.",
            )
            .await;
        let result = snipe::run_snipe(options).await;
        if let Err(error) = result {
            let _ = bot_clone.send(chat_id, &format!("Error: {error}")).await;
        }
        {
            let mut active = bot_clone.active.lock().await;
            if let Some(count) = active.get_mut(&chat_id) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    active.remove(&chat_id);
                }
            }
        }
        let _ = forwarder.await;
    });
}

async fn fire_snipe_sponsored(bot: &Arc<Bot>, chat_id: i64, wizard: Wizard) {
    let (tx, mut rx) = mpsc::unbounded_channel::<String>();
    let Some(options) = sponsored_options(bot, chat_id, &wizard, Some(tx)) else {
        let _ = bot
            .send(
                chat_id,
                "Sponsored mode is no longer configured — send /snipe to try again.",
            )
            .await;
        return;
    };

    {
        let mut active = bot.active.lock().await;
        *active.entry(chat_id).or_insert(0) += 1;
    }

    let bot_clone = bot.clone();
    let forwarder = tokio::spawn(async move {
        while let Some(line) = rx.recv().await {
            let _ = bot_clone.send(chat_id, &line).await;
        }
    });

    let bot_clone = bot.clone();
    tokio::spawn(async move {
        let _ = bot_clone
            .send(
                chat_id,
                "Arming sponsored snipe. Signing the batch — progress will stream here.",
            )
            .await;
        let result = sponsored_snipe::run_sponsored_snipe(options).await;
        if let Err(error) = result {
            let _ = bot_clone.send(chat_id, &format!("Error: {error}")).await;
        }
        {
            let mut active = bot_clone.active.lock().await;
            if let Some(count) = active.get_mut(&chat_id) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    active.remove(&chat_id);
                }
            }
        }
        let _ = forwarder.await;
    });
}

/// Telegram's hard cap is 4096 characters per message; it counts UTF-16 code
/// units, so an emoji-heavy line costs more than its `char` count suggests.
/// Split well under the limit rather than compute the exact encoding width.
const MAX_MESSAGE_CHARS: usize = 3500;

/// Break `text` into message-sized pieces, preferring line boundaries so a
/// wallet listing never splits mid-row. A single line longer than the limit is
/// cut on a character boundary — never mid-UTF-8-sequence.
fn split_message(text: &str) -> Vec<String> {
    if text.chars().count() <= MAX_MESSAGE_CHARS {
        return vec![text.to_owned()];
    }

    let mut chunks = Vec::new();
    let mut current = String::new();
    // Track lengths alongside the buffers: `chars().count()` walks the whole
    // string, so recomputing it per character turns a long line into
    // quadratic work.
    let mut current_len = 0usize;
    for line in text.split_inclusive('\n') {
        let line_len = line.chars().count();

        // A single oversized line cannot be placed whole; flush and hard-split.
        if line_len > MAX_MESSAGE_CHARS {
            if !current.is_empty() {
                chunks.push(std::mem::take(&mut current));
                current_len = 0;
            }
            let mut piece = String::new();
            let mut piece_len = 0usize;
            for character in line.chars() {
                if piece_len == MAX_MESSAGE_CHARS {
                    chunks.push(std::mem::take(&mut piece));
                    piece_len = 0;
                }
                piece.push(character);
                piece_len += 1;
            }
            if !piece.is_empty() {
                current = piece;
                current_len = piece_len;
            }
            continue;
        }

        if current_len + line_len > MAX_MESSAGE_CHARS {
            chunks.push(std::mem::take(&mut current));
            current_len = 0;
        }
        current.push_str(line);
        current_len += line_len;
    }
    if !current.is_empty() {
        chunks.push(current);
    }
    chunks
}

fn env_rpc_urls() -> Vec<String> {
    env::var("RPC_URL_BOT")
        .ok()
        .or_else(|| env::var("RPC_URL").ok())
        .map(|value| {
            value
                .split(',')
                .map(|entry| entry.trim().to_owned())
                .filter(|entry| !entry.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

fn format_gwei(wei: U256) -> String {
    let whole = wei / U256::from(1_000_000_000u128);
    let fraction = wei % U256::from(1_000_000_000u128);
    let millis = fraction * U256::from(1_000) / U256::from(1_000_000_000u128);
    format!("{whole}.{millis:0>3}")
}

fn eth_from_wei(wei: U256) -> f64 {
    let whole = wei / U256::from(1_000_000_000_000_000_000u128);
    let fraction = wei % U256::from(1_000_000_000_000_000_000u128);
    whole.to_string().parse::<f64>().unwrap_or(0.0)
        + fraction.to_string().parse::<f64>().unwrap_or(0.0) / 1_000_000_000_000_000_000.0
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The core multi-tenant invariant: two chats must never resolve to the
    /// same manifest, or one user can spend another's wallets.
    #[test]
    fn each_chat_gets_a_distinct_manifest_path() {
        let bot = Bot::new(
            "token".to_owned(),
            vec![1, 2],
            PathBuf::from("/data/wallets"),
            None,
        )
        .expect("client builds");

        let first = bot.manifest_path(111);
        let second = bot.manifest_path(222);

        assert_ne!(first, second);
        assert_eq!(first, PathBuf::from("/data/wallets/111.json"));
        // Telegram group ids are negative; they must stay inside the directory.
        assert_eq!(
            bot.manifest_path(-100_123),
            PathBuf::from("/data/wallets/-100123.json")
        );
        for chat_id in [111, 222, -100_123] {
            assert_eq!(
                bot.manifest_path(chat_id).parent(),
                Some(Path::new("/data/wallets")),
                "a manifest must never escape the wallets directory"
            );
        }
    }

    #[test]
    fn locator_detection_accepts_addresses_and_opensea_urls() {
        assert!(looks_like_collection(
            "0x1234567890abcdef1234567890abcdef12345678"
        ));
        assert!(looks_like_collection(
            "https://opensea.io/collection/some-drop"
        ));
        assert!(looks_like_collection(
            "https://opensea.io/item/base/0xabc/1"
        ));
    }

    /// Ordinary chat must never be mistaken for a collection — a false
    /// positive would hijack the message into the snipe wizard.
    #[test]
    fn locator_detection_rejects_conversation() {
        assert!(!looks_like_collection("snipe the new drop for me"));
        assert!(!looks_like_collection("0xdeadbeef")); // too short for an address
        assert!(!looks_like_collection(
            "0x1234567890abcdef1234567890abcdef1234567g" // non-hex
        ));
        assert!(!looks_like_collection("https://example.com/collection/x"));
        assert!(!looks_like_collection("check https://opensea.io/x please"));
        assert!(!looks_like_collection(""));
    }

    #[test]
    fn chain_is_lifted_from_item_and_asset_urls() {
        assert_eq!(
            infer_chain_from_url("https://opensea.io/item/base/0xabc/1").as_deref(),
            Some("base")
        );
        assert_eq!(
            infer_chain_from_url("https://opensea.io/assets/ethereum/0xabc/1").as_deref(),
            Some("ethereum")
        );
        // Collection-slug URLs carry no chain — the wizard must still ask.
        assert_eq!(
            infer_chain_from_url("https://opensea.io/collection/some-drop"),
            None
        );
        // An unsupported chain must not be silently coerced to a supported one.
        assert_eq!(
            infer_chain_from_url("https://opensea.io/assets/matic/0xabc/1"),
            None
        );
    }

    #[test]
    fn short_messages_are_not_split() {
        assert_eq!(split_message("hello"), vec!["hello".to_owned()]);
    }

    /// A 50-wallet listing exceeds Telegram's cap; every row must survive and
    /// no chunk may exceed the limit.
    #[test]
    fn long_listings_split_on_line_boundaries() {
        let listing = (0..200).fold(String::new(), |mut acc, index| {
            let _ = writeln!(acc, "  {index}: 0x{index:040x} (qty 1)");
            acc
        });
        let chunks = split_message(&listing);

        assert!(chunks.len() > 1, "expected the listing to split");
        for chunk in &chunks {
            assert!(chunk.chars().count() <= MAX_MESSAGE_CHARS);
        }
        assert_eq!(chunks.concat(), listing, "no content may be lost");
        for chunk in &chunks {
            assert!(
                chunk.starts_with("  "),
                "chunks must begin at a row boundary, got: {chunk:.20}"
            );
        }
    }

    /// An oversized line sitting between normal lines is the case most likely
    /// to drop or duplicate content, since it flushes and resumes the buffer.
    #[test]
    fn oversized_line_between_normal_lines_preserves_everything() {
        let text = format!(
            "first line\n{}\nlast line\n",
            "x".repeat(MAX_MESSAGE_CHARS * 2 + 17)
        );
        let chunks = split_message(&text);

        for chunk in &chunks {
            assert!(chunk.chars().count() <= MAX_MESSAGE_CHARS);
        }
        assert_eq!(
            chunks.concat(),
            text,
            "no content may be lost or duplicated"
        );
        assert!(
            chunks
                .first()
                .is_some_and(|chunk| chunk.starts_with("first line"))
        );
        assert!(
            chunks
                .last()
                .is_some_and(|chunk| chunk.ends_with("last line\n"))
        );
    }

    /// A single line longer than the cap has to be cut mid-line, and the cut
    /// must land on a character boundary rather than inside a UTF-8 sequence.
    #[test]
    fn oversized_single_line_splits_on_char_boundaries() {
        let line = "🦈".repeat(MAX_MESSAGE_CHARS + 500);
        let chunks = split_message(&line);

        assert!(chunks.len() > 1);
        for chunk in &chunks {
            assert!(chunk.chars().count() <= MAX_MESSAGE_CHARS);
        }
        assert_eq!(chunks.concat(), line);
    }
}
