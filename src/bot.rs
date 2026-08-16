//! Telegram bot control surface for the `SeaDrop` sniper.
//!
//! Raw long-polling (`getUpdates`) — no webhook, no framework dependency on
//! top of the existing `reqwest/serde_json/tokio` stack.
//!
//! Security model:
//! - Owner-only: every chat id must be in `ALLOWED_CHAT_IDS`.
//! - Private keys never appear in chat. Wallets come from the server-side
//!   manifest (`WALLETS_FILE`, default `wallets.json`) or from a `wallets.json`
//!   **file upload** (downloaded, validated, saved server-side).
//! - The fire path runs in a background task; progress streams to the chat.

use std::{
    collections::HashMap,
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
    logging,
    multi_wallet::WalletManifest,
    snipe::{self, SnipeOptions},
};

#[allow(unused_imports)]
use std::fmt::Write as _;

const API_BASE: &str = "https://api.telegram.org/bot";
const POLL_TIMEOUT_SECONDS: u64 = 25;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(70);
const DEFAULT_WALLETS_FILE: &str = "wallets.json";

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
    Wallets,
    Gas,
    Early,
    Confirm,
}

#[derive(Clone, Debug)]
struct Wizard {
    step: Step,
    collection: String,
    chain: Option<String>,
    quantity: u64,
    wallets: Option<Vec<usize>>,
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
            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
            early_fire_ms: 0,
        }
    }
}

struct Bot {
    http: reqwest::Client,
    token: String,
    allowed: Vec<i64>,
    wallets_file: PathBuf,
    wizards: Mutex<HashMap<i64, Wizard>>,
    active: Mutex<HashMap<i64, usize>>,
}

impl Bot {
    fn new(token: String, allowed: Vec<i64>, wallets_file: PathBuf) -> Result<Self, BotError> {
        let http = reqwest::Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .build()
            .map_err(|_| BotError::Http)?;
        Ok(Self {
            http,
            token,
            allowed,
            wallets_file,
            wizards: Mutex::new(HashMap::new()),
            active: Mutex::new(HashMap::new()),
        })
    }

    fn is_allowed(&self, chat_id: i64) -> bool {
        self.allowed.contains(&chat_id)
    }

    async fn api(&self, method: &str, params: Value) -> Result<Value, BotError> {
        let url = format!("{API_BASE}{}/{}", self.token, method);
        let response = self
            .http
            .post(&url)
            .json(&params)
            .send()
            .await
            .map_err(|error| BotError::Telegram(error.to_string()))?;
        let value: Value = response
            .json()
            .await
            .map_err(|error| BotError::Telegram(error.to_string()))?;
        if value.get("ok").and_then(Value::as_bool) != Some(true) {
            let description = value
                .get("description")
                .and_then(Value::as_str)
                .unwrap_or("unknown error");
            return Err(BotError::TelegramApi(format!("{method}: {description}")));
        }
        Ok(value.get("result").cloned().unwrap_or(Value::Null))
    }

    async fn send(&self, chat_id: i64, text: &str) -> Result<(), BotError> {
        self.api(
            "sendMessage",
            json!({
                "chat_id": chat_id,
                "text": text,
                "disable_web_page_preview": true,
            }),
        )
        .await?;
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
            .map_err(|error| BotError::Telegram(error.to_string()))?
            .bytes()
            .await
            .map_err(|error| BotError::Telegram(error.to_string()))?;
        std::fs::write(destination, bytes).map_err(|error| {
            BotError::Telegram(format!("cannot write {}: {error}", destination.display()))
        })
    }

    fn load_manifest(&self) -> Result<Vec<(usize, Address, u64)>, String> {
        let manifest =
            WalletManifest::load(&self.wallets_file).map_err(|error| error.to_string())?;
        Ok(manifest
            .wallets()
            .iter()
            .enumerate()
            .map(|(index, entry)| (index, entry.address(), entry.quantity()))
            .collect())
    }
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
    let wallets_file = env::var("WALLETS_FILE")
        .map_or_else(|_| PathBuf::from(DEFAULT_WALLETS_FILE), PathBuf::from);

    let bot = Arc::new(Bot::new(token, allowed, wallets_file)?);

    let me = bot.api("getMe", json!({})).await?;
    let username = me.get("username").and_then(Value::as_str).unwrap_or("?");
    logging::section_break();
    logging::success(format!(
        "Telegram bot @{username} online — owner chat(s): {:?}",
        bot.allowed
    ));
    logging::info(format!("Wallets manifest: {}", bot.wallets_file.display()));
    logging::info("Waiting for updates...");
    logging::section_break();

    let mut offset: i64 = 0;
    loop {
        match bot.get_updates(offset).await {
            Ok(updates) => {
                for update in updates {
                    if let Some(update_id) = update.get("update_id").and_then(Value::as_i64) {
                        offset = update_id + 1;
                    }
                    handle_update(&bot, update).await;
                }
            }
            Err(BotError::TelegramApi(error)) if error.contains("Conflict") => {
                logging::error("another bot instance is polling with this token — stop it first");
                return Ok(());
            }
            Err(error) => {
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

const HELP: &str = "🦈 SeaDrop sniper bot\n\n\
Commands:\n\
/wallets — list manifest wallets (addresses only)\n\
/snipe — start a snipe wizard (collection → chain → qty → wallets → gas → early fire)\n\
/cancel — abandon the current wizard\n\
/status — active snipe count\n\
/help — this message\n\n\
📎 Import a manifest by uploading a wallets.json file — keys are saved server-side and never shown in chat.";

async fn handle_text(bot: &Arc<Bot>, chat_id: i64, text: &str) {
    let trimmed = text.trim();
    if let Some(command) = trimmed.strip_prefix('/') {
        let command = command.split_whitespace().next().unwrap_or_default();
        match command {
            "start" | "help" => {
                let _ = bot.send(chat_id, HELP).await;
            }
            "wallets" => {
                let _ = list_wallets(bot, chat_id).await;
            }
            "snipe" => {
                let mut wizards = bot.wizards.lock().await;
                wizards.insert(chat_id, Wizard::new());
                drop(wizards);
                let _ = bot
                    .send(
                        chat_id,
                        "🎯 Start a snipe.\n\nSend the collection: an OpenSea link, a slug, or the 0x contract address.\n\n/cancel to abort.",
                    )
                    .await;
            }
            "cancel" => {
                bot.wizards.lock().await.remove(&chat_id);
                let _ = bot.send(chat_id, "Wizard cancelled.").await;
            }
            "status" => {
                let active = bot.active.lock().await.get(&chat_id).copied().unwrap_or(0);
                let _ = bot
                    .send(
                        chat_id,
                        &format!("🟢 active snipe(s) in flight: {active}\n🔴 idle"),
                    )
                    .await;
            }
            _ => {
                let _ = bot.send(chat_id, "Unknown command — /help").await;
            }
        }
        return;
    }
    advance_wizard(bot, chat_id, trimmed).await;
}

async fn list_wallets(bot: &Arc<Bot>, chat_id: i64) -> Result<(), BotError> {
    match bot.load_manifest() {
        Ok(wallets) if wallets.is_empty() => {
            bot.send(
                chat_id,
                &format!(
                    "⚠️ {} exists but has no wallets.\n\nGenerate with `opensea-mint wallets create` on the server, or upload a wallets.json here.",
                    bot.wallets_file.display()
                ),
            )
            .await
        }
        Ok(wallets) => {
            let mut lines = format!(
                "🗂 {} — {} wallet(s):\n",
                bot.wallets_file.display(),
                wallets.len()
            );
            for (index, address, quantity) in wallets {
                let _ = writeln!(lines, "  {index}: `{address}` (qty {quantity})");
            }
            bot.send(chat_id, &lines).await
        }
        Err(_) => {
            bot.send(
                chat_id,
                &format!(
                    "⚠️ No manifest at {}.\n\nGenerate one on the server (`opensea-mint wallets create --count N --output {}`) or upload a wallets.json file here.",
                    bot.wallets_file.display(),
                    bot.wallets_file.display()
                ),
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
                .send(chat_id, &format!("❌ Could not fetch file: {error}"))
                .await;
            return;
        }
    };
    let Some(file_path) = file.get("file_path").and_then(Value::as_str) else {
        let _ = bot
            .send(chat_id, "❌ Telegram returned no file path.")
            .await;
        return;
    };
    let destination = bot.wallets_file.clone();
    if let Err(error) = bot.download_file(file_path, &destination).await {
        let _ = bot
            .send(chat_id, &format!("❌ Could not save file: {error}"))
            .await;
        return;
    }
    match bot.load_manifest() {
        Ok(wallets) if wallets.is_empty() => {
            let _ = bot
                .send(chat_id, "⚠️ The file parsed but contains no wallets.")
                .await;
        }
        Ok(wallets) => {
            let mut lines = format!(
                "✅ Imported {} wallet(s) to {}:\n",
                wallets.len(),
                bot.wallets_file.display()
            );
            for (index, address, quantity) in wallets {
                let _ = writeln!(lines, "  {index}: `{address}` (qty {quantity})");
            }
            let _ = bot.send(chat_id, &lines).await;
        }
        Err(error) => {
            let _ = bot
                .send(chat_id, &format!("❌ Invalid wallets.json: {error}"))
                .await;
        }
    }
}

async fn handle_callback(bot: &Arc<Bot>, chat_id: i64, data: &str) {
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
    match data {
        "fire:yes" => {
            bot.wizards.lock().await.remove(&chat_id);
            fire_snipe(bot, chat_id).await;
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
                    ]],
                )
                .await;
        }
        Step::Quantity => match text.parse::<u64>() {
            Ok(quantity) if quantity > 0 => {
                wizard.quantity = quantity;
                wizard.step = Step::Wallets;
                *bot.wizards
                    .lock()
                    .await
                    .get_mut(&chat_id)
                    .expect("wizard exists") = wizard;
                let _ = bot
                    .send(
                        chat_id,
                        "Which wallets? Send indices from /wallets (e.g. `0,1,2`) or `all`.",
                    )
                    .await;
            }
            _ => {
                let _ = bot
                    .send(chat_id, "Send a positive integer for quantity.")
                    .await;
            }
        },
        Step::Wallets => match parse_wallet_selection(text) {
            Ok(selection) => {
                wizard.wallets = Some(selection);
                wizard.step = Step::Gas;
                *bot.wizards
                    .lock()
                    .await
                    .get_mut(&chat_id)
                    .expect("wizard exists") = wizard;
                let _ = bot
                    .send(
                        chat_id,
                        "Gas: send `max/priority` in gwei (e.g. `0.05/0.01`) or `auto`.",
                    )
                    .await;
            }
            Err(message) => {
                let _ = bot.send(chat_id, &message).await;
            }
        },
        Step::Gas => match parse_gas(text) {
            Ok((max, priority)) => {
                wizard.max_fee_per_gas = max;
                wizard.max_priority_fee_per_gas = priority;
                wizard.step = Step::Early;
                *bot.wizards
                    .lock()
                    .await
                    .get_mut(&chat_id)
                    .expect("wizard exists") = wizard;
                let _ = bot
                    .send(
                        chat_id,
                        "Early fire (ms before stage open)? Send a number or `0`.",
                    )
                    .await;
            }
            Err(message) => {
                let _ = bot.send(chat_id, &message).await;
            }
        },
        Step::Early => match text.parse::<u64>() {
            Ok(early) => {
                wizard.early_fire_ms = early;
                wizard.step = Step::Confirm;
                *bot.wizards
                    .lock()
                    .await
                    .get_mut(&chat_id)
                    .expect("wizard exists") = wizard.clone();
                show_confirm(bot, chat_id, &wizard).await;
            }
            _ => {
                let _ = bot
                    .send(chat_id, "Send a number of milliseconds or `0`.")
                    .await;
            }
        },
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

fn parse_wallet_selection(text: &str) -> Result<Vec<usize>, String> {
    let trimmed = text.trim().to_ascii_lowercase();
    if trimmed == "all" {
        return Ok(Vec::new());
    }
    let mut indices = Vec::new();
    for part in trimmed.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Ok(index) = part.parse::<usize>() {
            if !indices.contains(&index) {
                indices.push(index);
            }
        } else {
            return Err(format!(
                "Cannot parse `{part}` — send comma-separated indices or `all`."
            ));
        }
    }
    if indices.is_empty() {
        return Err("Send at least one wallet index or `all`.".to_owned());
    }
    Ok(indices)
}

fn parse_gas(text: &str) -> Result<(Option<U256>, Option<U256>), String> {
    let trimmed = text.trim().to_ascii_lowercase();
    if trimmed == "auto" || trimmed.is_empty() {
        return Ok((None, None));
    }
    let (max, priority) = match trimmed.split_once('/') {
        Some((max, priority)) => (max.trim(), priority.trim()),
        None => (trimmed.as_str(), ""),
    };
    let max = if max.is_empty() {
        None
    } else {
        Some(
            snipe::parse_gwei(max)
                .map_err(|_| format!("Invalid max fee `{max}` — e.g. `0.05/0.01` or `auto`."))?,
        )
    };
    let priority = if priority.is_empty() {
        None
    } else {
        Some(snipe::parse_gwei(priority).map_err(|_| {
            format!("Invalid priority fee `{priority}` — e.g. `0.05/0.01` or `auto`.")
        })?)
    };
    if max.is_none() && priority.is_none() {
        return Err("Send `max/priority` in gwei or `auto`.".to_owned());
    }
    Ok((max, priority))
}

async fn show_confirm(bot: &Arc<Bot>, chat_id: i64, wizard: &Wizard) {
    let chain = wizard.chain.clone().unwrap_or_default();
    let options = SnipeOptions {
        collection: wizard.collection.clone(),
        quantity: Some(wizard.quantity),
        keys: Vec::new(),
        wallets_file: Some(bot.wallets_file.clone()),
        wallet_indices: wizard.wallets.clone(),
        rpc_urls: env_rpc_urls(),
        chain: Some(chain.clone()),
        max_fee_per_gas: wizard.max_fee_per_gas,
        max_priority_fee_per_gas: wizard.max_priority_fee_per_gas,
        gas_limit: 250_000,
        early_fire_ms: wizard.early_fire_ms,
        fire_now: false,
        notify: None,
    };

    match snipe::preview(&options).await {
        Ok(preview) => {
            let now = i64::try_from(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_secs()),
            )
            .unwrap_or(i64::MAX);
            let stage_status = if i64::try_from(preview.start_time).unwrap_or(i64::MAX) <= now {
                "🟢 live now"
            } else {
                "⏳ scheduled"
            };
            let wallet_label = match &wizard.wallets {
                Some(indices) if !indices.is_empty() => {
                    format!("{} wallet(s) — indices {:?}", indices.len(), indices)
                }
                _ => format!("{} wallet(s) — all", preview.wallet_count),
            };
            let gas_label = match (wizard.max_fee_per_gas, wizard.max_priority_fee_per_gas) {
                (Some(max), Some(priority)) => format!(
                    "max {} / priority {} gwei",
                    format_gwei(max),
                    format_gwei(priority)
                ),
                (Some(max), None) => format!("max {} gwei / priority auto", format_gwei(max)),
                (None, Some(priority)) => {
                    format!("max auto / priority {} gwei", format_gwei(priority))
                }
                (None, None) => "auto (chain estimate)".to_owned(),
            };
            let summary = format!(
                "🎯 Snipe preview — {stage_status}\n\n\
                 📦 {}\n\
                 ⛓️ {}\n\
                 💰 price {} wei ({:.4} ETH)\n\
                 🗂 {wallet_label}\n\
                 ⛽ {gas_label}\n\
                 🔥 early fire: {} ms\n\n\
                 Confirm?",
                preview.nft_contract,
                preview.chain_name,
                preview.price,
                eth_from_wei(preview.price),
                wizard.early_fire_ms,
            );
            let _ = bot
                .send_keyboard(
                    chat_id,
                    &summary,
                    &[&[("✅ FIRE", "fire:yes"), ("❌ Cancel", "fire:no")]],
                )
                .await;
        }
        Err(error) => {
            bot.wizards.lock().await.remove(&chat_id);
            let _ = bot
                .send(
                    chat_id,
                    &format!("❌ Cannot preview this snipe: {error}\n\nSend /snipe to try again."),
                )
                .await;
        }
    }
}

async fn fire_snipe(bot: &Arc<Bot>, chat_id: i64) {
    let Some(wizard) = bot.wizards.lock().await.get(&chat_id).cloned() else {
        return;
    };
    let Some(chain) = wizard.chain.clone() else {
        return;
    };

    let (tx, mut rx) = mpsc::unbounded_channel::<String>();
    let options = SnipeOptions {
        collection: wizard.collection.clone(),
        quantity: Some(wizard.quantity),
        keys: Vec::new(),
        wallets_file: Some(bot.wallets_file.clone()),
        wallet_indices: wizard.wallets.clone(),
        rpc_urls: env_rpc_urls(),
        chain: Some(chain),
        max_fee_per_gas: wizard.max_fee_per_gas,
        max_priority_fee_per_gas: wizard.max_priority_fee_per_gas,
        gas_limit: 250_000,
        early_fire_ms: wizard.early_fire_ms,
        fire_now: false,
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
                "🎯 Arming — signing is done before the stage opens; progress will stream here.",
            )
            .await;
        let result = snipe::run_snipe(options).await;
        if let Err(error) = result {
            let _ = bot_clone.send(chat_id, &format!("❌ {error}")).await;
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

    #[test]
    fn wallet_selection_parses_indices() {
        assert_eq!(parse_wallet_selection("0,1,2").unwrap(), vec![0, 1, 2]);
        assert_eq!(parse_wallet_selection("all").unwrap(), Vec::<usize>::new());
        assert_eq!(parse_wallet_selection(" 2 , 0 , 2 ").unwrap(), vec![2, 0]);
        assert!(parse_wallet_selection("x").is_err());
        assert!(parse_wallet_selection("").is_err());
    }

    #[test]
    fn gas_parses_forms() {
        assert_eq!(parse_gas("auto").unwrap(), (None, None));
        assert_eq!(
            parse_gas("0.05/0.01").unwrap(),
            (
                Some(U256::from(50_000_000u128)),
                Some(U256::from(10_000_000u128))
            )
        );
        assert_eq!(
            parse_gas("0.05").unwrap(),
            (Some(U256::from(50_000_000u128)), None)
        );
        assert_eq!(
            parse_gas("/0.01").unwrap(),
            (None, Some(U256::from(10_000_000u128)))
        );
        assert!(parse_gas("nope").is_err());
    }
}
