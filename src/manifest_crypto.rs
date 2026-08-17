//! Encryption at rest for wallet manifests.
//!
//! # What this protects, and what it does not
//!
//! The bot signs autonomously when the operator presses FIRE, so the
//! decryption secret has to be reachable by the process at fire time. That
//! bounds what any scheme here can achieve, and it is worth being precise
//! rather than implying more:
//!
//! - **Protects against** the manifest file leaking on its own: a volume
//!   snapshot or backup, a stray copy, a shell on the box without the
//!   platform's environment, a misdirected upload. The file is useless without
//!   the passphrase, which lives only in the process environment.
//! - **Does not protect against** whoever controls the deployment: anyone who
//!   can read the platform's environment variables can also read the volume.
//!   It decouples "the file leaked" from "the keys leaked" — it is not a
//!   defence against a compromised hosting account.
//!
//! Funding wallets per drop remains the control that actually caps the loss.
//!
//! # Format
//!
//! Argon2id derives a 256-bit key from the passphrase and a random per-file
//! salt; ChaCha20-Poly1305 seals the plaintext manifest under a random
//! 96-bit nonce. KDF parameters are stored in the envelope so that raising
//! them later does not strand existing files. Tampering with any stored
//! parameter yields a different derived key, which fails Poly1305
//! authentication — so the envelope needs no separate integrity field.

use std::{
    fs,
    io::{self, Write as _},
    path::Path,
};

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce, aead::Aead};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroizing;

/// Environment variable holding the operator passphrase. Unset means manifests
/// are read and written in plaintext, which stays supported so an existing
/// deployment keeps working.
pub const PASSPHRASE_ENV: &str = "WALLETS_PASSPHRASE";

const ENVELOPE_FORMAT: &str = "drizzy-encrypted-manifest";
const ENVELOPE_VERSION: u32 = 1;
const KEY_BYTES: usize = 32;
const SALT_BYTES: usize = 16;
const NONCE_BYTES: usize = 12;

/// OWASP's recommended Argon2id floor (19 MiB, 2 iterations, 1 lane). Chosen
/// to stay well under a second on a small container: the manifest is decrypted
/// while arming, never on the fire path, but a multi-second stall would still
/// be felt on every `/wallets`.
const ARGON2_M_COST: u32 = 19_456;
const ARGON2_T_COST: u32 = 2;
const ARGON2_P_COST: u32 = 1;

#[derive(Debug, Error)]
pub enum ManifestCryptoError {
    #[error(
        "this manifest is encrypted but {PASSPHRASE_ENV} is not set — set it to the passphrase used when the wallets were created"
    )]
    PassphraseRequired,
    #[error(
        "cannot decrypt the manifest — wrong {PASSPHRASE_ENV}, or the file was modified. The wallets are unchanged; correct the passphrase and retry"
    )]
    Decrypt,
    #[error("cannot derive a key from the passphrase: {0}")]
    KeyDerivation(String),
    #[error("cannot encrypt the manifest")]
    Encrypt,
    #[error("malformed encrypted manifest: {0}")]
    Malformed(String),
    #[error("cannot read {path}: {source}")]
    Read {
        path: String,
        #[source]
        source: io::Error,
    },
    #[error("cannot write {path}: {source}")]
    Write {
        path: String,
        #[source]
        source: io::Error,
    },
}

#[derive(Debug, Deserialize, Serialize)]
struct Envelope {
    format: String,
    version: u32,
    kdf: String,
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
    salt: String,
    nonce: String,
    ciphertext: String,
}

/// The configured passphrase, if any. A blank value counts as unset so an
/// empty platform variable does not silently produce a key from "".
#[must_use]
pub fn passphrase_from_env() -> Option<Zeroizing<String>> {
    std::env::var(PASSPHRASE_ENV)
        .ok()
        .map(|value| Zeroizing::new(value.trim().to_owned()))
        .filter(|value| !value.is_empty())
}

/// Is encryption configured for this process?
#[must_use]
pub fn is_enabled() -> bool {
    passphrase_from_env().is_some()
}

/// Does this look like an encrypted envelope rather than a plaintext manifest?
#[must_use]
pub fn is_encrypted(source: &str) -> bool {
    serde_json::from_str::<Envelope>(source)
        .is_ok_and(|envelope| envelope.format == ENVELOPE_FORMAT)
}

fn derive_key(
    passphrase: &str,
    salt: &[u8],
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<Zeroizing<[u8; KEY_BYTES]>, ManifestCryptoError> {
    let params = Params::new(m_cost, t_cost, p_cost, Some(KEY_BYTES))
        .map_err(|error| ManifestCryptoError::KeyDerivation(error.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; KEY_BYTES]);
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, key.as_mut())
        .map_err(|error| ManifestCryptoError::KeyDerivation(error.to_string()))?;
    Ok(key)
}

/// Seal `plaintext` under `passphrase`, returning the JSON envelope.
pub fn encrypt(plaintext: &str, passphrase: &str) -> Result<String, ManifestCryptoError> {
    let mut salt = [0u8; SALT_BYTES];
    let mut nonce_bytes = [0u8; NONCE_BYTES];
    // A fresh salt and nonce per write. Reusing a nonce under one key would
    // break confidentiality outright, so these are never derived or reused.
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce_bytes);

    let key = derive_key(
        passphrase,
        &salt,
        ARGON2_M_COST,
        ARGON2_T_COST,
        ARGON2_P_COST,
    )?;
    let cipher = ChaCha20Poly1305::new(&Key::from(*key));
    let ciphertext = cipher
        .encrypt(&Nonce::from(nonce_bytes), plaintext.as_bytes())
        .map_err(|_| ManifestCryptoError::Encrypt)?;

    let envelope = Envelope {
        format: ENVELOPE_FORMAT.to_owned(),
        version: ENVELOPE_VERSION,
        kdf: "argon2id".to_owned(),
        m_cost: ARGON2_M_COST,
        t_cost: ARGON2_T_COST,
        p_cost: ARGON2_P_COST,
        salt: hex::encode(salt),
        nonce: hex::encode(nonce_bytes),
        ciphertext: hex::encode(&ciphertext),
    };
    serde_json::to_string_pretty(&envelope)
        .map_err(|error| ManifestCryptoError::Malformed(error.to_string()))
}

/// Open an envelope produced by [`encrypt`].
pub fn decrypt(source: &str, passphrase: &str) -> Result<Zeroizing<String>, ManifestCryptoError> {
    let envelope: Envelope = serde_json::from_str(source)
        .map_err(|error| ManifestCryptoError::Malformed(error.to_string()))?;
    if envelope.format != ENVELOPE_FORMAT {
        return Err(ManifestCryptoError::Malformed(
            "not an encrypted manifest".to_owned(),
        ));
    }
    if envelope.version != ENVELOPE_VERSION {
        return Err(ManifestCryptoError::Malformed(format!(
            "unsupported envelope version {}",
            envelope.version
        )));
    }
    if envelope.kdf != "argon2id" {
        return Err(ManifestCryptoError::Malformed(format!(
            "unsupported kdf {}",
            envelope.kdf
        )));
    }

    let salt = hex::decode(&envelope.salt)
        .map_err(|_| ManifestCryptoError::Malformed("salt is not hex".to_owned()))?;
    let nonce_bytes = hex::decode(&envelope.nonce)
        .map_err(|_| ManifestCryptoError::Malformed("nonce is not hex".to_owned()))?;
    if nonce_bytes.len() != NONCE_BYTES {
        return Err(ManifestCryptoError::Malformed(
            "nonce has the wrong length".to_owned(),
        ));
    }
    let ciphertext = hex::decode(&envelope.ciphertext)
        .map_err(|_| ManifestCryptoError::Malformed("ciphertext is not hex".to_owned()))?;

    let key = derive_key(
        passphrase,
        &salt,
        envelope.m_cost,
        envelope.t_cost,
        envelope.p_cost,
    )?;
    let nonce: [u8; NONCE_BYTES] = nonce_bytes
        .as_slice()
        .try_into()
        .map_err(|_| ManifestCryptoError::Malformed("nonce has the wrong length".to_owned()))?;
    let cipher = ChaCha20Poly1305::new(&Key::from(*key));
    let plaintext = cipher
        .decrypt(&Nonce::from(nonce), ciphertext.as_slice())
        .map_err(|_| ManifestCryptoError::Decrypt)?;

    let plaintext = Zeroizing::new(plaintext);
    let text = std::str::from_utf8(plaintext.as_ref())
        .map_err(|_| ManifestCryptoError::Decrypt)?
        .to_owned();
    Ok(Zeroizing::new(text))
}

/// Read a manifest, transparently decrypting when the file is an envelope.
///
/// Plaintext files still load, so an existing deployment keeps working after
/// the upgrade — but an encrypted file without a passphrase is a hard error
/// rather than a confusing JSON parse failure.
pub fn read_manifest(path: &Path) -> Result<Zeroizing<String>, ManifestCryptoError> {
    let source =
        Zeroizing::new(
            fs::read_to_string(path).map_err(|source| ManifestCryptoError::Read {
                path: path.display().to_string(),
                source,
            })?,
        );

    if !is_encrypted(&source) {
        return Ok(source);
    }
    let passphrase = passphrase_from_env().ok_or(ManifestCryptoError::PassphraseRequired)?;
    decrypt(&source, &passphrase)
}

/// Write a manifest, encrypting it when a passphrase is configured.
///
/// Writes to a temporary file in the same directory and renames, so an
/// interrupted write can never leave a truncated manifest where wallet keys
/// used to be.
pub fn write_manifest(path: &Path, plaintext: &str) -> Result<(), ManifestCryptoError> {
    let payload = Zeroizing::new(match passphrase_from_env() {
        Some(passphrase) => encrypt(plaintext, &passphrase)?,
        None => plaintext.to_owned(),
    });

    let temporary = path.with_extension("tmp");
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    set_private_file_permissions(&mut options);
    {
        let mut file = options
            .open(&temporary)
            .map_err(|source| ManifestCryptoError::Write {
                path: temporary.display().to_string(),
                source,
            })?;
        file.write_all(payload.as_bytes())
            .and_then(|()| file.sync_all())
            .map_err(|source| ManifestCryptoError::Write {
                path: temporary.display().to_string(),
                source,
            })?;
    }
    fs::rename(&temporary, path).map_err(|source| ManifestCryptoError::Write {
        path: path.display().to_string(),
        source,
    })
}

/// Encrypt any plaintext manifests in `directory` in place. Returns how many
/// were converted. A file already encrypted, or unreadable, is left alone.
pub fn migrate_directory(directory: &Path) -> Result<usize, ManifestCryptoError> {
    if !is_enabled() || !directory.is_dir() {
        return Ok(0);
    }
    let entries = fs::read_dir(directory).map_err(|source| ManifestCryptoError::Read {
        path: directory.display().to_string(),
        source,
    })?;

    let mut migrated = 0;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().is_none_or(|extension| extension != "json") {
            continue;
        }
        let Ok(source) = fs::read_to_string(&path).map(Zeroizing::new) else {
            continue;
        };
        if is_encrypted(&source) {
            continue;
        }
        write_manifest(&path, &source)?;
        migrated += 1;
    }
    Ok(migrated)
}

#[cfg(unix)]
fn set_private_file_permissions(options: &mut fs::OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt as _;
    options.mode(0o600);
}

#[cfg(not(unix))]
fn set_private_file_permissions(_options: &mut fs::OpenOptions) {}

#[cfg(test)]
mod tests {
    use super::*;

    const MANIFEST: &str = r#"{"version":1,"wallets":[{"private_key":"0xabc","quantity":1}]}"#;

    #[test]
    fn round_trips_a_manifest() {
        let sealed = encrypt(MANIFEST, "correct horse battery staple").unwrap();
        let opened = decrypt(&sealed, "correct horse battery staple").unwrap();
        assert_eq!(opened.as_str(), MANIFEST);
    }

    /// The whole point: the sealed file must not contain the key material.
    #[test]
    fn ciphertext_does_not_leak_plaintext() {
        let sealed = encrypt(MANIFEST, "passphrase").unwrap();
        assert!(!sealed.contains("0xabc"));
        assert!(!sealed.contains("private_key"));
    }

    #[test]
    fn a_wrong_passphrase_fails_authentication() {
        let sealed = encrypt(MANIFEST, "right").unwrap();
        assert!(matches!(
            decrypt(&sealed, "wrong"),
            Err(ManifestCryptoError::Decrypt)
        ));
    }

    /// Salt and nonce are per-write, so the same input never seals to the same
    /// bytes — otherwise identical manifests would be linkable and, worse, a
    /// repeated nonce would break confidentiality.
    #[test]
    fn each_encryption_is_unique() {
        let first = encrypt(MANIFEST, "passphrase").unwrap();
        let second = encrypt(MANIFEST, "passphrase").unwrap();
        assert_ne!(first, second);

        let first: Envelope = serde_json::from_str(&first).unwrap();
        let second: Envelope = serde_json::from_str(&second).unwrap();
        assert_ne!(first.salt, second.salt);
        assert_ne!(first.nonce, second.nonce);
    }

    /// Tampering with any stored parameter must be detected, not silently
    /// produce garbage — that is what makes a separate integrity field
    /// unnecessary.
    #[test]
    fn tampering_is_detected() {
        let sealed = encrypt(MANIFEST, "passphrase").unwrap();

        let mut envelope: Envelope = serde_json::from_str(&sealed).unwrap();
        envelope.t_cost += 1;
        let tampered = serde_json::to_string(&envelope).unwrap();
        assert!(decrypt(&tampered, "passphrase").is_err(), "params");

        let mut envelope: Envelope = serde_json::from_str(&sealed).unwrap();
        let mut salt = hex::decode(&envelope.salt).unwrap();
        salt[0] ^= 0xff;
        envelope.salt = hex::encode(salt);
        let tampered = serde_json::to_string(&envelope).unwrap();
        assert!(decrypt(&tampered, "passphrase").is_err(), "salt");

        let mut envelope: Envelope = serde_json::from_str(&sealed).unwrap();
        let mut ciphertext = hex::decode(&envelope.ciphertext).unwrap();
        ciphertext[0] ^= 0xff;
        envelope.ciphertext = hex::encode(ciphertext);
        let tampered = serde_json::to_string(&envelope).unwrap();
        assert!(decrypt(&tampered, "passphrase").is_err(), "ciphertext");
    }

    #[test]
    fn plaintext_manifests_are_not_mistaken_for_envelopes() {
        assert!(!is_encrypted(MANIFEST));
        assert!(is_encrypted(&encrypt(MANIFEST, "passphrase").unwrap()));
        assert!(!is_encrypted("not json at all"));
    }

    /// End-to-end on real files: what lands on disk must be sealed, and it
    /// must load back byte-identical through the same helper the bot uses.
    #[test]
    fn write_then_read_round_trips_through_a_real_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("42.json");

        // Without a passphrase configured, write_manifest stores plaintext and
        // read_manifest passes it straight through — the backward-compatible path.
        write_manifest(&path, MANIFEST).unwrap();
        let on_disk = std::fs::read_to_string(&path).unwrap();
        assert_eq!(
            on_disk, MANIFEST,
            "plaintext mode writes the manifest as-is"
        );
        assert_eq!(read_manifest(&path).unwrap().as_str(), MANIFEST);

        // Sealing the same content must hide it and still open.
        let sealed = encrypt(MANIFEST, "passphrase").unwrap();
        std::fs::write(&path, &sealed).unwrap();
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(!raw.contains("0xabc"), "keys must not be readable on disk");
        assert_eq!(decrypt(&raw, "passphrase").unwrap().as_str(), MANIFEST);
    }

    /// An encrypted manifest with no passphrase configured must fail loudly,
    /// not fall through to a confusing JSON parse error.
    #[test]
    fn reading_an_encrypted_file_without_a_passphrase_is_a_clear_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("42.json");
        std::fs::write(&path, encrypt(MANIFEST, "passphrase").unwrap()).unwrap();

        assert!(
            matches!(
                read_manifest(&path),
                Err(ManifestCryptoError::PassphraseRequired)
            ),
            "must name the missing passphrase rather than fail as malformed JSON"
        );
    }

    #[test]
    fn a_truncated_envelope_is_rejected_cleanly() {
        let sealed = encrypt(MANIFEST, "passphrase").unwrap();
        let truncated = &sealed[..sealed.len() / 2];
        assert!(matches!(
            decrypt(truncated, "passphrase"),
            Err(ManifestCryptoError::Malformed(_))
        ));
    }
}
