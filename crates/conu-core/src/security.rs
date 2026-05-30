//! Local security primitives for conU.
//!
//! This module owns local keys, payload encryption, card signatures, replay
//! protection, and peer key agreement helpers. Callers pass opaque bytes and
//! metadata AAD; this module never logs, prints, or interprets payload contents.

use std::collections::HashMap;
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
#[cfg(target_os = "linux")]
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use chacha20poly1305::aead::{Aead, AeadCore, KeyInit, OsRng, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

use crate::state::{self, StateError, StatePaths};

pub const STORAGE_ALGORITHM: &str = "XChaCha20Poly1305";
pub const AGENT_CARD_SIGNATURE_ALGORITHM: &str = "Ed25519";
pub const PEER_KEY_EXCHANGE_ALGORITHM: &str = "X25519+XChaCha20Poly1305";

const SECURITY_VERSION: &str = "1";
const NONCE_BYTES: usize = 24;
const SECRET_BACKEND_FILESYSTEM: &str = "filesystem-permissions";
const SECRET_BACKEND_WINDOWS_DPAPI: &str = "windows-dpapi-user";
const SECRET_BACKEND_MACOS_KEYCHAIN: &str = "macos-keychain-user";
const SECRET_BACKEND_LINUX_SECRET_SERVICE: &str = "linux-secret-service-user";
const SECRET_BACKEND_USER_MANAGED_WRAP_KEY: &str = "user-managed-wrap-key-v1";
const USER_MANAGED_SECRET_ALGORITHM: &str = "XChaCha20Poly1305";
#[cfg(target_os = "macos")]
const NATIVE_OS_SECRET_SERVICE: &str = "conu.local-secret";
const SECRET_WRAP_KEY_HEX_ENV: &str = "CONU_SECRET_WRAP_KEY_HEX";
const SECRET_WRAP_KEY_FILE_ENV: &str = "CONU_SECRET_WRAP_KEY_FILE";
#[cfg(not(windows))]
const DISABLE_OS_SECRET_BACKEND_ENV: &str = "CONU_DISABLE_OS_SECRET_BACKEND";

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SecretBackendKind {
    Filesystem,
    WindowsDpapi,
    MacosKeychain,
    LinuxSecretService,
    UserManagedWrapKey,
}

/// Result of ensuring the local security state exists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityReport {
    pub identity_signing_key_created: bool,
    pub identity_exchange_key_created: bool,
    pub storage_key_created: bool,
    pub replay_cache_created: bool,
    pub key_rotation_plan_created: bool,
    pub signing_key_id: String,
    pub signing_public_key_hex: String,
    pub exchange_key_id: String,
    pub exchange_public_key_hex: String,
    pub storage_key_id: String,
    pub secret_storage_backend: String,
    pub secrets_os_protected: bool,
}

/// Payload encrypted for local conU-owned storage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedPayload {
    pub algorithm: String,
    pub key_id: String,
    pub nonce_hex: String,
    pub ciphertext_hex: String,
    pub plaintext_len: usize,
}

/// Signature metadata for an agent card.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CardSignature {
    pub algorithm: String,
    pub key_id: String,
    pub public_key_hex: String,
    pub signature_hex: String,
}

/// Metadata returned after deriving a peer key agreement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerKeyAgreement {
    pub algorithm: String,
    pub key_id: String,
    pub local_exchange_public_key_hex: String,
    pub remote_exchange_public_key_hex: String,
}

/// Payload encrypted with a key derived from local X25519 and a peer public key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerEncryptedPayload {
    pub algorithm: String,
    pub key_id: String,
    pub sender_exchange_public_key_hex: String,
    pub nonce_hex: String,
    pub ciphertext_hex: String,
    pub plaintext_len: usize,
}

/// Read-only local security audit view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityAudit {
    pub initialized: bool,
    pub identity_signing_key: bool,
    pub identity_exchange_key: bool,
    pub storage_key: bool,
    pub replay_cache: bool,
    pub key_rotation_plan: bool,
    pub local_payload_encryption: bool,
    pub signed_agent_cards: bool,
    pub peer_key_exchange: bool,
    pub secret_storage_backend: String,
    pub secrets_os_protected: bool,
    pub contents_displayed: bool,
}

/// Payload-safe result of rotating the local storage encryption key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageKeyRotationReport {
    pub old_storage_key_id: String,
    pub new_storage_key_id: String,
    pub files_scanned: usize,
    pub files_migrated: usize,
    pub files_skipped: usize,
    pub archived_storage_keys: usize,
    pub contents_displayed: bool,
}

/// Payload-safe result of retiring unused archived local storage keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageKeyRetirementReport {
    pub archived_storage_keys_scanned: usize,
    pub retired_storage_keys: usize,
    pub retained_storage_keys: usize,
    pub files_scanned: usize,
    pub dependent_files: usize,
    pub contents_displayed: bool,
}

/// Payload-safe result of retiring archived local identity keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityKeyRetirementReport {
    pub archived_identity_keys_scanned: usize,
    pub retired_identity_keys: usize,
    pub retained_identity_keys: usize,
    pub peer_card_refresh_confirmed: bool,
    pub old_key_decrypt_compatibility_retired: bool,
    pub contents_displayed: bool,
}

/// Payload-safe result of rotating local identity signing and exchange keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityKeyRotationReport {
    pub old_signing_key_id: String,
    pub new_signing_key_id: String,
    pub old_exchange_key_id: String,
    pub new_exchange_key_id: String,
    pub archived_identity_keys: usize,
    pub peer_card_refresh_required: bool,
    pub signed_agent_card_refresh_required: bool,
    pub contents_displayed: bool,
}

/// Payload-safe status for the locally stored relay client credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayCredentialStatus {
    pub configured: bool,
    pub secret_storage_backend: String,
    pub os_protected: bool,
    pub contents_displayed: bool,
}

/// Errors produced by the security module.
#[derive(Debug)]
pub enum SecurityError {
    State(StateError),
    Io {
        action: &'static str,
        path: PathBuf,
        source: io::Error,
    },
    InvalidKey {
        path: PathBuf,
        reason: String,
    },
    InvalidPayload {
        reason: String,
    },
    Crypto {
        action: &'static str,
    },
    ReplayDetected {
        id: String,
    },
}

impl SecurityError {
    fn io(action: &'static str, path: &Path, source: io::Error) -> Self {
        Self::Io {
            action,
            path: path.to_path_buf(),
            source,
        }
    }
}

impl fmt::Display for SecurityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::State(error) => write!(formatter, "{error}"),
            Self::Io {
                action,
                path,
                source,
            } => write!(formatter, "{action} at {}: {source}", path.display()),
            Self::InvalidKey { path, reason } => {
                write!(
                    formatter,
                    "invalid security key at {}: {reason}",
                    path.display()
                )
            }
            Self::InvalidPayload { reason } => {
                write!(formatter, "invalid encrypted payload: {reason}")
            }
            Self::Crypto { action } => write!(formatter, "{action}"),
            Self::ReplayDetected { id } => write!(formatter, "replay detected for id {id}"),
        }
    }
}

impl std::error::Error for SecurityError {}

impl From<StateError> for SecurityError {
    fn from(error: StateError) -> Self {
        Self::State(error)
    }
}

/// Ensure all local security key material and planning files exist.
pub fn ensure_security_state(
    home_override: Option<PathBuf>,
) -> Result<SecurityReport, SecurityError> {
    let paths = StatePaths::resolve(home_override)?;
    ensure_security_state_from_paths(&paths)
}

/// Ensure all local security key material and planning files exist from paths.
pub fn ensure_security_state_from_paths(
    paths: &StatePaths,
) -> Result<SecurityReport, SecurityError> {
    state::ensure_state_directory(&paths.home)?;
    state::ensure_state_directory(&paths.security_dir)?;
    state::ensure_state_directory(&paths.storage_key_archive_dir)?;

    let identity_signing_key_created = ensure_identity_signing_key(paths)?;
    let identity_exchange_key_created = ensure_identity_exchange_key(paths)?;
    let storage_key_created = ensure_storage_key(paths)?;
    migrate_storage_key_archives_to_os_protection(paths)?;
    migrate_relay_credential_to_secret_protection(paths)?;
    let replay_cache_created = ensure_replay_cache(paths)?;
    let key_rotation_plan_created = ensure_key_rotation_plan(paths)?;

    let signing = read_identity_signing_key(paths)?;
    let exchange = read_identity_exchange_key(paths)?;
    let storage = read_storage_key(paths)?;
    let secrets_os_protected = all_secret_files_use_os_protection(paths);

    Ok(SecurityReport {
        identity_signing_key_created,
        identity_exchange_key_created,
        storage_key_created,
        replay_cache_created,
        key_rotation_plan_created,
        signing_key_id: signing.key_id,
        signing_public_key_hex: hex_encode(&signing.public_key),
        exchange_key_id: exchange.key_id,
        exchange_public_key_hex: hex_encode(&exchange.public_key),
        storage_key_id: storage.key_id,
        secret_storage_backend: secret_storage_backend().to_string(),
        secrets_os_protected,
    })
}

/// Return a payload-safe audit snapshot.
pub fn security_audit(home_override: Option<PathBuf>) -> Result<SecurityAudit, SecurityError> {
    let paths = StatePaths::resolve(home_override)?;
    let identity_signing_key = key_file_is_readable(&paths.identity_signing_key);
    let identity_exchange_key = key_file_is_readable(&paths.identity_exchange_key);
    let storage_key = key_file_is_readable(&paths.storage_key);
    let replay_cache = state::read_optional_regular_state_file(
        &paths.replay_cache,
        "inspect replay cache",
        "read replay cache",
    )?
    .is_some();
    let key_rotation_plan = state::read_optional_regular_state_file(
        &paths.key_rotation_plan,
        "inspect key rotation plan",
        "read key rotation plan",
    )?
    .is_some();
    let secrets_os_protected = all_secret_files_use_os_protection(&paths);
    let initialized = identity_signing_key
        && identity_exchange_key
        && storage_key
        && replay_cache
        && key_rotation_plan;

    Ok(SecurityAudit {
        initialized,
        identity_signing_key,
        identity_exchange_key,
        storage_key,
        replay_cache,
        key_rotation_plan,
        local_payload_encryption: storage_key,
        signed_agent_cards: identity_signing_key,
        peer_key_exchange: identity_exchange_key,
        secret_storage_backend: secret_storage_backend().to_string(),
        secrets_os_protected,
        contents_displayed: false,
    })
}

/// Store the relay client credential in local conU state without printing it.
pub fn store_relay_credential(
    home_override: Option<PathBuf>,
    token: &str,
) -> Result<RelayCredentialStatus, SecurityError> {
    let init = crate::state::init_state(home_override)?;
    store_relay_credential_from_paths(&init.paths, token)
}

/// Store the relay client credential from already resolved state paths.
pub fn store_relay_credential_from_paths(
    paths: &StatePaths,
    token: &str,
) -> Result<RelayCredentialStatus, SecurityError> {
    validate_relay_token(token)?;
    state::ensure_state_directory(&paths.home)?;
    state::ensure_state_directory(&paths.security_dir)?;
    let created_at = read_key_values(&paths.relay_credential)
        .ok()
        .and_then(|values| values.get("created_at_unix").cloned())
        .unwrap_or_else(|| current_unix_seconds().to_string());
    let contents = render_relay_credential_file(token, &created_at)?;

    if secret_file_exists(&paths.relay_credential)? {
        replace_secret_file(&paths.relay_credential, &contents)?;
    } else {
        write_new_secret_file(&paths.relay_credential, &contents)?;
    }

    relay_credential_status_from_paths(paths)
}

/// Remove the stored relay client credential, if present.
pub fn clear_relay_credential(
    home_override: Option<PathBuf>,
) -> Result<RelayCredentialStatus, SecurityError> {
    let paths = StatePaths::resolve(home_override)?;
    delete_secret_references(&paths.relay_credential, "token")?;
    match fs::remove_file(&paths.relay_credential) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(SecurityError::io(
                "remove relay credential",
                &paths.relay_credential,
                error,
            ));
        }
    }
    relay_credential_status_from_paths(&paths)
}

/// Return payload-safe status for the stored relay client credential.
pub fn relay_credential_status(
    home_override: Option<PathBuf>,
) -> Result<RelayCredentialStatus, SecurityError> {
    let paths = StatePaths::resolve(home_override)?;
    relay_credential_status_from_paths(&paths)
}

/// Read the stored relay client credential for runtime use.
pub fn read_relay_credential_from_paths(
    paths: &StatePaths,
) -> Result<Option<String>, SecurityError> {
    if !secret_file_exists(&paths.relay_credential)? {
        return Ok(None);
    }
    migrate_relay_credential_to_secret_protection(paths)?;
    let values = read_key_values(&paths.relay_credential)?;
    if required(&values, "kind", &paths.relay_credential)? != "relay_token" {
        return Err(SecurityError::InvalidKey {
            path: paths.relay_credential.clone(),
            reason: "expected relay token credential".to_string(),
        });
    }
    let token = relay_token_from_values(&values, &paths.relay_credential)?;
    validate_relay_token(&token)?;
    Ok(Some(token))
}

/// Encrypt bytes for conU-owned local storage.
pub fn encrypt_for_storage_from_paths(
    paths: &StatePaths,
    plaintext: &[u8],
    aad: &[u8],
) -> Result<EncryptedPayload, SecurityError> {
    ensure_security_state_from_paths(paths)?;
    let key = read_storage_key(paths)?;
    encrypt_with_storage_key(&key, plaintext, aad)
}

/// Decrypt bytes from conU-owned local storage.
pub fn decrypt_from_storage_from_paths(
    paths: &StatePaths,
    encrypted: &EncryptedPayload,
    aad: &[u8],
) -> Result<Vec<u8>, SecurityError> {
    if encrypted.algorithm != STORAGE_ALGORITHM {
        return Err(SecurityError::InvalidPayload {
            reason: "unsupported storage cipher".to_string(),
        });
    }
    let key = read_storage_key_for_id(paths, &encrypted.key_id)?;
    decrypt_with_storage_key(&key, encrypted, aad)
}

/// Rotate the local storage encryption key and re-encrypt conU-owned payload files.
pub fn rotate_storage_key(
    home_override: Option<PathBuf>,
) -> Result<StorageKeyRotationReport, SecurityError> {
    let init = crate::state::init_state(home_override)?;
    rotate_storage_key_from_paths(&init.paths)
}

/// Rotate the local storage encryption key from already resolved state paths.
pub fn rotate_storage_key_from_paths(
    paths: &StatePaths,
) -> Result<StorageKeyRotationReport, SecurityError> {
    ensure_security_state_from_paths(paths)?;
    let old_key = read_storage_key(paths)?;
    let payload_files = local_storage_payload_files(paths)?;
    let archived_storage_keys = archive_storage_key(paths, &old_key)?;
    let new_key = generate_storage_key();
    let contents = render_storage_key_file(
        &new_key.key,
        &new_key.key_id,
        &current_unix_seconds().to_string(),
    )?;
    replace_secret_file(&paths.storage_key, &contents)?;

    let mut report = StorageKeyRotationReport {
        old_storage_key_id: old_key.key_id.clone(),
        new_storage_key_id: new_key.key_id.clone(),
        files_scanned: 0,
        files_migrated: 0,
        files_skipped: 0,
        archived_storage_keys: if archived_storage_keys { 1 } else { 0 },
        contents_displayed: false,
    };

    for payload_file in payload_files {
        report.files_scanned += 1;
        let Some(payload) = payload_file else {
            report.files_skipped += 1;
            continue;
        };
        if payload.encrypted.key_id == new_key.key_id {
            report.files_skipped += 1;
            continue;
        }

        let plaintext = decrypt_from_storage_from_paths(paths, &payload.encrypted, &payload.aad)?;
        let encrypted = encrypt_with_storage_key(&new_key, &plaintext, &payload.aad)?;
        let rewritten = rewrite_payload_metadata(&payload.contents, &encrypted);
        rewrite_local_storage_payload_file(&payload.path, &rewritten)?;
        report.files_migrated += 1;
    }

    Ok(report)
}

/// Retire archived storage keys that no local encrypted-at-rest payload references.
pub fn retire_unused_storage_keys(
    home_override: Option<PathBuf>,
) -> Result<StorageKeyRetirementReport, SecurityError> {
    let init = crate::state::init_state(home_override)?;
    retire_unused_storage_keys_from_paths(&init.paths)
}

/// Retire unused archived storage keys from already resolved state paths.
pub fn retire_unused_storage_keys_from_paths(
    paths: &StatePaths,
) -> Result<StorageKeyRetirementReport, SecurityError> {
    ensure_security_state_from_paths(paths)?;
    let current_key = read_storage_key(paths)?;
    let mut key_references = HashMap::<String, usize>::new();
    let mut files_scanned = 0;

    for payload_file in local_storage_payload_files(paths)? {
        files_scanned += 1;
        if let Some(payload) = payload_file {
            *key_references
                .entry(payload.encrypted.key_id.clone())
                .or_default() += 1;
        }
    }

    let mut report = StorageKeyRetirementReport {
        archived_storage_keys_scanned: 0,
        retired_storage_keys: 0,
        retained_storage_keys: 0,
        files_scanned,
        dependent_files: 0,
        contents_displayed: false,
    };

    for archive_path in archived_storage_key_files(paths)? {
        let key = read_storage_key_file(&archive_path)?;
        report.archived_storage_keys_scanned += 1;
        let dependent_files = if key.key_id == current_key.key_id {
            0
        } else {
            key_references.get(&key.key_id).copied().unwrap_or_default()
        };
        if dependent_files > 0 {
            report.retained_storage_keys += 1;
            report.dependent_files += dependent_files;
            continue;
        }

        fs::remove_file(&archive_path).map_err(|error| {
            SecurityError::io("remove unused archived storage key", &archive_path, error)
        })?;
        report.retired_storage_keys += 1;
    }

    Ok(report)
}

/// Retire archived identity keys after peer-card refresh has completed.
pub fn retire_archived_identity_keys(
    home_override: Option<PathBuf>,
) -> Result<IdentityKeyRetirementReport, SecurityError> {
    let init = crate::state::init_state(home_override)?;
    retire_archived_identity_keys_from_paths(&init.paths)
}

/// Retire archived identity keys from already resolved state paths.
pub fn retire_archived_identity_keys_from_paths(
    paths: &StatePaths,
) -> Result<IdentityKeyRetirementReport, SecurityError> {
    ensure_security_state_from_paths(paths)?;
    let current_signing_key_id = read_identity_signing_key(paths)?.key_id;
    let current_exchange_key_id = read_identity_exchange_key(paths)?.key_id;
    let mut report = IdentityKeyRetirementReport {
        archived_identity_keys_scanned: 0,
        retired_identity_keys: 0,
        retained_identity_keys: 0,
        peer_card_refresh_confirmed: true,
        old_key_decrypt_compatibility_retired: false,
        contents_displayed: false,
    };

    for archive_path in archived_identity_key_files(paths)? {
        let key_id = archived_identity_key_id(&archive_path)?;
        report.archived_identity_keys_scanned += 1;
        if key_id == current_signing_key_id || key_id == current_exchange_key_id {
            report.retained_identity_keys += 1;
            continue;
        }

        fs::remove_file(&archive_path).map_err(|error| {
            SecurityError::io("remove archived identity key", &archive_path, error)
        })?;
        report.retired_identity_keys += 1;
    }
    report.old_key_decrypt_compatibility_retired = report.retired_identity_keys > 0;

    Ok(report)
}

/// Rotate local signing and exchange keys, archiving the previous key material.
pub fn rotate_identity_keys(
    home_override: Option<PathBuf>,
) -> Result<IdentityKeyRotationReport, SecurityError> {
    let init = crate::state::init_state(home_override)?;
    rotate_identity_keys_from_paths(&init.paths)
}

/// Rotate local signing and exchange keys from already resolved state paths.
pub fn rotate_identity_keys_from_paths(
    paths: &StatePaths,
) -> Result<IdentityKeyRotationReport, SecurityError> {
    ensure_security_state_from_paths(paths)?;
    let old_signing = read_identity_signing_key(paths)?;
    let old_exchange = read_identity_exchange_key(paths)?;
    let mut archived_identity_keys = 0;

    if archive_identity_signing_key(paths, &old_signing)? {
        archived_identity_keys += 1;
    }
    if archive_identity_exchange_key(paths, &old_exchange)? {
        archived_identity_keys += 1;
    }

    let new_signing = generate_identity_signing_key();
    let new_exchange = generate_identity_exchange_key();
    let created_at = current_unix_seconds().to_string();
    let signing_contents = render_identity_signing_key_file(
        &new_signing.secret_key,
        &new_signing.public_key,
        &new_signing.key_id,
        &created_at,
    )?;
    let exchange_contents = render_identity_exchange_key_file(
        &new_exchange.secret_key,
        &new_exchange.public_key,
        &new_exchange.key_id,
        &created_at,
    )?;

    replace_secret_file(&paths.identity_signing_key, &signing_contents)?;
    replace_secret_file(&paths.identity_exchange_key, &exchange_contents)?;

    Ok(IdentityKeyRotationReport {
        old_signing_key_id: old_signing.key_id,
        new_signing_key_id: new_signing.key_id,
        old_exchange_key_id: old_exchange.key_id,
        new_exchange_key_id: new_exchange.key_id,
        archived_identity_keys,
        peer_card_refresh_required: true,
        signed_agent_card_refresh_required: true,
        contents_displayed: false,
    })
}

fn encrypt_with_storage_key(
    key: &StorageKeyRecord,
    plaintext: &[u8],
    aad: &[u8],
) -> Result<EncryptedPayload, SecurityError> {
    let cipher =
        XChaCha20Poly1305::new_from_slice(&key.key).map_err(|_| SecurityError::Crypto {
            action: "create storage cipher failed",
        })?;
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| SecurityError::Crypto {
            action: "encrypt storage payload failed",
        })?;

    Ok(EncryptedPayload {
        algorithm: STORAGE_ALGORITHM.to_string(),
        key_id: key.key_id.clone(),
        nonce_hex: hex_encode(&nonce),
        ciphertext_hex: hex_encode(&ciphertext),
        plaintext_len: plaintext.len(),
    })
}

fn decrypt_with_storage_key(
    key: &StorageKeyRecord,
    encrypted: &EncryptedPayload,
    aad: &[u8],
) -> Result<Vec<u8>, SecurityError> {
    if encrypted.algorithm != STORAGE_ALGORITHM {
        return Err(SecurityError::InvalidPayload {
            reason: "unsupported storage cipher".to_string(),
        });
    }
    if encrypted.key_id != key.key_id {
        return Err(SecurityError::InvalidPayload {
            reason: "storage key id does not match selected local key".to_string(),
        });
    }

    let nonce = hex_decode_exact::<NONCE_BYTES>(&encrypted.nonce_hex)
        .map_err(|reason| SecurityError::InvalidPayload { reason })?;
    let ciphertext = hex_decode(&encrypted.ciphertext_hex)
        .map_err(|reason| SecurityError::InvalidPayload { reason })?;
    let cipher =
        XChaCha20Poly1305::new_from_slice(&key.key).map_err(|_| SecurityError::Crypto {
            action: "create storage cipher failed",
        })?;
    let plaintext = cipher
        .decrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &ciphertext,
                aad,
            },
        )
        .map_err(|_| SecurityError::Crypto {
            action: "decrypt storage payload failed",
        })?;

    if plaintext.len() != encrypted.plaintext_len {
        return Err(SecurityError::InvalidPayload {
            reason: "decrypted payload length mismatch".to_string(),
        });
    }

    Ok(plaintext)
}

/// Sign an agent-card canonical byte string with the local node signing key.
pub fn sign_agent_card_from_paths(
    paths: &StatePaths,
    canonical_card: &str,
) -> Result<CardSignature, SecurityError> {
    ensure_security_state_from_paths(paths)?;
    let key = read_identity_signing_key(paths)?;
    let signing_key = SigningKey::from_bytes(&key.secret_key);
    let signature: Signature = signing_key.sign(canonical_card.as_bytes());

    Ok(CardSignature {
        algorithm: AGENT_CARD_SIGNATURE_ALGORITHM.to_string(),
        key_id: key.key_id,
        public_key_hex: hex_encode(&key.public_key),
        signature_hex: hex_encode(&signature.to_bytes()),
    })
}

/// Verify an agent-card signature.
pub fn verify_agent_card_signature(
    canonical_card: &str,
    public_key_hex: &str,
    signature_hex: &str,
) -> Result<bool, SecurityError> {
    let public_key = hex_decode_exact::<32>(public_key_hex)
        .map_err(|reason| SecurityError::InvalidPayload { reason })?;
    let signature_bytes =
        hex_decode(signature_hex).map_err(|reason| SecurityError::InvalidPayload { reason })?;
    let verifying_key =
        VerifyingKey::from_bytes(&public_key).map_err(|_| SecurityError::InvalidPayload {
            reason: "invalid Ed25519 public key".to_string(),
        })?;
    let signature =
        Signature::from_slice(&signature_bytes).map_err(|_| SecurityError::InvalidPayload {
            reason: "invalid Ed25519 signature".to_string(),
        })?;

    Ok(verifying_key
        .verify(canonical_card.as_bytes(), &signature)
        .is_ok())
}

/// Return local public key material peers need for explicit trust verification.
pub fn local_peer_key_material(paths: &StatePaths) -> Result<PeerKeyAgreement, SecurityError> {
    ensure_security_state_from_paths(paths)?;
    let exchange = read_identity_exchange_key(paths)?;

    Ok(PeerKeyAgreement {
        algorithm: "X25519-public-material".to_string(),
        key_id: exchange.key_id,
        local_exchange_public_key_hex: hex_encode(&exchange.public_key),
        remote_exchange_public_key_hex: String::new(),
    })
}

/// Derive a peer key agreement id without exposing the shared secret.
pub fn derive_peer_key_agreement_from_paths(
    paths: &StatePaths,
    remote_exchange_public_key_hex: &str,
    context: &[u8],
) -> Result<PeerKeyAgreement, SecurityError> {
    let (_, key_id, local_public_key_hex) =
        derive_peer_key(paths, remote_exchange_public_key_hex, context)?;

    Ok(PeerKeyAgreement {
        algorithm: PEER_KEY_EXCHANGE_ALGORITHM.to_string(),
        key_id,
        local_exchange_public_key_hex: local_public_key_hex,
        remote_exchange_public_key_hex: remote_exchange_public_key_hex.to_string(),
    })
}

/// Encrypt bytes for a peer using a key derived from X25519 agreement.
pub fn encrypt_for_peer_from_paths(
    paths: &StatePaths,
    remote_exchange_public_key_hex: &str,
    plaintext: &[u8],
    aad: &[u8],
) -> Result<PeerEncryptedPayload, SecurityError> {
    let (key, key_id, local_public_key_hex) =
        derive_peer_key(paths, remote_exchange_public_key_hex, aad)?;
    let cipher = XChaCha20Poly1305::new_from_slice(&key).map_err(|_| SecurityError::Crypto {
        action: "create peer cipher failed",
    })?;
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| SecurityError::Crypto {
            action: "encrypt peer payload failed",
        })?;

    Ok(PeerEncryptedPayload {
        algorithm: PEER_KEY_EXCHANGE_ALGORITHM.to_string(),
        key_id,
        sender_exchange_public_key_hex: local_public_key_hex,
        nonce_hex: hex_encode(&nonce),
        ciphertext_hex: hex_encode(&ciphertext),
        plaintext_len: plaintext.len(),
    })
}

/// Decrypt bytes received from a peer using local X25519 agreement.
pub fn decrypt_from_peer_from_paths(
    paths: &StatePaths,
    sender_exchange_public_key_hex: &str,
    encrypted: &PeerEncryptedPayload,
    aad: &[u8],
) -> Result<Vec<u8>, SecurityError> {
    if encrypted.algorithm != PEER_KEY_EXCHANGE_ALGORITHM {
        return Err(SecurityError::InvalidPayload {
            reason: "unsupported peer payload cipher".to_string(),
        });
    }
    if encrypted.sender_exchange_public_key_hex != sender_exchange_public_key_hex {
        return Err(SecurityError::InvalidPayload {
            reason: "sender exchange public key mismatch".to_string(),
        });
    }

    let (key, _) = derive_peer_key_candidates(paths, sender_exchange_public_key_hex, aad)?
        .into_iter()
        .find(|(_, key_id)| encrypted.key_id == *key_id)
        .ok_or_else(|| SecurityError::InvalidPayload {
            reason: "peer key id does not match derived key".to_string(),
        })?;

    let nonce = hex_decode_exact::<NONCE_BYTES>(&encrypted.nonce_hex)
        .map_err(|reason| SecurityError::InvalidPayload { reason })?;
    let ciphertext = hex_decode(&encrypted.ciphertext_hex)
        .map_err(|reason| SecurityError::InvalidPayload { reason })?;
    let cipher = XChaCha20Poly1305::new_from_slice(&key).map_err(|_| SecurityError::Crypto {
        action: "create peer cipher failed",
    })?;
    let plaintext = cipher
        .decrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &ciphertext,
                aad,
            },
        )
        .map_err(|_| SecurityError::Crypto {
            action: "decrypt peer payload failed",
        })?;

    if plaintext.len() != encrypted.plaintext_len {
        return Err(SecurityError::InvalidPayload {
            reason: "decrypted peer payload length mismatch".to_string(),
        });
    }

    Ok(plaintext)
}

/// Record an idempotency/replay id and reject duplicates.
pub fn record_replay_id_from_paths(
    paths: &StatePaths,
    id: &str,
    source: &str,
) -> Result<(), SecurityError> {
    validate_replay_value(id, "replay id")?;
    validate_replay_value(source, "replay source")?;
    state::ensure_state_directory(&paths.home)?;
    state::ensure_state_directory(&paths.security_dir)?;
    ensure_replay_cache(paths)?;

    let contents = state::read_optional_regular_state_file(
        &paths.replay_cache,
        "inspect replay cache",
        "read replay cache",
    )?
    .unwrap_or_default();
    for line in contents.lines().map(str::trim) {
        if let Some(value) = line.strip_prefix("id = ") {
            if clean_value(value) == id {
                return Err(SecurityError::ReplayDetected { id: id.to_string() });
            }
        }
    }

    let entry = format!(
        "\n[[seen]]\nid = \"{}\"\nsource = \"{}\"\nfirst_seen_unix = {}\n",
        escape_file_value(id),
        escape_file_value(source),
        current_unix_seconds()
    );
    state::append_regular_state_file(
        &paths.replay_cache,
        &entry,
        "inspect replay cache",
        "create replay cache",
        "open replay cache",
        "write replay cache",
    )?;
    Ok(())
}

fn ensure_identity_signing_key(paths: &StatePaths) -> Result<bool, SecurityError> {
    if secret_file_exists(&paths.identity_signing_key)? {
        migrate_identity_signing_key_to_os_protection(paths)?;
        return Ok(false);
    }

    let key = generate_identity_signing_key();
    let contents = render_identity_signing_key_file(
        &key.secret_key,
        &key.public_key,
        &key.key_id,
        &current_unix_seconds().to_string(),
    )?;
    write_new_secret_file(&paths.identity_signing_key, &contents)
}

fn ensure_identity_exchange_key(paths: &StatePaths) -> Result<bool, SecurityError> {
    if secret_file_exists(&paths.identity_exchange_key)? {
        migrate_identity_exchange_key_to_os_protection(paths)?;
        return Ok(false);
    }

    let key = generate_identity_exchange_key();
    let contents = render_identity_exchange_key_file(
        &key.secret_key,
        &key.public_key,
        &key.key_id,
        &current_unix_seconds().to_string(),
    )?;
    write_new_secret_file(&paths.identity_exchange_key, &contents)
}

fn generate_identity_signing_key() -> SigningKeyRecord {
    let signing_key = SigningKey::generate(&mut OsRng);
    let public_key = signing_key.verifying_key().to_bytes();
    let secret_key = signing_key.to_bytes();
    let key_id = key_id("ed25519", &public_key);
    SigningKeyRecord {
        key_id,
        secret_key,
        public_key,
    }
}

fn generate_identity_exchange_key() -> ExchangeKeyRecord {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = X25519PublicKey::from(&secret);
    let secret_key = secret.to_bytes();
    let public_key = public.to_bytes();
    let key_id = key_id("x25519", &public_key);
    ExchangeKeyRecord {
        key_id,
        secret_key,
        public_key,
    }
}

fn ensure_storage_key(paths: &StatePaths) -> Result<bool, SecurityError> {
    if secret_file_exists(&paths.storage_key)? {
        migrate_storage_key_to_os_protection(paths)?;
        return Ok(false);
    }

    let storage = generate_storage_key();
    let contents = render_storage_key_file(
        &storage.key,
        &storage.key_id,
        &current_unix_seconds().to_string(),
    )?;
    write_new_secret_file(&paths.storage_key, &contents)
}

fn generate_storage_key() -> StorageKeyRecord {
    let key: [u8; 32] = XChaCha20Poly1305::generate_key(&mut OsRng).into();
    let key_id = key_id("storage", &key);
    StorageKeyRecord { key_id, key }
}

fn migrate_identity_signing_key_to_os_protection(paths: &StatePaths) -> Result<(), SecurityError> {
    if !secret_protection_available() {
        return Ok(());
    }
    let values = read_key_values(&paths.identity_signing_key)?;
    if secret_file_uses_selected_protection(&values, "secret_key") {
        return Ok(());
    }

    let key = read_identity_signing_key(paths)?;
    let contents = render_identity_signing_key_file(
        &key.secret_key,
        &key.public_key,
        &key.key_id,
        &created_at_value(&values),
    )?;
    replace_secret_file(&paths.identity_signing_key, &contents)
}

fn migrate_identity_exchange_key_to_os_protection(paths: &StatePaths) -> Result<(), SecurityError> {
    if !secret_protection_available() {
        return Ok(());
    }
    let values = read_key_values(&paths.identity_exchange_key)?;
    if secret_file_uses_selected_protection(&values, "secret_key") {
        return Ok(());
    }

    let key = read_identity_exchange_key(paths)?;
    let contents = render_identity_exchange_key_file(
        &key.secret_key,
        &key.public_key,
        &key.key_id,
        &created_at_value(&values),
    )?;
    replace_secret_file(&paths.identity_exchange_key, &contents)
}

fn migrate_identity_signing_key_file_to_os_protection(path: &Path) -> Result<(), SecurityError> {
    if !secret_protection_available() || !secret_file_exists(path)? {
        return Ok(());
    }
    let values = read_key_values(path)?;
    if secret_file_uses_selected_protection(&values, "secret_key") {
        return Ok(());
    }

    let key = read_identity_signing_key_file(path)?;
    let contents = render_identity_signing_key_file(
        &key.secret_key,
        &key.public_key,
        &key.key_id,
        &created_at_value(&values),
    )?;
    replace_secret_file(path, &contents)
}

fn migrate_identity_exchange_key_file_to_os_protection(path: &Path) -> Result<(), SecurityError> {
    if !secret_protection_available() || !secret_file_exists(path)? {
        return Ok(());
    }
    let values = read_key_values(path)?;
    if secret_file_uses_selected_protection(&values, "secret_key") {
        return Ok(());
    }

    let key = read_identity_exchange_key_file(path)?;
    let contents = render_identity_exchange_key_file(
        &key.secret_key,
        &key.public_key,
        &key.key_id,
        &created_at_value(&values),
    )?;
    replace_secret_file(path, &contents)
}

fn migrate_storage_key_to_os_protection(paths: &StatePaths) -> Result<(), SecurityError> {
    if !secret_protection_available() {
        return Ok(());
    }
    let values = read_key_values(&paths.storage_key)?;
    if secret_file_uses_selected_protection(&values, "key") {
        return Ok(());
    }

    let key = read_storage_key(paths)?;
    let contents = render_storage_key_file(&key.key, &key.key_id, &created_at_value(&values))?;
    replace_secret_file(&paths.storage_key, &contents)
}

fn archive_storage_key(paths: &StatePaths, key: &StorageKeyRecord) -> Result<bool, SecurityError> {
    state::ensure_state_directory(&paths.storage_key_archive_dir)?;
    let archive_path = paths
        .storage_key_archive_dir
        .join(format!("{}.key", key.key_id));
    if secret_file_exists(&archive_path)? {
        migrate_storage_key_file_to_os_protection(&archive_path)?;
        return Ok(false);
    }

    let values = read_key_values(&paths.storage_key)?;
    let contents = render_storage_key_file(&key.key, &key.key_id, &created_at_value(&values))?;
    write_new_secret_file(&archive_path, &contents)
}

fn archive_identity_signing_key(
    paths: &StatePaths,
    key: &SigningKeyRecord,
) -> Result<bool, SecurityError> {
    let archive_dir = identity_key_archive_dir(paths);
    state::ensure_state_directory(&archive_dir)?;
    let archive_path = archive_dir.join(format!("{}.signing.key", key.key_id));
    if secret_file_exists(&archive_path)? {
        migrate_identity_signing_key_file_to_os_protection(&archive_path)?;
        return Ok(false);
    }

    let values = read_key_values(&paths.identity_signing_key)?;
    let contents = render_identity_signing_key_file(
        &key.secret_key,
        &key.public_key,
        &key.key_id,
        &created_at_value(&values),
    )?;
    write_new_secret_file(&archive_path, &contents)
}

fn archive_identity_exchange_key(
    paths: &StatePaths,
    key: &ExchangeKeyRecord,
) -> Result<bool, SecurityError> {
    let archive_dir = identity_key_archive_dir(paths);
    state::ensure_state_directory(&archive_dir)?;
    let archive_path = archive_dir.join(format!("{}.exchange.key", key.key_id));
    if secret_file_exists(&archive_path)? {
        migrate_identity_exchange_key_file_to_os_protection(&archive_path)?;
        return Ok(false);
    }

    let values = read_key_values(&paths.identity_exchange_key)?;
    let contents = render_identity_exchange_key_file(
        &key.secret_key,
        &key.public_key,
        &key.key_id,
        &created_at_value(&values),
    )?;
    write_new_secret_file(&archive_path, &contents)
}

fn identity_key_archive_dir(paths: &StatePaths) -> PathBuf {
    paths.security_dir.join("identity-keys")
}

fn migrate_storage_key_file_to_os_protection(path: &Path) -> Result<(), SecurityError> {
    if !secret_protection_available() || !secret_file_exists(path)? {
        return Ok(());
    }
    let values = read_key_values(path)?;
    if secret_file_uses_selected_protection(&values, "key") {
        return Ok(());
    }

    let key = read_storage_key_file(path)?;
    let contents = render_storage_key_file(&key.key, &key.key_id, &created_at_value(&values))?;
    replace_secret_file(path, &contents)
}

fn migrate_storage_key_archives_to_os_protection(paths: &StatePaths) -> Result<(), SecurityError> {
    for archive_path in archived_storage_key_files(paths)? {
        migrate_storage_key_file_to_os_protection(&archive_path)?;
    }
    Ok(())
}

fn render_identity_signing_key_file(
    secret_key: &[u8; 32],
    public_key: &[u8; 32],
    key_id: &str,
    created_at_unix: &str,
) -> Result<String, SecurityError> {
    Ok(format!(
        "# conU node signing key\nversion = \"{}\"\nalgorithm = \"{}\"\nkey_id = \"{}\"\n{}public_key_hex = \"{}\"\ncreated_at_unix = {}\n",
        SECURITY_VERSION,
        AGENT_CARD_SIGNATURE_ALGORITHM,
        escape_file_value(key_id),
        render_secret_field("secret_key", key_id, secret_key)?,
        hex_encode(public_key),
        created_at_unix
    ))
}

fn render_identity_exchange_key_file(
    secret_key: &[u8; 32],
    public_key: &[u8; 32],
    key_id: &str,
    created_at_unix: &str,
) -> Result<String, SecurityError> {
    Ok(format!(
        "# conU node X25519 exchange key\nversion = \"{}\"\nalgorithm = \"X25519\"\nkey_id = \"{}\"\n{}public_key_hex = \"{}\"\ncreated_at_unix = {}\n",
        SECURITY_VERSION,
        escape_file_value(key_id),
        render_secret_field("secret_key", key_id, secret_key)?,
        hex_encode(public_key),
        created_at_unix
    ))
}

fn render_storage_key_file(
    key: &[u8; 32],
    key_id: &str,
    created_at_unix: &str,
) -> Result<String, SecurityError> {
    Ok(format!(
        "# conU local storage encryption key\nversion = \"{}\"\nalgorithm = \"{}\"\nkey_id = \"{}\"\n{}created_at_unix = {}\n",
        SECURITY_VERSION,
        STORAGE_ALGORITHM,
        escape_file_value(key_id),
        render_secret_field("key", key_id, key)?,
        created_at_unix
    ))
}

fn render_relay_credential_file(
    token: &str,
    created_at_unix: &str,
) -> Result<String, SecurityError> {
    Ok(format!(
        "# conU relay client credential\nversion = \"{}\"\nkind = \"relay_token\"\n{}created_at_unix = {}\nupdated_at_unix = {}\ncontents_displayed = false\n",
        SECURITY_VERSION,
        render_secret_field("token", "relay-credential", token.as_bytes())?,
        created_at_unix,
        current_unix_seconds()
    ))
}

fn render_secret_field(
    field: &'static str,
    key_id: &str,
    secret: &[u8],
) -> Result<String, SecurityError> {
    match selected_secret_backend() {
        SecretBackendKind::WindowsDpapi => {
            let protected = protect_os_secret(secret, field, key_id)?;
            Ok(format!(
                "secret_protection = \"{}\"\n{}_dpapi_hex = \"{}\"\n",
                SECRET_BACKEND_WINDOWS_DPAPI,
                field,
                hex_encode(&protected)
            ))
        }
        SecretBackendKind::MacosKeychain | SecretBackendKind::LinuxSecretService => {
            let reference = native_os_secret_reference(field, key_id);
            protect_native_os_secret(&reference, secret)?;
            Ok(format!(
                "secret_protection = \"{}\"\n{}_os_secret_ref = \"{}\"\n{}_plaintext_len = {}\n",
                secret_storage_backend(),
                field,
                escape_file_value(&reference),
                field,
                secret.len()
            ))
        }
        SecretBackendKind::UserManagedWrapKey => {
            let protected = protect_user_managed_secret(secret, field, key_id)?;
            Ok(format!(
                "secret_protection = \"{}\"\nsecret_algorithm = \"{}\"\n{}_wrap_nonce_hex = \"{}\"\n{}_wrapped_hex = \"{}\"\n{}_plaintext_len = {}\n",
                SECRET_BACKEND_USER_MANAGED_WRAP_KEY,
                USER_MANAGED_SECRET_ALGORITHM,
                field,
                hex_encode(&protected.nonce),
                field,
                hex_encode(&protected.ciphertext),
                field,
                secret.len()
            ))
        }
        SecretBackendKind::Filesystem => {
            Ok(format!("{}_hex = \"{}\"\n", field, hex_encode(secret)))
        }
    }
}

fn created_at_value(values: &HashMap<String, String>) -> String {
    values
        .get("created_at_unix")
        .filter(|value| !value.trim().is_empty())
        .cloned()
        .unwrap_or_else(|| current_unix_seconds().to_string())
}

fn relay_credential_status_from_paths(
    paths: &StatePaths,
) -> Result<RelayCredentialStatus, SecurityError> {
    if !secret_file_exists(&paths.relay_credential)? {
        return Ok(RelayCredentialStatus {
            configured: false,
            secret_storage_backend: secret_storage_backend().to_string(),
            os_protected: false,
            contents_displayed: false,
        });
    }
    migrate_relay_credential_to_secret_protection(paths)?;
    let values = read_key_values(&paths.relay_credential)?;
    if required(&values, "kind", &paths.relay_credential)? != "relay_token" {
        return Err(SecurityError::InvalidKey {
            path: paths.relay_credential.clone(),
            reason: "expected relay token credential".to_string(),
        });
    }
    Ok(RelayCredentialStatus {
        configured: true,
        secret_storage_backend: secret_storage_backend().to_string(),
        os_protected: secret_file_uses_os_protection(&values, "token"),
        contents_displayed: false,
    })
}

fn migrate_relay_credential_to_secret_protection(paths: &StatePaths) -> Result<(), SecurityError> {
    if !secret_protection_available() || !secret_file_exists(&paths.relay_credential)? {
        return Ok(());
    }
    let values = read_key_values(&paths.relay_credential)?;
    if required(&values, "kind", &paths.relay_credential)? != "relay_token" {
        return Err(SecurityError::InvalidKey {
            path: paths.relay_credential.clone(),
            reason: "expected relay token credential".to_string(),
        });
    }
    if secret_file_uses_selected_protection(&values, "token") {
        return Ok(());
    }

    let token = relay_token_from_values(&values, &paths.relay_credential)?;
    validate_relay_token(&token)?;
    let created_at = created_at_value(&values);
    let contents = render_relay_credential_file(&token, &created_at)?;
    replace_secret_file(&paths.relay_credential, &contents)
}

fn delete_secret_references(path: &Path, field: &'static str) -> Result<(), SecurityError> {
    if !secret_file_exists(path)? {
        return Ok(());
    }
    let values = read_key_values(path)?;
    if let Some(reference) = values
        .get(&format!("{field}_os_secret_ref"))
        .filter(|value| !value.trim().is_empty())
    {
        delete_native_os_secret(reference)?;
    }
    Ok(())
}

fn relay_token_from_values(
    values: &HashMap<String, String>,
    path: &Path,
) -> Result<String, SecurityError> {
    let token_bytes = secret_bytes_vec(values, "token", "relay-credential", path)?;
    String::from_utf8(token_bytes).map_err(|_| SecurityError::InvalidKey {
        path: path.to_path_buf(),
        reason: "relay token credential is not UTF-8".to_string(),
    })
}

fn validate_relay_token(token: &str) -> Result<(), SecurityError> {
    if token.trim().is_empty() {
        return Err(SecurityError::InvalidPayload {
            reason: "relay token cannot be empty".to_string(),
        });
    }
    if token.chars().any(char::is_whitespace) {
        return Err(SecurityError::InvalidPayload {
            reason: "relay token cannot contain whitespace".to_string(),
        });
    }
    if token.len() > 4096 {
        return Err(SecurityError::InvalidPayload {
            reason: "relay token is too long".to_string(),
        });
    }
    Ok(())
}

fn ensure_replay_cache(paths: &StatePaths) -> Result<bool, SecurityError> {
    ensure_regular_security_file(
        &paths.replay_cache,
        "# conU replay cache\nversion = \"1\"\n",
        "inspect replay cache",
        "read replay cache",
        "replay cache disappeared after create collision",
    )
}

fn ensure_key_rotation_plan(paths: &StatePaths) -> Result<bool, SecurityError> {
    ensure_regular_security_file(
        &paths.key_rotation_plan,
        key_rotation_plan_contents(),
        "inspect key rotation plan",
        "read key rotation plan",
        "key rotation plan disappeared after create collision",
    )
}

fn ensure_regular_security_file(
    path: &Path,
    contents: &str,
    inspect_action: &'static str,
    read_action: &'static str,
    disappeared_reason: &'static str,
) -> Result<bool, SecurityError> {
    if state::read_optional_regular_state_file(path, inspect_action, read_action)?.is_some() {
        return Ok(false);
    }

    match write_new_file(path, contents) {
        Ok(created) => Ok(created),
        Err(SecurityError::Io { source, .. }) if source.kind() == io::ErrorKind::AlreadyExists => {
            if state::read_optional_regular_state_file(path, inspect_action, read_action)?.is_some()
            {
                Ok(false)
            } else {
                Err(SecurityError::io(
                    inspect_action,
                    path,
                    io::Error::new(io::ErrorKind::NotFound, disappeared_reason),
                ))
            }
        }
        Err(error) => Err(error),
    }
}

fn read_identity_signing_key(paths: &StatePaths) -> Result<SigningKeyRecord, SecurityError> {
    read_identity_signing_key_file(&paths.identity_signing_key)
}

fn read_identity_signing_key_file(path: &Path) -> Result<SigningKeyRecord, SecurityError> {
    let values = read_key_values(path)?;
    if required(&values, "algorithm", path)? != AGENT_CARD_SIGNATURE_ALGORITHM {
        return Err(SecurityError::InvalidKey {
            path: path.to_path_buf(),
            reason: "expected Ed25519 signing key".to_string(),
        });
    }
    let record_key_id = required(&values, "key_id", path)?;
    let secret_key = secret_bytes::<32>(&values, "secret_key", path)?;
    let public_key = key_bytes::<32>(&values, "public_key_hex", path)?;
    let signing_key = SigningKey::from_bytes(&secret_key);
    if signing_key.verifying_key().to_bytes() != public_key {
        return Err(SecurityError::InvalidKey {
            path: path.to_path_buf(),
            reason: "public key does not match signing key".to_string(),
        });
    }
    if key_id("ed25519", &public_key) != record_key_id {
        return Err(SecurityError::InvalidKey {
            path: path.to_path_buf(),
            reason: "key id does not match signing public key".to_string(),
        });
    }

    Ok(SigningKeyRecord {
        key_id: record_key_id,
        secret_key,
        public_key,
    })
}

fn read_identity_exchange_key(paths: &StatePaths) -> Result<ExchangeKeyRecord, SecurityError> {
    read_identity_exchange_key_file(&paths.identity_exchange_key)
}

fn read_identity_exchange_key_file(path: &Path) -> Result<ExchangeKeyRecord, SecurityError> {
    let values = read_key_values(path)?;
    if required(&values, "algorithm", path)? != "X25519" {
        return Err(SecurityError::InvalidKey {
            path: path.to_path_buf(),
            reason: "expected X25519 exchange key".to_string(),
        });
    }
    let record_key_id = required(&values, "key_id", path)?;
    let secret_key = secret_bytes::<32>(&values, "secret_key", path)?;
    let public_key = key_bytes::<32>(&values, "public_key_hex", path)?;
    let secret = StaticSecret::from(secret_key);
    if X25519PublicKey::from(&secret).to_bytes() != public_key {
        return Err(SecurityError::InvalidKey {
            path: path.to_path_buf(),
            reason: "public key does not match exchange key".to_string(),
        });
    }
    if key_id("x25519", &public_key) != record_key_id {
        return Err(SecurityError::InvalidKey {
            path: path.to_path_buf(),
            reason: "key id does not match exchange public key".to_string(),
        });
    }

    Ok(ExchangeKeyRecord {
        key_id: record_key_id,
        secret_key,
        public_key,
    })
}

fn read_storage_key(paths: &StatePaths) -> Result<StorageKeyRecord, SecurityError> {
    read_storage_key_file(&paths.storage_key)
}

fn read_storage_key_file(path: &Path) -> Result<StorageKeyRecord, SecurityError> {
    let values = read_key_values(path)?;
    if required(&values, "algorithm", path)? != STORAGE_ALGORITHM {
        return Err(SecurityError::InvalidKey {
            path: path.to_path_buf(),
            reason: "expected XChaCha20Poly1305 storage key".to_string(),
        });
    }

    let record_key_id = required(&values, "key_id", path)?;
    let key = secret_bytes::<32>(&values, "key", path)?;
    if key_id("storage", &key) != record_key_id {
        return Err(SecurityError::InvalidKey {
            path: path.to_path_buf(),
            reason: "key id does not match storage key".to_string(),
        });
    }

    Ok(StorageKeyRecord {
        key_id: record_key_id,
        key,
    })
}

fn read_storage_key_for_id(
    paths: &StatePaths,
    key_id_value: &str,
) -> Result<StorageKeyRecord, SecurityError> {
    let current = read_storage_key(paths)?;
    if current.key_id == key_id_value {
        return Ok(current);
    }

    for archive_path in archived_storage_key_files(paths)? {
        let key = read_storage_key_file(&archive_path)?;
        if key.key_id == key_id_value {
            return Ok(key);
        }
    }

    Err(SecurityError::InvalidPayload {
        reason: "storage key id is not available locally".to_string(),
    })
}

fn archived_storage_key_files(paths: &StatePaths) -> Result<Vec<PathBuf>, SecurityError> {
    if !security_directory_exists(&paths.storage_key_archive_dir)? {
        return Ok(Vec::new());
    }

    let mut files = Vec::new();
    for entry in fs::read_dir(&paths.storage_key_archive_dir).map_err(|error| {
        SecurityError::io(
            "read storage key archive directory",
            &paths.storage_key_archive_dir,
            error,
        )
    })? {
        let entry = entry.map_err(|error| {
            SecurityError::io(
                "read storage key archive entry",
                &paths.storage_key_archive_dir,
                error,
            )
        })?;
        let path = entry.path();
        if path.extension().and_then(|extension| extension.to_str()) == Some("key") {
            files.push(path);
        }
    }
    files.sort();
    Ok(files)
}

fn archived_identity_exchange_key_files(paths: &StatePaths) -> Result<Vec<PathBuf>, SecurityError> {
    let files = archived_identity_key_files(paths)?
        .into_iter()
        .filter(|path| {
            path.file_name()
                .and_then(|file_name| file_name.to_str())
                .is_some_and(|file_name| file_name.ends_with(".exchange.key"))
        })
        .collect();
    Ok(files)
}

fn archived_identity_key_files(paths: &StatePaths) -> Result<Vec<PathBuf>, SecurityError> {
    let archive_dir = identity_key_archive_dir(paths);
    if !security_directory_exists(&archive_dir)? {
        return Ok(Vec::new());
    }

    let mut files = Vec::new();
    for entry in fs::read_dir(&archive_dir).map_err(|error| {
        SecurityError::io("read identity key archive directory", &archive_dir, error)
    })? {
        let entry = entry.map_err(|error| {
            SecurityError::io("read identity key archive entry", &archive_dir, error)
        })?;
        let path = entry.path();
        if path.extension().and_then(|extension| extension.to_str()) == Some("key") {
            files.push(path);
        }
    }
    files.sort();
    Ok(files)
}

fn archived_identity_key_id(path: &Path) -> Result<String, SecurityError> {
    let file_name = path
        .file_name()
        .and_then(|file_name| file_name.to_str())
        .unwrap_or_default();
    if file_name.ends_with(".signing.key") {
        return Ok(read_identity_signing_key_file(path)?.key_id);
    }
    if file_name.ends_with(".exchange.key") {
        return Ok(read_identity_exchange_key_file(path)?.key_id);
    }

    Err(SecurityError::InvalidKey {
        path: path.to_path_buf(),
        reason: "expected archived identity signing or exchange key".to_string(),
    })
}

fn local_storage_payload_files(
    paths: &StatePaths,
) -> Result<Vec<Option<LocalStoragePayloadFile>>, SecurityError> {
    let mut paths_to_scan = Vec::new();
    collect_files_with_extension(&paths.message_ipc_inbox_dir, "msg", &mut paths_to_scan)?;
    collect_files_with_extension(&paths.message_inbox_dir, "env", &mut paths_to_scan)?;
    paths_to_scan.sort();

    paths_to_scan
        .into_iter()
        .map(|path| local_storage_payload_file(&path))
        .collect()
}

fn collect_files_with_extension(
    root: &Path,
    extension: &str,
    files: &mut Vec<PathBuf>,
) -> Result<(), SecurityError> {
    if !local_payload_directory_exists(root)? {
        return Ok(());
    }

    for entry in fs::read_dir(root)
        .map_err(|error| SecurityError::io("read local payload directory", root, error))?
    {
        let entry = entry.map_err(|error| {
            SecurityError::io("read local payload directory entry", root, error)
        })?;
        let path = entry.path();
        let file_type = entry.file_type().map_err(|error| {
            SecurityError::io("inspect local payload directory entry", &path, error)
        })?;
        if file_type.is_symlink() {
            return Err(invalid_local_payload_path(
                &path,
                "local payload path is not a regular file or directory",
            ));
        }
        if file_type.is_dir() {
            collect_files_with_extension(&path, extension, files)?;
        } else if file_type.is_file()
            && path.extension().and_then(|value| value.to_str()) == Some(extension)
        {
            files.push(path);
        } else if !file_type.is_file() {
            return Err(invalid_local_payload_path(
                &path,
                "local payload path is not a regular file or directory",
            ));
        }
    }

    Ok(())
}

fn local_storage_payload_file(
    path: &Path,
) -> Result<Option<LocalStoragePayloadFile>, SecurityError> {
    ensure_regular_local_payload_file(path)?;
    let contents = fs::read_to_string(path)
        .map_err(|error| SecurityError::io("read local encrypted payload file", path, error))?;
    let values = parse_key_values(&contents);
    if !values.contains_key("payload_ciphertext_hex") {
        return Ok(None);
    }

    let encrypted = EncryptedPayload {
        algorithm: required_payload_value(&values, "payload_cipher", path)?,
        key_id: required_payload_value(&values, "payload_key_id", path)?,
        nonce_hex: required_payload_value(&values, "payload_nonce_hex", path)?,
        ciphertext_hex: required_payload_value(&values, "payload_ciphertext_hex", path)?,
        plaintext_len: parse_payload_len(
            &required_payload_value(&values, "payload_len", path)?,
            path,
        )?,
    };
    let aad = local_storage_payload_aad(path, &values)?;

    Ok(Some(LocalStoragePayloadFile {
        path: path.to_path_buf(),
        contents,
        encrypted,
        aad,
    }))
}

fn rewrite_local_storage_payload_file(path: &Path, contents: &str) -> Result<(), SecurityError> {
    state::rewrite_existing_regular_state_file(
        path,
        contents,
        "inspect local encrypted payload file",
        "open re-encrypted local payload file",
        "write re-encrypted local payload file",
    )?;
    Ok(())
}

fn local_payload_directory_exists(path: &Path) -> Result<bool, SecurityError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(invalid_local_payload_path(
                    path,
                    "local payload directory path is not a directory",
                ));
            }
            Ok(true)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(SecurityError::io(
            "inspect local payload directory",
            path,
            error,
        )),
    }
}

fn ensure_regular_local_payload_file(path: &Path) -> Result<(), SecurityError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| SecurityError::io("inspect local encrypted payload file", path, error))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(invalid_local_payload_path(
            path,
            "local payload path is not a regular file",
        ));
    }
    Ok(())
}

fn invalid_local_payload_path(path: &Path, reason: &'static str) -> SecurityError {
    SecurityError::InvalidPayload {
        reason: format!("{reason} at {}", path.display()),
    }
}

fn local_storage_payload_aad(
    path: &Path,
    values: &HashMap<String, String>,
) -> Result<Vec<u8>, SecurityError> {
    match path.extension().and_then(|extension| extension.to_str()) {
        Some("msg") => {
            if required_payload_value(values, "type", path)? != "send_message" {
                return Err(SecurityError::InvalidPayload {
                    reason: format!("unsupported local message request at {}", path.display()),
                });
            }
            let request_id = required_payload_value(values, "request_id", path)?;
            let from_agent_id = required_payload_value(values, "from_agent_id", path)?;
            let to_agent_id = required_payload_value(values, "to_agent_id", path)?;
            Ok(
                format!("conu:message-request:v1:{request_id}:{from_agent_id}:{to_agent_id}")
                    .into_bytes(),
            )
        }
        Some("env") => {
            let envelope_id = required_payload_value(values, "envelope_id", path)?;
            let from_agent_id = required_payload_value(values, "from_agent_id", path)?;
            let to_agent_id = required_payload_value(values, "to_agent_id", path)?;
            if let Some(stream_id) = values.get("stream_id").filter(|value| !value.is_empty()) {
                Ok(format!(
                    "conu:stream-envelope:v1:{envelope_id}:{from_agent_id}:{to_agent_id}:{stream_id}"
                )
                .into_bytes())
            } else {
                Ok(
                    format!("conu:message-envelope:v1:{envelope_id}:{from_agent_id}:{to_agent_id}")
                        .into_bytes(),
                )
            }
        }
        _ => Err(SecurityError::InvalidPayload {
            reason: format!("unsupported local payload file at {}", path.display()),
        }),
    }
}

fn required_payload_value(
    values: &HashMap<String, String>,
    key: &str,
    path: &Path,
) -> Result<String, SecurityError> {
    values
        .get(key)
        .filter(|value| !value.trim().is_empty())
        .cloned()
        .ok_or_else(|| SecurityError::InvalidPayload {
            reason: format!("missing {key} in local payload file {}", path.display()),
        })
}

fn parse_payload_len(value: &str, path: &Path) -> Result<usize, SecurityError> {
    value
        .parse::<usize>()
        .map_err(|_| SecurityError::InvalidPayload {
            reason: format!(
                "invalid payload_len in local payload file {}",
                path.display()
            ),
        })
}

fn rewrite_payload_metadata(contents: &str, encrypted: &EncryptedPayload) -> String {
    let mut rewritten = String::with_capacity(contents.len());
    let mut saw_cipher = false;
    let mut saw_key_id = false;
    let mut saw_nonce = false;
    let mut saw_ciphertext = false;

    for line in contents.lines() {
        match key_for_line(line) {
            Some("payload_cipher") => {
                saw_cipher = true;
                rewritten.push_str(&format!(
                    "payload_cipher = \"{}\"",
                    escape_file_value(&encrypted.algorithm)
                ));
            }
            Some("payload_key_id") => {
                saw_key_id = true;
                rewritten.push_str(&format!(
                    "payload_key_id = \"{}\"",
                    escape_file_value(&encrypted.key_id)
                ));
            }
            Some("payload_nonce_hex") => {
                saw_nonce = true;
                rewritten.push_str(&format!(
                    "payload_nonce_hex = \"{}\"",
                    escape_file_value(&encrypted.nonce_hex)
                ));
            }
            Some("payload_ciphertext_hex") => {
                saw_ciphertext = true;
                rewritten.push_str(&format!(
                    "payload_ciphertext_hex = \"{}\"",
                    escape_file_value(&encrypted.ciphertext_hex)
                ));
            }
            _ => rewritten.push_str(line),
        }
        rewritten.push('\n');
    }

    if !saw_cipher {
        rewritten.push_str(&format!(
            "payload_cipher = \"{}\"\n",
            escape_file_value(&encrypted.algorithm)
        ));
    }
    if !saw_key_id {
        rewritten.push_str(&format!(
            "payload_key_id = \"{}\"\n",
            escape_file_value(&encrypted.key_id)
        ));
    }
    if !saw_nonce {
        rewritten.push_str(&format!(
            "payload_nonce_hex = \"{}\"\n",
            escape_file_value(&encrypted.nonce_hex)
        ));
    }
    if !saw_ciphertext {
        rewritten.push_str(&format!(
            "payload_ciphertext_hex = \"{}\"\n",
            escape_file_value(&encrypted.ciphertext_hex)
        ));
    }

    rewritten
}

fn key_for_line(line: &str) -> Option<&str> {
    let trimmed = line.trim_start();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return None;
    }
    trimmed.split_once('=').map(|(key, _)| key.trim())
}

fn derive_peer_key(
    paths: &StatePaths,
    remote_exchange_public_key_hex: &str,
    context: &[u8],
) -> Result<([u8; 32], String, String), SecurityError> {
    ensure_security_state_from_paths(paths)?;
    let local = read_identity_exchange_key(paths)?;
    derive_peer_key_with_local(&local, remote_exchange_public_key_hex, context)
}

fn derive_peer_key_candidates(
    paths: &StatePaths,
    remote_exchange_public_key_hex: &str,
    context: &[u8],
) -> Result<Vec<([u8; 32], String)>, SecurityError> {
    ensure_security_state_from_paths(paths)?;
    let mut candidates = Vec::new();
    let active = read_identity_exchange_key(paths)?;
    let (key, key_id, _) =
        derive_peer_key_with_local(&active, remote_exchange_public_key_hex, context)?;
    candidates.push((key, key_id));

    for archive_path in archived_identity_exchange_key_files(paths)? {
        let archived = read_identity_exchange_key_file(&archive_path)?;
        if archived.key_id == active.key_id {
            continue;
        }
        let (key, key_id, _) =
            derive_peer_key_with_local(&archived, remote_exchange_public_key_hex, context)?;
        candidates.push((key, key_id));
    }

    Ok(candidates)
}

fn derive_peer_key_with_local(
    local: &ExchangeKeyRecord,
    remote_exchange_public_key_hex: &str,
    context: &[u8],
) -> Result<([u8; 32], String, String), SecurityError> {
    let remote_public = hex_decode_exact::<32>(remote_exchange_public_key_hex)
        .map_err(|reason| SecurityError::InvalidPayload { reason })?;
    let secret = StaticSecret::from(local.secret_key);
    let remote = X25519PublicKey::from(remote_public);
    let shared = secret.diffie_hellman(&remote);
    let local_public_key_hex = hex_encode(&local.public_key);
    let remote_public_key_hex = hex_encode(&remote_public);
    let (first, second) = if local_public_key_hex <= remote_public_key_hex {
        (&local_public_key_hex, &remote_public_key_hex)
    } else {
        (&remote_public_key_hex, &local_public_key_hex)
    };
    let mut hasher = Sha256::new();
    hasher.update(b"conu peer session key v1");
    hasher.update(shared.to_bytes());
    hasher.update(first.as_bytes());
    hasher.update(second.as_bytes());
    hasher.update(context);
    let key: [u8; 32] = hasher.finalize().into();
    let key_id = key_id("peer", &key);

    Ok((key, key_id, local_public_key_hex))
}

fn key_file_is_readable(path: &Path) -> bool {
    ensure_existing_secret_file(path).is_ok() && fs::read_to_string(path).is_ok()
}

fn read_key_values(path: &Path) -> Result<HashMap<String, String>, SecurityError> {
    ensure_existing_secret_file(path)?;
    let contents = fs::read_to_string(path)
        .map_err(|error| SecurityError::io("read security key", path, error))?;
    Ok(parse_key_values(&contents))
}

fn secret_bytes<const N: usize>(
    values: &HashMap<String, String>,
    field: &'static str,
    path: &Path,
) -> Result<[u8; N], SecurityError> {
    let key_id = required(values, "key_id", path)?;
    if secret_field_has_protected_data(values, field) {
        let secret = secret_bytes_vec(values, field, &key_id, path)?;
        return secret.try_into().map_err(|_| SecurityError::InvalidKey {
            path: path.to_path_buf(),
            reason: format!("expected {N} bytes of protected secret data"),
        });
    }

    key_bytes::<N>(values, &format!("{field}_hex"), path)
}

fn secret_bytes_vec(
    values: &HashMap<String, String>,
    field: &'static str,
    entropy_id: &str,
    path: &Path,
) -> Result<Vec<u8>, SecurityError> {
    let protected_field = format!("{field}_dpapi_hex");
    if let Some(protected) = values
        .get(&protected_field)
        .filter(|value| !value.trim().is_empty())
    {
        let wrapped = hex_decode(protected).map_err(|reason| SecurityError::InvalidKey {
            path: path.to_path_buf(),
            reason,
        })?;
        return unprotect_os_secret(&wrapped, field, entropy_id, path);
    }

    let native_ref_field = format!("{field}_os_secret_ref");
    if let Some(reference) = values
        .get(&native_ref_field)
        .filter(|value| !value.trim().is_empty())
    {
        return unprotect_native_os_secret(values, field, entropy_id, reference, path);
    }

    let wrapped_field = format!("{field}_wrapped_hex");
    if let Some(wrapped) = values
        .get(&wrapped_field)
        .filter(|value| !value.trim().is_empty())
    {
        return unprotect_user_managed_secret(values, field, entropy_id, wrapped, path);
    }

    let raw_field = format!("{field}_hex");
    let value = required(values, &raw_field, path)?;
    hex_decode(&value).map_err(|reason| SecurityError::InvalidKey {
        path: path.to_path_buf(),
        reason,
    })
}

fn key_bytes<const N: usize>(
    values: &HashMap<String, String>,
    field: &str,
    path: &Path,
) -> Result<[u8; N], SecurityError> {
    let value = required(values, field, path)?;
    hex_decode_exact::<N>(&value).map_err(|reason| SecurityError::InvalidKey {
        path: path.to_path_buf(),
        reason,
    })
}

fn secret_field_has_protected_data(values: &HashMap<String, String>, field: &str) -> bool {
    values
        .get(&format!("{field}_dpapi_hex"))
        .is_some_and(|value| !value.trim().is_empty())
        || values
            .get(&format!("{field}_os_secret_ref"))
            .is_some_and(|value| !value.trim().is_empty())
        || values
            .get(&format!("{field}_wrapped_hex"))
            .is_some_and(|value| !value.trim().is_empty())
}

fn all_secret_files_use_os_protection(paths: &StatePaths) -> bool {
    if !os_secret_protection_available() {
        return false;
    }

    let active_keys_protected = [
        (&paths.identity_signing_key, "secret_key"),
        (&paths.identity_exchange_key, "secret_key"),
        (&paths.storage_key, "key"),
    ]
    .into_iter()
    .all(|(path, field)| {
        read_key_values(path)
            .map(|values| secret_file_uses_os_protection(&values, field))
            .unwrap_or(false)
    });
    if !active_keys_protected {
        return false;
    }

    let archived_storage_keys_protected = archived_storage_key_files(paths)
        .map(|archives| {
            archives.into_iter().all(|path| {
                read_key_values(&path)
                    .map(|values| secret_file_uses_os_protection(&values, "key"))
                    .unwrap_or(false)
            })
        })
        .unwrap_or(false);
    let archived_identity_keys_protected = archived_identity_key_files(paths)
        .map(|archives| {
            archives.into_iter().all(|path| {
                read_key_values(&path)
                    .map(|values| secret_file_uses_os_protection(&values, "secret_key"))
                    .unwrap_or(false)
            })
        })
        .unwrap_or(false);

    archived_storage_keys_protected && archived_identity_keys_protected
}

fn secret_file_uses_selected_protection(values: &HashMap<String, String>, field: &str) -> bool {
    match selected_secret_backend() {
        SecretBackendKind::WindowsDpapi => secret_file_uses_os_protection(values, field),
        SecretBackendKind::MacosKeychain | SecretBackendKind::LinuxSecretService => {
            secret_file_uses_os_protection(values, field)
        }
        SecretBackendKind::UserManagedWrapKey => {
            secret_file_uses_user_managed_protection(values, field)
        }
        SecretBackendKind::Filesystem => false,
    }
}

fn secret_file_uses_os_protection(values: &HashMap<String, String>, field: &str) -> bool {
    match values.get("secret_protection").map(String::as_str) {
        Some(SECRET_BACKEND_WINDOWS_DPAPI) if cfg!(windows) => values
            .get(&format!("{field}_dpapi_hex"))
            .is_some_and(|value| !value.trim().is_empty()),
        Some(SECRET_BACKEND_MACOS_KEYCHAIN) if cfg!(target_os = "macos") => {
            values
                .get(&format!("{field}_os_secret_ref"))
                .is_some_and(|value| !value.trim().is_empty())
                && values
                    .get(&format!("{field}_plaintext_len"))
                    .is_some_and(|value| value.parse::<usize>().is_ok())
        }
        Some(SECRET_BACKEND_LINUX_SECRET_SERVICE) if cfg!(target_os = "linux") => {
            values
                .get(&format!("{field}_os_secret_ref"))
                .is_some_and(|value| !value.trim().is_empty())
                && values
                    .get(&format!("{field}_plaintext_len"))
                    .is_some_and(|value| value.parse::<usize>().is_ok())
        }
        _ => false,
    }
}

fn secret_file_uses_user_managed_protection(values: &HashMap<String, String>, field: &str) -> bool {
    values
        .get("secret_protection")
        .is_some_and(|value| value == SECRET_BACKEND_USER_MANAGED_WRAP_KEY)
        && values
            .get("secret_algorithm")
            .is_some_and(|value| value == USER_MANAGED_SECRET_ALGORITHM)
        && values
            .get(&format!("{field}_wrap_nonce_hex"))
            .is_some_and(|value| !value.trim().is_empty())
        && values
            .get(&format!("{field}_wrapped_hex"))
            .is_some_and(|value| !value.trim().is_empty())
}

fn secret_storage_backend() -> &'static str {
    match selected_secret_backend() {
        SecretBackendKind::WindowsDpapi => SECRET_BACKEND_WINDOWS_DPAPI,
        SecretBackendKind::MacosKeychain => SECRET_BACKEND_MACOS_KEYCHAIN,
        SecretBackendKind::LinuxSecretService => SECRET_BACKEND_LINUX_SECRET_SERVICE,
        SecretBackendKind::UserManagedWrapKey => SECRET_BACKEND_USER_MANAGED_WRAP_KEY,
        SecretBackendKind::Filesystem => SECRET_BACKEND_FILESYSTEM,
    }
}

fn secret_protection_available() -> bool {
    selected_secret_backend() != SecretBackendKind::Filesystem
}

#[cfg(windows)]
fn selected_secret_backend() -> SecretBackendKind {
    SecretBackendKind::WindowsDpapi
}

#[cfg(target_os = "macos")]
fn selected_secret_backend() -> SecretBackendKind {
    if os_secret_protection_available() {
        SecretBackendKind::MacosKeychain
    } else if user_managed_wrap_key_configured() {
        SecretBackendKind::UserManagedWrapKey
    } else {
        SecretBackendKind::Filesystem
    }
}

#[cfg(target_os = "linux")]
fn selected_secret_backend() -> SecretBackendKind {
    if os_secret_protection_available() {
        SecretBackendKind::LinuxSecretService
    } else if user_managed_wrap_key_configured() {
        SecretBackendKind::UserManagedWrapKey
    } else {
        SecretBackendKind::Filesystem
    }
}

#[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
fn selected_secret_backend() -> SecretBackendKind {
    if user_managed_wrap_key_configured() {
        SecretBackendKind::UserManagedWrapKey
    } else {
        SecretBackendKind::Filesystem
    }
}

struct UserManagedProtectedSecret {
    nonce: [u8; NONCE_BYTES],
    ciphertext: Vec<u8>,
}

fn protect_user_managed_secret(
    secret: &[u8],
    field: &'static str,
    key_id: &str,
) -> Result<UserManagedProtectedSecret, SecurityError> {
    let key = user_managed_wrap_key()?;
    let cipher = XChaCha20Poly1305::new_from_slice(&key).map_err(|_| SecurityError::Crypto {
        action: "create user-managed secret wrap cipher failed",
    })?;
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let aad = user_managed_secret_aad(field, key_id);
    let ciphertext = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: secret,
                aad: aad.as_bytes(),
            },
        )
        .map_err(|_| SecurityError::Crypto {
            action: "wrap local secret with user-managed key failed",
        })?;

    let mut nonce_bytes = [0_u8; NONCE_BYTES];
    nonce_bytes.copy_from_slice(&nonce);

    Ok(UserManagedProtectedSecret {
        nonce: nonce_bytes,
        ciphertext,
    })
}

fn unprotect_user_managed_secret(
    values: &HashMap<String, String>,
    field: &'static str,
    key_id: &str,
    wrapped_hex: &str,
    path: &Path,
) -> Result<Vec<u8>, SecurityError> {
    if !secret_file_uses_user_managed_protection(values, field) {
        return Err(SecurityError::InvalidKey {
            path: path.to_path_buf(),
            reason: "invalid user-managed secret protection fields".to_string(),
        });
    }

    let nonce = hex_decode_exact::<NONCE_BYTES>(&required(
        values,
        &format!("{field}_wrap_nonce_hex"),
        path,
    )?)
    .map_err(|reason| SecurityError::InvalidKey {
        path: path.to_path_buf(),
        reason,
    })?;
    let ciphertext = hex_decode(wrapped_hex).map_err(|reason| SecurityError::InvalidKey {
        path: path.to_path_buf(),
        reason,
    })?;
    let plaintext_len = required(values, &format!("{field}_plaintext_len"), path)?
        .parse::<usize>()
        .map_err(|_| SecurityError::InvalidKey {
            path: path.to_path_buf(),
            reason: "invalid protected secret length".to_string(),
        })?;
    let key = user_managed_wrap_key()?;
    let cipher = XChaCha20Poly1305::new_from_slice(&key).map_err(|_| SecurityError::Crypto {
        action: "create user-managed secret wrap cipher failed",
    })?;
    let aad = user_managed_secret_aad(field, key_id);
    let plaintext = cipher
        .decrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &ciphertext,
                aad: aad.as_bytes(),
            },
        )
        .map_err(|_| SecurityError::InvalidKey {
            path: path.to_path_buf(),
            reason: "could not unwrap local secret with user-managed key".to_string(),
        })?;

    if plaintext.len() != plaintext_len {
        return Err(SecurityError::InvalidKey {
            path: path.to_path_buf(),
            reason: "unwrapped local secret length mismatch".to_string(),
        });
    }

    Ok(plaintext)
}

fn user_managed_secret_aad(field: &str, key_id: &str) -> String {
    format!("conu user-managed local secret v1:{field}:{key_id}")
}

#[cfg(not(windows))]
fn user_managed_wrap_key_configured() -> bool {
    #[cfg(test)]
    {
        if test_user_managed_wrap_key().is_some() {
            return true;
        }
    }

    std::env::var(SECRET_WRAP_KEY_HEX_ENV)
        .map(|value| !value.trim().is_empty())
        .unwrap_or(false)
        || std::env::var(SECRET_WRAP_KEY_FILE_ENV)
            .map(|value| !value.trim().is_empty())
            .unwrap_or(false)
}

fn user_managed_wrap_key() -> Result<[u8; 32], SecurityError> {
    #[cfg(all(test, not(windows)))]
    {
        if let Some(key) = test_user_managed_wrap_key() {
            return Ok(key);
        }
    }

    if let Ok(value) = std::env::var(SECRET_WRAP_KEY_HEX_ENV) {
        if !value.trim().is_empty() {
            return parse_user_managed_wrap_key(&value);
        }
    }

    if let Ok(path_value) = std::env::var(SECRET_WRAP_KEY_FILE_ENV) {
        if !path_value.trim().is_empty() {
            let path = PathBuf::from(path_value);
            let contents = fs::read_to_string(&path).map_err(|error| {
                SecurityError::io("read user-managed secret wrap key file", &path, error)
            })?;
            let value = contents
                .lines()
                .map(str::trim)
                .find(|line| !line.is_empty() && !line.starts_with('#'))
                .ok_or_else(|| SecurityError::InvalidPayload {
                    reason: "user-managed secret wrap key file is empty".to_string(),
                })?;
            return parse_user_managed_wrap_key(value);
        }
    }

    Err(SecurityError::InvalidPayload {
        reason: format!(
            "{SECRET_WRAP_KEY_HEX_ENV} or {SECRET_WRAP_KEY_FILE_ENV} is required for user-managed secret wrapping"
        ),
    })
}

fn parse_user_managed_wrap_key(value: &str) -> Result<[u8; 32], SecurityError> {
    hex_decode_exact::<32>(value.trim()).map_err(|reason| SecurityError::InvalidPayload {
        reason: format!("user-managed secret wrap key must be 32 bytes of hex: {reason}"),
    })
}

#[cfg(all(test, not(windows)))]
thread_local! {
    static TEST_USER_MANAGED_WRAP_KEY: std::cell::RefCell<Option<[u8; 32]>> =
        const { std::cell::RefCell::new(None) };
    static TEST_NATIVE_OS_SECRET_STORE: std::cell::RefCell<Option<HashMap<String, Vec<u8>>>> =
        const { std::cell::RefCell::new(None) };
    static TEST_NATIVE_OS_SECRET_BACKEND_DISABLED: std::cell::RefCell<bool> =
        const { std::cell::RefCell::new(false) };
}

#[cfg(all(test, not(windows)))]
fn test_user_managed_wrap_key() -> Option<[u8; 32]> {
    TEST_USER_MANAGED_WRAP_KEY.with(|key| *key.borrow())
}

#[cfg(all(test, not(windows)))]
fn test_native_os_secret_store_enabled() -> bool {
    TEST_NATIVE_OS_SECRET_STORE.with(|store| store.borrow().is_some())
}

#[cfg(all(test, not(windows)))]
fn test_native_os_secret_backend_disabled() -> bool {
    TEST_NATIVE_OS_SECRET_BACKEND_DISABLED.with(|disabled| *disabled.borrow())
}

#[cfg(all(test, not(windows)))]
fn test_native_os_secret_store_write(reference: &str, secret: &[u8]) -> bool {
    TEST_NATIVE_OS_SECRET_STORE.with(|store| {
        let mut store = store.borrow_mut();
        if let Some(secrets) = store.as_mut() {
            secrets.insert(reference.to_string(), secret.to_vec());
            true
        } else {
            false
        }
    })
}

#[cfg(all(test, not(windows)))]
fn test_native_os_secret_store_read(reference: &str) -> Option<Vec<u8>> {
    TEST_NATIVE_OS_SECRET_STORE.with(|store| {
        store
            .borrow()
            .as_ref()
            .and_then(|secrets| secrets.get(reference).cloned())
    })
}

#[cfg(all(test, not(windows)))]
fn test_native_os_secret_store_delete(reference: &str) -> bool {
    TEST_NATIVE_OS_SECRET_STORE.with(|store| {
        let mut store = store.borrow_mut();
        if let Some(secrets) = store.as_mut() {
            secrets.remove(reference);
            true
        } else {
            false
        }
    })
}

#[cfg(windows)]
fn os_secret_protection_available() -> bool {
    true
}

#[cfg(target_os = "macos")]
fn os_secret_protection_available() -> bool {
    if os_secret_backend_disabled() {
        return false;
    }

    #[cfg(test)]
    {
        test_native_os_secret_store_enabled()
    }

    #[cfg(not(test))]
    {
        true
    }
}

#[cfg(target_os = "linux")]
fn os_secret_protection_available() -> bool {
    if os_secret_backend_disabled() {
        return false;
    }

    #[cfg(test)]
    {
        test_native_os_secret_store_enabled()
    }

    #[cfg(not(test))]
    {
        linux_secret_service_available()
    }
}

#[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
fn os_secret_protection_available() -> bool {
    false
}

#[cfg(not(windows))]
fn os_secret_backend_disabled() -> bool {
    #[cfg(test)]
    {
        if test_native_os_secret_backend_disabled() {
            return true;
        }
    }

    std::env::var(DISABLE_OS_SECRET_BACKEND_ENV)
        .map(|value| matches!(value.trim(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false)
}

#[cfg(all(target_os = "linux", not(test)))]
fn linux_secret_service_available() -> bool {
    let has_session = std::env::var("DBUS_SESSION_BUS_ADDRESS")
        .map(|value| !value.trim().is_empty())
        .unwrap_or(false)
        || std::env::var("XDG_RUNTIME_DIR")
            .map(|value| !value.trim().is_empty())
            .unwrap_or(false);

    has_session && command_available("secret-tool")
}

#[cfg(all(target_os = "linux", not(test)))]
fn command_available(command: &str) -> bool {
    Command::new(command)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok()
}

fn native_os_secret_reference(field: &str, key_id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"conu native local secret v1");
    hasher.update([0]);
    hasher.update(field.as_bytes());
    hasher.update([0]);
    hasher.update(key_id.as_bytes());
    let digest = hex_encode(&hasher.finalize());
    format!("conu-local-secret-v1-{field}-{}", &digest[..32])
}

fn unprotect_native_os_secret(
    values: &HashMap<String, String>,
    field: &'static str,
    _key_id: &str,
    reference: &str,
    path: &Path,
) -> Result<Vec<u8>, SecurityError> {
    if !secret_file_uses_os_protection(values, field) {
        return Err(SecurityError::InvalidKey {
            path: path.to_path_buf(),
            reason: "invalid native OS secret protection fields".to_string(),
        });
    }

    let plaintext_len = required(values, &format!("{field}_plaintext_len"), path)?
        .parse::<usize>()
        .map_err(|_| SecurityError::InvalidKey {
            path: path.to_path_buf(),
            reason: "invalid native OS protected secret length".to_string(),
        })?;
    let secret = read_native_os_secret(reference, path)?;
    if secret.len() != plaintext_len {
        return Err(SecurityError::InvalidKey {
            path: path.to_path_buf(),
            reason: "native OS protected secret length mismatch".to_string(),
        });
    }
    Ok(secret)
}

fn protect_native_os_secret(reference: &str, secret: &[u8]) -> Result<(), SecurityError> {
    #[cfg(all(test, not(windows)))]
    {
        if test_native_os_secret_store_write(reference, secret) {
            return Ok(());
        }
    }

    protect_native_os_secret_platform(reference, secret)
}

fn read_native_os_secret(reference: &str, path: &Path) -> Result<Vec<u8>, SecurityError> {
    #[cfg(all(test, not(windows)))]
    {
        if let Some(secret) = test_native_os_secret_store_read(reference) {
            return Ok(secret);
        }
    }

    read_native_os_secret_platform(reference, path)
}

fn delete_native_os_secret(reference: &str) -> Result<(), SecurityError> {
    #[cfg(all(test, not(windows)))]
    {
        if test_native_os_secret_store_delete(reference) {
            return Ok(());
        }
    }

    delete_native_os_secret_platform(reference)
}

#[cfg(target_os = "macos")]
fn protect_native_os_secret_platform(reference: &str, secret: &[u8]) -> Result<(), SecurityError> {
    let entry = keyring::Entry::new(NATIVE_OS_SECRET_SERVICE, reference).map_err(|_| {
        SecurityError::Crypto {
            action: "open macOS Keychain entry failed",
        }
    })?;
    entry.set_secret(secret).map_err(|_| SecurityError::Crypto {
        action: "store local secret in macOS Keychain failed",
    })
}

#[cfg(target_os = "macos")]
fn read_native_os_secret_platform(reference: &str, path: &Path) -> Result<Vec<u8>, SecurityError> {
    let entry = keyring::Entry::new(NATIVE_OS_SECRET_SERVICE, reference).map_err(|_| {
        SecurityError::InvalidKey {
            path: path.to_path_buf(),
            reason: "open macOS Keychain entry failed".to_string(),
        }
    })?;
    entry.get_secret().map_err(|_| SecurityError::InvalidKey {
        path: path.to_path_buf(),
        reason: "could not read local secret from macOS Keychain".to_string(),
    })
}

#[cfg(target_os = "macos")]
fn delete_native_os_secret_platform(reference: &str) -> Result<(), SecurityError> {
    let entry = keyring::Entry::new(NATIVE_OS_SECRET_SERVICE, reference).map_err(|_| {
        SecurityError::Crypto {
            action: "open macOS Keychain entry for deletion failed",
        }
    })?;
    match entry.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(_) => Err(SecurityError::Crypto {
            action: "delete local secret from macOS Keychain failed",
        }),
    }
}

#[cfg(target_os = "linux")]
fn protect_native_os_secret_platform(reference: &str, secret: &[u8]) -> Result<(), SecurityError> {
    let mut child = Command::new("secret-tool")
        .arg("store")
        .arg("--label")
        .arg("conU local secret")
        .arg("conu-ref")
        .arg(reference)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| SecurityError::Crypto {
            action: "open Linux Secret Service store failed",
        })?;

    if let Some(stdin) = child.stdin.as_mut() {
        stdin
            .write_all(hex_encode(secret).as_bytes())
            .map_err(|_| SecurityError::Crypto {
                action: "write local secret to Linux Secret Service failed",
            })?;
    }

    child
        .wait()
        .map_err(|_| SecurityError::Crypto {
            action: "wait for Linux Secret Service store failed",
        })
        .and_then(|status| {
            if status.success() {
                Ok(())
            } else {
                Err(SecurityError::Crypto {
                    action: "store local secret in Linux Secret Service failed",
                })
            }
        })
}

#[cfg(target_os = "linux")]
fn read_native_os_secret_platform(reference: &str, path: &Path) -> Result<Vec<u8>, SecurityError> {
    let output = Command::new("secret-tool")
        .arg("lookup")
        .arg("conu-ref")
        .arg(reference)
        .stderr(Stdio::null())
        .output()
        .map_err(|_| SecurityError::InvalidKey {
            path: path.to_path_buf(),
            reason: "open Linux Secret Service lookup failed".to_string(),
        })?;
    if !output.status.success() {
        return Err(SecurityError::InvalidKey {
            path: path.to_path_buf(),
            reason: "could not read local secret from Linux Secret Service".to_string(),
        });
    }

    let value = String::from_utf8(output.stdout).map_err(|_| SecurityError::InvalidKey {
        path: path.to_path_buf(),
        reason: "Linux Secret Service returned non-UTF-8 secret data".to_string(),
    })?;
    hex_decode(value.trim_end_matches(['\r', '\n'])).map_err(|reason| SecurityError::InvalidKey {
        path: path.to_path_buf(),
        reason,
    })
}

#[cfg(target_os = "linux")]
fn delete_native_os_secret_platform(reference: &str) -> Result<(), SecurityError> {
    let _ = Command::new("secret-tool")
        .arg("clear")
        .arg("conu-ref")
        .arg(reference)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    Ok(())
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn protect_native_os_secret_platform(
    _reference: &str,
    _secret: &[u8],
) -> Result<(), SecurityError> {
    Err(SecurityError::Crypto {
        action: "native OS secret storage is unavailable on this platform",
    })
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn read_native_os_secret_platform(_reference: &str, path: &Path) -> Result<Vec<u8>, SecurityError> {
    Err(SecurityError::InvalidKey {
        path: path.to_path_buf(),
        reason: "native OS protected secret cannot be read on this platform".to_string(),
    })
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn delete_native_os_secret_platform(_reference: &str) -> Result<(), SecurityError> {
    Ok(())
}

#[cfg(windows)]
fn protect_os_secret(
    secret: &[u8],
    field: &'static str,
    key_id: &str,
) -> Result<Vec<u8>, SecurityError> {
    let entropy = secret_entropy(field, key_id);
    windows_dpapi::encrypt_data(secret, windows_dpapi::Scope::User, Some(entropy.as_bytes()))
        .map_err(|_| SecurityError::Crypto {
            action: "protect local secret with Windows DPAPI failed",
        })
}

#[cfg(not(windows))]
fn protect_os_secret(
    _secret: &[u8],
    _field: &'static str,
    _key_id: &str,
) -> Result<Vec<u8>, SecurityError> {
    Err(SecurityError::Crypto {
        action: "OS secret protection is unavailable on this platform",
    })
}

#[cfg(windows)]
fn unprotect_os_secret(
    protected: &[u8],
    field: &'static str,
    key_id: &str,
    path: &Path,
) -> Result<Vec<u8>, SecurityError> {
    let entropy = secret_entropy(field, key_id);
    windows_dpapi::decrypt_data(
        protected,
        windows_dpapi::Scope::User,
        Some(entropy.as_bytes()),
    )
    .map_err(|_| SecurityError::InvalidKey {
        path: path.to_path_buf(),
        reason: "could not unprotect local secret with Windows DPAPI".to_string(),
    })
}

#[cfg(not(windows))]
fn unprotect_os_secret(
    _protected: &[u8],
    _field: &'static str,
    _key_id: &str,
    path: &Path,
) -> Result<Vec<u8>, SecurityError> {
    Err(SecurityError::InvalidKey {
        path: path.to_path_buf(),
        reason: "OS-protected secret cannot be read on this platform".to_string(),
    })
}

#[cfg(windows)]
fn secret_entropy(field: &str, key_id: &str) -> String {
    format!("conu local secret v1:{field}:{key_id}")
}

fn required(
    values: &HashMap<String, String>,
    key: &str,
    path: &Path,
) -> Result<String, SecurityError> {
    values
        .get(key)
        .filter(|value| !value.trim().is_empty())
        .cloned()
        .ok_or_else(|| SecurityError::InvalidKey {
            path: path.to_path_buf(),
            reason: format!("missing {key}"),
        })
}

fn write_new_secret_file(path: &Path, contents: &str) -> Result<bool, SecurityError> {
    match OpenOptions::new().write(true).create_new(true).open(path) {
        Ok(mut file) => {
            set_sensitive_file_permissions(&file, path)?;
            file.write_all(contents.as_bytes())
                .map_err(|error| SecurityError::io("write security file", path, error))?;
            Ok(true)
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            ensure_existing_secret_file(path)?;
            Ok(false)
        }
        Err(error) => Err(SecurityError::io("create security file", path, error)),
    }
}

fn replace_secret_file(path: &Path, contents: &str) -> Result<(), SecurityError> {
    ensure_replaceable_secret_file(path)?;
    let mut file = OpenOptions::new()
        .write(true)
        .open(path)
        .map_err(|error| SecurityError::io("open replacement security file", path, error))?;
    set_sensitive_file_permissions(&file, path)?;
    file.set_len(0)
        .map_err(|error| SecurityError::io("truncate replacement security file", path, error))?;
    file.write_all(contents.as_bytes())
        .map_err(|error| SecurityError::io("write replacement security file", path, error))
}

fn ensure_existing_secret_file(path: &Path) -> Result<(), SecurityError> {
    ensure_regular_secret_file(path, "inspect existing security file")
}

fn ensure_replaceable_secret_file(path: &Path) -> Result<(), SecurityError> {
    ensure_regular_secret_file(path, "inspect replacement security file")
}

fn ensure_regular_secret_file(path: &Path, action: &'static str) -> Result<(), SecurityError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|error| SecurityError::io(action, path, error))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(SecurityError::InvalidKey {
            path: path.to_path_buf(),
            reason: "security file path is not a regular file".to_string(),
        });
    }
    Ok(())
}

fn secret_file_exists(path: &Path) -> Result<bool, SecurityError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(SecurityError::InvalidKey {
                    path: path.to_path_buf(),
                    reason: "security file path is not a regular file".to_string(),
                });
            }
            Ok(true)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(SecurityError::io("inspect security file", path, error)),
    }
}

fn security_directory_exists(path: &Path) -> Result<bool, SecurityError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(SecurityError::InvalidKey {
                    path: path.to_path_buf(),
                    reason: "security directory path is not a directory".to_string(),
                });
            }
            Ok(true)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(SecurityError::io("inspect security directory", path, error)),
    }
}

fn write_new_file(path: &Path, contents: &str) -> Result<bool, SecurityError> {
    match OpenOptions::new().write(true).create_new(true).open(path) {
        Ok(mut file) => {
            file.write_all(contents.as_bytes())
                .map_err(|error| SecurityError::io("write security file", path, error))?;
            Ok(true)
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => Ok(false),
        Err(error) => Err(SecurityError::io("create security file", path, error)),
    }
}

#[cfg(unix)]
fn set_sensitive_file_permissions(file: &fs::File, path: &Path) -> Result<(), SecurityError> {
    use std::os::unix::fs::PermissionsExt;

    let permissions = fs::Permissions::from_mode(0o600);
    file.set_permissions(permissions)
        .map_err(|error| SecurityError::io("set security file permissions", path, error))
}

#[cfg(not(unix))]
fn set_sensitive_file_permissions(_file: &fs::File, _path: &Path) -> Result<(), SecurityError> {
    Ok(())
}

fn parse_key_values(contents: &str) -> HashMap<String, String> {
    let mut values = HashMap::new();

    for line in contents.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') || line == "[[seen]]" {
            continue;
        }

        let Some((key, value)) = line.split_once('=') else {
            continue;
        };

        values.insert(key.trim().to_string(), clean_value(value));
    }

    values
}

fn clean_value(value: &str) -> String {
    value
        .trim()
        .trim_matches('"')
        .trim_matches('\'')
        .trim()
        .to_string()
}

fn validate_replay_value(value: &str, field: &'static str) -> Result<(), SecurityError> {
    if value.trim().is_empty() {
        return Err(SecurityError::InvalidPayload {
            reason: format!("{field} cannot be empty"),
        });
    }
    if value.len() > 140 {
        return Err(SecurityError::InvalidPayload {
            reason: format!("{field} is too long"),
        });
    }
    if !value
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.'))
    {
        return Err(SecurityError::InvalidPayload {
            reason: format!("{field} must use ASCII letters, numbers, dash, underscore, or dot"),
        });
    }
    Ok(())
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);

    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }

    encoded
}

fn hex_decode_exact<const N: usize>(value: &str) -> Result<[u8; N], String> {
    let bytes = hex_decode(value)?;
    bytes
        .try_into()
        .map_err(|_| format!("expected {N} bytes of hex data"))
}

fn hex_decode(value: &str) -> Result<Vec<u8>, String> {
    let value = value.trim();
    if value.len() % 2 != 0 {
        return Err("hex value must have an even number of characters".to_string());
    }

    let mut bytes = Vec::with_capacity(value.len() / 2);
    for pair in value.as_bytes().chunks_exact(2) {
        let high = hex_nibble(pair[0])?;
        let low = hex_nibble(pair[1])?;
        bytes.push((high << 4) | low);
    }

    Ok(bytes)
}

fn hex_nibble(byte: u8) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err("hex value must contain only hex characters".to_string()),
    }
}

fn key_id(prefix: &str, bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"conu key id v1");
    hasher.update(prefix.as_bytes());
    hasher.update(bytes);
    let digest = hasher.finalize();
    format!("{prefix}_{}", &hex_encode(&digest)[..16])
}

fn escape_file_value(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

fn key_rotation_plan_contents() -> &'static str {
    "# conU Local Key Rotation Plan\n\n\
Phase 11 creates three local key families:\n\n\
- Ed25519 node signing key for local agent-card signatures.\n\
- X25519 node exchange key for explicit peer key agreement.\n\
- XChaCha20Poly1305 storage key for conU-owned local payload storage.\n\n\
Rotation rules:\n\n\
1. Use `conu security rotate identity --confirm-peer-refresh` to archive old signing/exchange private keys and create fresh active public peer-card material.\n\
2. After identity rotation, run `conu identity export` and share the refreshed signed public peer card with trusted peers before expecting them to accept new signed agent cards or encrypt to the new exchange key.\n\
3. Archived exchange keys remain available locally for decrypting peer envelopes sent to the previous exchange public key during the refresh window.\n\
4. Use `conu security rotate storage --confirm` to archive the old storage key, mark a new storage key active, and re-encrypt local encrypted-at-rest message queue and inbox files.\n\
5. Use `conu security retire identity --confirm-peer-refresh-complete` only after refreshed peer cards have been redistributed and old-key decrypt compatibility is no longer required.\n\
6. Use `conu security retire storage --confirm` to remove archived storage keys only after local payload metadata proves no queue or inbox file still references them.\n\
7. Reject revoked peer keys during discovery, message delivery, and stream setup.\n\
8. Never print private keys, shared secrets, plaintext payloads, or decrypted payloads in CLI, logs, telemetry, docs, or tests.\n\n\
Production hardening still needs non-Windows OS keychain/HSM integration before a high-security public release.\n"
}

fn current_unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
fn current_unix_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
}

struct SigningKeyRecord {
    key_id: String,
    secret_key: [u8; 32],
    public_key: [u8; 32],
}

struct ExchangeKeyRecord {
    key_id: String,
    secret_key: [u8; 32],
    public_key: [u8; 32],
}

struct StorageKeyRecord {
    key_id: String,
    key: [u8; 32],
}

struct LocalStoragePayloadFile {
    path: PathBuf,
    contents: String,
    encrypted: EncryptedPayload,
    aad: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::process;

    #[test]
    fn security_state_creates_key_material_without_plaintext_payloads() {
        let home = test_home("state");
        let paths = StatePaths::from_home(home.clone());
        let report = ensure_security_state(Some(home)).expect("security state initializes");

        assert!(report.identity_signing_key_created);
        assert!(report.identity_exchange_key_created);
        assert!(report.storage_key_created);
        assert!(paths.identity_signing_key.exists());
        assert!(paths.identity_exchange_key.exists());
        assert!(paths.storage_key.exists());
        assert!(paths.replay_cache.exists());
        assert!(paths.key_rotation_plan.exists());

        let signing = fs::read_to_string(paths.identity_signing_key).expect("signing key reads");
        if os_secret_protection_available() {
            let values = parse_key_values(&signing);
            assert!(secret_file_uses_os_protection(&values, "secret_key"));
            assert!(!signing.contains("secret_key_hex"));
            assert!(report.secrets_os_protected);
        } else {
            assert!(signing.contains("secret_key_hex"));
            assert!(!report.secrets_os_protected);
        }
        assert!(!signing.contains("private message contents"));
    }

    #[cfg(unix)]
    #[test]
    fn new_secret_file_rejects_existing_symlink_without_touching_target() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let home = test_home("new-secret-symlink");
        fs::create_dir_all(&home).expect("home directory created");
        let target = home.join("outside-secret-target");
        let link = home.join("secret.key");
        fs::write(&target, "existing secret").expect("target writes");
        fs::set_permissions(&target, fs::Permissions::from_mode(0o644))
            .expect("target permissions set");
        symlink(&target, &link).expect("symlink creates");

        let error = write_new_secret_file(&link, "new secret")
            .expect_err("existing symlink should fail closed");

        assert!(error.to_string().contains("not a regular file"));
        assert_eq!(
            fs::read_to_string(&target).expect("target reads"),
            "existing secret"
        );
        assert_eq!(
            fs::metadata(&target)
                .expect("target metadata reads")
                .permissions()
                .mode()
                & 0o777,
            0o644
        );
    }

    #[cfg(unix)]
    #[test]
    fn replacement_secret_file_rejects_symlink_without_truncating_target() {
        use std::os::unix::fs::symlink;

        let home = test_home("replace-secret-symlink");
        fs::create_dir_all(&home).expect("home directory created");
        let target = home.join("outside-secret-target");
        let link = home.join("secret.key");
        fs::write(&target, "existing secret").expect("target writes");
        symlink(&target, &link).expect("symlink creates");

        let error =
            replace_secret_file(&link, "new secret").expect_err("symlink replacement fails closed");

        assert!(error.to_string().contains("not a regular file"));
        assert_eq!(
            fs::read_to_string(&target).expect("target reads"),
            "existing secret"
        );
    }

    #[cfg(unix)]
    #[test]
    fn secret_key_read_rejects_symlink_without_reading_target() {
        use std::os::unix::fs::symlink;

        let home = test_home("read-secret-symlink");
        fs::create_dir_all(&home).expect("home directory created");
        let target = home.join("outside-secret-target");
        let link = home.join("secret.key");
        fs::write(&target, "version = \"1\"\nsecret_key_hex = \"outside\"\n")
            .expect("target writes");
        symlink(&target, &link).expect("symlink creates");

        let error = read_key_values(&link).expect_err("symlink read fails closed");

        assert!(error.to_string().contains("not a regular file"));
        assert_eq!(
            fs::read_to_string(&target).expect("target reads"),
            "version = \"1\"\nsecret_key_hex = \"outside\"\n"
        );
    }

    #[cfg(unix)]
    #[test]
    fn relay_credential_status_rejects_broken_symlink_instead_of_absent() {
        use std::os::unix::fs::symlink;

        let home = test_home("relay-credential-broken-symlink");
        let paths = StatePaths::from_home(home);
        fs::create_dir_all(&paths.security_dir).expect("security dir created");
        let missing_target = paths.security_dir.join("missing-relay-token-target");
        symlink(&missing_target, &paths.relay_credential).expect("credential symlink creates");

        let error = relay_credential_status_from_paths(&paths)
            .expect_err("credential symlink should fail closed");

        assert!(error.to_string().contains("not a regular file"));
        assert!(
            fs::symlink_metadata(&paths.relay_credential)
                .expect("credential link metadata reads")
                .file_type()
                .is_symlink()
        );
    }

    #[test]
    fn existing_plaintext_secret_files_are_read_and_migrated_when_supported() {
        let home = test_home("plaintext-migration");
        let paths = StatePaths::from_home(home);
        fs::create_dir_all(&paths.security_dir).expect("security dir created");

        let signing_key = SigningKey::generate(&mut OsRng);
        let signing_public = signing_key.verifying_key().to_bytes();
        let signing_secret = signing_key.to_bytes();
        let signing_key_id = key_id("ed25519", &signing_public);
        fs::write(
            &paths.identity_signing_key,
            format!(
                "# conU node signing key\nversion = \"1\"\nalgorithm = \"Ed25519\"\nkey_id = \"{}\"\nsecret_key_hex = \"{}\"\npublic_key_hex = \"{}\"\ncreated_at_unix = 1\n",
                signing_key_id,
                hex_encode(&signing_secret),
                hex_encode(&signing_public)
            ),
        )
        .expect("signing key writes");

        let exchange_secret = StaticSecret::random_from_rng(OsRng);
        let exchange_public = X25519PublicKey::from(&exchange_secret).to_bytes();
        let exchange_secret_bytes = exchange_secret.to_bytes();
        let exchange_key_id = key_id("x25519", &exchange_public);
        fs::write(
            &paths.identity_exchange_key,
            format!(
                "# conU node X25519 exchange key\nversion = \"1\"\nalgorithm = \"X25519\"\nkey_id = \"{}\"\nsecret_key_hex = \"{}\"\npublic_key_hex = \"{}\"\ncreated_at_unix = 1\n",
                exchange_key_id,
                hex_encode(&exchange_secret_bytes),
                hex_encode(&exchange_public)
            ),
        )
        .expect("exchange key writes");

        let storage_key: [u8; 32] = XChaCha20Poly1305::generate_key(&mut OsRng).into();
        let storage_key_id = key_id("storage", &storage_key);
        fs::write(
            &paths.storage_key,
            format!(
                "# conU local storage encryption key\nversion = \"1\"\nalgorithm = \"XChaCha20Poly1305\"\nkey_id = \"{}\"\nkey_hex = \"{}\"\ncreated_at_unix = 1\n",
                storage_key_id,
                hex_encode(&storage_key)
            ),
        )
        .expect("storage key writes");

        let report =
            ensure_security_state_from_paths(&paths).expect("existing security state is readable");
        let signing = fs::read_to_string(&paths.identity_signing_key).expect("signing key reads");
        let storage = read_storage_key(&paths).expect("storage key reads");

        assert_eq!(report.signing_key_id, signing_key_id);
        assert_eq!(storage.key, storage_key);
        if os_secret_protection_available() {
            let values = parse_key_values(&signing);
            assert!(report.secrets_os_protected);
            assert!(secret_file_uses_os_protection(&values, "secret_key"));
            assert!(!signing.contains("secret_key_hex"));
        } else {
            assert!(!report.secrets_os_protected);
            assert!(signing.contains("secret_key_hex"));
        }
        assert!(!signing.contains("private message contents"));
    }

    #[test]
    fn relay_credential_storage_hides_token_and_reports_backend() {
        let home = test_home("relay-credential");
        let token = "relay-token-for-node-a-1234567890";
        let status =
            store_relay_credential(Some(home.clone()), token).expect("relay credential stores");
        let paths = StatePaths::from_home(home.clone());
        let contents = fs::read_to_string(&paths.relay_credential).expect("relay credential reads");
        let read_back =
            read_relay_credential_from_paths(&paths).expect("relay credential decrypts");

        assert!(status.configured);
        assert_eq!(read_back.as_deref(), Some(token));
        assert!(contents.contains("kind = \"relay_token\""));
        assert!(contents.contains("contents_displayed = false"));
        assert!(!contents.contains(token));
        if os_secret_protection_available() {
            let values = parse_key_values(&contents);
            assert!(status.os_protected);
            assert!(secret_file_uses_os_protection(&values, "token"));
            assert!(!contents.contains("token_hex"));
        } else {
            assert!(!status.os_protected);
            assert!(contents.contains("token_hex"));
        }

        let cleared = clear_relay_credential(Some(home)).expect("relay credential clears");
        assert!(!cleared.configured);
        assert!(!paths.relay_credential.exists());
    }

    #[cfg(unix)]
    #[test]
    fn identity_rotation_rejects_symlinked_archive_directory() {
        use std::os::unix::fs::symlink;

        let home = test_home("identity-archive-dir-symlink");
        let paths = StatePaths::from_home(home.clone());
        ensure_security_state_from_paths(&paths).expect("security state initializes");
        let outside = home.join("outside-identity-archives");
        fs::create_dir_all(&outside).expect("outside archive directory creates");
        let archive_dir = identity_key_archive_dir(&paths);
        symlink(&outside, &archive_dir).expect("identity archive symlink creates");

        let error = rotate_identity_keys_from_paths(&paths)
            .expect_err("symlinked identity archive directory fails closed");

        assert!(error.to_string().contains("not a directory"));
        assert_eq!(
            fs::read_dir(&outside)
                .expect("outside archive dir reads")
                .count(),
            0
        );
        assert!(
            fs::symlink_metadata(&archive_dir)
                .expect("archive link metadata reads")
                .file_type()
                .is_symlink()
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn user_managed_wrap_key_encrypts_and_migrates_non_windows_secrets() {
        with_test_native_os_secret_backend_disabled(|| {
            with_test_user_managed_wrap_key([42_u8; 32], || {
                let home = test_home("user-managed-wrap");
                let paths = StatePaths::from_home(home.clone());
                fs::create_dir_all(&paths.security_dir).expect("security dir created");

                let signing_key = SigningKey::generate(&mut OsRng);
                let signing_public = signing_key.verifying_key().to_bytes();
                let signing_secret = signing_key.to_bytes();
                let signing_key_id = key_id("ed25519", &signing_public);
                fs::write(
                &paths.identity_signing_key,
                format!(
                    "# conU node signing key\nversion = \"1\"\nalgorithm = \"Ed25519\"\nkey_id = \"{}\"\nsecret_key_hex = \"{}\"\npublic_key_hex = \"{}\"\ncreated_at_unix = 1\n",
                    signing_key_id,
                    hex_encode(&signing_secret),
                    hex_encode(&signing_public)
                ),
            )
            .expect("signing key writes");

                let exchange_secret = StaticSecret::random_from_rng(OsRng);
                let exchange_public = X25519PublicKey::from(&exchange_secret).to_bytes();
                let exchange_secret_bytes = exchange_secret.to_bytes();
                let exchange_key_id = key_id("x25519", &exchange_public);
                fs::write(
                &paths.identity_exchange_key,
                format!(
                    "# conU node X25519 exchange key\nversion = \"1\"\nalgorithm = \"X25519\"\nkey_id = \"{}\"\nsecret_key_hex = \"{}\"\npublic_key_hex = \"{}\"\ncreated_at_unix = 1\n",
                    exchange_key_id,
                    hex_encode(&exchange_secret_bytes),
                    hex_encode(&exchange_public)
                ),
            )
            .expect("exchange key writes");

                let storage_key: [u8; 32] = XChaCha20Poly1305::generate_key(&mut OsRng).into();
                let storage_key_id = key_id("storage", &storage_key);
                fs::write(
                &paths.storage_key,
                format!(
                    "# conU local storage encryption key\nversion = \"1\"\nalgorithm = \"XChaCha20Poly1305\"\nkey_id = \"{}\"\nkey_hex = \"{}\"\ncreated_at_unix = 1\n",
                    storage_key_id,
                    hex_encode(&storage_key)
                ),
            )
            .expect("storage key writes");
                let token = "relay-token-for-node-a-1234567890";
                fs::write(
                &paths.relay_credential,
                format!(
                    "# conU relay client credential\nversion = \"1\"\nkind = \"relay_token\"\ntoken_hex = \"{}\"\ncreated_at_unix = 1\nupdated_at_unix = 1\ncontents_displayed = false\n",
                    hex_encode(token.as_bytes())
                ),
            )
            .expect("relay credential writes");

                let report = ensure_security_state_from_paths(&paths)
                    .expect("security state migrates to user-managed wrapping");
                let audit = security_audit(Some(home)).expect("audit reads wrapped secrets");
                let signing = fs::read_to_string(&paths.identity_signing_key)
                    .expect("wrapped signing key reads");
                let exchange = fs::read_to_string(&paths.identity_exchange_key)
                    .expect("wrapped exchange key reads");
                let storage =
                    fs::read_to_string(&paths.storage_key).expect("wrapped storage reads");
                let credential_status =
                    relay_credential_status_from_paths(&paths).expect("credential status reads");
                let credential =
                    fs::read_to_string(&paths.relay_credential).expect("credential reads");
                let read_back =
                    read_relay_credential_from_paths(&paths).expect("credential unwraps");

                assert_eq!(
                    report.secret_storage_backend,
                    SECRET_BACKEND_USER_MANAGED_WRAP_KEY
                );
                assert_eq!(
                    audit.secret_storage_backend,
                    SECRET_BACKEND_USER_MANAGED_WRAP_KEY
                );
                assert!(!report.secrets_os_protected);
                assert!(!audit.secrets_os_protected);
                assert_eq!(report.signing_key_id, signing_key_id);
                assert_eq!(
                    read_identity_exchange_key(&paths)
                        .expect("exchange key unwraps")
                        .key_id,
                    exchange_key_id
                );
                assert_eq!(
                    read_storage_key(&paths).expect("storage key unwraps").key,
                    storage_key
                );
                assert_eq!(read_back.as_deref(), Some(token));
                assert!(credential_status.configured);
                assert!(!credential_status.os_protected);

                let contains_field = |contents: &str, field: &str| {
                    let prefix = format!("{field} =");
                    contents
                        .lines()
                        .any(|line| line.trim_start().starts_with(&prefix))
                };

                for contents in [&signing, &exchange, &storage, &credential] {
                    assert!(contents.contains(&format!(
                        "secret_protection = \"{}\"",
                        SECRET_BACKEND_USER_MANAGED_WRAP_KEY
                    )));
                    assert!(contents.contains("secret_algorithm = \"XChaCha20Poly1305\""));
                    assert!(contents.contains("_wrapped_hex"));
                    assert!(contents.contains("_wrap_nonce_hex"));
                    assert!(!contains_field(contents, "secret_key_hex"));
                    assert!(!contains_field(contents, "key_hex"));
                    assert!(!contains_field(contents, "token_hex"));
                    assert!(!contents.contains(token));
                    assert!(!contents.contains("private message contents"));
                }
            });
        });
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn native_os_secret_store_encrypts_and_migrates_non_windows_secrets() {
        with_test_native_os_secret_store(|| {
            let home = test_home("native-os-secret-store");
            let paths = StatePaths::from_home(home.clone());
            fs::create_dir_all(&paths.security_dir).expect("security dir created");

            let signing_key = SigningKey::generate(&mut OsRng);
            let signing_public = signing_key.verifying_key().to_bytes();
            let signing_secret = signing_key.to_bytes();
            let signing_key_id = key_id("ed25519", &signing_public);
            fs::write(
                &paths.identity_signing_key,
                format!(
                    "# conU node signing key\nversion = \"1\"\nalgorithm = \"Ed25519\"\nkey_id = \"{}\"\nsecret_key_hex = \"{}\"\npublic_key_hex = \"{}\"\ncreated_at_unix = 1\n",
                    signing_key_id,
                    hex_encode(&signing_secret),
                    hex_encode(&signing_public)
                ),
            )
            .expect("signing key writes");

            let exchange_secret = StaticSecret::random_from_rng(OsRng);
            let exchange_public = X25519PublicKey::from(&exchange_secret).to_bytes();
            let exchange_secret_bytes = exchange_secret.to_bytes();
            let exchange_key_id = key_id("x25519", &exchange_public);
            fs::write(
                &paths.identity_exchange_key,
                format!(
                    "# conU node X25519 exchange key\nversion = \"1\"\nalgorithm = \"X25519\"\nkey_id = \"{}\"\nsecret_key_hex = \"{}\"\npublic_key_hex = \"{}\"\ncreated_at_unix = 1\n",
                    exchange_key_id,
                    hex_encode(&exchange_secret_bytes),
                    hex_encode(&exchange_public)
                ),
            )
            .expect("exchange key writes");

            let storage_key: [u8; 32] = XChaCha20Poly1305::generate_key(&mut OsRng).into();
            let storage_key_id = key_id("storage", &storage_key);
            fs::write(
                &paths.storage_key,
                format!(
                    "# conU local storage encryption key\nversion = \"1\"\nalgorithm = \"XChaCha20Poly1305\"\nkey_id = \"{}\"\nkey_hex = \"{}\"\ncreated_at_unix = 1\n",
                    storage_key_id,
                    hex_encode(&storage_key)
                ),
            )
            .expect("storage key writes");
            let token = "relay-token-for-node-a-1234567890";
            fs::write(
                &paths.relay_credential,
                format!(
                    "# conU relay client credential\nversion = \"1\"\nkind = \"relay_token\"\ntoken_hex = \"{}\"\ncreated_at_unix = 1\nupdated_at_unix = 1\ncontents_displayed = false\n",
                    hex_encode(token.as_bytes())
                ),
            )
            .expect("relay credential writes");

            let report = ensure_security_state_from_paths(&paths)
                .expect("security state migrates to native OS store");
            let audit = security_audit(Some(home)).expect("audit reads native OS secrets");
            let signing =
                fs::read_to_string(&paths.identity_signing_key).expect("native signing key reads");
            let exchange = fs::read_to_string(&paths.identity_exchange_key)
                .expect("native exchange key reads");
            let storage = fs::read_to_string(&paths.storage_key).expect("native storage reads");
            let credential_status =
                relay_credential_status_from_paths(&paths).expect("credential status reads");
            let credential = fs::read_to_string(&paths.relay_credential).expect("credential reads");
            let read_back = read_relay_credential_from_paths(&paths).expect("credential unwraps");

            assert_eq!(report.secret_storage_backend, native_test_backend_name());
            assert_eq!(audit.secret_storage_backend, native_test_backend_name());
            assert!(report.secrets_os_protected);
            assert!(audit.secrets_os_protected);
            assert_eq!(report.signing_key_id, signing_key_id);
            assert_eq!(
                read_identity_exchange_key(&paths)
                    .expect("exchange key unwraps")
                    .key_id,
                exchange_key_id
            );
            assert_eq!(
                read_storage_key(&paths).expect("storage key unwraps").key,
                storage_key
            );
            assert_eq!(read_back.as_deref(), Some(token));
            assert!(credential_status.configured);
            assert!(credential_status.os_protected);

            let contains_field = |contents: &str, field: &str| {
                let prefix = format!("{field} =");
                contents
                    .lines()
                    .any(|line| line.trim_start().starts_with(&prefix))
            };

            for (contents, field) in [
                (&signing, "secret_key"),
                (&exchange, "secret_key"),
                (&storage, "key"),
                (&credential, "token"),
            ] {
                let values = parse_key_values(contents);
                assert!(contents.contains(&format!(
                    "secret_protection = \"{}\"",
                    native_test_backend_name()
                )));
                assert!(contents.contains("_os_secret_ref"));
                assert!(secret_file_uses_os_protection(&values, field));
                assert!(!contains_field(contents, "secret_key_hex"));
                assert!(!contains_field(contents, "key_hex"));
                assert!(!contains_field(contents, "token_hex"));
                assert!(!contents.contains(token));
                assert!(!contents.contains("private message contents"));
            }

            clear_relay_credential(Some(paths.home.clone())).expect("relay credential clears");
            assert!(
                test_native_os_secret_store_read(&native_os_secret_reference(
                    "token",
                    "relay-credential"
                ))
                .is_none()
            );
        });
    }

    #[test]
    fn storage_encryption_round_trips_and_hides_plaintext() {
        let home = test_home("storage");
        let paths = StatePaths::from_home(home);
        ensure_security_state_from_paths(&paths).expect("security state initializes");
        let encrypted = encrypt_for_storage_from_paths(
            &paths,
            b"private message contents",
            b"message:agent.a:agent.b",
        )
        .expect("encrypts");
        let decrypted =
            decrypt_from_storage_from_paths(&paths, &encrypted, b"message:agent.a:agent.b")
                .expect("decrypts");

        assert_eq!(decrypted, b"private message contents");
        assert_eq!(encrypted.algorithm, STORAGE_ALGORITHM);
        assert!(
            !encrypted
                .ciphertext_hex
                .contains("private message contents")
        );
        assert_ne!(
            encrypted.ciphertext_hex,
            hex_encode(b"private message contents")
        );
    }

    #[test]
    fn storage_key_rotation_reencrypts_local_payload_files() {
        let home = test_home("storage-rotation");
        let paths = StatePaths::from_home(home);
        ensure_security_state_from_paths(&paths).expect("security state initializes");
        fs::create_dir_all(&paths.message_ipc_inbox_dir).expect("message ipc inbox created");
        fs::create_dir_all(paths.message_inbox_dir.join("agent.receiver"))
            .expect("message inbox created");
        let old_key_id = read_storage_key(&paths).expect("old key reads").key_id;

        let request_aad =
            b"conu:message-request:v1:req.rotate:agent.sender:agent.receiver".to_vec();
        let request_payload =
            encrypt_for_storage_from_paths(&paths, b"private message contents", &request_aad)
                .expect("request encrypts");
        let request_path = paths.message_ipc_inbox_dir.join("req.rotate.msg");
        fs::write(
            &request_path,
            format!(
                "version = \"1\"\ntype = \"send_message\"\nrequest_id = \"req.rotate\"\nfrom_agent_id = \"agent.sender\"\nto_agent_id = \"agent.receiver\"\npayload_len = 24\npayload_privacy = \"encrypted_at_rest\"\npayload_cipher = \"{}\"\npayload_key_id = \"{}\"\npayload_nonce_hex = \"{}\"\npayload_ciphertext_hex = \"{}\"\n",
                request_payload.algorithm,
                request_payload.key_id,
                request_payload.nonce_hex,
                request_payload.ciphertext_hex
            ),
        )
        .expect("request writes");

        let envelope_aad =
            b"conu:message-envelope:v1:env.rotate:agent.sender:agent.receiver".to_vec();
        let envelope_payload =
            encrypt_for_storage_from_paths(&paths, b"another private payload", &envelope_aad)
                .expect("envelope encrypts");
        let envelope_path = paths
            .message_inbox_dir
            .join("agent.receiver")
            .join("env.rotate.env");
        fs::write(
            &envelope_path,
            format!(
                "version = \"1\"\nenvelope_id = \"env.rotate\"\nfrom_agent_id = \"agent.sender\"\nto_agent_id = \"agent.receiver\"\nkind = \"message\"\nreceipt_id = \"rcpt.rotate\"\ndelivered_at_unix = 1\npayload_len = 23\npayload_privacy = \"encrypted_at_rest\"\npayload_cipher = \"{}\"\npayload_key_id = \"{}\"\npayload_nonce_hex = \"{}\"\npayload_ciphertext_hex = \"{}\"\n",
                envelope_payload.algorithm,
                envelope_payload.key_id,
                envelope_payload.nonce_hex,
                envelope_payload.ciphertext_hex
            ),
        )
        .expect("envelope writes");

        let report = rotate_storage_key_from_paths(&paths).expect("storage key rotation succeeds");
        let new_key_id = read_storage_key(&paths).expect("new key reads").key_id;
        let request_after = fs::read_to_string(&request_path).expect("request reads");
        let envelope_after = fs::read_to_string(&envelope_path).expect("envelope reads");
        let request_values = parse_key_values(&request_after);
        let envelope_values = parse_key_values(&envelope_after);
        let request_rotated = encrypted_payload_from_values(&request_values);
        let envelope_rotated = encrypted_payload_from_values(&envelope_values);

        assert_ne!(old_key_id, new_key_id);
        assert!(
            paths
                .storage_key_archive_dir
                .join(format!("{old_key_id}.key"))
                .exists()
        );
        assert_eq!(report.files_scanned, 2);
        assert_eq!(report.files_migrated, 2);
        assert_eq!(report.files_skipped, 0);
        assert!(!report.contents_displayed);
        assert!(request_after.contains(&format!("payload_key_id = \"{new_key_id}\"")));
        assert!(envelope_after.contains(&format!("payload_key_id = \"{new_key_id}\"")));
        assert!(!request_after.contains("private message contents"));
        assert!(!envelope_after.contains("another private payload"));
        assert_eq!(
            decrypt_from_storage_from_paths(&paths, &request_rotated, &request_aad)
                .expect("request decrypts"),
            b"private message contents"
        );
        assert_eq!(
            decrypt_from_storage_from_paths(&paths, &envelope_rotated, &envelope_aad)
                .expect("envelope decrypts"),
            b"another private payload"
        );
    }

    #[cfg(unix)]
    #[test]
    fn storage_key_rotation_rejects_symlinked_payload_scan_root_before_key_change() {
        use std::os::unix::fs::symlink;

        let home = test_home("storage-rotation-symlink-root");
        let paths = StatePaths::from_home(home.clone());
        ensure_security_state_from_paths(&paths).expect("security state initializes");
        let old_key_id = read_storage_key(&paths).expect("old key reads").key_id;
        let outside = home.join("outside-payload-root");
        fs::create_dir_all(&outside).expect("outside payload root creates");
        fs::create_dir_all(
            paths
                .message_ipc_inbox_dir
                .parent()
                .expect("message ipc inbox has parent"),
        )
        .expect("message ipc parent creates");
        symlink(&outside, &paths.message_ipc_inbox_dir).expect("payload root symlink creates");

        let error = rotate_storage_key_from_paths(&paths)
            .expect_err("symlinked payload scan root fails closed");

        assert!(error.to_string().contains("not a directory"));
        assert_eq!(
            read_storage_key(&paths)
                .expect("storage key still reads")
                .key_id,
            old_key_id
        );
        assert_eq!(
            fs::read_dir(&outside)
                .expect("outside payload root reads")
                .count(),
            0
        );
        assert!(
            fs::symlink_metadata(&paths.message_ipc_inbox_dir)
                .expect("payload root link metadata reads")
                .file_type()
                .is_symlink()
        );
    }

    #[cfg(unix)]
    #[test]
    fn storage_key_rotation_rejects_symlinked_payload_file_without_touching_target() {
        use std::os::unix::fs::symlink;

        let home = test_home("storage-rotation-symlink-file");
        let paths = StatePaths::from_home(home.clone());
        ensure_security_state_from_paths(&paths).expect("security state initializes");
        fs::create_dir_all(&paths.message_ipc_inbox_dir).expect("message ipc inbox created");
        let old_key_id = read_storage_key(&paths).expect("old key reads").key_id;
        let outside = home.join("outside-payload-target.msg");
        let outside_contents = "outside payload marker\n";
        fs::write(&outside, outside_contents).expect("outside payload target writes");
        let link = paths.message_ipc_inbox_dir.join("req.link.msg");
        symlink(&outside, &link).expect("payload file symlink creates");

        let error =
            rotate_storage_key_from_paths(&paths).expect_err("symlinked payload file fails closed");

        assert!(
            error
                .to_string()
                .contains("not a regular file or directory")
        );
        assert_eq!(
            read_storage_key(&paths)
                .expect("storage key still reads")
                .key_id,
            old_key_id
        );
        assert_eq!(
            fs::read_to_string(&outside).expect("outside payload target reads"),
            outside_contents
        );
        assert!(
            fs::symlink_metadata(&link)
                .expect("payload file link metadata reads")
                .file_type()
                .is_symlink()
        );
    }

    #[cfg(unix)]
    #[test]
    fn storage_payload_rewrite_rejects_symlink_without_touching_target() {
        use std::os::unix::fs::symlink;

        let home = test_home("storage-rewrite-symlink");
        fs::create_dir_all(&home).expect("home creates");
        let outside = home.join("outside-payload-target.msg");
        let link = home.join("payload.msg");
        let outside_contents = "outside payload marker\n";
        fs::write(&outside, outside_contents).expect("outside target writes");
        symlink(&outside, &link).expect("payload symlink creates");

        let error = rewrite_local_storage_payload_file(&link, "new encrypted metadata\n")
            .expect_err("symlinked rewrite target fails closed");

        assert!(error.to_string().contains("not a regular file"));
        assert_eq!(
            fs::read_to_string(&outside).expect("outside target reads"),
            outside_contents
        );
        assert!(
            fs::symlink_metadata(&link)
                .expect("payload link metadata reads")
                .file_type()
                .is_symlink()
        );
    }

    #[test]
    fn storage_payload_rewrite_rejects_missing_target_without_creating_file() {
        let home = test_home("storage-rewrite-missing");
        fs::create_dir_all(&home).expect("home creates");
        let missing = home.join("missing-payload.msg");

        let error = rewrite_local_storage_payload_file(&missing, "new encrypted metadata\n")
            .expect_err("missing rewrite target fails closed");

        assert!(error.to_string().contains("missing"));
        assert!(!missing.exists());
    }

    #[test]
    fn storage_key_archive_keeps_old_payloads_readable_after_rotation() {
        let home = test_home("storage-archive-read");
        let paths = StatePaths::from_home(home);
        ensure_security_state_from_paths(&paths).expect("security state initializes");
        let encrypted = encrypt_for_storage_from_paths(&paths, b"private message contents", b"aad")
            .expect("encrypts");
        let old_key_id = encrypted.key_id.clone();

        let report = rotate_storage_key_from_paths(&paths).expect("storage key rotation succeeds");
        let decrypted =
            decrypt_from_storage_from_paths(&paths, &encrypted, b"aad").expect("decrypts");

        assert_eq!(report.files_migrated, 0);
        assert_ne!(report.new_storage_key_id, old_key_id);
        assert_eq!(decrypted, b"private message contents");
    }

    #[test]
    fn storage_key_rotation_migrates_older_archived_key_payloads() {
        let home = test_home("storage-older-archive-migration");
        let paths = StatePaths::from_home(home);
        ensure_security_state_from_paths(&paths).expect("security state initializes");
        fs::create_dir_all(&paths.message_ipc_inbox_dir).expect("message ipc inbox created");
        let aad = b"conu:message-request:v1:req.archive:agent.sender:agent.receiver".to_vec();
        let original = encrypt_for_storage_from_paths(&paths, b"private message contents", &aad)
            .expect("encrypts under original key");
        let request_path = paths.message_ipc_inbox_dir.join("req.archive.msg");
        fs::write(&request_path, render_test_request(&original)).expect("request writes");

        rotate_storage_key_from_paths(&paths).expect("first rotation succeeds");
        fs::write(&request_path, render_test_request(&original))
            .expect("stale archived-key request rewrites");
        let second = rotate_storage_key_from_paths(&paths).expect("second rotation succeeds");
        let request_after = fs::read_to_string(&request_path).expect("request reads");
        let values = parse_key_values(&request_after);
        let rotated = encrypted_payload_from_values(&values);

        assert_eq!(second.files_scanned, 1);
        assert_eq!(second.files_migrated, 1);
        assert_eq!(rotated.key_id, second.new_storage_key_id);
        assert_ne!(rotated.key_id, original.key_id);
        assert_eq!(
            decrypt_from_storage_from_paths(&paths, &rotated, &aad).expect("request decrypts"),
            b"private message contents"
        );
    }

    #[test]
    fn storage_key_retirement_removes_unused_archives_after_migration() {
        let home = test_home("storage-retire-unused");
        let paths = StatePaths::from_home(home);
        ensure_security_state_from_paths(&paths).expect("security state initializes");
        fs::create_dir_all(&paths.message_ipc_inbox_dir).expect("message ipc inbox created");
        let aad = b"conu:message-request:v1:req.archive:agent.sender:agent.receiver".to_vec();
        let original = encrypt_for_storage_from_paths(&paths, b"private message contents", &aad)
            .expect("encrypts under original key");
        let request_path = paths.message_ipc_inbox_dir.join("req.archive.msg");
        fs::write(&request_path, render_test_request(&original)).expect("request writes");

        let rotation = rotate_storage_key_from_paths(&paths).expect("rotation succeeds");
        let archive_path = paths
            .storage_key_archive_dir
            .join(format!("{}.key", rotation.old_storage_key_id));
        let retirement =
            retire_unused_storage_keys_from_paths(&paths).expect("retirement succeeds");
        let request_after = fs::read_to_string(&request_path).expect("request reads");
        let values = parse_key_values(&request_after);
        let rotated = encrypted_payload_from_values(&values);

        assert_eq!(retirement.archived_storage_keys_scanned, 1);
        assert_eq!(retirement.retired_storage_keys, 1);
        assert_eq!(retirement.retained_storage_keys, 0);
        assert_eq!(retirement.files_scanned, 1);
        assert_eq!(retirement.dependent_files, 0);
        assert!(!retirement.contents_displayed);
        assert!(!archive_path.exists());
        assert_eq!(
            decrypt_from_storage_from_paths(&paths, &rotated, &aad).expect("request decrypts"),
            b"private message contents"
        );
    }

    #[test]
    fn storage_key_retirement_retains_archives_with_dependencies() {
        let home = test_home("storage-retire-retain");
        let paths = StatePaths::from_home(home);
        ensure_security_state_from_paths(&paths).expect("security state initializes");
        fs::create_dir_all(&paths.message_ipc_inbox_dir).expect("message ipc inbox created");
        let aad = b"conu:message-request:v1:req.archive:agent.sender:agent.receiver".to_vec();
        let original = encrypt_for_storage_from_paths(&paths, b"private message contents", &aad)
            .expect("encrypts under original key");
        let request_path = paths.message_ipc_inbox_dir.join("req.archive.msg");
        fs::write(&request_path, render_test_request(&original)).expect("request writes");

        let rotation = rotate_storage_key_from_paths(&paths).expect("rotation succeeds");
        fs::write(&request_path, render_test_request(&original))
            .expect("stale archived-key request rewrites");
        let archive_path = paths
            .storage_key_archive_dir
            .join(format!("{}.key", rotation.old_storage_key_id));
        let retirement =
            retire_unused_storage_keys_from_paths(&paths).expect("retirement succeeds");

        assert_eq!(retirement.archived_storage_keys_scanned, 1);
        assert_eq!(retirement.retired_storage_keys, 0);
        assert_eq!(retirement.retained_storage_keys, 1);
        assert_eq!(retirement.files_scanned, 1);
        assert_eq!(retirement.dependent_files, 1);
        assert!(archive_path.exists());
        assert_eq!(
            decrypt_from_storage_from_paths(&paths, &original, &aad).expect("request decrypts"),
            b"private message contents"
        );
    }

    #[test]
    fn agent_card_signature_verifies_and_tampering_fails() {
        let home = test_home("signature");
        let paths = StatePaths::from_home(home);
        let canonical = "agent_id=agent.codex\nnode_id=node_test\ncap_messages=true\n";
        let signature = sign_agent_card_from_paths(&paths, canonical).expect("signs");

        assert!(
            verify_agent_card_signature(
                canonical,
                &signature.public_key_hex,
                &signature.signature_hex,
            )
            .expect("verifies")
        );
        assert!(
            !verify_agent_card_signature(
                "agent_id=agent.tampered\nnode_id=node_test\ncap_messages=true\n",
                &signature.public_key_hex,
                &signature.signature_hex,
            )
            .expect("tamper verifies false")
        );
    }

    #[test]
    fn replay_cache_rejects_duplicate_ids() {
        let home = test_home("replay");
        let paths = StatePaths::from_home(home);
        ensure_security_state_from_paths(&paths).expect("security state initializes");

        record_replay_id_from_paths(&paths, "request_123", "message_request")
            .expect("first id records");
        let duplicate = record_replay_id_from_paths(&paths, "request_123", "message_request")
            .expect_err("duplicate fails");

        assert!(matches!(duplicate, SecurityError::ReplayDetected { .. }));
    }

    #[cfg(unix)]
    #[test]
    fn replay_cache_rejects_symlink_without_writing_target() {
        use std::os::unix::fs::symlink;

        let home = test_home("replay-symlink");
        state::init_state(Some(home.clone())).expect("state initializes");
        let paths = StatePaths::from_home(home.clone());
        let outside = home.with_extension("outside-replay-cache");
        let outside_contents = "outside replay cache\n";
        fs::write(&outside, outside_contents).expect("outside replay cache writes");
        symlink(&outside, &paths.replay_cache).expect("replay cache symlink creates");

        let error = record_replay_id_from_paths(&paths, "request_456", "message_request")
            .expect_err("symlinked replay cache fails closed");

        assert!(error.to_string().contains("inspect replay cache"));
        assert_eq!(
            fs::read_to_string(&outside).expect("outside replay cache reads"),
            outside_contents
        );
        assert!(
            fs::symlink_metadata(&paths.replay_cache)
                .expect("replay cache metadata")
                .file_type()
                .is_symlink()
        );
    }

    #[test]
    fn peer_key_agreement_encrypts_between_two_nodes() {
        let alice_home = test_home("peer-alice");
        let bob_home = test_home("peer-bob");
        let alice = StatePaths::from_home(alice_home);
        let bob = StatePaths::from_home(bob_home);
        let alice_material = local_peer_key_material(&alice).expect("alice material");
        let bob_material = local_peer_key_material(&bob).expect("bob material");
        let context = b"conu test peer envelope";
        let alice_agreement = derive_peer_key_agreement_from_paths(
            &alice,
            &bob_material.local_exchange_public_key_hex,
            context,
        )
        .expect("alice derives");
        let bob_agreement = derive_peer_key_agreement_from_paths(
            &bob,
            &alice_material.local_exchange_public_key_hex,
            context,
        )
        .expect("bob derives");
        let encrypted = encrypt_for_peer_from_paths(
            &alice,
            &bob_material.local_exchange_public_key_hex,
            b"private message contents",
            context,
        )
        .expect("peer encrypts");
        let decrypted = decrypt_from_peer_from_paths(
            &bob,
            &alice_material.local_exchange_public_key_hex,
            &encrypted,
            context,
        )
        .expect("peer decrypts");

        assert_eq!(alice_agreement.key_id, bob_agreement.key_id);
        assert_eq!(decrypted, b"private message contents");
        assert!(
            !encrypted
                .ciphertext_hex
                .contains("private message contents")
        );
    }

    #[test]
    fn identity_key_rotation_archives_old_exchange_key_without_secret_output() {
        let alice_home = test_home("identity-rotation-alice");
        let bob_home = test_home("identity-rotation-bob");
        let alice = StatePaths::from_home(alice_home);
        let bob = StatePaths::from_home(bob_home);
        let alice_material_before = local_peer_key_material(&alice).expect("alice material");
        let bob_material = local_peer_key_material(&bob).expect("bob material");
        let context = b"conu test stale peer envelope";
        let encrypted_to_old_alice = encrypt_for_peer_from_paths(
            &bob,
            &alice_material_before.local_exchange_public_key_hex,
            b"private message contents",
            context,
        )
        .expect("peer encrypts to old alice key");
        let signing_before = read_identity_signing_key(&alice).expect("signing reads");
        let exchange_before = read_identity_exchange_key(&alice).expect("exchange reads");

        let report = rotate_identity_keys_from_paths(&alice).expect("identity rotates");
        let signing_after = read_identity_signing_key(&alice).expect("new signing reads");
        let exchange_after = read_identity_exchange_key(&alice).expect("new exchange reads");
        let decrypted = decrypt_from_peer_from_paths(
            &alice,
            &bob_material.local_exchange_public_key_hex,
            &encrypted_to_old_alice,
            context,
        )
        .expect("old-key peer envelope remains decryptable");
        let debug = format!("{report:?}");

        assert_eq!(report.old_signing_key_id, signing_before.key_id);
        assert_eq!(report.old_exchange_key_id, exchange_before.key_id);
        assert_eq!(report.new_signing_key_id, signing_after.key_id);
        assert_eq!(report.new_exchange_key_id, exchange_after.key_id);
        assert_ne!(report.old_signing_key_id, report.new_signing_key_id);
        assert_ne!(report.old_exchange_key_id, report.new_exchange_key_id);
        assert_eq!(report.archived_identity_keys, 2);
        assert!(report.peer_card_refresh_required);
        assert!(report.signed_agent_card_refresh_required);
        assert!(!report.contents_displayed);
        assert_eq!(decrypted, b"private message contents");
        assert!(!debug.contains(&hex_encode(&signing_before.secret_key)));
        assert!(!debug.contains(&hex_encode(&exchange_before.secret_key)));
        assert!(!debug.contains("private message contents"));
        assert!(
            identity_key_archive_dir(&alice)
                .join(format!("{}.signing.key", report.old_signing_key_id))
                .exists()
        );
        assert!(
            identity_key_archive_dir(&alice)
                .join(format!("{}.exchange.key", report.old_exchange_key_id))
                .exists()
        );
    }

    #[test]
    fn identity_key_retirement_removes_archives_after_refresh_confirmation() {
        let alice_home = test_home("identity-retirement-alice");
        let bob_home = test_home("identity-retirement-bob");
        let alice = StatePaths::from_home(alice_home);
        let bob = StatePaths::from_home(bob_home);
        let alice_material_before = local_peer_key_material(&alice).expect("alice material");
        let bob_material = local_peer_key_material(&bob).expect("bob material");
        let context = b"conu test retired identity archive";
        let encrypted_to_old_alice = encrypt_for_peer_from_paths(
            &bob,
            &alice_material_before.local_exchange_public_key_hex,
            b"private message contents",
            context,
        )
        .expect("peer encrypts to old alice key");
        let signing_before = read_identity_signing_key(&alice).expect("signing reads");
        let exchange_before = read_identity_exchange_key(&alice).expect("exchange reads");

        rotate_identity_keys_from_paths(&alice).expect("identity rotates");
        let alice_material_after = local_peer_key_material(&alice).expect("new alice material");
        let encrypted_to_new_alice = encrypt_for_peer_from_paths(
            &bob,
            &alice_material_after.local_exchange_public_key_hex,
            b"new private message contents",
            context,
        )
        .expect("peer encrypts to new alice key");
        let report = retire_archived_identity_keys_from_paths(&alice).expect("identity retires");
        let debug = format!("{report:?}");
        let old_decrypt = decrypt_from_peer_from_paths(
            &alice,
            &bob_material.local_exchange_public_key_hex,
            &encrypted_to_old_alice,
            context,
        );
        let new_decrypt = decrypt_from_peer_from_paths(
            &alice,
            &bob_material.local_exchange_public_key_hex,
            &encrypted_to_new_alice,
            context,
        )
        .expect("new-key peer envelope remains decryptable");

        assert_eq!(report.archived_identity_keys_scanned, 2);
        assert_eq!(report.retired_identity_keys, 2);
        assert_eq!(report.retained_identity_keys, 0);
        assert!(report.peer_card_refresh_confirmed);
        assert!(report.old_key_decrypt_compatibility_retired);
        assert!(!report.contents_displayed);
        assert!(old_decrypt.is_err());
        assert_eq!(new_decrypt, b"new private message contents");
        assert!(
            !identity_key_archive_dir(&alice)
                .join(format!("{}.signing.key", signing_before.key_id))
                .exists()
        );
        assert!(
            !identity_key_archive_dir(&alice)
                .join(format!("{}.exchange.key", exchange_before.key_id))
                .exists()
        );
        assert!(!debug.contains(&hex_encode(&signing_before.secret_key)));
        assert!(!debug.contains(&hex_encode(&exchange_before.secret_key)));
        assert!(!debug.contains("private message contents"));
    }

    fn encrypted_payload_from_values(values: &HashMap<String, String>) -> EncryptedPayload {
        EncryptedPayload {
            algorithm: values
                .get("payload_cipher")
                .expect("payload cipher")
                .to_string(),
            key_id: values
                .get("payload_key_id")
                .expect("payload key id")
                .to_string(),
            nonce_hex: values
                .get("payload_nonce_hex")
                .expect("payload nonce")
                .to_string(),
            ciphertext_hex: values
                .get("payload_ciphertext_hex")
                .expect("payload ciphertext")
                .to_string(),
            plaintext_len: values
                .get("payload_len")
                .expect("payload len")
                .parse()
                .expect("payload len parses"),
        }
    }

    fn render_test_request(encrypted: &EncryptedPayload) -> String {
        format!(
            "version = \"1\"\ntype = \"send_message\"\nrequest_id = \"req.archive\"\nfrom_agent_id = \"agent.sender\"\nto_agent_id = \"agent.receiver\"\npayload_len = 24\npayload_privacy = \"encrypted_at_rest\"\npayload_cipher = \"{}\"\npayload_key_id = \"{}\"\npayload_nonce_hex = \"{}\"\npayload_ciphertext_hex = \"{}\"\n",
            encrypted.algorithm, encrypted.key_id, encrypted.nonce_hex, encrypted.ciphertext_hex
        )
    }

    #[cfg(not(windows))]
    fn with_test_user_managed_wrap_key<T>(key: [u8; 32], test: impl FnOnce() -> T) -> T {
        TEST_USER_MANAGED_WRAP_KEY.with(|slot| {
            let previous = slot.replace(Some(key));
            let result = test();
            slot.replace(previous);
            result
        })
    }

    #[cfg(not(windows))]
    fn with_test_native_os_secret_store<T>(test: impl FnOnce() -> T) -> T {
        TEST_NATIVE_OS_SECRET_STORE.with(|slot| {
            let previous = slot.replace(Some(HashMap::new()));
            let result = test();
            slot.replace(previous);
            result
        })
    }

    #[cfg(not(windows))]
    fn with_test_native_os_secret_backend_disabled<T>(test: impl FnOnce() -> T) -> T {
        TEST_NATIVE_OS_SECRET_BACKEND_DISABLED.with(|slot| {
            let previous = slot.replace(true);
            let result = test();
            slot.replace(previous);
            result
        })
    }

    #[cfg(target_os = "macos")]
    fn native_test_backend_name() -> &'static str {
        SECRET_BACKEND_MACOS_KEYCHAIN
    }

    #[cfg(target_os = "linux")]
    fn native_test_backend_name() -> &'static str {
        SECRET_BACKEND_LINUX_SECRET_SERVICE
    }

    #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
    fn native_test_backend_name() -> &'static str {
        SECRET_BACKEND_FILESYSTEM
    }

    fn test_home(label: &str) -> PathBuf {
        env::temp_dir().join(format!(
            "conu-security-test-{label}-{}-{}",
            process::id(),
            current_unix_nanos()
        ))
    }
}
