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
use std::time::{SystemTime, UNIX_EPOCH};

use chacha20poly1305::aead::{Aead, AeadCore, KeyInit, OsRng, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

use crate::state::{StateError, StatePaths};

pub const STORAGE_ALGORITHM: &str = "XChaCha20Poly1305";
pub const AGENT_CARD_SIGNATURE_ALGORITHM: &str = "Ed25519";
pub const PEER_KEY_EXCHANGE_ALGORITHM: &str = "X25519+XChaCha20Poly1305";

const SECURITY_VERSION: &str = "1";
const NONCE_BYTES: usize = 24;

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
    fs::create_dir_all(&paths.security_dir).map_err(|error| {
        SecurityError::io("create security directory", &paths.security_dir, error)
    })?;

    let identity_signing_key_created = ensure_identity_signing_key(paths)?;
    let identity_exchange_key_created = ensure_identity_exchange_key(paths)?;
    let storage_key_created = ensure_storage_key(paths)?;
    let replay_cache_created = ensure_replay_cache(paths)?;
    let key_rotation_plan_created = ensure_key_rotation_plan(paths)?;

    let signing = read_identity_signing_key(paths)?;
    let exchange = read_identity_exchange_key(paths)?;
    let storage = read_storage_key(paths)?;

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
    })
}

/// Return a payload-safe audit snapshot.
pub fn security_audit(home_override: Option<PathBuf>) -> Result<SecurityAudit, SecurityError> {
    let paths = StatePaths::resolve(home_override)?;
    let identity_signing_key = key_file_is_readable(&paths.identity_signing_key);
    let identity_exchange_key = key_file_is_readable(&paths.identity_exchange_key);
    let storage_key = key_file_is_readable(&paths.storage_key);
    let replay_cache = paths.replay_cache.exists();
    let key_rotation_plan = paths.key_rotation_plan.exists();
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
        contents_displayed: false,
    })
}

/// Encrypt bytes for conU-owned local storage.
pub fn encrypt_for_storage_from_paths(
    paths: &StatePaths,
    plaintext: &[u8],
    aad: &[u8],
) -> Result<EncryptedPayload, SecurityError> {
    ensure_security_state_from_paths(paths)?;
    let key = read_storage_key(paths)?;
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
        key_id: key.key_id,
        nonce_hex: hex_encode(&nonce),
        ciphertext_hex: hex_encode(&ciphertext),
        plaintext_len: plaintext.len(),
    })
}

/// Decrypt bytes from conU-owned local storage.
pub fn decrypt_from_storage_from_paths(
    paths: &StatePaths,
    encrypted: &EncryptedPayload,
    aad: &[u8],
) -> Result<Vec<u8>, SecurityError> {
    let key = read_storage_key(paths)?;
    if encrypted.algorithm != STORAGE_ALGORITHM {
        return Err(SecurityError::InvalidPayload {
            reason: "unsupported storage cipher".to_string(),
        });
    }
    if encrypted.key_id != key.key_id {
        return Err(SecurityError::InvalidPayload {
            reason: "storage key id does not match local key".to_string(),
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

    let (key, key_id, _) = derive_peer_key(paths, sender_exchange_public_key_hex, aad)?;
    if encrypted.key_id != key_id {
        return Err(SecurityError::InvalidPayload {
            reason: "peer key id does not match derived key".to_string(),
        });
    }

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
    fs::create_dir_all(&paths.security_dir).map_err(|error| {
        SecurityError::io("create security directory", &paths.security_dir, error)
    })?;
    ensure_replay_cache(paths)?;

    let contents = fs::read_to_string(&paths.replay_cache)
        .map_err(|error| SecurityError::io("read replay cache", &paths.replay_cache, error))?;
    for line in contents.lines().map(str::trim) {
        if let Some(value) = line.strip_prefix("id = ") {
            if clean_value(value) == id {
                return Err(SecurityError::ReplayDetected { id: id.to_string() });
            }
        }
    }

    let mut file = OpenOptions::new()
        .append(true)
        .create(true)
        .open(&paths.replay_cache)
        .map_err(|error| SecurityError::io("open replay cache", &paths.replay_cache, error))?;
    writeln!(
        file,
        "\n[[seen]]\nid = \"{}\"\nsource = \"{}\"\nfirst_seen_unix = {}\n",
        escape_file_value(id),
        escape_file_value(source),
        current_unix_seconds()
    )
    .map_err(|error| SecurityError::io("write replay cache", &paths.replay_cache, error))
}

fn ensure_identity_signing_key(paths: &StatePaths) -> Result<bool, SecurityError> {
    if paths.identity_signing_key.exists() {
        return Ok(false);
    }

    let signing_key = SigningKey::generate(&mut OsRng);
    let public_key = signing_key.verifying_key().to_bytes();
    let secret_key = signing_key.to_bytes();
    let key_id = key_id("ed25519", &public_key);
    let contents = format!(
        "# conU node signing key\nversion = \"{}\"\nalgorithm = \"{}\"\nkey_id = \"{}\"\nsecret_key_hex = \"{}\"\npublic_key_hex = \"{}\"\ncreated_at_unix = {}\n",
        SECURITY_VERSION,
        AGENT_CARD_SIGNATURE_ALGORITHM,
        escape_file_value(&key_id),
        hex_encode(&secret_key),
        hex_encode(&public_key),
        current_unix_seconds()
    );
    write_new_secret_file(&paths.identity_signing_key, &contents)
}

fn ensure_identity_exchange_key(paths: &StatePaths) -> Result<bool, SecurityError> {
    if paths.identity_exchange_key.exists() {
        return Ok(false);
    }

    let secret = StaticSecret::random_from_rng(OsRng);
    let public = X25519PublicKey::from(&secret);
    let secret_key = secret.to_bytes();
    let public_key = public.to_bytes();
    let key_id = key_id("x25519", &public_key);
    let contents = format!(
        "# conU node X25519 exchange key\nversion = \"{}\"\nalgorithm = \"X25519\"\nkey_id = \"{}\"\nsecret_key_hex = \"{}\"\npublic_key_hex = \"{}\"\ncreated_at_unix = {}\n",
        SECURITY_VERSION,
        escape_file_value(&key_id),
        hex_encode(&secret_key),
        hex_encode(&public_key),
        current_unix_seconds()
    );
    write_new_secret_file(&paths.identity_exchange_key, &contents)
}

fn ensure_storage_key(paths: &StatePaths) -> Result<bool, SecurityError> {
    if paths.storage_key.exists() {
        return Ok(false);
    }

    let key = XChaCha20Poly1305::generate_key(&mut OsRng);
    let key_id = key_id("storage", &key);
    let contents = format!(
        "# conU local storage encryption key\nversion = \"{}\"\nalgorithm = \"{}\"\nkey_id = \"{}\"\nkey_hex = \"{}\"\ncreated_at_unix = {}\n",
        SECURITY_VERSION,
        STORAGE_ALGORITHM,
        escape_file_value(&key_id),
        hex_encode(&key),
        current_unix_seconds()
    );
    write_new_secret_file(&paths.storage_key, &contents)
}

fn ensure_replay_cache(paths: &StatePaths) -> Result<bool, SecurityError> {
    if paths.replay_cache.exists() {
        return Ok(false);
    }

    write_new_file(
        &paths.replay_cache,
        "# conU replay cache\nversion = \"1\"\n",
    )
}

fn ensure_key_rotation_plan(paths: &StatePaths) -> Result<bool, SecurityError> {
    if paths.key_rotation_plan.exists() {
        return Ok(false);
    }

    write_new_file(&paths.key_rotation_plan, key_rotation_plan_contents())
}

fn read_identity_signing_key(paths: &StatePaths) -> Result<SigningKeyRecord, SecurityError> {
    let values = read_key_values(&paths.identity_signing_key)?;
    if required(&values, "algorithm", &paths.identity_signing_key)?
        != AGENT_CARD_SIGNATURE_ALGORITHM
    {
        return Err(SecurityError::InvalidKey {
            path: paths.identity_signing_key.clone(),
            reason: "expected Ed25519 signing key".to_string(),
        });
    }
    let secret_key = key_bytes::<32>(&values, "secret_key_hex", &paths.identity_signing_key)?;
    let public_key = key_bytes::<32>(&values, "public_key_hex", &paths.identity_signing_key)?;
    let signing_key = SigningKey::from_bytes(&secret_key);
    if signing_key.verifying_key().to_bytes() != public_key {
        return Err(SecurityError::InvalidKey {
            path: paths.identity_signing_key.clone(),
            reason: "public key does not match signing key".to_string(),
        });
    }

    Ok(SigningKeyRecord {
        key_id: required(&values, "key_id", &paths.identity_signing_key)?,
        secret_key,
        public_key,
    })
}

fn read_identity_exchange_key(paths: &StatePaths) -> Result<ExchangeKeyRecord, SecurityError> {
    let values = read_key_values(&paths.identity_exchange_key)?;
    if required(&values, "algorithm", &paths.identity_exchange_key)? != "X25519" {
        return Err(SecurityError::InvalidKey {
            path: paths.identity_exchange_key.clone(),
            reason: "expected X25519 exchange key".to_string(),
        });
    }
    let secret_key = key_bytes::<32>(&values, "secret_key_hex", &paths.identity_exchange_key)?;
    let public_key = key_bytes::<32>(&values, "public_key_hex", &paths.identity_exchange_key)?;
    let secret = StaticSecret::from(secret_key);
    if X25519PublicKey::from(&secret).to_bytes() != public_key {
        return Err(SecurityError::InvalidKey {
            path: paths.identity_exchange_key.clone(),
            reason: "public key does not match exchange key".to_string(),
        });
    }

    Ok(ExchangeKeyRecord {
        key_id: required(&values, "key_id", &paths.identity_exchange_key)?,
        secret_key,
        public_key,
    })
}

fn read_storage_key(paths: &StatePaths) -> Result<StorageKeyRecord, SecurityError> {
    let values = read_key_values(&paths.storage_key)?;
    if required(&values, "algorithm", &paths.storage_key)? != STORAGE_ALGORITHM {
        return Err(SecurityError::InvalidKey {
            path: paths.storage_key.clone(),
            reason: "expected XChaCha20Poly1305 storage key".to_string(),
        });
    }

    Ok(StorageKeyRecord {
        key_id: required(&values, "key_id", &paths.storage_key)?,
        key: key_bytes::<32>(&values, "key_hex", &paths.storage_key)?,
    })
}

fn derive_peer_key(
    paths: &StatePaths,
    remote_exchange_public_key_hex: &str,
    context: &[u8],
) -> Result<([u8; 32], String, String), SecurityError> {
    ensure_security_state_from_paths(paths)?;
    let local = read_identity_exchange_key(paths)?;
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
    path.exists() && fs::read_to_string(path).is_ok()
}

fn read_key_values(path: &Path) -> Result<HashMap<String, String>, SecurityError> {
    let contents = fs::read_to_string(path)
        .map_err(|error| SecurityError::io("read security key", path, error))?;
    Ok(parse_key_values(&contents))
}

fn key_bytes<const N: usize>(
    values: &HashMap<String, String>,
    field: &'static str,
    path: &Path,
) -> Result<[u8; N], SecurityError> {
    let value = required(values, field, path)?;
    hex_decode_exact::<N>(&value).map_err(|reason| SecurityError::InvalidKey {
        path: path.to_path_buf(),
        reason,
    })
}

fn required(
    values: &HashMap<String, String>,
    key: &'static str,
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
    let created = write_new_file(path, contents)?;
    set_sensitive_file_permissions(path)?;
    Ok(created)
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
fn set_sensitive_file_permissions(path: &Path) -> Result<(), SecurityError> {
    use std::os::unix::fs::PermissionsExt;

    let permissions = fs::Permissions::from_mode(0o600);
    fs::set_permissions(path, permissions)
        .map_err(|error| SecurityError::io("set security file permissions", path, error))
}

#[cfg(not(unix))]
fn set_sensitive_file_permissions(_path: &Path) -> Result<(), SecurityError> {
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
1. Create a new key beside the active key and mark the new key id as active.\n\
2. Keep old public signing and exchange keys available until trusted peers refresh cards.\n\
3. Re-encrypt encrypted-at-rest message and mailbox files with the new storage key before removing the old storage key.\n\
4. Reject revoked peer keys during discovery, message delivery, and stream setup.\n\
5. Never print private keys, shared secrets, plaintext payloads, or decrypted payloads in CLI, logs, telemetry, docs, or tests.\n\n\
Production hardening still needs OS keychain/HSM integration and automated multi-key migration before a public release.\n"
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
        assert!(signing.contains("secret_key_hex"));
        assert!(!signing.contains("private message contents"));
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

    fn test_home(label: &str) -> PathBuf {
        env::temp_dir().join(format!(
            "conu-security-test-{label}-{}-{}",
            process::id(),
            current_unix_nanos()
        ))
    }
}
