//! Hashing and signatures used by the `.mota` format.
//!
//! MeshCore uses **truncated SHA-256** everywhere it needs a short digest (`sha2-256:N` = the first `N`
//! bytes of the SHA-256 of the data) and **Ed25519** (RFC 8032) for optional container signing. Ed25519 is
//! deterministic, so signatures produced here are byte-identical to the firmware's / the previous OpenSSL
//! implementation for the same key and message.

use anyhow::{bail, Context, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

/// First `N` bytes of `SHA-256(data)` (`sha2-256:N`). `N` must be ≤ 32.
pub fn mh<const N: usize>(data: &[u8]) -> [u8; N] {
    const {
        assert!(N <= 32, "SHA-256 truncation length must be <= 32");
    }
    let digest = Sha256::digest(data);
    let mut out = [0u8; N];
    out.copy_from_slice(&digest[..N]);
    out
}

/// `sha2-256:32` — the full digest (image hash).
pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// Sign `msg` with a 32-byte Ed25519 seed (raw private key), returning the 64-byte signature.
pub fn ed25519_sign(seed: &[u8; 32], msg: &[u8]) -> [u8; 64] {
    SigningKey::from_bytes(seed).sign(msg).to_bytes()
}

/// Verify a 64-byte Ed25519 signature over `msg` against a 32-byte public key.
pub fn ed25519_verify(public_key: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> bool {
    let Ok(vk) = VerifyingKey::from_bytes(public_key) else {
        return false;
    };
    vk.verify(msg, &Signature::from_bytes(sig)).is_ok()
}

/// Derive the 32-byte Ed25519 public key from a 32-byte seed.
pub fn ed25519_public_from_seed(seed: &[u8; 32]) -> [u8; 32] {
    SigningKey::from_bytes(seed).verifying_key().to_bytes()
}

/// Generate a fresh Ed25519 keypair as `(seed, public_key)`, each 32 bytes.
pub fn ed25519_keygen() -> ([u8; 32], [u8; 32]) {
    let sk = SigningKey::generate(&mut rand_core::OsRng);
    (sk.to_bytes(), sk.verifying_key().to_bytes())
}

/// Load a 32-byte Ed25519 key from a file that holds either 64 hex chars (the `keygen` format) or 32 raw
/// bytes. Used for both `--sign <priv>` and `--pub <pub>`.
pub fn load_key32(path: &str) -> Result<[u8; 32]> {
    let raw = std::fs::read(path).with_context(|| format!("cannot read key file {path}"))?;
    if let Ok(text) = std::str::from_utf8(&raw) {
        if let Ok(bytes) = hex::decode(text.trim()) {
            if let Ok(key) = <[u8; 32]>::try_from(bytes.as_slice()) {
                return Ok(key);
            }
        }
    }
    <[u8; 32]>::try_from(raw.as_slice())
        .map_err(|_| ())
        .or_else(|_| bail!("key must be 64 hex chars or 32 raw bytes: {path}"))
}
