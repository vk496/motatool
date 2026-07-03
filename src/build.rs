//! Assemble a `.mota` container from a firmware image.
//!
//! Phase 1 builds **full images** only. Delta encoding (`--base`) needs the detools encoder and is a
//! separate, deferred piece — [`build`] returns a clear error for now rather than producing a bad container.

use crate::crypto::{ed25519_public_from_seed, ed25519_sign, sha256};
use crate::endf::{ensure_endf, parse_ident, version_str};
use crate::format::*;
use crate::merkle;
use anyhow::{bail, Result};

pub struct BuildOpts {
    pub fw: Vec<u8>,
    pub base: Option<Vec<u8>>,
    pub target_id: Option<u32>,  // overrides the EndF identity
    pub fw_version: Option<u32>, // overrides the EndF identity
    pub hw_id: Option<String>,   // overrides the EndF identity
    pub sign_seed: Option<[u8; 32]>,
    pub block_size: u32,
    pub force: bool,
}

pub struct Built {
    pub bytes: Vec<u8>,
    pub suggested_name: String,
    pub manifest: Manifest,
}

pub fn build(o: &BuildOpts) -> Result<Built> {
    if o.base.is_some() {
        bail!("delta builds (--base) are not supported yet — full-image builds only");
    }
    let _ = o.force; // (only meaningful for the deferred cross-hardware delta guard)

    // Resolve identity: explicit flags win over the firmware's self-describing EndF trailer.
    let from_fw = parse_ident(&o.fw);
    let ident = FwIdent {
        fw_version: o.fw_version.unwrap_or(from_fw.fw_version),
        target_id: o.target_id.unwrap_or(from_fw.target_id),
        hw_id: o.hw_id.clone().unwrap_or(from_fw.hw_id),
    };

    let (image, _body_hash) = ensure_endf(&o.fw, &ident);
    let payload = &image; // full image: the payload IS the (EndF-trailed) image
    let codec = Codec::Full;

    let leaves = merkle::leaf_hashes(payload, o.block_size as usize);
    let block_count = leaves.len();
    if !(1..=0xFFFF).contains(&block_count) {
        bail!("payload yields an invalid block count ({block_count})");
    }
    let root = merkle::root(&leaves);
    let image_hash = sha256(&image);
    let signed = o.sign_seed.is_some();

    // ---- assemble the fixed 197-byte manifest ----
    let mut mf = [0u8; MFL];
    mf[off::FORMAT_VER] = FORMAT_VER;
    mf[off::FLAGS] = MFLAG_FULL | if signed { MFLAG_SIGNED } else { 0 };
    mf[off::HASH_ALGO] = HASH_ALGO_SHA256;
    wr_u32(&mut mf, off::TARGET_ID, ident.target_id);
    wr_u32(&mut mf, off::FW_VERSION, ident.fw_version);
    wr_u32(&mut mf, off::IMAGE_SIZE, image.len() as u32);
    wr_u32(&mut mf, off::PAYLOAD_SIZE, payload.len() as u32);
    mf[off::BLOCK_SIZE_LOG2] = block_size_log2(o.block_size);
    mf[off::MERKLE_ROOT..off::MERKLE_ROOT + 4].copy_from_slice(&root);
    mf[off::IMAGE_HASH..off::IMAGE_HASH + 32].copy_from_slice(&image_hash);
    mf[off::CODEC_ID] = codec as u8;
    let hw = ident.hw_id.as_bytes();
    mf[off::HW_ID..off::HW_ID + hw.len().min(HW_ID_LEN)]
        .copy_from_slice(&hw[..hw.len().min(HW_ID_LEN)]);
    // base_hash stays zero for a full image.
    if let Some(seed) = &o.sign_seed {
        mf[off::SIGNER..off::SIGNER + 32].copy_from_slice(&ed25519_public_from_seed(seed));
        let sig = ed25519_sign(seed, &mf[..SIGNED_LEN]);
        mf[off::SIGNATURE..off::SIGNATURE + 64].copy_from_slice(&sig);
    }
    mf[off::APPROVAL..off::APPROVAL + 4].copy_from_slice(&APPROVAL_NONE);

    // ---- container = MAGIC ‖ total(4) ‖ manifest ‖ leaves[] ‖ payload ‖ TRAILER ----
    let leaves_bytes: Vec<u8> = leaves.into_iter().flatten().collect();
    let total = HEADER_LEN + MFL + leaves_bytes.len() + payload.len() + TRAILER_LEN;
    let mut bytes = Vec::with_capacity(total);
    bytes.extend_from_slice(&MAGIC);
    bytes.extend_from_slice(&(total as u32).to_le_bytes());
    bytes.extend_from_slice(&mf);
    bytes.extend_from_slice(&leaves_bytes);
    bytes.extend_from_slice(payload);
    bytes.extend_from_slice(&TRAILER);

    let manifest = Manifest::parse(&bytes)?; // our own output must parse
    let suggested_name = suggested_name(&ident, codec, &root);
    Ok(Built {
        bytes,
        suggested_name,
        manifest,
    })
}

/// log2 of a power-of-two block size (1024 → 10).
fn block_size_log2(bs: u32) -> u8 {
    (u32::BITS - 1 - bs.max(1).leading_zeros()) as u8
}

/// `<hw|fw>_<target8>_v<version>_<full|seqdelta|ipdelta>_<mid8>.mota`
fn suggested_name(ident: &FwIdent, codec: Codec, root: &[u8; 4]) -> String {
    let hw = if ident.hw_id.is_empty() {
        "fw"
    } else {
        ident.hw_id.as_str()
    };
    format!(
        "{hw}_{:08X}_v{}_{}_{}.mota",
        ident.target_id,
        version_str(ident.fw_version),
        codec.name_tag(),
        hex::encode_upper(root)
    )
}
