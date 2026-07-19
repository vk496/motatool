//! Assemble a `.mota` container from a firmware image.
//!
//! Full images are 100% Rust. A **delta** (`--base`) diffs the base against the target with detools (see
//! [`crate::delta`] — a dev-only dependency until a pure-Rust encoder lands): the container is identical
//! except the payload is the detools patch, `codec_id` marks the patch type, and `base_hash` pins the
//! image the delta must be applied to.

use crate::crypto::{ed25519_public_from_seed, ed25519_sign, sha256};
use crate::encode::PatchType;
use crate::endf::{ensure_endf, has_endf, parse_ident, version_str};
use crate::format::*;
use crate::merkle;
use crate::targets;
use anyhow::{bail, Result};

pub struct BuildOpts {
    pub fw: Vec<u8>,
    pub base: Option<Vec<u8>>,
    pub patch_type: PatchType,   // delta layout; used iff base.is_some()
    pub inplace_memory: Option<u32>, // in-place apply window; None = auto from target ceiling + patch
    pub segment_size: u32,       // in-place segment; used iff patch_type == InPlace
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
    // Resolve identity: explicit flags win over the firmware's self-describing EndF trailer.
    let from_fw = parse_ident(&o.fw);
    let ident = FwIdent {
        fw_version: o.fw_version.unwrap_or(from_fw.fw_version),
        target_id: o.target_id.unwrap_or(from_fw.target_id),
        hw_id: o.hw_id.clone().unwrap_or(from_fw.hw_id),
    };

    // The target image (EndF-trailed) is what image_size/image_hash always describe.
    let (image, _body_hash) = ensure_endf(&o.fw, &ident);

    // Full: the payload IS the image. Delta: the payload is a detools patch base_image -> image, and
    // base_hash pins the running image it applies to (the device checks it against its EndF body_hash).
    let (codec, payload, base_hash) = match &o.base {
        None => (Codec::Full, image.clone(), [0u8; 8]),
        Some(base_fw) => build_delta(o, &ident, &image, base_fw)?,
    };
    let is_full = codec == Codec::Full;

    let leaves = merkle::leaf_hashes(&payload, o.block_size as usize);
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
    mf[off::FLAGS] = if is_full { MFLAG_FULL } else { 0 } | if signed { MFLAG_SIGNED } else { 0 };
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
    mf[off::BASE_HASH..off::BASE_HASH + 8].copy_from_slice(&base_hash); // zero for a full image
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
    bytes.extend_from_slice(&payload);
    bytes.extend_from_slice(&TRAILER);

    let manifest = Manifest::parse(&bytes)?; // our own output must parse
    let suggested_name = suggested_name(&ident, codec, &root);
    Ok(Built {
        bytes,
        suggested_name,
        manifest,
    })
}

/// Diff `base_fw` against the target `image` into a detools patch (the delta payload), returning the codec,
/// that patch, and the 8-byte `base_hash` the device matches against its running image's EndF body hash.
fn build_delta(
    o: &BuildOpts,
    ident: &FwIdent,
    image: &[u8],
    base_fw: &[u8],
) -> Result<(Codec, Vec<u8>, [u8; 8])> {
    // The delta must apply to the device's *actual* running image, which carries its own EndF trailer.
    // Requiring one here stops a silently-wrong patch built against a re-stamped base (it would fail the
    // on-device base_hash check anyway, but failing early is clearer).
    if !has_endf(base_fw) {
        bail!(
            "--base must be a real firmware image with its EndF trailer (the device's running image); \
             this one has none"
        );
    }
    let base_ident = parse_ident(base_fw);
    if !o.force && base_ident.hw_id != ident.hw_id {
        bail!(
            "base hardware {:?} != target hardware {:?}; a cross-hardware delta will not apply (use --force to override)",
            base_ident.hw_id,
            ident.hw_id
        );
    }
    let (base_image, base_hash) = ensure_endf(base_fw, &base_ident);

    // Both patch types are the pure-Rust encoder now — no detools/Python at runtime.
    let (codec, patch) = match o.patch_type {
        PatchType::Sequential => (
            Codec::DetoolsSequential,
            crate::encode::encode_sequential(&base_image, image),
        ),
        PatchType::InPlace => {
            if o.segment_size == 0 {
                bail!("in-place: --segment-size must be non-zero");
            }
            let stage_ceiling = targets::nrf52_stage_ceiling_for_target(ident.target_id);
            let memory_size = match o.inplace_memory {
                Some(m) => {
                    if m == 0 || m % o.segment_size != 0 {
                        bail!(
                            "in-place: --inplace-memory ({m}) must be a non-zero multiple of --segment-size ({})",
                            o.segment_size
                        );
                    }
                    m
                }
                None => compute_inplace_memory(
                    &base_image,
                    image,
                    stage_ceiling,
                    o.segment_size,
                    o.block_size,
                )?,
            };
            (
                Codec::DetoolsInplace,
                crate::encode::encode_in_place(
                    &base_image,
                    image,
                    memory_size,
                    o.segment_size,
                ),
            )
        }
    };
    Ok((codec, patch, base_hash))
}

/// Derive the in-place apply window from the target's staging ceiling and the patch size. Iterates
/// because mota_total ↔ patch bytes ↔ mota_addr ↔ memory_size are circular.
fn compute_inplace_memory(
    from: &[u8],
    to: &[u8],
    stage_ceiling: u32,
    segment_size: u32,
    block_size: u32,
) -> Result<u32> {
    let to_len = to.len() as u32;
    let max_memory = stage_ceiling - NRF52_APP_BASE;
    if to_len > max_memory {
        bail!(
            "target image {to_len} B exceeds max apply window {max_memory} B for ceiling 0x{stage_ceiling:X}"
        );
    }

    let est_patch = (from.len().max(to.len()) / 4 + 4096) as u32;
    let est_leaves = 64u32;
    let est_mota = (HEADER_LEN + MFL + est_leaves as usize * 4 + est_patch as usize + TRAILER_LEN) as u32;
    let mut memory = nrf52_align_down(
        nrf52_mota_stage_start(est_mota, stage_ceiling) - NRF52_APP_BASE,
        segment_size,
    );
    if memory == 0 {
        memory = segment_size;
    }

    for _ in 0..8 {
        if to_len > memory {
            bail!(
                "target image {to_len} B exceeds apply window {memory} B (ceiling 0x{stage_ceiling:X})"
            );
        }
        let patch = crate::encode::encode_in_place(from, to, memory, segment_size);
        let leaves = merkle::leaf_hashes(&patch, block_size as usize);
        let total = (HEADER_LEN + MFL + leaves.len() * 4 + patch.len() + TRAILER_LEN) as u32;
        let new_memory = nrf52_align_down(
            nrf52_mota_stage_start(total, stage_ceiling) - NRF52_APP_BASE,
            segment_size,
        );
        if new_memory == memory {
            return Ok(memory);
        }
        memory = new_memory.max(segment_size);
    }
    bail!("in-place memory_size did not converge for ceiling 0x{stage_ceiling:X}")
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
