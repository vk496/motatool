//! Delta-patch generation — **option B** (a development/test dependency, never shipped).
//!
//! motatool's full-image path is 100% Rust. For deltas (`build --base`) it currently shells out to the
//! pinned `third_party/detools` submodule through an embedded Python shim to produce a byte-compatible
//! detools patch (`--codec sequential|in-place --compression crle`) — the on-device vendored detools **C
//! decoder** is the counterpart that applies it. A future pure-Rust encoder replaces [`encode_patch`] with
//! no `.mota` format change; [`apply_patch`] (the real detools decoder) stays as the apply-equivalence
//! oracle the tests hold it to.
//!
//! Nothing here is reachable from the full-image build/verify/inspect/serve paths, so a user who never
//! builds a delta needs no Python or detools at all.

use anyhow::{bail, Context, Result};
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

/// The one and only place motatool touches detools. Embedded so the delta path needs only a Python with
/// the pinned detools installed (see the Makefile `dev-setup` target) — not the repo checkout at runtime.
const SHIM_SRC: &str = include_str!("../scripts/detools_shim.py");

/// detools patch layout. `Sequential` decodes into a fresh buffer (ESP32 A/B slot); `InPlace` reconstructs
/// within a bounded window that starts holding the base (nRF52 single-slot, bootloader-applied).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PatchType {
    Sequential,
    InPlace,
}

impl PatchType {
    fn cli(self) -> &'static str {
        match self {
            PatchType::Sequential => "sequential",
            PatchType::InPlace => "in-place",
        }
    }
}

/// In-place apply window. Must match the device's bootloader layout (nRF52: memory 0x98000, one flash page
/// per segment) — the patch header carries these and the bootloader bounds its writes to them.
#[derive(Clone, Copy, Debug)]
pub struct InPlaceParams {
    pub memory_size: u32,
    pub segment_size: u32,
}

/// Produce a detools patch that turns `base_image` into `target_image` (both the full EndF-trailed images
/// exactly as they live in flash). `crle`-compressed, matching the device decoder's compile-time config.
pub fn encode_patch(
    base_image: &[u8],
    target_image: &[u8],
    ptype: PatchType,
    ip: Option<InPlaceParams>,
) -> Result<Vec<u8>> {
    let dir = scratch()?;
    let base_f = dir.join("base.bin");
    let new_f = dir.join("new.bin");
    let out_f = dir.join("out.patch");
    std::fs::write(&base_f, base_image)?;
    std::fs::write(&new_f, target_image)?;

    let (mem, seg);
    let mut args: Vec<String> = vec![
        "encode".into(),
        path(&base_f),
        path(&new_f),
        path(&out_f),
        "--patch-type".into(),
        ptype.cli().into(),
        "--compression".into(),
        "crle".into(),
    ];
    if ptype == PatchType::InPlace {
        let p = ip.context("in-place patch requires memory/segment sizes")?;
        mem = p.memory_size.to_string();
        seg = p.segment_size.to_string();
        args.extend(["--memory-size".into(), mem, "--segment-size".into(), seg]);
    }

    run_shim(&args)?;
    let patch = std::fs::read(&out_f).with_context(|| "detools produced no patch")?;
    let _ = std::fs::remove_dir_all(&dir);
    Ok(patch)
}

/// Apply `patch` to `base_image` with the **real** detools decoder and return the reconstructed target.
/// This is the test oracle (and could back a `--verify-apply` self-check): a Rust-produced patch is correct
/// iff `apply_patch(base, ours) == apply_patch(base, detools) == target`, byte for byte.
pub fn apply_patch(
    base_image: &[u8],
    patch: &[u8],
    ptype: PatchType,
    memory_size: u32,
    to_size: u32,
) -> Result<Vec<u8>> {
    let dir = scratch()?;
    let base_f = dir.join("base.bin");
    let patch_f = dir.join("in.patch");
    let out_f = dir.join("out.bin");
    std::fs::write(&base_f, base_image)?;
    std::fs::write(&patch_f, patch)?;

    let mut args: Vec<String> = vec![
        "apply".into(),
        path(&base_f),
        path(&patch_f),
        path(&out_f),
        "--patch-type".into(),
        ptype.cli().into(),
    ];
    if ptype == PatchType::InPlace {
        args.extend([
            "--memory-size".into(),
            memory_size.to_string(),
            "--to-size".into(),
            to_size.to_string(),
        ]);
    }

    run_shim(&args)?;
    let out = std::fs::read(&out_f).with_context(|| "detools apply produced no output")?;
    let _ = std::fs::remove_dir_all(&dir);
    Ok(out)
}

/// Whether the dev-only detools backend can run right now (the shim imports detools successfully). Lets
/// tests exercise the real encode/apply where it's set up and skip cleanly on a bare checkout.
pub fn available() -> bool {
    run_shim(&["--detools-version".into()]).is_ok()
}

/// The Python that has the pinned detools installed. Override with `$MOTATOOL_DETOOLS_PYTHON`; defaults to
/// the repo dev venv if present, else `python3`.
fn detools_python() -> String {
    if let Ok(p) = std::env::var("MOTATOOL_DETOOLS_PYTHON") {
        return p;
    }
    let venv = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(".venv/bin/python");
    if venv.exists() {
        return venv.to_string_lossy().into_owned();
    }
    "python3".into()
}

fn run_shim(args: &[String]) -> Result<()> {
    let dir = scratch()?;
    let shim = dir.join("detools_shim.py");
    std::fs::File::create(&shim)?.write_all(SHIM_SRC.as_bytes())?;

    let py = detools_python();
    let out = Command::new(&py)
        .arg(&shim)
        .args(args)
        .output()
        .with_context(|| {
            format!(
                "cannot run the detools shim with `{py}`. Delta builds need the pinned detools \
                 (dev-only): run `make dev-setup`, or set $MOTATOOL_DETOOLS_PYTHON to a Python that \
                 has detools 0.53.0 installed."
            )
        })?;
    let _ = std::fs::remove_dir_all(&dir);
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        bail!("detools shim failed:\n{}", stderr.trim());
    }
    Ok(())
}

static SEQ: AtomicU64 = AtomicU64::new(0);

/// A fresh, unique scratch dir (safe under parallel `cargo test`).
fn scratch() -> Result<PathBuf> {
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    let d = std::env::temp_dir().join(format!("motatool-delta-{}-{}", std::process::id(), n));
    std::fs::create_dir_all(&d).with_context(|| format!("cannot create scratch dir {d:?}"))?;
    Ok(d)
}

fn path(p: &std::path::Path) -> String {
    p.to_string_lossy().into_owned()
}
