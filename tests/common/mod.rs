//! Dev/test-only **detools oracle** — the independent reference the pure-Rust encoder is proven against.
//!
//! This is NOT part of the shipped `motatool` binary (the tool needs no detools at runtime). It shells out
//! to the pinned `third_party/detools` (built by `make dev-setup`) via the embedded Python shim, to:
//!
//! * decode our patches with the real detools decoder (the on-device counterpart) — [`apply`],
//! * produce detools' own reference patch for cross-checking — [`encode`],
//! * decompress our crle output — [`crle_decompress`].
//!
//! Tests call [`available`] first and skip cleanly when detools isn't set up.

#![allow(dead_code)] // not every integration-test crate uses every helper

use motatool::PatchType;
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

const SHIM_SRC: &str = include_str!("../../scripts/detools_shim.py");

fn ptype_arg(p: PatchType) -> &'static str {
    match p {
        PatchType::Sequential => "sequential",
        PatchType::InPlace => "in-place",
    }
}

/// True when the pinned detools can run (shim imports it). Gate every oracle-backed test on this.
pub fn available() -> bool {
    run_shim(&["--detools-version".into()]).is_ok()
}

/// Decode `patch` against `base` with the REAL detools decoder; returns the reconstructed target.
pub fn apply(
    base: &[u8],
    patch: &[u8],
    ptype: PatchType,
    memory_size: u32,
    to_size: u32,
) -> Vec<u8> {
    let dir = scratch();
    let (base_f, patch_f, out_f) = (dir.join("base"), dir.join("patch"), dir.join("out"));
    std::fs::write(&base_f, base).unwrap();
    std::fs::write(&patch_f, patch).unwrap();
    let mut args = vec![
        "apply".into(),
        p(&base_f),
        p(&patch_f),
        p(&out_f),
        "--patch-type".into(),
        ptype_arg(ptype).into(),
    ];
    if ptype == PatchType::InPlace {
        args.extend([
            "--memory-size".into(),
            memory_size.to_string(),
            "--to-size".into(),
            to_size.to_string(),
        ]);
    }
    run_shim(&args).expect("detools apply");
    let out = std::fs::read(&out_f).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    out
}

/// Produce detools' OWN reference patch for `base -> target` (for apply-equivalence cross-checks).
pub fn encode(
    base: &[u8],
    target: &[u8],
    ptype: PatchType,
    memory_size: u32,
    segment_size: u32,
) -> Vec<u8> {
    let dir = scratch();
    let (base_f, new_f, out_f) = (dir.join("base"), dir.join("new"), dir.join("patch"));
    std::fs::write(&base_f, base).unwrap();
    std::fs::write(&new_f, target).unwrap();
    let mut args = vec![
        "encode".into(),
        p(&base_f),
        p(&new_f),
        p(&out_f),
        "--patch-type".into(),
        ptype_arg(ptype).into(),
        "--compression".into(),
        "crle".into(),
    ];
    if ptype == PatchType::InPlace {
        args.extend([
            "--memory-size".into(),
            memory_size.to_string(),
            "--segment-size".into(),
            segment_size.to_string(),
        ]);
    }
    run_shim(&args).expect("detools encode");
    let out = std::fs::read(&out_f).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    out
}

/// Decompress a crle stream with the real detools decompressor (`size` = expected output length).
pub fn crle_decompress(data: &[u8], size: usize) -> Vec<u8> {
    let dir = scratch();
    let (in_f, out_f) = (dir.join("in"), dir.join("out"));
    std::fs::write(&in_f, data).unwrap();
    run_shim(&[
        "crle-decompress".into(),
        p(&in_f),
        p(&out_f),
        "--size".into(),
        size.to_string(),
    ])
    .expect("detools crle-decompress");
    let out = std::fs::read(&out_f).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    out
}

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

fn run_shim(args: &[String]) -> Result<(), String> {
    let dir = scratch();
    let shim = dir.join("detools_shim.py");
    std::fs::File::create(&shim)
        .and_then(|mut f| f.write_all(SHIM_SRC.as_bytes()))
        .map_err(|e| e.to_string())?;
    let out = Command::new(detools_python())
        .arg(&shim)
        .args(args)
        .output()
        .map_err(|e| e.to_string())?;
    let _ = std::fs::remove_dir_all(&dir);
    if out.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
    }
}

static SEQ: AtomicU64 = AtomicU64::new(0);

fn scratch() -> PathBuf {
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    let d = std::env::temp_dir().join(format!("motatool-oracle-{}-{}", std::process::id(), n));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn p(path: &std::path::Path) -> String {
    path.to_string_lossy().into_owned()
}
