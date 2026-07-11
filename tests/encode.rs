//! Correctness sweep for the pure-Rust encoders (`src/encode.rs`), both patch types.
//!
//! For firmware OTA a single wrong bit corrupts the device, so every generated patch is decoded with the
//! **real detools decoder** ([`common`]) and its output is hash-compared to the exact bytes we asked to
//! reconstruct. Inputs are DETERMINISTIC (seeded PRNG + fixed edit scripts across many lengths), so a
//! failure is reproducible. We also cross-check against detools' OWN patch: our decode and detools' decode
//! must hash equal (apply-equivalence, the on-device contract). Gated on the dev detools oracle; skips
//! cleanly without it (the pure-Rust `build --base` path itself needs no detools).

mod common;

use motatool::crypto::sha256;
use motatool::{encode, PatchType};

/// Deterministic byte stream (SplitMix64) — reproducible across runs and machines.
fn prng(seed: u64, n: usize) -> Vec<u8> {
    let mut z = seed;
    (0..n)
        .map(|_| {
            z = z.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut x = z;
            x = (x ^ (x >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            x = (x ^ (x >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            (x ^ (x >> 31)) as u8
        })
        .collect()
}

/// (name, base, target) cases: identical, scattered edits, insert/delete/append/prepend, truncate/grow,
/// wholly different, empty edges, and a run-heavy image (exercises crle REPEATED). Lengths span 0..~20k.
fn cases() -> Vec<(String, Vec<u8>, Vec<u8>)> {
    let mut v: Vec<(String, Vec<u8>, Vec<u8>)> = Vec::new();

    for n in [0usize, 1, 2, 3, 7, 15, 64] {
        let b = prng(1000 + n as u64, n);
        v.push((format!("identical/{n}"), b.clone(), b.clone()));
        let mut t = b.clone();
        if !t.is_empty() {
            t[n / 2] ^= 0xFF;
        }
        v.push((format!("one-flip/{n}"), b, t));
    }

    for &n in &[256usize, 1000, 4096, 20000] {
        let base = prng(42 + n as u64, n);

        let mut t = base.clone();
        for k in [0usize, 3, 4, n / 3, n / 2, n - 1] {
            t[k] ^= 0x5A;
        }
        v.push((format!("scattered/{n}"), base.clone(), t));

        let mut t = base.clone();
        t.extend(prng(7, n / 10));
        v.push((format!("append/{n}"), base.clone(), t));

        let mut t = prng(9, n / 10);
        t.extend_from_slice(&base);
        v.push((format!("prepend/{n}"), base.clone(), t));

        let mut t = base[..n / 4].to_vec();
        t.extend_from_slice(&base[n / 2..]);
        v.push((format!("delete-mid/{n}"), base.clone(), t));

        v.push((
            format!("truncate/{n}"),
            base.clone(),
            base[..n / 2].to_vec(),
        ));
        let mut t = base.clone();
        t.extend(prng(11, n / 2));
        v.push((format!("grow/{n}"), base.clone(), t));

        v.push((
            format!("different/{n}"),
            base.clone(),
            prng(999 + n as u64, n),
        ));

        v.push((format!("base-empty/{n}"), Vec::new(), base.clone()));
        v.push((format!("target-empty/{n}"), base.clone(), Vec::new()));
    }

    // run-heavy target (many >=6 identical byte runs) to stress crle REPEATED segments end-to-end
    let base = prng(5, 3000);
    let mut t = base.clone();
    for (i, chunk) in t.chunks_mut(50).enumerate() {
        if i % 2 == 0 {
            chunk.fill(0x00);
        }
    }
    v.push(("run-heavy/3000".into(), base, t));

    v
}

/// The core assertion for one case + patch type: our patch and detools' patch, decoded by the real detools
/// decoder, both reconstruct `target` byte-for-byte (via hashes). `mem`/`seg` are unused for sequential.
fn assert_case(name: &str, base: &[u8], target: &[u8], ptype: PatchType, mem: u32, seg: u32) {
    let patch = match ptype {
        PatchType::Sequential => encode::encode_sequential(base, target),
        PatchType::InPlace => encode::encode_in_place(base, target, mem, seg),
    };

    // Deterministic: identical inputs must yield identical bytes (no nondeterminism/races).
    let patch2 = match ptype {
        PatchType::Sequential => encode::encode_sequential(base, target),
        PatchType::InPlace => encode::encode_in_place(base, target, mem, seg),
    };
    assert_eq!(patch, patch2, "[{name}] encoder is not deterministic");

    // THE guarantee: real detools rebuilds `target` from `base` + our patch, byte-for-byte.
    let decoded = common::apply(base, &patch, ptype, mem, target.len() as u32);
    assert_eq!(
        sha256(&decoded),
        sha256(target),
        "[{name}] decoded hash != target (len {} vs {})",
        decoded.len(),
        target.len()
    );

    // Apply-equivalence vs detools' OWN patch: both decode to the same bytes.
    let dt = common::encode(base, target, ptype, mem, seg);
    let decoded_dt = common::apply(base, &dt, ptype, mem, target.len() as u32);
    assert_eq!(
        sha256(&decoded),
        sha256(&decoded_dt),
        "[{name}] our patch and detools' patch decode differently"
    );
}

/// A memory window that always yields a valid in-place patch for a case (base + target fit without overlap,
/// so no segment ever clobbers base bytes a later one needs). Multiple of `seg`. Tight-memory (real device)
/// is exercised separately by `in_place_realistic_device_window`.
fn generous_mem(from: usize, to: usize, seg: usize) -> u32 {
    (((from + to).div_ceil(seg)) + 2) as u32 * seg as u32
}

#[test]
fn sequential_encoder_reconstructs_every_case() {
    if !common::available() {
        eprintln!("SKIP: detools backend unavailable (run `make dev-setup`)");
        return;
    }
    for (name, base, target) in cases() {
        assert_case(&name, &base, &target, PatchType::Sequential, 0, 0);
    }
}

#[test]
fn in_place_encoder_reconstructs_every_case() {
    if !common::available() {
        eprintln!("SKIP: detools backend unavailable");
        return;
    }
    let seg = 256usize;
    for (name, base, target) in cases() {
        let mem = generous_mem(base.len(), target.len(), seg);
        assert_case(&name, &base, &target, PatchType::InPlace, mem, seg as u32);
    }
}

#[test]
fn in_place_realistic_device_window() {
    // Real nRF52 params: memory 0x98000, one flash page per segment, a ~500 KB image with a small delta —
    // tight memory where the shift/overlap logic actually matters, reconstructed byte-exact by detools.
    if !common::available() {
        eprintln!("SKIP: detools backend unavailable");
        return;
    }
    let base = prng(2024, 500_000);
    let mut target = base.clone();
    for k in (0..base.len()).step_by(9000) {
        target[k] ^= 0x5A; // ~55 scattered edits (version-bump scale)
    }
    target.extend(prng(3, 400));
    assert_case(
        "realistic-inplace",
        &base,
        &target,
        PatchType::InPlace,
        0x98000,
        4096,
    );
}

#[test]
fn crle_output_is_a_valid_detools_stream() {
    if !common::available() {
        eprintln!("SKIP: detools backend unavailable");
        return;
    }
    let mut inputs: Vec<Vec<u8>> = vec![Vec::new(), vec![0u8; 6], vec![0xAA; 1000]];
    inputs.push(prng(1, 500));
    let mut mixed = prng(2, 400);
    mixed.extend(vec![0x11; 40]);
    mixed.extend(prng(3, 400));
    mixed.extend(vec![0x22; 7]);
    inputs.push(mixed);
    for n in [1usize, 5, 6, 7, 100] {
        inputs.push(vec![0x5A; n]);
    }

    for data in inputs {
        let comp = encode::crle_compress(&data);
        let back = common::crle_decompress(&comp, data.len());
        assert_eq!(back, data, "crle round-trip mismatch (len {})", data.len());
    }
}

#[test]
fn encoders_are_thread_safe_and_deterministic_under_load() {
    // The encoders hold no shared state; prove it: many threads encoding concurrently must each match the
    // single-threaded result exactly. (No detools needed — a pure-Rust property.)
    let base = prng(100, 8000);
    let mut target = base.clone();
    for k in [10usize, 2000, 4000, 7999] {
        target[k] ^= 0x33;
    }
    let seq = sha256(&encode::encode_sequential(&base, &target));
    let ip = sha256(&encode::encode_in_place(&base, &target, 0x8000, 4096));

    let handles: Vec<_> = (0..8)
        .map(|_| {
            let (b, t) = (base.clone(), target.clone());
            std::thread::spawn(move || {
                (
                    sha256(&encode::encode_sequential(&b, &t)),
                    sha256(&encode::encode_in_place(&b, &t, 0x8000, 4096)),
                )
            })
        })
        .collect();
    for h in handles {
        let (s, i) = h.join().unwrap();
        assert_eq!(s, seq, "concurrent sequential encode diverged");
        assert_eq!(i, ip, "concurrent in-place encode diverged");
    }
}
