//! Correctness sweep for the pure-Rust sequential encoder (`src/encode.rs`).
//!
//! For firmware OTA a single wrong bit corrupts the device, so every generated patch is decoded with the
//! **real detools decoder** and its output is hash-compared to the exact bytes we asked to reconstruct.
//! Inputs are DETERMINISTIC (seeded PRNG + fixed edit scripts across many lengths), so a failure is
//! reproducible. We also cross-check against detools' OWN patch: our decode and detools' decode must hash
//! equal (apply-equivalence, the on-device contract). Gated on the dev detools backend; skips cleanly
//! without it (the pure-Rust `build --base` path itself needs no detools).

use motatool::crypto::sha256;
use motatool::{delta, encode, PatchType};

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

    // tiny lengths, base == target and base != target
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

        // version-bump: a handful of scattered edits
        let mut t = base.clone();
        for k in [0usize, 3, 4, n / 3, n / 2, n - 1] {
            t[k] ^= 0x5A;
        }
        v.push((format!("scattered/{n}"), base.clone(), t));

        // append a tail
        let mut t = base.clone();
        t.extend(prng(7, n / 10));
        v.push((format!("append/{n}"), base.clone(), t));

        // prepend (insertion at front — worst case for naive diffs)
        let mut t = prng(9, n / 10);
        t.extend_from_slice(&base);
        v.push((format!("prepend/{n}"), base.clone(), t));

        // delete a middle chunk
        let mut t = base[..n / 4].to_vec();
        t.extend_from_slice(&base[n / 2..]);
        v.push((format!("delete-mid/{n}"), base.clone(), t));

        // truncate and grow
        v.push((
            format!("truncate/{n}"),
            base.clone(),
            base[..n / 2].to_vec(),
        ));
        let mut t = base.clone();
        t.extend(prng(11, n / 2));
        v.push((format!("grow/{n}"), base.clone(), t));

        // wholly different content of the same length
        v.push((
            format!("different/{n}"),
            base.clone(),
            prng(999 + n as u64, n),
        ));

        // empty edges
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

fn assert_case(name: &str, base: &[u8], target: &[u8]) {
    let patch = encode::encode_sequential(base, target);

    // Deterministic: identical inputs must yield identical bytes (no nondeterminism/races in the encoder).
    assert_eq!(
        patch,
        encode::encode_sequential(base, target),
        "[{name}] encoder is not deterministic"
    );

    // THE guarantee: the real detools decoder rebuilds `target` from `base` + our patch, byte-for-byte.
    let decoded = delta::apply_patch(base, &patch, PatchType::Sequential, 0, target.len() as u32)
        .unwrap_or_else(|e| panic!("[{name}] detools apply failed: {e}"));
    assert_eq!(
        sha256(&decoded),
        sha256(target),
        "[{name}] decoded image hash != target (len {} vs {})",
        decoded.len(),
        target.len()
    );

    // Apply-equivalence vs detools' OWN patch: both decode to the same bytes.
    let dt = delta::encode_patch(base, target, PatchType::Sequential, None)
        .unwrap_or_else(|e| panic!("[{name}] detools encode failed: {e}"));
    let decoded_dt =
        delta::apply_patch(base, &dt, PatchType::Sequential, 0, target.len() as u32).unwrap();
    assert_eq!(
        sha256(&decoded),
        sha256(&decoded_dt),
        "[{name}] our patch and detools' patch decode differently"
    );
}

#[test]
fn sequential_encoder_reconstructs_every_case() {
    if !delta::available() {
        eprintln!("SKIP: detools backend unavailable (run `make dev-setup`)");
        return;
    }
    for (name, base, target) in cases() {
        assert_case(&name, &base, &target);
    }
}

#[test]
fn crle_output_is_a_valid_detools_stream() {
    if !delta::available() {
        eprintln!("SKIP: detools backend unavailable");
        return;
    }
    // random (scattered), constant runs (repeated), mixed, and empty — decompressed by REAL detools.
    let mut inputs: Vec<Vec<u8>> = vec![Vec::new(), vec![0u8; 6], vec![0xAA; 1000]];
    inputs.push(prng(1, 500)); // essentially all-scattered
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
        let back = delta::crle_decompress(&comp, data.len()).unwrap();
        assert_eq!(back, data, "crle round-trip mismatch (len {})", data.len());
    }
}

#[test]
fn encoder_is_thread_safe_and_deterministic_under_load() {
    // The encoder holds no shared state; prove it: many threads encoding concurrently must each match the
    // single-threaded result exactly. (No detools needed — this is a pure-Rust property.)
    let base = prng(100, 8000);
    let mut target = base.clone();
    for k in [10usize, 2000, 4000, 7999] {
        target[k] ^= 0x33;
    }
    let expected = sha256(&encode::encode_sequential(&base, &target));

    let handles: Vec<_> = (0..8)
        .map(|_| {
            let (b, t) = (base.clone(), target.clone());
            std::thread::spawn(move || sha256(&encode::encode_sequential(&b, &t)))
        })
        .collect();
    for h in handles {
        assert_eq!(h.join().unwrap(), expected, "concurrent encode diverged");
    }
}
