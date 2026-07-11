# motatool

Build, verify, inspect, and (soon) serve **MeshCore `.mota` firmware-update containers**.

A `.mota` is a signed, self-verifying package of a firmware update that [MeshCore](https://github.com/meshcore-dev/MeshCore)
nodes fetch over LoRa, block by block. This tool makes those packages, checks them, and serves a folder of
them to a node. It is a Rust rewrite of the C++ `motatool` that used to live in the MeshCore tree, kept
**byte-for-byte compatible** with the firmware's on-wire format.

## Status

Ported and validated:

| Command | State |
|---|---|
| `build` (full image) | ✅ byte-identical to the reference C++ tool |
| `verify` | ✅ (structure, block hashes, merkle root, image hash, Ed25519 signature) |
| `inspect` | ✅ |
| `keygen` | ✅ |
| `serve` (USB/WiFi seeder link) | ✅ (folder relay + pull-to-folder capture + `--seed` warm-start) |
| `build --base` sequential (ESP32) | ✅ **pure Rust** (no runtime detools); apply-equivalence tested — see [Deltas](#deltas) |
| `build --base` in-place (nRF52) | ✅ via detools (**dev-only** backend); pure-Rust port is future work |

## Build

```sh
cargo build --release      # -> target/release/motatool
cargo test                 # unit + round-trip tests
```

## Usage

```sh
# package a firmware (identity — target/version/hardware — is read from its EndF trailer)
motatool build --fw firmware.hex --out-dir ./motas
motatool build --fw firmware.bin --sign signer.key --out-dir ./motas   # signed
motatool build --fw https://example.org/RAK_4631_repeater.bin          # straight from a URL

# check containers (per-file OK / FAIL; non-zero exit if any fails)
motatool verify ./motas/*.mota
motatool verify update.mota --pub signer.key.pub

# dump every manifest field
motatool inspect ./motas/RAK4631_04D413FD_v1.17.0_full_ABCD1234.mota

# make an Ed25519 signing keypair
motatool keygen --out signer.key   # writes signer.key + signer.key.pub (hex)
```

`--fw` accepts a file path or an `http(s)://` URL; a `.hex` (nRF52/STM32 build) is parsed to its flat image
first. Firmware identity comes from the image's `EndF` trailer, overridable with `--target-env` /
`--target-id`, `--fw-version`, `--hw-id`.

## Compatibility

The container format, merkle tree (MMR of 4-byte truncated-SHA-256 leaves), `EndF` identity trailer, and
hash truncation are held **byte-identical** to the MeshCore firmware (`src/helpers/ota/OtaFormat.h`,
`MerkleTree.cpp`, and `docs/ota_protocol.md` are the spec). Ed25519 signing is deterministic (RFC 8032), so
signed containers match the firmware's / OpenSSL's output exactly. This is validated by building the same
firmware with this tool and the reference C++ `motatool` and confirming the outputs are byte-for-byte equal
(and that each tool verifies the other's).

`src/targets.rs` is a vendored snapshot of the firmware's generated `OtaTargets.h`
(`target_id = sha2-256:4(env_name)`); regenerate it from there when the OTA-capable env set changes.

## Deltas

```sh
# diff a NEW firmware against the device's current image -> a tiny delta .mota
motatool build --base running_firmware.bin --fw new_firmware.bin --out-dir ./motas                 # sequential (ESP32)
motatool build --base running_firmware.bin --fw new_firmware.bin --patch-type in-place --out-dir . # in-place (nRF52)
```

`--base` must be the device's **real running image, with its `EndF` trailer** — the delta is applied to
exactly that image on-device, and its 8-byte `base_hash` is checked against the running firmware before apply.
The delta payload is a **detools** patch (`--compression crle`, matching the firmware's compile-time decoder
config); `--patch-type in-place` also takes `--inplace-memory` (nRF52 default `0x98000`) and `--segment-size`.

**Sequential (ESP32) is pure Rust** — [`src/encode.rs`](src/encode.rs) implements the detools
`sequential` + `crle` format (canonical bsdiff + conditional-RLE), so `build --base --patch-type sequential`
needs **no Python or detools at runtime**. The **in-place (nRF52)** path still shells out to the pinned
detools (git submodule `third_party/detools`) via `scripts/detools_shim.py`; porting it is future work. That
one path, plus the test oracle, is the only reason to install detools:

```sh
make dev-setup     # inits the submodule + builds a local .venv with detools 0.53.0
```

detools is a **development/test-only** dependency. Full-image `build`/`verify`/`inspect`/`serve` and the
pure-Rust sequential delta need none of it.

### Correctness: apply-equivalence, not byte-identity

A delta is correct when the **real detools C decoder** (the one on the device), fed our patch, reconstructs
the target **byte-for-byte** — *not* when our patch bytes equal detools'. Because a single wrong bit corrupts
a firmware image, the encoder is held to that directly:

- `tests/encode.rs` runs a **deterministic sweep** (seeded PRNG + fixed edit scripts across lengths 0…20 k:
  identical, scattered edits, insert/delete/append/prepend, truncate/grow, wholly-different, empty edges,
  run-heavy). Every generated patch is decoded by real detools and **hash-compared** to the exact target,
  and cross-checked so `apply(base, our_patch) == apply(base, detools_patch) == target`.
- The `crle` compressor is round-tripped through the real detools decompressor; `pack_size`/`crle` framing
  have unit tests; the encoder is proven deterministic and thread-safe under concurrent load.
- Validated at scale: a ~500 KB image with ~55 edits → an **829-byte** delta in ~0.2 s, reconstructed
  byte-exact by detools.

The in-place path is held to the same apply-equivalence bar in `tests/delta.rs`. When the in-place encoder is
ported to Rust, detools drops to a pure test oracle (or frozen vectors), leaving the shipped binary
Python-free for all delta types.

## License

GPL-3.0-or-later. Derived from the MeshCore project.
