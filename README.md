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
| `build --base` (delta) | ✅ via detools (**dev-only** backend); apply-equivalence tested — see [Deltas](#deltas) |

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

**detools is a development-only dependency.** MeshCore's device/bootloader decodes deltas with detools'
vendored **C decoder**, but detools has **no C/Rust encoder** — patch *creation* lives in its Python
`create.py`. So, for now, `build --base` shells out to the pinned detools (git submodule
`third_party/detools`) through `scripts/detools_shim.py`. Set it up once:

```sh
make dev-setup     # inits the submodule + builds a local .venv with detools 0.53.0
```

Everything else — full-image `build`, `verify`, `inspect`, `serve` — is **pure Rust and needs none of this**.

### Correctness: apply-equivalence, not byte-identity

A delta is correct when the **real detools decoder**, fed our patch, reconstructs the target byte-for-byte —
*not* when our patch bytes equal detools'. `tests/delta.rs` asserts exactly that, for both patch types:
`apply(base, our_patch) == apply(base, detools_patch) == target`. That is the contract a future **pure-Rust
encoder** must satisfy; when it lands it replaces the shim with no `.mota` format change, and detools drops to
a test-only oracle (or frozen golden vectors), leaving the shipped binary Python-free even for deltas.

## License

GPL-3.0-or-later. Derived from the MeshCore project.
