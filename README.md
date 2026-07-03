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
| `build --base` (delta) | ⏳ deferred — see [Deltas](#deltas) |
| `serve` (USB/WiFi seeder link) | ⏳ next |

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

Delta builds (`--base`) are deferred, on purpose. MeshCore deltas use the **detools** *sequential* / *in-place*
patch format, which the firmware/bootloader decodes with detools' vendored **C decoder**. detools has **no C
encoder** — patch *creation* lives in its Python `create.py` — so a byte-compatible encoder must call detools
(pinned as a git submodule) rather than reimplement the codec. Full-image builds (the common case, and the
warm-start capture flow) need none of this and are pure Rust.

## License

GPL-3.0-or-later. Derived from the MeshCore project.
