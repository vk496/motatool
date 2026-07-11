#!/usr/bin/env python3
"""Thin, dev-only bridge between motatool and the pinned `detools` encoder/decoder.

This is the ONLY place motatool touches detools. It exists for two reasons:

  * `encode` — option B: motatool shells out here to produce a byte-compatible detools
    patch (`--codec sequential|in-place --compression crle`) until a pure-Rust encoder
    replaces it. Mirrors exactly how MeshCore's `tools/mota/gen_vectors.py` calls detools,
    so the produced patch is what the on-device vendored detools C decoder expects.
  * `apply` — the *test oracle*: reconstruct `new` from `old` + patch with the real
    detools decoder, so a Rust-produced patch can be proven apply-equivalent
    (`apply(old, ours) == apply(old, detools) == new`), byte for byte.

detools (and this shim) is a **development/test dependency only** — the shipped
`motatool` binary never needs it for the full-image path, and won't need it for deltas
once the pure-Rust encoder lands. Run under the venv built from `third_party/detools`
(see the Makefile `dev-setup` target).
"""
import argparse
import io
import sys

import detools  # from the pinned third_party/detools submodule (built into the dev venv)


def _read(path):
    with open(path, "rb") as f:
        return f.read()


def cmd_encode(a):
    frm, to = _read(a.base), _read(a.new)
    out = io.BytesIO()
    kw = dict(patch_type=a.patch_type, compression=a.compression)
    if a.patch_type == "in-place":
        kw.update(memory_size=a.memory_size, segment_size=a.segment_size)
    detools.create_patch(io.BytesIO(frm), io.BytesIO(to), out, **kw)
    with open(a.out, "wb") as f:
        f.write(out.getvalue())


def cmd_crle_decompress(a):
    """Oracle: decompress a crle stream with the real detools CrleDecompressor (proves our crle output is a
    valid detools stream). `--size` is the expected decompressed length."""
    from detools.compression.crle import CrleDecompressor

    comp = _read(a.data)
    dec = CrleDecompressor(len(comp))
    out = b""
    while len(out) < a.size:
        out += dec.decompress(comp if dec.needs_input else b"", a.size - len(out))
    with open(a.out, "wb") as f:
        f.write(out)


def cmd_apply(a):
    """Oracle: apply `patch` to `base` with the real detools decoder, write the target."""
    base, patch = _read(a.base), _read(a.patch)
    if a.patch_type == "in-place":
        # The device applies in place over a bounded RAM/flash window preloaded with the
        # base image; the reconstructed target is the low `to_size` bytes afterwards.
        mem = bytearray(base) + bytes(a.memory_size - len(base))
        fmem = io.BytesIO(mem)
        detools.apply_patch_in_place(fmem, io.BytesIO(patch))
        result = fmem.getvalue()[: a.to_size]
    else:
        fto = io.BytesIO()
        detools.apply_patch(io.BytesIO(base), io.BytesIO(patch), fto)
        result = fto.getvalue()
    with open(a.out, "wb") as f:
        f.write(result)


def main():
    p = argparse.ArgumentParser(description="motatool <-> detools dev bridge")
    p.add_argument("--detools-version", action="store_true",
                   help="print the linked detools version and exit")
    sub = p.add_subparsers(dest="cmd")

    e = sub.add_parser("encode", help="create a detools patch (option B)")
    e.add_argument("base"); e.add_argument("new"); e.add_argument("out")
    e.add_argument("--patch-type", choices=["sequential", "in-place"], default="sequential")
    e.add_argument("--compression", choices=["crle", "none"], default="crle")
    e.add_argument("--memory-size", type=int, default=0)
    e.add_argument("--segment-size", type=int, default=0)
    e.set_defaults(func=cmd_encode)

    ap = sub.add_parser("apply", help="apply a patch with the real detools decoder (oracle)")
    ap.add_argument("base"); ap.add_argument("patch"); ap.add_argument("out")
    ap.add_argument("--patch-type", choices=["sequential", "in-place"], default="sequential")
    ap.add_argument("--memory-size", type=int, default=0)
    ap.add_argument("--to-size", type=int, default=0)
    ap.set_defaults(func=cmd_apply)

    cd = sub.add_parser("crle-decompress", help="decompress a crle stream with the real detools decoder")
    cd.add_argument("data"); cd.add_argument("out")
    cd.add_argument("--size", type=int, required=True)
    cd.set_defaults(func=cmd_crle_decompress)

    a = p.parse_args()
    if a.detools_version:
        print(detools.__version__); return
    if not getattr(a, "func", None):
        p.print_help(sys.stderr); sys.exit(2)
    a.func(a)


if __name__ == "__main__":
    main()
