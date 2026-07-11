# motatool — dev tasks.
#
# The tool itself is pure Rust (`cargo build`). Only DELTA builds (`build --base`) need the pinned
# `detools` encoder, and only during development — it is not required to build/verify/inspect/serve full
# images, and won't be needed for deltas once a pure-Rust encoder lands. `dev-setup` builds a local venv
# with detools from the third_party/detools submodule; the tests and the delta path find it automatically.

PY ?= python3
VENV := .venv

.PHONY: build test dev-setup clean-venv

build:
	cargo build --release

# One-time (or after bumping the submodule): fetch the pinned detools + its nested HDiffPatch and install
# it into a local venv. Requires a C toolchain (detools has C/C++ extension modules).
dev-setup:
	git submodule update --init --recursive
	$(PY) -m venv $(VENV)
	$(VENV)/bin/pip install --upgrade pip
	$(VENV)/bin/pip install ./third_party/detools
	@$(VENV)/bin/python scripts/detools_shim.py --detools-version | sed 's/^/detools ready: /'

# Full suite. Delta tests auto-skip if the detools venv isn't set up; run `make dev-setup` first to
# exercise them (they assert apply-equivalence against the real detools decoder).
test:
	cargo test

clean-venv:
	rm -rf $(VENV)
