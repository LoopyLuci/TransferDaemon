"""Shared helpers for the test suite.

The vectors are written by the Rust reference (see `crates/transferd-crypto/examples/` and
`crates/transferd-overlay/examples/`), so these tests check this implementation against it.
"""

import json
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
VECTORS = REPO / "vectors"


def _load(name: str):
    path = VECTORS / name
    if not path.exists():
        pytest.skip(f"{path} is missing; regenerate it from the Rust reference examples in the repository root")
    return json.loads(path.read_text(encoding="utf-8"))


@pytest.fixture(scope="session")
def crypto_vectors():
    return _load("crypto.json")


@pytest.fixture(scope="session")
def wire_vectors():
    return _load("wire.json")


@pytest.fixture(scope="session")
def ghost_vectors():
    """A ghost key certificate and a relay registration from the Rust reference (`relayd/examples/gen_ghost_vectors.rs`)."""
    return _load("ghost.json")


@pytest.fixture(scope="session")
def ratchet_vectors():
    """Ratchet envelopes from the Rust reference for a fixed root (`transferd-crypto/examples/gen_ratchet_vectors.rs`)."""
    return _load("ratchet.json")


def pattern(length: int, tag: int) -> bytes:
    """The generator's byte pattern: `i * 13 + tag` modulo 256."""
    return bytes(((i * 13) + tag) & 0xFF for i in range(length))


def pattern32(tag: int) -> bytes:
    return pattern(32, tag)
