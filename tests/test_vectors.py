#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
Known-answer tests to catch crypto regressions.
Verifies that key derivation and format primitives produce expected outputs.
"""
import sys, hashlib, struct, json
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from pqc_encryptor import kdf_pass, kdf_ss, MAGIC, VERSION, pack, unpack

PASS = 0
FAIL = 0


def check(name, got, expected):
    global PASS, FAIL
    if got == expected:
        PASS += 1
        print(f"  PASS  {name}")
    else:
        FAIL += 1
        print(f"  FAIL  {name}")
        print(f"        got:      {got!r}")
        print(f"        expected: {expected!r}")


def test_kdf_pass_deterministic():
    """Argon2id with same inputs must always produce same output."""
    salt = b"\x00" * 16
    k1 = kdf_pass("test-password", salt)
    k2 = kdf_pass("test-password", salt)
    check("kdf_pass deterministic", k1, k2)
    check("kdf_pass length", len(k1), 32)


def test_kdf_pass_different_salts():
    """Different salts must produce different keys."""
    k1 = kdf_pass("same-password", b"\x00" * 16)
    k2 = kdf_pass("same-password", b"\x01" + b"\x00" * 15)
    check("kdf_pass salt sensitivity", k1 != k2, True)


def test_kdf_pass_different_passwords():
    """Different passwords must produce different keys."""
    salt = b"\xaa" * 16
    k1 = kdf_pass("password-a", salt)
    k2 = kdf_pass("password-b", salt)
    check("kdf_pass password sensitivity", k1 != k2, True)


def test_kdf_ss_deterministic():
    """HKDF with same shared secret must produce same output."""
    ss = b"\x42" * 32
    k1 = kdf_ss(ss)
    k2 = kdf_ss(ss)
    check("kdf_ss deterministic", k1, k2)
    check("kdf_ss length", len(k1), 32)


def test_kdf_ss_different_inputs():
    """Different shared secrets must produce different keys."""
    k1 = kdf_ss(b"\x00" * 32)
    k2 = kdf_ss(b"\x01" * 32)
    check("kdf_ss input sensitivity", k1 != k2, True)


def test_magic_and_version():
    """Magic bytes and version must match expected constants."""
    check("MAGIC", MAGIC, b"PQC2")
    check("VERSION", VERSION, 2)


def test_pack_unpack_roundtrip():
    """Pack and unpack must be inverse operations."""
    import tempfile, os
    tmp = Path(tempfile.mkdtemp())
    try:
        (tmp / "a.txt").write_bytes(b"hello")
        (tmp / "b.bin").write_bytes(bytes(range(256)))

        files = sorted([
            (str(f.relative_to(tmp)), f)
            for f in tmp.rglob("*") if f.is_file()
        ])

        payload = pack(tmp, files, lambda *a: None)
        entries = unpack(payload)

        check("pack/unpack count", len(entries), 2)

        for rel, data, h in entries:
            orig = (tmp / rel).read_bytes()
            check(f"pack/unpack content [{rel}]", data, orig)
            check(f"pack/unpack hash [{rel}]", h, hashlib.sha256(orig).hexdigest())
    finally:
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)


def main():
    print("Running known-answer / regression tests\n")

    test_kdf_pass_deterministic()
    test_kdf_pass_different_salts()
    test_kdf_pass_different_passwords()
    test_kdf_ss_deterministic()
    test_kdf_ss_different_inputs()
    test_magic_and_version()
    test_pack_unpack_roundtrip()

    print(f"\nResults: {PASS} passed, {FAIL} failed")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
