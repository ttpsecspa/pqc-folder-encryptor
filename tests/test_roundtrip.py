#!/usr/bin/env python3
"""
Round-trip test: encrypt a folder, decrypt it, verify all files match.
Exit 0 on success, 1 on failure.
"""
import sys, os, tempfile, shutil, hashlib
from pathlib import Path

# Add parent dir to path so we can import pqc_encryptor
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from pqc_encryptor import encrypt_folder, decrypt_folder


def sha256_file(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    tmp = Path(tempfile.mkdtemp(prefix="pqc_test_"))
    try:
        # Create test folder with various files
        src = tmp / "test_folder"
        src.mkdir()
        (src / "hello.txt").write_text("Hello, Post-Quantum World!", encoding="utf-8")
        (src / "binary.bin").write_bytes(os.urandom(4096))
        sub = src / "subdir" / "nested"
        sub.mkdir(parents=True)
        (sub / "deep.txt").write_text("Nested file content", encoding="utf-8")
        (src / "empty.txt").write_bytes(b"")

        # Collect original hashes
        originals = {}
        for f in src.rglob("*"):
            if f.is_file():
                rel = str(f.relative_to(src))
                originals[rel] = sha256_file(f)

        print(f"Created {len(originals)} test files")

        # Encrypt
        pqc_file = tmp / "test.pqc"
        passphrase = "test-passphrase-!@#$%^&*()"
        r = encrypt_folder(str(src), str(pqc_file), passphrase)
        print(f"Encrypted: {r['files']} files, {r['output_size']:,} bytes")
        assert pqc_file.exists(), "PQC file not created"

        # Decrypt
        dst = tmp / "restored"
        dst.mkdir()
        r = decrypt_folder(str(pqc_file), str(dst), passphrase)
        print(f"Decrypted: {r['files']} files")

        # Verify
        restored_dir = dst / "test_folder"
        assert restored_dir.exists(), "Restored folder not found"

        for rel, orig_hash in originals.items():
            restored_file = restored_dir / rel
            assert restored_file.exists(), f"Missing file: {rel}"
            restored_hash = sha256_file(restored_file)
            assert orig_hash == restored_hash, f"Hash mismatch: {rel}"

        print(f"Verified {len(originals)} files - ALL MATCH")

        # Test wrong passphrase
        try:
            decrypt_folder(str(pqc_file), str(tmp / "bad"), "wrong-password")
            print("FAIL: Should have raised error for wrong passphrase")
            return 1
        except ValueError as e:
            print(f"Wrong passphrase correctly rejected: {e}")

        print("\nAll tests PASSED")
        return 0

    except Exception as e:
        print(f"\nFAILED: {e}")
        import traceback
        traceback.print_exc()
        return 1
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
