# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2026-03-09

### Added
- GUI application with dark theme (tkinter)
- CLI mode with progress bar
- ML-KEM-768 (FIPS 203) key encapsulation
- ML-DSA-65 (FIPS 204) digital signatures
- AES-256-GCM authenticated encryption
- Argon2id password-based key derivation (64 MB, 3 iterations)
- HKDF-SHA256 shared secret expansion
- Per-file SHA-256 integrity verification
- Password strength indicator in GUI
- Auto-dependency installation on first run
- Windows standalone .exe build script
- Round-trip test suite
- GitHub Actions CI/CD pipeline
- Automated release builds with SHA-256 checksums
