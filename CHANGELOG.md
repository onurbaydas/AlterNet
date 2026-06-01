# Changelog

All notable changes to AlterNet will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- Fixed: Browser CSP removed `unsafe-eval` and `unsafe-inline` from `script-src`
- Fixed: Dockerfile binary name was `alternet-daemon`, corrected to `alternet-node`
- Fixed: WASM host functions silently returned success; now trap with descriptive errors
- Fixed: Onion routing sent packets with empty `reply_pubkey`; now returns error
- Added: Ed25519 signed provider announcements for DHT poisoning resistance

### Added

- `BrowserStatusBar` component with fetch progress, error, offline states
- `AddressBar` component for `alter://` URI navigation
- Multi-node integration test (`cargo test -- --ignored two_node_publish_fetch`)
- CI matrix expanded to ubuntu-22.04, windows-latest, macos-latest
- `cargo audit` and `npm audit` in CI
