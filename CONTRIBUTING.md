# Contributing to AlterNet

Thank you for contributing to AlterNet. The project combines peer-to-peer
networking, signed publishing, local identity, browser integration, and WASM
sandboxing, so small changes can have security impact.

## Principles

- Preserve serverless operation.
- Preserve local key ownership.
- Verify content by CID before trusting bytes.
- Verify signatures before trusting mutable records.
- Treat all peer, DHT, website, and WASM input as hostile.
- Keep privacy claims tied to implemented behavior.
- Update documentation with protocol or security changes.

## Setup

Requirements:

- Rust 1.95+
- Node.js 20+
- npm
- Tauri v2 prerequisites

```bash
git clone https://github.com/onurbaydas/AlterNet.git
cd AlterNet
rustup update stable
cargo check --workspace
```

Browser setup:

```bash
cd alternet-browser
npm install
npx tauri dev
```

## Checks

Before opening a PR:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
```

Browser:

```bash
cd alternet-browser
npm run build
```

If a check cannot be run, explain the reason in the PR.

## Pull Request Guidance

Good PRs include:

- clear summary
- motivation
- affected modules
- test plan
- security impact
- migration notes
- screenshots for browser UI changes
- documentation updates

Keep PRs scoped. Protocol, browser security, and cryptography changes should be
small enough to review carefully.

## Security-Sensitive Areas

Request extra review for changes touching:

- `alternet-core/src/content.rs`
- `alternet-core/src/types.rs`
- `alternet-core/src/publish.rs`
- `alternet-core/src/network.rs`
- `alternet-core/src/exchange.rs`
- `alternet-core/src/naming.rs`
- `alternet-core/src/replication.rs`
- `alternet-core/src/routing.rs`
- `alternet-core/src/onion.rs`
- `alternet-core/src/apps.rs`
- `alternet-browser/src-tauri/src/commands/browse.rs`
- GitHub Actions release workflows

## Test Ideas

- corrupted block is rejected
- manifest tampering fails verification
- manifest rollback is rejected by local history
- large files produce multi-block DAGs
- encrypted content fails with wrong key
- pin GC preserves pinned blocks
- petname and zone delegation tampering fails
- WASM without granted capability fails to instantiate
- browser `alter://` path traversal is impossible
- malformed network payload does not panic the node

## Documentation

Update Markdown docs when:

- CLI commands change
- network protocol messages change
- DHT keys or record formats change
- manifest format changes
- browser behavior changes
- security assumptions change
- a feature moves from experimental to supported

## Vulnerabilities

Do not report exploitable vulnerabilities in public issues. Follow
[SECURITY.md](SECURITY.md).
