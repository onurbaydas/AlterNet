## Summary

<!-- What changed? Keep it concrete. -->

## Motivation

<!-- Why is this needed? What problem does it solve? -->

## Type of Change

- [ ] Documentation only
- [ ] Bug fix
- [ ] Feature
- [ ] Refactor
- [ ] Security hardening
- [ ] Build, CI, or release

## Affected Area

- [ ] AlterFS / content store
- [ ] Manifest publishing
- [ ] libp2p network / DHT
- [ ] Naming / Web of Trust
- [ ] Replication / pinning / GC
- [ ] Privacy routing / Tor / onion
- [ ] WASM apps
- [ ] CLI
- [ ] Tauri browser
- [ ] Docker or service files

## Security Impact

<!-- Mention integrity, signatures, DHT records, browser handling, WASM capabilities, privacy, or "None". -->

## Testing

- [ ] `cargo fmt --all -- --check`
- [ ] `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- [ ] `cargo test --workspace`
- [ ] `npm run build` from `alternet-browser`
- [ ] Manual CLI test
- [ ] Manual browser test

Notes:

<!-- Include commands, OS, logs, screenshots, or why a check was not run. -->

## Documentation

- [ ] README or architecture docs updated
- [ ] Threat model updated
- [ ] Security notes updated
- [ ] Not needed

## Checklist

- [ ] Content integrity is preserved with CID verification.
- [ ] Mutable records are signed or safely scoped.
- [ ] Browser and WASM input is treated as untrusted.
- [ ] No required central authority was introduced.
- [ ] No secrets, identity files, or private data are included.
