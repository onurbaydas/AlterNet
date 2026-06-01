# AlterNet Security Audit Preparation

## Scope

List the exact modules/files an auditor should focus on:

- `alternet-core/src/publish.rs` (manifest signing)
- `alternet-core/src/identity.rs` (keypair management)
- `alternet-core/src/content.rs` (BLAKE3 CID, block verification)
- `alternet-core/src/apps.rs` (WASM sandbox, capability model)
- `alternet-core/src/network.rs` (DHT, block exchange)
- `alternet-browser/src/browse.rs` (protocol handler, content rendering)

## Known Issues (Pre-Audit)

List what we already know needs attention:

- WASM host functions stub: some host-function imports are placeholders and do not enforce real storage or network isolation
- Onion reply encryption incomplete: onion packet forwarding exists but reply-path encryption is not fully implemented
- Shared webview (now sandboxed iframe): browser isolation has been improved to sandboxed iframes but the isolation boundary has not been independently verified
- No independent audit: AlterNet has not undergone an external cryptographic or application security review

Additional known gaps identified in the threat model:

- DHT record freshness and signatures are not uniformly enforced across all namespaces
- First-contact trust for manifests is a user problem with no automated safeguard
- Petname-list publication to the DHT leaks social-graph metadata
- Browser CSP and content isolation need hardening; fetched `alter://` content can contain malicious HTML, JavaScript, or WASM
- No global Sybil resistance; tag and WoT discovery quality depends entirely on user trust decisions
- No password means identity key is stored in plaintext (warned but not blocked)
- Tor transport does not prevent application-level identity leaks without careful integration
- Dependency audit tooling not yet integrated into CI

## Questions for Auditor

- Is BLAKE3 appropriate for content addressing in this threat model, and are there any length-extension or collision concerns relevant to the CID scheme?
- Is the Ed25519 manifest signing scheme (including sequence-number rollback protection) sound and correctly implemented?
- Is the WASM capability model sufficient to prevent a malicious app from accessing host resources beyond its granted permissions?
- Can sandboxed iframes escape to Tauri IPC, and is the `alter://` protocol handler fully isolated from the local filesystem and native APIs?
- Are there exploitable gaps between the stub host functions and the real isolation boundaries that a malicious WASM module could reach before the stubs are replaced?
- Does the block-verification path in `FsBlockStore::get` and `NodeHandle::request_block` cover all code paths through which blocks can be consumed?
- Is the onion packet format resistant to traffic analysis, and what is the security impact of the incomplete reply-path encryption?
- Are the DHT namespaces that currently lack signature verification exploitable for impersonation, record injection, or denial-of-service?
- Is optional AES-256-GCM leaf-block encryption correctly keyed and does it fully hide content from a block-store observer?
- Does the manifest rollback defense hold when a receiver has no prior sequence history for a publisher?

## Audit Deliverables Requested

- Cryptographic design review (BLAKE3 CID, Ed25519 manifest signing, AES-256-GCM content encryption, Argon2id identity key protection)
- Code-level vulnerability assessment
- WASM sandbox and capability model review
- Browser protocol handler and iframe isolation review
- Threat model validation
- Remediation recommendations

## How to Build and Run Tests

```
cargo test --all-features
cargo +nightly fuzz run fuzz_cbor_payload -- -max_total_time=300
```

Additional recommended test coverage noted in the threat model:

```
# Corrupt block from local store and over request-response
# Oversized block response handling
# Manifest rollback (lower sequence number) rejection
# DHT record with missing or wrong signature
# WASM app instantiation failure on ungranted capability import
# Fuel-limit enforcement for infinite-loop WASM programs
# End-to-end multi-node publish / fetch / pin test
```

## Threat Model Reference

The full threat model is in `THREAT_MODEL.md`. The high-priority hardening items listed there are:

1. Add dependency audit tooling (`cargo audit`, `cargo deny`)
2. Add fuzz tests for CBOR protocol payloads and DAG extraction
3. Add end-to-end multi-node publish/fetch/pin tests
4. Review every DHT namespace for signatures and freshness
5. Harden browser CSP and content isolation
6. Complete WASM host-function storage/network isolation
7. Add key-change and first-contact UX
8. Document safe seed-node operations
9. Measure privacy modes under realistic traffic
10. Perform independent cryptographic and application security review

## Security Boundaries Summary

Trusted within scope of this audit:

- Local operating system
- Rust compiler and cargo dependencies
- libp2p
- BLAKE3, Ed25519, AES-GCM, Argon2 implementations
- wasmtime
- Tauri and webview runtime
- User-managed secrets

Untrusted (all must be treated as adversarial input):

- All data received over the network (blocks, manifests, DHT records, protocol messages)
- WASM app bytes and manifests provided by network content
- Fetched `alter://` site content (HTML, JavaScript, WASM, files)
- mDNS and bootstrap-node responses
- Petname lists and zone delegations received from peers

## Disclosure

Report vulnerabilities privately per the process in `SECURITY.md`. Do not open public issues for security findings.
