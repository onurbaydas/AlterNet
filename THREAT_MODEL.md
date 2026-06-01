# AlterNet Threat Model

AlterNet is a peer-to-peer publishing and browsing system. Its security depends
on content addressing, signatures, local trust, transport encryption, careful
browser isolation, and safe handling of untrusted peer data.

This document describes current goals and gaps. It is not an audit report.

## Security Goals

AlterNet aims to protect:

- content integrity
- publisher identity
- manifest freshness
- local identity keys
- pinned content availability
- local petname decisions
- WASM app integrity and capability boundaries
- user privacy against basic traffic analysis

AlterNet does not currently claim to fully protect against malware on the local
device, a global passive adversary, or a large Sybil network with unlimited
resources.

## Assets

| Asset | Location | Impact if Compromised |
| --- | --- | --- |
| Ed25519 identity key | `~/.alternet/identity.key` | attacker can publish as the user |
| block store | `~/.alternet/blocks/` | cached content can be deleted or inspected |
| manifest records | DHT and local cache | stale or forged manifests can mislead users if accepted |
| petname store | `~/.alternet/petnames.cbor` | human-readable names can point to wrong keys |
| pin store | `~/.alternet/pins.cbor` | GC and seeding behavior can be manipulated |
| extracted sites | `~/.alternet/extracted/` | browser can serve stale or malicious content |
| WASM app manifests | user-provided files or network content | app integrity and permissions can be bypassed if verification fails |
| DHT records | Kademlia | public metadata about providers, tags, names, and manifests |

## Adversaries

### Malicious Content Provider

Serves corrupted blocks, wrong manifests, oversized payloads, or incomplete
DAGs.

### Malicious Publisher

Publishes harmful content, malicious WASM, confusing names, or misleading tag
claims while using valid signatures for their own key.

### DHT Attacker

Attempts to poison records, hide providers, return stale values, or observe
queries.

### Sybil Operator

Creates many identities to pollute routing tables, tags, provider results, or
Web-of-Trust paths.

### Local Network Observer

Observes mDNS discovery, local connections, and timing.

### ISP or Censor

Observes IP addresses, blocks known peers, fingerprints P2P traffic, or
correlates timing.

### Compromised Seed Node

Logs requests, serves incomplete data, withholds blocks, or disappears.

### Malicious Website or WASM App

Attempts browser exploitation, local-file access, infinite loops, network
exfiltration, or capability abuse.

### Local Malware

Reads keys, modifies local stores, captures passwords, or tampers with binaries.

## Implemented Mitigations

### Content Integrity

Mitigation:

- CIDs are BLAKE3 hashes of encoded blocks.
- `FsBlockStore::get` verifies the block before returning it.
- `NodeHandle::request_block` verifies received block data.
- oversized blocks are rejected in the network receive path.

Residual risk:

- content can still be malicious while hash-valid
- directory names and sizes can leak metadata
- incomplete DAGs can cause fetch failure

### Manifest Authenticity

Mitigation:

- manifests are Ed25519 signed
- verification rejects missing signatures, wrong keys, and tampering
- `ManifestStore` rejects replay/rollback through monotonic sequence checks

Residual risk:

- DHT may return stale records if local sequence history is missing
- first-contact trust remains a user problem
- a stolen publisher key can sign malicious updates

### Optional Content Encryption

Mitigation:

- leaf blocks can be encrypted with AES-256-GCM using a user-provided key
- wrong keys fail decryption
- encryption key is not stored in the manifest

Residual risk:

- metadata in directories/internal nodes remains visible
- passphrase sharing is outside the protocol
- encrypted content can still be deleted or censored

### Local Identity Protection

Mitigation:

- identity can be stored encrypted when a password is supplied
- backup/restore commands preserve user control of the key

Residual risk:

- no password means plaintext key storage with warning
- local malware can steal unlocked keys
- key loss has no central recovery

### Block Exchange

Mitigation:

- request-response protocol is typed
- receivers verify CIDs
- `DontHave` responses avoid pretending availability

Residual risk:

- peers can withhold data
- provider discovery can be incomplete
- malformed payload fuzzing should be expanded

### Naming

Mitigation:

- self-certifying `alter://` addresses bind identity to key material
- local petnames avoid global squatting
- signed petname lists and zone delegations verify authorship
- WoT search depth is bounded

Residual risk:

- users can assign a petname to the wrong key
- trusted peers can be wrong or compromised
- DHT-published petname lists leak social metadata

### Replication and Availability

Mitigation:

- pinning records all transitive blocks under a root
- seed nodes refresh provider records
- GC preserves pinned blocks
- quota-aware GC removes older unpinned/pinned content as configured

Residual risk:

- content disappears if no peer retains it
- malicious peers can claim availability but fail to serve
- provider records are public metadata

### WASM Sandbox

Mitigation:

- app manifests are signed
- WASM bytes must match manifest CID
- deny-all capability policy by default
- host functions are only linked when capabilities are granted
- fuel limit stops infinite-loop programs

Residual risk:

- some host functions are placeholders
- side channels are not fully addressed
- browser rendering of app output still requires care
- wasmtime and dependency vulnerabilities remain part of the trusted computing
  base

### Privacy Routing

Mitigation:

- default privacy level is padded
- padding and chaff primitives exist
- time-blind delay exists
- onion packet wrapping and forwarding exist
- Tor transport can be enabled

Residual risk:

- DHT metadata remains observable
- Tor does not hide application-level identity leaks
- onion reply encryption is incomplete
- global timing correlation remains possible

## Specific Threats

### Corrupted Block Injection

Threat:

A provider sends bytes that do not match the requested CID.

Mitigation:

CID verification rejects the data.

Recommended tests:

- corrupt block from local store
- corrupt block over request-response
- oversized block response

### Manifest Rollback

Threat:

An attacker returns an older signed manifest to hide a newer update.

Mitigation:

`ManifestStore` rejects manifests with sequence numbers lower than or equal to
the latest known sequence for that author.

Gap:

The receiver must have prior sequence history. First contact with a stale but
valid manifest is difficult to distinguish without witnesses or feeds.

### DHT Record Poisoning

Threat:

An attacker writes conflicting or malicious records into DHT namespaces.

Mitigation:

Security-critical records should be signed and verified. Some paths already
verify manifests, tag claims, petname lists, and zone delegations.

Gap:

Every DHT namespace should be reviewed for signature, freshness, and size
limits.

### Name Confusion

Threat:

A user types `alice` expecting one person but resolves another key.

Mitigation:

Petnames are local and explicit. Self-certifying URIs are cryptographic.

Gap:

The UI/CLI should make first-contact and changed-key situations very visible.

### Malicious `alter://` Content

Threat:

A fetched site contains malicious JavaScript, WASM, HTML, or files.

Mitigation:

Content integrity tells the user that bytes match the publisher's signed
manifest. It does not make the content safe.

Gap:

Browser sandboxing, CSP, app permissions, and user warnings need hardening.

### WASM Capability Bypass

Threat:

A WASM app imports a host function without user permission.

Mitigation:

The host only links functions for granted capabilities. Missing imports cause
instantiation failure.

Gap:

Placeholder host functions must be completed with real isolation and storage
boundaries before broad use.

### Sybil Search Pollution

Threat:

Many fake identities publish tag claims or Web-of-Trust edges to dominate
discovery.

Mitigation:

Claims are signed and WoT resolution is local and bounded.

Gap:

No global Sybil resistance is complete. User trust decisions and scoring policy
remain central to quality.

### Traffic Analysis

Threat:

An observer correlates request timing and provider connections to infer what a
user reads.

Mitigation:

Padded mode, chaff, time-blind delay, onion mode, and Tor mode reduce some
signals.

Gap:

Strong anonymity requires deployment discipline, careful route selection, and
measured behavior. It cannot be guaranteed by a transport flag alone.

## Trusted Computing Base

AlterNet currently trusts:

- local operating system
- Rust compiler and cargo dependencies
- libp2p
- BLAKE3, Ed25519, AES-GCM, Argon2 implementations
- wasmtime
- Tauri and webview runtime
- user-managed secrets

## High-Priority Hardening

1. Add dependency audit tooling.
2. Add fuzz tests for CBOR protocol payloads and DAG extraction.
3. Add end-to-end multi-node publish/fetch/pin tests.
4. Review every DHT namespace for signatures and freshness.
5. Harden browser CSP and content isolation.
6. Complete WASM host-function storage/network isolation.
7. Add key-change and first-contact UX.
8. Document safe seed-node operations.
9. Measure privacy modes under realistic traffic.
10. Perform independent cryptographic and application security review.

## Disclosure

Please report vulnerabilities privately using [SECURITY.md](SECURITY.md).
