# AlterNet Threat Model & Mitigation Strategy

AlterNet is a decentralized peer-to-peer network designed to operate in hostile environments. The lack of a central authority means the network must protect itself against malicious peers, state-level adversaries, and localized network attacks.

## 1. Network Level Threats

### 1.1 Sybil Attacks
**Threat:** An attacker generates thousands of cryptographic identities (Peer IDs) to overwhelm the DHT, isolate a target (Eclipse Attack), or exhaust network resources.
**Mitigation:** 
- **Proof-of-Work (PoW):** Peer identities are bound to computational work. Establishing a direct connection or publishing to the DHT requires the peer to solve an Argon2id PoW puzzle dynamically adjusted by network capacity.
- **Trust Scores:** Peers maintain a local reputation matrix. High-capacity, long-lived peers gain higher trust scores, making cheap, ephemeral Sybil nodes ineffective.

### 1.2 Eclipse Attacks
**Threat:** An attacker surrounds a node with malicious peers, feeding it false DHT routing tables and dropping all outbound connections to the honest network.
**Mitigation:**
- **Bootstrap Hardening:** AlterNet uses hardcoded, community-vetted bootstrap nodes (`COMMUNITY_BOOTSTRAP_ADDRS`) combined with dynamic discovery.
- **Multipath Routing:** Queries are dispatched across multiple disjoint paths in the Kademlia DHT, ensuring that a single malicious path cannot drop a query silently.

### 1.3 Passive Observation & Metadata Leakage
**Threat:** ISPs or DPI (Deep Packet Inspection) tools analyze packet sizes and timing to determine if a user is using AlterNet, who they are talking to, or what files they are fetching.
**Mitigation:**
- **Chaff Traffic:** Nodes generate continuous dummy traffic padded to 512-byte boundaries. This masks real requests.
- **Noise Protocol:** All TCP/QUIC connections are fully encrypted with the Noise Protocol Framework, preventing DPI from reading headers or payloads.
- **Pluggable Transports:** AlterNet supports Obfs4 and Snowflake to disguise the handshake and protocol signature entirely.

## 2. Storage & Content Threats

### 2.1 Content Poisoning
**Threat:** A malicious node responds to a block request with corrupted or malicious data.
**Mitigation:**
- **Content-Addressing:** Every block is addressed by its SHA-256 hash. Received blocks are immediately hashed; if the hash does not match the requested CID, the block is discarded and the sending peer's reputation is penalized.

### 2.2 Storage Exhaustion
**Threat:** Malicious apps or peers attempt to fill a node's local hard drive with junk data.
**Mitigation:**
- **PinStore GC:** AlterNet enforces strict disk quotas (e.g., 5GB max). Orphaned or unpinned blocks are aggressively swept by the background Garbage Collector.

## 3. Application (WASM) Threats

### 3.1 Malicious WebAssembly Execution
**Threat:** A downloaded WebAssembly application attempts to access the local file system, mine cryptocurrency, or exfiltrate data.
**Mitigation:**
- **Wasmtime Sandboxing:** Apps run in a mathematically proven sandbox. They have NO access to the OS file system or network sockets.
- **Fuel Limits:** CPU execution is capped. Infinite loops trigger an immediate termination of the WASM instance.
- **Capability Gating:** Apps must explicitly request capabilities (`StorageWrite`, `NetworkAccess`) in their manifest, which the user must approve.
