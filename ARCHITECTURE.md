# AlterNet Architecture & Protocol Specification

## 1. The Distributed State Machine
AlterNet functions as a globally distributed, highly concurrent state machine. At the core is the `alternet-core` library, driven by `tokio`, which manages network traversal, cryptography, and the `wasmtime` runtime environment.

## 2. Block Exchange & Pinning (The Data Layer)

### 2.1. Merkle DAGs (Directed Acyclic Graphs)
When a user uploads a website or application (e.g., a 10MB folder) to AlterNet:
1. The file is split into chunks of exactly 256KB.
2. Each chunk is hashed using SHA-256 to generate a Content Identifier (CID).
3. A "Root Block" is created, containing pointers (CIDs) to all the child chunks.
4. The Root CID becomes the absolute address of the application: `alter://<Root-CID>`.

### 2.2. The Want-List Protocol
AlterNet nodes do not fetch files via HTTP GET. They use a gossip-based `WantList` protocol.
- When `Node A` wants `CID_X`, it broadcasts a `Want(CID_X)` message to its connected peers.
- If `Node B` has `CID_X` in its SQLite PinStore, it replies with a `Block(CID_X, Data)` payload.
- This allows a 10MB file to be downloaded in parallel from 40 different peers, drastically increasing speed and preventing central server bottlenecks.

## 3. WebAssembly Sandbox Execution (The Compute Layer)

### 3.1. Why WASM?
Instead of rendering HTML/JS through a massive, insecure browser engine like V8/Chromium, AlterNet applications are distributed as pre-compiled WebAssembly binaries (`.wasm`). This provides:
- **Near-Native Performance:** WASM executes at 90% the speed of C++.
- **Absolute Sandboxing:** WASM memory is linearly isolated. A malicious app cannot read the host operating system's RAM or escape the VM.
- **Language Agnosticism:** Developers can write AlterNet apps in Rust, C, Go, or Python (via py2wasm).

### 3.2. Capability Gating & The Linker
The `wasmtime::Linker` is the bouncer of the AlterNet club. When a WASM module is instantiated, the Linker explicitly injects "Host Functions" into the module's environment.
- If an app tries to access the network, it must call the imported `env::network_fetch(cid)`. 
- The Rust host intercepts this call, checks if the user has granted this app "Network Access" permissions, and only then executes the request via the Kademlia DHT.
- **Zero-Day Resilience:** Even if a WASM app contains malware, it is completely trapped in the sandbox with zero access to the host OS syscalls.

## 4. Network Topology & Obfuscation

### 4.1. Proof-of-Work Handshake
To prevent automated Botnets from flooding the AlterNet DHT (Eclipse attacks), every incoming connection to the Swarm requires solving a computational puzzle.
- The connecting node receives a random `Nonce` from the host.
- It must find a value `X` such that `SHA256(Nonce + X)` starts with `N` leading zeros.
- This delays connection establishment by ~2 seconds per peer, making large-scale Sybil attacks mathematically unviable.

### 4.2. Traffic Obfuscation
To bypass ISP throttling and Deep Packet Inspection (DPI) in restrictive regimes, AlterNet integrates Pluggable Transports. The TCP streams are wrapped in `Obfs4`, completely randomizing packet lengths and timing intervals to look like unpredictable white noise.
