# AlterNet Comprehensive Threat Model & Security Posture

AlterNet operates on the assumption that the network is entirely composed of Byzantine (malicious) actors who will attempt to corrupt data, execute malicious code, and take down the network architecture. 

## 1. Data Integrity & Poisoning Attacks

### 1.1. Content Poisoning (Man-in-the-Middle Data Substitution)
**The Threat:** When `Node A` requests a WASM application via its hash (`alter://QmHash`), a malicious `Node B` intercepts the request and sends back a corrupted or malicious WASM file.
**Mitigation:** Absolute Cryptographic Verification. The CID (Content Identifier) is literally the SHA-256 hash of the data. When `Node A` receives the chunks from `Node B`, the AlterNet core hashes the received bytes. If `SHA256(received) != requested_hash`, the data is instantly discarded, the connection to `Node B` is severed, and `Node B` is added to a local IP ban-list. It is mathematically impossible for an attacker to spoof the content without breaking the SHA-256 hashing algorithm.

### 1.2. Garbage Collection (GC) Poisoning
**The Threat:** An attacker blasts millions of fake, small blocks to a victim's node, attempting to fill up their SQLite `PinStore` and exhaust their disk space.
**Mitigation:** Nodes enforce a strict Storage Quota (e.g., 5GB max). More importantly, blocks that are not explicitly "Pinned" by the user (or blocks that are not dependencies of a pinned root hash) are treated as volatile cache. The background GC task sweeps the database every 10 minutes and deletes all unpinned blocks starting with the oldest (LRU Cache eviction). The attacker's blocks are simply deleted.

## 2. WebAssembly Execution Threats

### 2.1. VM Sandbox Escape
**The Threat:** A malicious WASM application attempts to exploit a buffer overflow or memory corruption bug inside the AlterNet browser to gain arbitrary code execution (RCE) on the host's Windows/Mac OS.
**Mitigation:** AlterNet uses `wasmtime`, the most secure, production-grade WebAssembly runtime developed by the Bytecode Alliance. `wasmtime` compiles WASM to native machine code ahead-of-time (AOT) with strict linear memory isolation and guard pages. If a WASM app tries to access memory outside its allocated 4GB linear memory, the host OS page fault handler catches it and forcefully terminates the VM. No host memory can be leaked.

### 2.2. Infinite Loop Cryptojacking (Resource Exhaustion)
**The Threat:** A malicious website runs an infinite `while(true)` loop to mine cryptocurrency or freeze the AlterNet Browser UI thread.
**Mitigation:** 
1. **Asynchronous Execution:** The WASM executor runs in a dedicated thread pool managed by `tokio`, meaning the Tauri UI thread is never blocked.
2. **Fuel Consumption:** AlterNet utilizes `wasmtime`'s "Fuel" mechanism. When an app is launched, it is granted a specific amount of computation cycles (fuel). Every instruction executed by the WASM module consumes fuel. If the fuel drops to zero, the module is preempted and killed via a `Trap::OutOfFuel` exception. The attacker's infinite loop simply results in their app crashing.

## 3. Network Infrastructure Threats

### 3.1. Distributed Denial of Service (DDoS)
**The Threat:** An attacker coordinates a botnet to open thousands of concurrent TCP connections to a public AlterNet Daemon, exhausting its file descriptors and CPU.
**Mitigation:** 
- **Proof-of-Work (PoW) Handshakes:** Before a peer multiplexing stream is negotiated, the incoming IP must solve a computational puzzle. A botnet trying to open 10,000 connections would require massive CPU resources, neutralizing cheap volumetric DDoS attacks.
- **Connection Limits:** `libp2p::Swarm` enforces strict limits on inbound connections per IP and global connection limits.

### 3.2. Sybil & Routing Table Pollution
**The Threat:** An attacker generates millions of fake cryptographic identities to flood the Kademlia DHT, isolating nodes and preventing them from finding legitimate content providers.
**Mitigation:** Kademlia's routing table bucket logic heavily favors long-lived, stable connections. Newly created Sybil nodes are placed at the bottom of the routing priority. Furthermore, the PoW cost to generate a valid `PeerId` makes generating millions of identities computationally prohibitive.
