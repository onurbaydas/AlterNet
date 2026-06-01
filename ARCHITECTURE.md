# AlterNet Architecture & Topology

AlterNet operates purely on a peer-to-peer basis. There are no client-server distinctions. Every instance of AlterNet acts as both a client and a relay node.

## Network Topology

### Layer 1: Transport & Routing (libp2p)
- **Multiplexing:** Yamux is used to multiplex multiple substreams (e.g., Kademlia queries, file transfers) over a single TCP/QUIC connection.
- **Routing:** Kademlia DHT maintains the routing table. Nodes are grouped into buckets based on the XOR distance between their Peer IDs.

### Layer 2: Secure Application Protocols
- **File Exchange:** AlterNet uses a custom request/response protocol for block exchange (`/alternet/exchange/1.0.0`). Instead of IPFS Bitswap, we use an optimized pipelined Want-List exchange protocol.
- **Discovery:** Nodes register their capabilities and services (e.g., "WebAssembly Host", "Storage Provider") on the Kademlia DHT using Provider Records.

### Layer 3: Application & Sandboxing
- **WASM Runtime:** The `wasmtime` crate is embedded into the core.
- **CRDT Synchronization:** For distributed states (Boards, Chats), AlterNet utilizes Conflict-Free Replicated Data Types to ensure all nodes eventually converge on the same state without a master server.

## Data Flow: Fetching an Application
1. **Request:** The UI requests `alter://bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi`.
2. **Resolution:** The AlterNet core queries the DHT for peers providing this CID.
3. **Connection:** The core connects to the providers, negotiates Noise encryption, and requests the block.
4. **Verification:** The received block is hashed. If it matches `bafy...`, it is written to the SQLite PinStore.
5. **Execution:** The WASM engine loads the block into isolated memory and begins execution, bound by the manifest's capabilities.
