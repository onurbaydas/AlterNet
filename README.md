<div align="center">
  <h1>بِسْمِ اللَّهِ الرَّحْمَنِ الرَّحِيمِ</h1>
  <h2>AlterNet</h2>
  <p><b>Distributed, Immutable, Serverless Web Architecture & WASM Host</b></p>
  
  [![Rust](https://img.shields.io/badge/rust-v1.85.0-orange?style=flat-square&logo=rust)](https://www.rust-lang.org)
  [![Tauri](https://img.shields.io/badge/Tauri-v2-blue?style=flat-square&logo=tauri)](https://tauri.app/)
  [![WebAssembly](https://img.shields.io/badge/WASM-Host-purple?style=flat-square)](https://webassembly.org/)
  [![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg?style=flat-square)](LICENSE)
</div>

---

## 📖 What is AlterNet?

AlterNet is a paradigm shift in how we conceive the World Wide Web. It replaces the fragile, centralized client-server model (AWS, Cloudflare, DNS) with an **immutable, mathematically verifiable, peer-to-peer hyperspace**.

In AlterNet, there are no IP addresses to host websites, no DNS registrars to censor domains, and no central servers to crash. Content and Applications are packaged into WebAssembly (WASM), cryptographically hashed, and distributed across a global Swarm network.

### 🌌 The Three Pillars
1. **Content Addressing (The Immutable Web):** You don't browse to a location (`https://server.com`); you request a mathematical hash (`alter://QmHash...`). If a government alters the website, the hash changes, and the network mathematically rejects the counterfeit.
2. **Distributed Block Store (The Global Hard Drive):** Files are sliced into 256KB Merkle DAG blocks and scattered across thousands of nodes. When you request a file, bits and pieces are streamed from multiple peers simultaneously, resembling BitTorrent on steroids.
3. **Sandboxed Compute (WASM Edge Runtime):** Web applications on AlterNet are not just HTML/JS. They are compiled WebAssembly modules executing safely inside an isolated `wasmtime` sandbox on the client's machine, eliminating server-side rendering entirely.

---

## 🚀 Deep Technical Architecture

### 1. The Block Exchange Protocol (Want-lists)
When an AlterNet node needs to load a webpage (`alter://cid`), it queries the network for the root block.
- Nodes maintain a `WantList`—a dynamic ledger of blocks they are looking for.
- When connected peers possess these blocks, they push them via highly optimized, pipelined multiplexed streams.
- The AlterNet core uses a Garbage-Collected SQLite `PinStore` to cache these blocks, serving them to other peers to keep the network alive.

### 2. Capability-Gated WASM Runtime
AlterNet does not trust the applications it runs. Every app is executed within a secure virtual machine.
- **No Arbitrary Networking:** An AlterNet app cannot open a raw TCP socket to phone home.
- **Host Functions:** Apps can only interact with the outside world through heavily audited Rust Host Functions injected into the WASM memory space (e.g., `alter_network_request()`, `alter_storage_write()`).
- **Fuel Limits:** To prevent infinite loop attacks (Cryptojacking), the WASM executor assigns a specific amount of "Fuel" (CPU cycles). Once the fuel is exhausted, the app is forcefully terminated.

### 3. Proof-of-Work (PoW) Handshakes
To prevent network flooding, every connection between two AlterNet nodes begins with a cryptographic challenge. A node must spend CPU cycles calculating a valid SHA-256 hash before the connection is accepted.

---

## 💻 Installation & Compilation Guide

AlterNet ships in two variants: the **Browser** (Desktop UI for end-users) and the **Daemon** (Headless server node for enthusiasts who want to seed the network).

### Prerequisites
- **Rust Toolchain:** `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`
- **Node.js (v20+):** `nvm install 20`
- **Docker:** (Optional, for deploying the daemon).

### Compiling the Desktop Browser

1. **Clone the Source:**
   ```bash
   git clone https://github.com/onurbaydas/AlterNet.git
   cd AlterNet
   ```

2. **Install Frontend Dependencies:**
   ```bash
   cd alternet-browser
   npm install
   ```

3. **Run in Development Mode:**
   ```bash
   npm run tauri dev
   ```

4. **Build Production Binary:**
   ```bash
   npm run tauri build
   ```

### Deploying the Headless Daemon (1-Click Docker)

For developers wanting to contribute storage and bandwidth to the AlterNet ecosystem without running the GUI:

```bash
docker-compose up -d --build
```
This spins up the `alternet-daemon` inside an isolated container, automatically mapping port `4001` and mounting a persistent volume for the SQLite PinStore.

---

## 🛠 Application Development (Building for AlterNet)

Developers can build applications for AlterNet using any language that compiles to `wasm32-wasi` (Rust, C, AssemblyScript, Go).

**Example Rust AlterNet App:**
```rust
#[no_mangle]
pub extern "C" fn alter_main() {
    // This calls the AlterNet Host Function to read from the P2P network
    let content = unsafe { host_request_block("QmRootHash...") };
    
    // Render to the DOM via the AlterNet Browser IPC
    unsafe { host_render_dom(content) };
}
```
*A dedicated AlterNet SDK is currently under development to wrap these unsafe FFI calls into safe, ergonomic Rust macros.*

---

## 🖤 Support & Donate
If you believe in decentralized, censorship-resistant networks and want to support the ongoing development of AlterNet, consider donating. Your support helps keep the development sovereign and independent.

- **Monero (XMR):** `43bMdGQAkByAkbiGkgsuGbWf5afr2RBa42swxuqe7M8ohUSVbzaFAQabDivDtLcXJwQDNztZyhMSoiFkSvsCNouV2jACZyA` _(Privacy focused)_
- **Bitcoin (BTC):** `bc1q66wc9qq5w5k219ayv9mgm9jc3dkan757a7ufst`
- **Ethereum (ETH / ERC-20):** `0xC47BDDc11F70eb48f3c261186BdAA5A16E4448D0`
