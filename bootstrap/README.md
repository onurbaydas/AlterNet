# AlterNet Seed Node

A seed node (also called a bootstrap or relay node) is a long-running `alternet-node`
instance with a stable public address. It serves two purposes:

1. **DHT routing** — answers Kademlia lookup requests so new peers can find others on
   the network without knowing any prior contacts.
2. **Content replication** — participates in the distributed storage layer, holding
   replicated chunks so content remains available even when the original publisher is
   offline.

Running a seed node is voluntary. You keep full control of your machine; the node
carries no administrative authority over the network.

---

## How to Run an AlterNet Seed Node

The `alternet-node` binary (built by `cargo build --release --package alternet-node`) is
the only process you need to run. In seed mode it does not expose any user-facing UI —
it connects to peers, joins the DHT, and serves routing and storage requests.

### Build from source

```bash
git clone https://github.com/your-org/alternet
cd alternet
cargo build --release --package alternet-node
sudo cp target/release/alternet-node /usr/local/bin/alternet-node
```

### Quick start (bare metal)

```bash
ALTERNET_DATA_DIR=/var/lib/alternet RUST_LOG=info alternet-node
```

On first run the node creates `$ALTERNET_DATA_DIR/identity` (persistent Ed25519 keypair)
and prints its full multiaddr:

```
INFO  alternet_node: Listening on /ip4/0.0.0.0/tcp/4001/p2p/12D3KooWExampleXXXXXXXX
INFO  alternet_node: Listening on /ip4/0.0.0.0/udp/4002/quic-v1/p2p/12D3KooWExampleXXXXXXXX
```

---

## Docker Compose

The repository ships a `docker-compose.yml` in the project root that is ready to use:

```bash
# From the alternet-master directory
docker compose up -d
docker compose logs -f
```

To rebuild after a source change:

```bash
docker compose build && docker compose up -d
```

The compose file maps:
- Port **4001/tcp** — libp2p TCP transport
- Port **4002/udp** — libp2p QUIC transport
- Volume **alternet-data** — persisted node identity and DHT state at `/var/lib/alternet`

---

## systemd Setup

The repository ships `alternet.service`. Install it with:

```bash
# Create a dedicated system user
sudo useradd -r -s /usr/sbin/nologin -d /var/lib/alternet alternet
sudo mkdir -p /var/lib/alternet
sudo chown alternet:alternet /var/lib/alternet

# Install the binary (if not already done)
sudo cp target/release/alternet-node /usr/local/bin/alternet-node

# Install and enable the service
sudo cp alternet.service /etc/systemd/system/alternet.service
sudo systemctl daemon-reload
sudo systemctl enable --now alternet
sudo journalctl -u alternet -f
```

The bundled `alternet.service` already sets `User=alternet`, `Restart=on-failure`,
and `LimitNOFILE=65535`. To add environment variables without editing the service file
use a drop-in override:

```bash
sudo systemctl edit alternet
```

Add:

```ini
[Service]
Environment=RUST_LOG=info
Environment=ALTERNET_DATA_DIR=/var/lib/alternet
```

---

## Node Configuration Options

| Variable | Default | Description |
|---|---|---|
| `ALTERNET_DATA_DIR` | `/var/lib/alternet` | Directory for the persistent identity keypair and DHT state |
| `RUST_LOG` | `info` | Log verbosity (`error`, `warn`, `info`, `debug`, `trace`) |
| `ALTERNET_LISTEN_TCP` | `0.0.0.0:4001` | Bind address for the TCP transport |
| `ALTERNET_LISTEN_QUIC` | `0.0.0.0:4002` | Bind address for the QUIC/UDP transport |
| `ALTERNET_BOOTSTRAP` | _(compiled-in list)_ | Comma-separated multiaddrs to dial on startup; overrides the built-in seed list |

**Port summary**

| Port | Protocol | Purpose |
|---|---|---|
| 4001 | TCP | libp2p TCP transport (peer connections, Kademlia, relay) |
| 4002 | UDP | libp2p QUIC transport (lower-latency peer connections) |

Open both ports in your firewall and, if behind NAT, configure port forwarding for
both TCP 4001 and UDP 4002.

---

## Submitting Your Node as a Community Bootstrap Node

Community seed nodes are listed directly in the source so every client knows about them
without any external coordination server. To add yours:

1. Run the node with a fixed `ALTERNET_DATA_DIR` so the identity keypair stays stable.
   The peer ID must not change between restarts.
2. Keep the node online for at least 48 hours and confirm both ports are reachable from
   the public internet:
   ```bash
   # From an external machine
   nc -zv <YOUR_IP> 4001   # TCP
   ```
3. Note your full multiaddr from the startup log, for example:
   ```
   /ip4/1.2.3.4/tcp/4001/p2p/12D3KooW...
   /ip4/1.2.3.4/udp/4002/quic-v1/p2p/12D3KooW...
   ```
4. Fork the repository and open a pull request that adds your multiaddrs to the
   compiled-in bootstrap list (check `src/` or the node configuration module for the
   relevant constant, analogous to `COMMUNITY_BOOTSTRAP_ADDRS` in the alterchat-core
   crate).
5. In the PR description include your multiaddrs, the hosting region/country, and your
   expected uptime commitment.

A maintainer will verify reachability before merging.

---

## What a Seed Node Does

### DHT Routing (Kademlia)

When a new peer starts it dials one or more known seed nodes and performs a Kademlia
bootstrap walk. This populates its local routing table with dozens of peers close to its
own peer ID. After that the new peer no longer needs to contact seed nodes directly —
it finds peers through its routing table. Seed nodes therefore see the highest connection
churn but carry low per-connection bandwidth once the newcomer is bootstrapped.

### Content Replication

AlterNet stores published content as content-addressed chunks distributed across the
DHT. Seed nodes, because they are online continuously and cover a wide region of the
Kademlia keyspace, store more chunks than typical peers. This improves availability:
chunks remain reachable even when their original publisher goes offline. Replication is
automatic; you do not configure it manually.

### What a Seed Node Does NOT Do

- It does not decrypt or inspect user content (content is encrypted at rest in the DHT).
- It carries no administrative authority — it cannot ban peers, modify content, or
  override network rules.
- It does not store private user data or metadata beyond what any ordinary DHT participant
  stores.

---

## Security Considerations

- Run as the unprivileged `alternet` user as shown in the systemd instructions above.
- Restrict filesystem access: the process only needs `ALTERNET_DATA_DIR`.
- Rate-limit inbound TCP connections at the firewall (`ufw limit 4001/tcp`) to mitigate
  connection-flood attacks.
- Keep the binary up to date and subscribe to security advisories for the repository.
- Back up `$ALTERNET_DATA_DIR/identity` — losing it means losing your stable peer ID
  and your position in the DHT keyspace (community list entry would need to be updated).
  Set permissions to `600` owned by the `alternet` user.
