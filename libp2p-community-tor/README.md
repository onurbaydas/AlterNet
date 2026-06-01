# libp2p Community Tor Transport

This directory contains the vendored `libp2p-community-tor` transport used by
AlterNet for Tor-backed libp2p experiments.

The crate originates from community work around `libp2p-tor` and is built on top
of Arti. It allows libp2p transports to dial TCP listeners through Tor.

## Why It Is Vendored Here

AlterNet has privacy-routing modes that need a reviewable Tor path. Vendoring
the transport keeps the exact implementation visible to repository reviewers and
allows integration notes to live beside the code that uses it.

## Misuse Warning

Tor transport alone does not make an AlterNet node anonymous.

The application can still leak identity through:

- stable libp2p peer IDs
- Identify protocol information
- DHT provider records
- manifest publication records
- tag and petname records
- bootstrap choices
- request timing and volume
- direct TCP listeners enabled in parallel

Treat Tor as one layer, not a complete privacy proof.

## Minimal Example

```rust
use libp2p::core::Transport;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let address = "/dns/www.torproject.org/tcp/443".parse()?;
    let mut transport = libp2p_community_tor::TorTransport::bootstrapped().await?;
    let _conn = transport.dial(address)?.await?;
    Ok(())
}
```

## AlterNet Integration

`alternet-core/src/network.rs` enables this transport when
`AlterNetConfig.tor_enabled` is true. The transport is upgraded through libp2p,
authenticated with Noise, and multiplexed with Yamux.

Before relying on Tor mode for sensitive use, audit:

- whether Identify should be disabled or minimized
- which DHT records are published
- whether provider records reveal the content being served
- whether direct listeners remain reachable
- how bootstrap peers are selected
- whether the same peer ID is reused across privacy contexts

## Runtime Notes

- Tor bootstrap can take time.
- The transport uses Tokio-compatible Arti runtime components.
- Tor mode should expose clear status to users and operators.
- Privacy claims should be tested against real traffic captures.

## License

This vendored crate keeps its original MIT license. AlterNet as a whole is
licensed under AGPL-3.0; see the repository root for details.
