# Changelog

This vendored copy follows the upstream `libp2p-community-tor` history and adds
AlterNet-specific documentation around safe use.

## Vendored in AlterNet

- Documented AlterNet integration expectations.
- Added explicit misuse warnings for libp2p and DHT metadata leaks over Tor.
- Kept the transport source compatible with the workspace dependency path.

## 0.4.1

- Removed duplicate features.
- Corrected a typo in `src/lib.rs`.
- Updated changelog metadata.

Upstream reference: <https://github.com/umgefahren/libp2p-tor/pull/21>

## 0.4.0

- Updated dependencies:
  - `arti-client` to `v0.24.0`
  - `libp2p` to `v0.53.0`
  - `tor-rtcompat` to `v0.24.0`
- Added tracing.
- Updated CI.

Upstream references:

- <https://github.com/umgefahren/libp2p-tor/pull/18>
- <https://github.com/umgefahren/libp2p-tor/pull/20>

## 0.3.0-alpha

- Updated Arti and libp2p dependencies.
- Continued alpha-stage API iteration.

Upstream references:

- <https://github.com/umgefahren/libp2p-tor/pull/6>
- <https://github.com/umgefahren/libp2p-tor/pull/8>

## 0.2.0-alpha

- Updated early libp2p dependencies.
- Continued experimental Tor transport work.
