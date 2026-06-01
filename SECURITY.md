# Security Policy

AlterNet handles identities, signed publishing, DHT records, local block stores,
browser protocol handling, and WASM execution. Please report security issues
privately.

## Supported Versions

| Version | Supported |
| --- | --- |
| `main` branch | Yes |
| tagged pre-releases | Best effort |
| old commits or forks | No |

AlterNet is alpha-stage software and has not completed an independent security
audit.

## Report Privately

Please do not open a public issue for:

- private key extraction or identity-file decryption
- manifest signature bypass
- CID verification bypass
- DHT poisoning that enables impersonation
- petname, zone delegation, or trust-edge forgery
- browser `alter://` protocol escape
- local file read/write through fetched content
- WASM capability bypass
- infinite-loop or resource-exhaustion bypass in the WASM host
- remote crash from malformed peer data
- Tor/privacy-mode identity leak with a practical exploit path
- CI or release-chain compromise

## What to Include

- affected commit, branch, or release
- operating system
- Rust and Node.js versions
- component: core, CLI, node, browser, Docker, workflow
- reproduction steps
- proof-of-concept data if safe to share
- expected impact
- logs with secrets removed
- whether the issue appears actively exploitable

## Research Guidelines

Allowed:

- local testing against your own clone
- temporary identities and local nodes
- controlled fuzzing
- proof-of-concept reports shared privately

Not allowed:

- attacking other users or public seed nodes
- publishing private keys, content, or logs from others
- destructive testing against infrastructure you do not own
- public disclosure before maintainers have had time to respond

## Maintainer Response

Maintainers will try to:

- acknowledge the report
- reproduce and classify the issue
- prepare a fix or mitigation
- coordinate disclosure timing
- credit the reporter if requested

If you are unsure whether an issue is security-sensitive, report it privately
first.
