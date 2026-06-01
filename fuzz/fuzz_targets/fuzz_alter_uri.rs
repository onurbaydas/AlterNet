#![no_main]

// Fuzz target: parse arbitrary bytes as an alter:// URI.
//
// parse_alter_uri (alternet-core/src/naming.rs) splits an "alter://" URI into a
// base address and an optional subpath.  identity::alter_uri_to_pubkey
// (alternet-core/src/identity.rs) is then called on the base part when the
// PetnameStore tries to resolve a self-certifying address.
//
// The goal is to confirm that neither parse_alter_uri nor the follow-on pubkey
// decoding panics on arbitrary input.
//
// To run:
//   cargo +nightly fuzz run fuzz_alter_uri -- -max_total_time=60

use libfuzzer_sys::fuzz_target;
use alternet_core::naming::parse_alter_uri;
use alternet_core::identity::alter_uri_to_pubkey;

fuzz_target!(|data: &[u8]| {
    // Only work with valid UTF-8 — the URI parsing functions take &str.
    let s = match std::str::from_utf8(data) {
        Ok(s) => s,
        Err(_) => return,
    };

    // Exercise the URI parser — returns Err on malformed input, must not panic.
    if let Ok((base_uri, _subpath)) = parse_alter_uri(s) {
        // If parsing succeeded, also attempt pubkey extraction from the base URI.
        // alter_uri_to_pubkey decodes a base32-encoded Ed25519 public key; it must
        // not panic on arbitrary (but valid-UTF-8) content.
        let _ = alter_uri_to_pubkey(&base_uri);
    }
});
