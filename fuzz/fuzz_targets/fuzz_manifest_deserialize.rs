#![no_main]

// Fuzz target: deserialize arbitrary bytes as an alternet-core Manifest.
//
// Manifest (alternet-core/src/types.rs) is serialized with CBOR (ciborium) throughout
// the AlterNet codebase (see publish.rs: manifest_signing_bytes, create_manifest,
// verify_manifest).  The type derives serde::Deserialize via ciborium.
//
// The goal is to confirm that feeding malformed bytes into the CBOR deserializer
// never causes a panic.  After deserialization we also call verify_manifest to
// exercise the signature-validation path on arbitrary input.
//
// To run:
//   cargo +nightly fuzz run fuzz_manifest_deserialize -- -max_total_time=60

use libfuzzer_sys::fuzz_target;
use alternet_core::types::Manifest;
use alternet_core::publish::verify_manifest;

fuzz_target!(|data: &[u8]| {
    // Attempt CBOR deserialization — must never panic on arbitrary bytes.
    let manifest: Manifest = match ciborium::from_reader(data) {
        Ok(m) => m,
        Err(_) => return, // Not valid CBOR for a Manifest — no panic, skip.
    };

    // If we got a Manifest, try verifying it.  Signature validation will almost
    // always fail on fuzz-generated content, but must not panic.
    let _ = verify_manifest(&manifest);
});
