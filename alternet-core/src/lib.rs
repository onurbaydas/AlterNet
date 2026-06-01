//! # AlterNet Core — Protokol Kütüphanesi
//!
//! AlterNet, sunucusuz, hesapsız, sansüre dayanıklı bir "Alternatif İnternet"tir.
//!
//! Bu crate, AlterNet protokolünün tüm katmanlarını implemente eder:
//!
//! | Katman | Modül | Açıklama |
//! |--------|-------|----------|
//! | L1 | `identity` | Ed25519 egemen kimlik |
//! | L2 | `naming` | Self-certifying adresler + petname/WoT |
//! | L3 | `content` | İçerik adresli dağıtık depolama (AlterFS) |
//! | L4 | `exchange` | Bitswap-benzeri blok değişim |
//! | L5 | `publish` | İmzalı append-only site yayınlama |
//! | L6 | `routing` | Onion routing + sansür direnci |
//! | L7 | `apps` | WASM sandbox uygulamalar |
//! | L8 | `discovery` | WoT feed + dağıtık arama |
//!
//! ## Manifesto
//!
//! Bu kütüphanenin her satırı AlterNet manifestosuna tabidir.
//! Şifreleme kapatılamaz, merkez yoktur, hesap yoktur.
//! Kod söz verir — yalan söyletme.

// ═══════════════════════════════════════════════
// Yardımcı Modüller
// ═══════════════════════════════════════════════
pub mod error;
pub mod types;
pub mod config;

// ═══════════════════════════════════════════════
// AlterChat Mirası — Kriptografik Temeller
// ═══════════════════════════════════════════════
pub mod identity;
pub mod crypto;
pub mod secure_storage;
pub mod governance;
pub mod pow;
pub mod traffic;
pub mod onion;
pub mod sharding;
pub mod pluggable;
pub mod crdt;

// ═══════════════════════════════════════════════
// AlterNet Yeni Modüller
// ═══════════════════════════════════════════════
pub mod content;     // Faz 1: AlterFS — CID, Merkle DAG, BlockStore
pub mod exchange;    // Faz 1: AlterExchange — blok değişim protokol tipleri
pub mod network;     // Faz 1: libp2p Swarm + NodeHandle
pub mod publish;     // Faz 1: AlterSites — imzalı manifest
pub mod naming;      // Faz 2: AlterNS — self-cert + petname/WoT
pub mod replication; // Faz 2: Pin/Seed/GC
pub mod routing;     // Faz 4: Onion Routing + Privacy Layer
pub mod discovery;   // Faz 5: WoT feed, etiket indeksi, arama
pub mod apps;
pub mod ffi; // For Phase 5
pub mod error; // For Phase 6

pub fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_thread_ids(true)
        .with_target(false)
        .try_init();
}
pub mod board;       // Faz 5: CRDT board (forum/wiki) — merkeziz ortak durum

// Re-export for convenience
pub use libp2p;

/// Sistem kapasitesi hesaplama (AlterChat'ten).
/// Manifesto II: güçlü makine daha fazla taşır.
pub fn calculate_system_capacity() -> u32 {
    use sysinfo::System;
    let mut sys = System::new_all();
    sys.refresh_all();
    let memory_gb = sys.total_memory() / (1024 * 1024 * 1024);
    let cpu_cores = sys.cpus().len() as u64;
    (memory_gb + cpu_cores) as u32
}
