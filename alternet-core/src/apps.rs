//! # AlterNet AlterApps — WASM Sandbox & Capability Modeli (L7)
//!
//! AlterNet üzerinden dağıtılan etkileşimli uygulamalar WASM sandbox içinde çalışır.
//! Capability-based izin modeli: uygulama yalnızca kullanıcının **açıkça** verdiği
//! yeteneklere erişebilir.
//!
//! **Manifesto IV:** Güven dayatılmaz — varsayılan "her şeyi reddet"; kullanıcı izin verir.
//! **Manifesto VII:** İmzasız uygulama çalıştırılamaz; her modül Ed25519 ile imzalıdır.
//! **Manifesto V:** Sandbox, uygulamanın ana sisteme metadata sızdırmasını engeller.
//!
//! ## Güvenlik mekanizmaları
//! - **Capability gating:** Host fonksiyonları (saat, ağ, depolama) yalnızca ilgili
//!   capability verilmişse linker'a eklenir. İzinsiz import → instantiation başarısız.
//! - **Fuel limiti:** Her çalıştırma yakıt sınırlıdır → sonsuz döngü trap ile durur.
//! - **İmza doğrulama:** `AppManifest` yazarın anahtarıyla imzalıdır; çalıştırmadan önce
//!   doğrulanır (Manifesto VII).
//!
//! AlterChat `plugin.rs` capability deseninden uyarlanmıştır.
//!
//! ## Tehdit Modeli
//! - **Korunan:** Yetkisiz kaynak erişimi (capability gating + WASM bellek izolasyonu)
//! - **Korunan:** Kaynak tüketimi/DoS (fuel limiti)
//! - **Korunan:** Sahte uygulama (Ed25519 imza)
//! - **Sınır:** Yan-kanal saldırıları (zamanlama) sandbox kapsamı dışında

use crate::error::{AlterNetError, Result};
use crate::governance::{decode_public_key, sign_bytes, verify_bytes};
use libp2p::identity::Keypair;
use serde::{Deserialize, Serialize};
use wasmtime::{Config, Engine, Linker, Module, Store, Trap};

/// Host functions gated as experimental in v0.1.0.
/// See TODO comments for planned v0.2.0 implementations.
const WASM_HOST_FUNCTIONS_VERSION: &str = "0.1.0-experimental";

// ═══════════════════════════════════════════════
// Capability Modeli
// ═══════════════════════════════════════════════

/// Bir uygulamanın talep edebileceği yetenekler.
///
/// Manifesto IV: Varsayılan hiçbir yetenek verilmez; kullanıcı bilinçli olarak verir.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Capability {
    /// Sistem saatine erişim (`alternet.now`).
    Clock,
    /// İçerik okuma (`alternet.content_read`).
    ContentRead,
    /// Yerel depolama yazma (`alternet.storage_write`).
    StorageWrite,
    /// Ağ erişimi (`alternet.net_request`).
    NetworkAccess,
}

/// Uygulamayı çalıştıran kullanıcının verdiği izin politikası.
///
/// Varsayılan: **deny-all** (`Default` boş set). Manifesto IV.
#[derive(Debug, Clone, Default)]
pub struct AppPolicy {
    granted: Vec<Capability>,
}

impl AppPolicy {
    /// Hiçbir yetenek vermeyen politika (güvenli varsayılan).
    pub fn deny_all() -> Self {
        Self::default()
    }

    /// Belirtilen yetenekleri veren politika.
    pub fn with(capabilities: Vec<Capability>) -> Self {
        Self { granted: capabilities }
    }

    /// Bir yetenek verilmiş mi?
    pub fn allows(&self, cap: Capability) -> bool {
        self.granted.contains(&cap)
    }

    /// Bir yetenek ekle (kullanıcı onayı).
    pub fn grant(&mut self, cap: Capability) {
        if !self.granted.contains(&cap) {
            self.granted.push(cap);
        }
    }
}

// ═══════════════════════════════════════════════
// İmzalı Uygulama Manifesti
// ═══════════════════════════════════════════════

/// WASM uygulamasının imzalı manifesti.
///
/// Manifesto VII: İmza zorunludur — `verify_app` geçmeyen uygulama çalıştırılmaz.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppManifest {
    /// Uygulama kimliği.
    pub id: String,
    /// İnsan okunabilir ad.
    pub name: String,
    /// Sürüm.
    pub version: String,
    /// Yazarın public key'i (protobuf encoded).
    pub author: Vec<u8>,
    /// Çalıştırılacak dışa aktarılan fonksiyon adı.
    pub entrypoint: String,
    /// Talep edilen yetenekler.
    pub capabilities: Vec<Capability>,
    /// WASM modülünün BLAKE3 hash'i (bütünlük bağı).
    pub wasm_cid: crate::types::Cid,
    /// Ed25519 imza.
    pub signature: Vec<u8>,
}

fn app_signing_bytes(m: &AppManifest) -> Vec<u8> {
    let mut c = m.clone();
    c.signature.clear();
    let mut buf = Vec::new();
    ciborium::into_writer(&c, &mut buf).unwrap_or_default();
    buf
}

/// İmzalı uygulama manifesti oluştur (WASM hash'i dahil).
pub fn create_app_manifest(
    keypair: &Keypair,
    id: String,
    name: String,
    version: String,
    entrypoint: String,
    capabilities: Vec<Capability>,
    wasm_bytes: &[u8],
) -> Result<AppManifest> {
    let mut m = AppManifest {
        id,
        name,
        version,
        author: keypair.public().encode_protobuf(),
        entrypoint,
        capabilities,
        wasm_cid: crate::types::Cid::from_data(wasm_bytes),
        signature: Vec::new(),
    };
    m.signature = sign_bytes(keypair, &app_signing_bytes(&m)).map_err(AlterNetError::Crypto)?;
    Ok(m)
}

/// Manifest imzasını ve WASM bütünlüğünü doğrula.
///
/// Manifesto VII: İmza geçersizse veya WASM hash'i uyuşmazsa reddedilir.
pub fn verify_app(manifest: &AppManifest, wasm_bytes: &[u8]) -> Result<()> {
    let pk = decode_public_key(&manifest.author).map_err(AlterNetError::Crypto)?;
    if !verify_bytes(&pk, &app_signing_bytes(manifest), &manifest.signature) {
        return Err(AlterNetError::SignatureInvalid);
    }
    // WASM içeriği manifest'teki hash ile eşleşmeli (Manifesto III: bütünlük)
    if !manifest.wasm_cid.verify(wasm_bytes) {
        return Err(AlterNetError::ManifestInvalid(
            "WASM hash manifest ile uyuşmuyor".into(),
        ));
    }
    Ok(())
}

// ═══════════════════════════════════════════════
// WASM Host
// ═══════════════════════════════════════════════

/// WASM uygulama çalıştırma ortamı.
pub struct AppHost {
    engine: Engine,
}

/// Çalıştırma sırasında WASM'a verilen durum.
struct HostState {
    /// Uygulamanın `host_log` çağrılarıyla biriktirdiği çıktı.
    log: Vec<String>,
}

impl AppHost {
    /// Yeni host. Fuel tüketimi açık (sonsuz döngü koruması).
    pub fn new() -> Result<Self> {
        let mut config = Config::new();
        config.consume_fuel(true);
        let engine = Engine::new(&config)
            .map_err(|e| AlterNetError::Network(format!("WASM engine: {e}")))?;
        Ok(Self { engine })
    }

    /// İmzalı bir uygulamayı verilen politika ve fuel limitiyle çalıştır.
    ///
    /// Akış:
    /// 1. `verify_app` — imza + WASM bütünlüğü (Manifesto VII).
    /// 2. Linker'a yalnızca **verilen** capability'lerin host fonksiyonları eklenir.
    /// 3. Fuel limiti ile çalıştır; `entrypoint(i32) -> i32` çağrılır.
    ///
    /// İzinsiz bir host fonksiyonu import eden modül **instantiation'da başarısız olur**
    /// (capability enforcement). Fuel biterse trap ile durur.
    pub fn run_app(
        &self,
        manifest: &AppManifest,
        wasm_bytes: &[u8],
        policy: &AppPolicy,
        input: i32,
        fuel: u64,
    ) -> Result<AppRunResult> {
        verify_app(manifest, wasm_bytes)?;

        let module = Module::new(&self.engine, wasm_bytes)
            .map_err(|e| AlterNetError::ManifestInvalid(format!("WASM derleme: {e}")))?;

        let mut store = Store::new(&self.engine, HostState { log: Vec::new() });
        store
            .set_fuel(fuel)
            .map_err(|e| AlterNetError::Network(format!("fuel: {e}")))?;

        let mut linker: Linker<HostState> = Linker::new(&self.engine);

        // Her zaman güvenli: host_log (yan etkisiz, yalnızca string biriktirir).
        linker
            .func_wrap("alternet", "log", |mut caller: wasmtime::Caller<'_, HostState>, ptr: i32, len: i32| {
                // Basit demo: bellekten string oku (capability gerektirmez, yalnızca kayıt).
                // Önce sahiplenilmiş string çıkar (immutable borrow), sonra data_mut'a yaz.
                let extracted: Option<String> = match caller.get_export("memory") {
                    Some(wasmtime::Extern::Memory(mem)) => {
                        let data = mem.data(&caller);
                        let (start, end) = (ptr as usize, (ptr + len) as usize);
                        if end <= data.len() {
                            std::str::from_utf8(&data[start..end]).ok().map(|s| s.to_string())
                        } else {
                            None
                        }
                    }
                    _ => None,
                };
                if let Some(s) = extracted {
                    caller.data_mut().log.push(s);
                }
            })
            .ok();

        // Capability-gated host fonksiyonları — yalnızca izin verilmişse eklenir.
        if policy.allows(Capability::Clock) {
            linker
                .func_wrap("alternet", "now", |_caller: wasmtime::Caller<'_, HostState>| -> i64 {
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs() as i64)
                        .unwrap_or(0)
                })
                .ok();
        }

        if policy.allows(Capability::ContentRead) {
            // TODO v0.2.0: implement block read via NodeHandle
            linker
                .func_wrap("alternet", "content_read", |_caller: wasmtime::Caller<'_, HostState>, _cid_ptr: i32, _cid_len: i32| -> std::result::Result<i32, Trap> {
                    Err(Trap::new("content_read: not yet implemented in v0.1.0"))
                })
                .ok();
        }

        if policy.allows(Capability::StorageWrite) {
            // TODO v0.2.0: implement with quota-gated write
            linker
                .func_wrap("alternet", "storage_write", |_caller: wasmtime::Caller<'_, HostState>, _data_ptr: i32, _data_len: i32| -> std::result::Result<i32, Trap> {
                    Err(Trap::new("storage_write: not yet implemented in v0.1.0"))
                })
                .ok();
        }

        if policy.allows(Capability::NetworkAccess) {
            // TODO v0.2.0: allow only alter:// URIs, deny all others
            linker
                .func_wrap("alternet", "net_request", |_caller: wasmtime::Caller<'_, HostState>, _req_ptr: i32, _req_len: i32| -> std::result::Result<i32, Trap> {
                    Err(Trap::new("net_request: not yet implemented in v0.1.0"))
                })
                .ok();
        }

        let instance = linker
            .instantiate(&mut store, &module)
            .map_err(|e| AlterNetError::Network(format!(
                "WASM instantiate (capability reddi olabilir): {e}"
            )))?;

        let func = instance
            .get_typed_func::<i32, i32>(&mut store, &manifest.entrypoint)
            .map_err(|e| AlterNetError::ManifestInvalid(format!(
                "entrypoint '{}' bulunamadı: {e}", manifest.entrypoint
            )))?;

        let output = func.call(&mut store, input).map_err(|e| {
            // Fuel bitti mi yoksa başka trap mı?
            AlterNetError::Network(format!("WASM çalıştırma trap: {e}"))
        })?;

        let fuel_remaining = store.get_fuel().unwrap_or(0);
        let log = std::mem::take(&mut store.data_mut().log);

        Ok(AppRunResult { output, fuel_remaining, log })
    }
}

/// Uygulama çalıştırma sonucu.
#[derive(Debug, Clone)]
pub struct AppRunResult {
    /// entrypoint'in döndürdüğü değer.
    pub output: i32,
    /// Kalan fuel.
    pub fuel_remaining: u64,
    /// host_log çağrılarından biriken çıktı.
    pub log: Vec<String>,
}

// ═══════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // i32 alıp 1 ekleyen basit modül (host fonksiyonu import etmez).
    const ADD_ONE_WAT: &str = r#"
        (module
          (func (export "entry") (param i32) (result i32)
            local.get 0
            i32.const 1
            i32.add))
    "#;

    // alternet.now (Clock) import eden modül.
    const NEEDS_CLOCK_WAT: &str = r#"
        (module
          (import "alternet" "now" (func $now (result i64)))
          (func (export "entry") (param i32) (result i32)
            call $now
            i32.wrap_i64))
    "#;

    // Sonsuz döngü — fuel limitini tüketmeli.
    const INFINITE_LOOP_WAT: &str = r#"
        (module
          (func (export "entry") (param i32) (result i32)
            (loop $l (br $l))
            i32.const 0))
    "#;

    // WAT metnini doğrudan bytes olarak kullanırız; wasmtime `wat` feature'ı
    // `Module::new` içinde metni ikiliye çevirir. Hash, geçirdiğimiz bytes üzerinden
    // hesaplandığından (`wasm_cid`) verify ile tutarlıdır.
    fn signed(wat: &str, entry: &str, caps: Vec<Capability>) -> (AppManifest, Vec<u8>, Keypair) {
        let wasm = wat.as_bytes().to_vec();
        let kp = Keypair::generate_ed25519();
        let manifest = create_app_manifest(
            &kp,
            "test-app".into(),
            "Test".into(),
            "1.0".into(),
            entry.into(),
            caps,
            &wasm,
        )
        .unwrap();
        (manifest, wasm, kp)
    }

    #[test]
    fn app_manifest_sign_verify() {
        let (manifest, wasm, _) = signed(ADD_ONE_WAT, "entry", vec![]);
        assert!(verify_app(&manifest, &wasm).is_ok());
    }

    #[test]
    fn app_verify_rejects_tampered_wasm() {
        let (manifest, _wasm, _) = signed(ADD_ONE_WAT, "entry", vec![]);
        let other = NEEDS_CLOCK_WAT.as_bytes().to_vec();
        // Farklı WASM → hash uyuşmaz → reddedilir
        assert!(verify_app(&manifest, &other).is_err());
    }

    #[test]
    fn app_runs_pure_function() {
        let (manifest, wasm, _) = signed(ADD_ONE_WAT, "entry", vec![]);
        let host = AppHost::new().unwrap();
        let result = host
            .run_app(&manifest, &wasm, &AppPolicy::deny_all(), 41, 100_000)
            .unwrap();
        assert_eq!(result.output, 42, "entry(41) = 42");
    }

    #[test]
    fn capability_granted_clock_runs() {
        let (manifest, wasm, _) = signed(NEEDS_CLOCK_WAT, "entry", vec![Capability::Clock]);
        let host = AppHost::new().unwrap();
        let policy = AppPolicy::with(vec![Capability::Clock]);
        let result = host.run_app(&manifest, &wasm, &policy, 0, 1_000_000);
        assert!(result.is_ok(), "Clock verilince now() çağrısı çalışmalı");
    }

    #[test]
    fn capability_denied_clock_fails() {
        // Modül alternet.now import ediyor ama Clock verilmedi → instantiation başarısız.
        let (manifest, wasm, _) = signed(NEEDS_CLOCK_WAT, "entry", vec![Capability::Clock]);
        let host = AppHost::new().unwrap();
        let policy = AppPolicy::deny_all(); // izin yok
        let result = host.run_app(&manifest, &wasm, &policy, 0, 1_000_000);
        assert!(
            result.is_err(),
            "Clock verilmeyince now() import'u çözülemez — capability reddi"
        );
    }

    #[test]
    fn fuel_limit_stops_infinite_loop() {
        let (manifest, wasm, _) = signed(INFINITE_LOOP_WAT, "entry", vec![]);
        let host = AppHost::new().unwrap();
        // Düşük fuel → sonsuz döngü trap etmeli (DoS koruması)
        let result = host.run_app(&manifest, &wasm, &AppPolicy::deny_all(), 0, 10_000);
        assert!(result.is_err(), "fuel bitince çalıştırma trap etmeli");
    }

    #[test]
    fn deny_all_is_default() {
        let policy = AppPolicy::default();
        assert!(!policy.allows(Capability::Clock));
        assert!(!policy.allows(Capability::NetworkAccess));
    }
}
