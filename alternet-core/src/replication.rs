//! # AlterNet Replication — Pin / Seed / Garbage Collection
//!
//! İçeriği yeniden barındırma (pin), sağlayıcı olarak duyurma (seed) ve
//! disk kotası aşıldığında eski blokları temizleme (GC) altyapısı.
//!
//! **Manifesto II:** "Ziyaretçi değer verdiği siteyi yeniden barındırabilir →
//! ilgi = replikasyon = erişilebilirlik. Popüler içerik daha çok yaşar."
//!
//! ## Tehdit Modeli
//! - **Korunan:** Sahte blok pinleme (her blok BLAKE3 ile doğrulanır)
//! - **Sınır:** GC kararları yereldir — ağdaki başka kopyaları bilmez
//! - **Sınır:** Pin TTL'i olan içerik herhangi bir node'da silinirse kaybolabilir

use crate::content::{BlockStore, FsBlockStore};
use crate::error::{AlterNetError, Result};
use crate::types::Cid;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

// ═══════════════════════════════════════════════
// PinRecord
// ═══════════════════════════════════════════════

/// Tek bir pinlenmiş içerik kaydı.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PinRecord {
    /// Kök CID (Merkle DAG kökü).
    pub root_cid: Cid,
    /// Yayıncının public key hex'i (manifest sahibi).
    pub author_pubkey_hex: String,
    /// İnsan okunabilir etiket (opsiyonel).
    pub label: Option<String>,
    /// Pin zamanı (unix epoch seconds).
    pub pinned_at: u64,
    /// Son erişim (TTL hesaplama için).
    pub last_accessed: u64,
    /// Bu CID altındaki tüm bloklar (transitif).
    pub block_cids: Vec<Cid>,
}

impl PinRecord {
    fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    pub fn new(
        root_cid: Cid,
        author_pubkey_hex: String,
        label: Option<String>,
        block_cids: Vec<Cid>,
    ) -> Self {
        let now = Self::now();
        Self { root_cid, author_pubkey_hex, label, pinned_at: now, last_accessed: now, block_cids }
    }

    pub fn touch(&mut self) {
        self.last_accessed = Self::now();
    }
}

// ═══════════════════════════════════════════════
// PinStore
// ═══════════════════════════════════════════════

/// Pinlenmiş içeriklerin yerel kaydı.
///
/// CBOR olarak `<data_dir>/pins.cbor` konumunda saklanır.
#[derive(Debug, Default)]
pub struct PinStore {
    pins: HashMap<String, PinRecord>, // hex(root_cid) → PinRecord
    path: Option<PathBuf>,
}

impl PinStore {
    /// Bellekte pin deposu (testler için).
    pub fn in_memory() -> Self {
        Self::default()
    }

    /// Dosya tabanlı pin deposu. Mevcut dosya varsa yükler.
    pub async fn open(data_dir: &Path) -> Result<Self> {
        let path = data_dir.join("pins.cbor");
        let pins = if path.exists() {
            let bytes = tokio::fs::read(&path).await.map_err(AlterNetError::Io)?;
            let list: Vec<PinRecord> = ciborium::from_reader(bytes.as_slice())
                .map_err(|e| AlterNetError::CborDecode(e.to_string()))?;
            list.into_iter().map(|r| (r.root_cid.to_hex(), r)).collect()
        } else {
            HashMap::new()
        };
        Ok(Self { pins, path: Some(path) })
    }

    /// Pin ekle.
    pub fn add(&mut self, record: PinRecord) {
        self.pins.insert(record.root_cid.to_hex(), record);
    }

    /// Pin kaldır.
    pub fn remove(&mut self, root_cid: &Cid) -> Option<PinRecord> {
        self.pins.remove(&root_cid.to_hex())
    }

    /// Pin var mı?
    pub fn contains(&self, root_cid: &Cid) -> bool {
        self.pins.contains_key(&root_cid.to_hex())
    }

    /// Tüm pinleri listele.
    pub fn list(&self) -> Vec<&PinRecord> {
        self.pins.values().collect()
    }

    /// Erişim zamanını güncelle.
    pub fn touch(&mut self, root_cid: &Cid) {
        if let Some(r) = self.pins.get_mut(&root_cid.to_hex()) {
            r.touch();
        }
    }

    /// Kayıt sayısı.
    pub fn len(&self) -> usize {
        self.pins.len()
    }

    pub fn is_empty(&self) -> bool {
        self.pins.is_empty()
    }

    /// Tüm pinlenmiş blokların CID setini döndür (GC için).
    pub fn all_pinned_cids(&self) -> HashSet<Cid> {
        self.pins.values().flat_map(|r| r.block_cids.iter().cloned()).collect()
    }

    /// Diske yaz.
    pub async fn save(&self) -> Result<()> {
        let Some(ref path) = self.path else { return Ok(()) };
        let list: Vec<&PinRecord> = self.pins.values().collect();
        let mut buf = Vec::new();
        ciborium::into_writer(&list, &mut buf)
            .map_err(|e| AlterNetError::CborEncode(e.to_string()))?;
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await.map_err(AlterNetError::Io)?;
        }
        tokio::fs::write(path, &buf).await.map_err(AlterNetError::Io)
    }
}

// ═══════════════════════════════════════════════
// Replicator
// ═══════════════════════════════════════════════

/// Replikasyon yöneticisi: pin, unpin ve GC işlemleri.
///
/// Manifesto II: "Güçlü makine ağın daha fazla içeriğini taşır."
pub struct Replicator {
    pub store: std::sync::Arc<FsBlockStore>,
    pub pins: PinStore,
    /// Disk kotası (byte, 0 = sınırsız).
    pub quota: u64,
}

impl Replicator {
    pub fn new(store: std::sync::Arc<FsBlockStore>, pins: PinStore, quota: u64) -> Self {
        Self { store, pins, quota }
    }

    /// İçeriği pin'le: zaten depoda olan bloklarla birlikte pin kaydı oluştur.
    ///
    /// Blokların daha önce `FsBlockStore`'a yüklenmiş olması beklenir.
    pub fn pin(
        &mut self,
        root_cid: Cid,
        author_pubkey_hex: String,
        block_cids: Vec<Cid>,
        label: Option<String>,
    ) {
        let record = PinRecord::new(root_cid, author_pubkey_hex, label, block_cids);
        self.pins.add(record);
    }

    /// İçeriği unpin'le.
    pub fn unpin(&mut self, root_cid: &Cid) -> Option<PinRecord> {
        self.pins.remove(root_cid)
    }

    /// Garbage Collection: pinlenmeyen blokları sil.
    ///
    /// Algoritma:
    /// 1. Tüm pinlenmiş blokların CID kümesini oluştur (mark).
    /// 2. Block store'daki blokları tara.
    /// 3. Marklanmamış blokları sil (sweep).
    ///
    /// `dry_run = true` ise silmez, sayım döndürür.
    pub async fn gc(&self, dry_run: bool) -> Result<GcReport> {
        let pinned = self.pins.all_pinned_cids();
        let all_cids = self.store.list_cids().await?;

        let mut deleted = 0u64;
        let mut freed_bytes = 0u64;
        let mut would_delete = 0u64;

        for cid in &all_cids {
            if !pinned.contains(cid) && let Ok(Some(data)) = self.store.get(cid).await {
                if dry_run {
                    would_delete += 1;
                    freed_bytes += data.len() as u64;
                } else {
                    freed_bytes += data.len() as u64;
                    self.store.delete(cid).await?;
                    deleted += 1;
                }
            }
        }

        Ok(GcReport {
            deleted_blocks: if dry_run { would_delete } else { deleted },
            freed_bytes,
            dry_run,
        })
    }

    /// Disk kotası aşıldıysa en eski erişilen pinleri kaldırarak GC çalıştır.
    ///
    /// Manifesto II: disk kotasını kullanıcı belirler, sistem saygı gösterir.
    pub async fn gc_if_over_quota(&mut self) -> Result<Option<GcReport>> {
        if self.quota == 0 {
            return Ok(None);
        }
        let used = self.store.total_size().await?;
        if used <= self.quota {
            return Ok(None);
        }

        // En eski erişilen pinleri unpin et ta ki kota altına inene kadar
        let mut pins_by_age: Vec<(u64, Cid)> = self
            .pins
            .list()
            .iter()
            .map(|r| (r.last_accessed, r.root_cid.clone()))
            .collect();
        pins_by_age.sort_by_key(|(t, _)| *t);

        for (_, cid) in pins_by_age {
            if self.store.total_size().await? <= self.quota {
                break;
            }
            self.unpin(&cid);
        }

        let report = self.gc(false).await?;
        Ok(Some(report))
    }
}

/// GC işlemi sonuç raporu.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GcReport {
    /// Silinen (veya silinecek) blok sayısı.
    pub deleted_blocks: u64,
    /// Serbest bırakılan (veya bırakılacak) byte sayısı.
    pub freed_bytes: u64,
    /// Kuru çalıştırma mı?
    pub dry_run: bool,
}

// ═══════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::content::BlockStore as _;
    use std::sync::Arc;
    use tempfile::tempdir;

    async fn make_store() -> (Arc<FsBlockStore>, tempfile::TempDir) {
        let tmp = tempdir().unwrap();
        let store = Arc::new(
            FsBlockStore::new(tmp.path().join("blocks"), 0).await.unwrap(),
        );
        (store, tmp)
    }

    #[test]
    fn pin_store_add_remove_contains() {
        let mut ps = PinStore::in_memory();
        let cid = Cid::from_data(b"test");
        let record = PinRecord::new(cid.clone(), "pubhex".into(), None, vec![cid.clone()]);

        ps.add(record);
        assert!(ps.contains(&cid));
        assert_eq!(ps.len(), 1);

        ps.remove(&cid);
        assert!(!ps.contains(&cid));
        assert_eq!(ps.len(), 0);
    }

    #[test]
    fn pin_store_all_pinned_cids() {
        let mut ps = PinStore::in_memory();
        let c1 = Cid::from_data(b"block1");
        let c2 = Cid::from_data(b"block2");
        let root = Cid::from_data(b"root");
        let record = PinRecord::new(root.clone(), "pub".into(), None, vec![c1.clone(), c2.clone()]);
        ps.add(record);

        let set = ps.all_pinned_cids();
        assert!(set.contains(&c1));
        assert!(set.contains(&c2));
        assert!(!set.contains(&root)); // root ayrıca belirtilmedi
    }

    #[tokio::test]
    async fn gc_removes_unpinned_blocks() {
        let (store, _tmp) = make_store().await;
        let ps = PinStore::in_memory();
        let mut replicator = Replicator::new(Arc::clone(&store), ps, 0);

        // Blok ekle (pin'siz)
        let data = b"orphan block";
        let cid = store.put(data).await.unwrap();
        assert!(store.has(&cid).await.unwrap());

        // GC çalıştır → orphan blok silinmeli
        let report = replicator.gc(false).await.unwrap();
        assert_eq!(report.deleted_blocks, 1);
        assert!(!store.has(&cid).await.unwrap());
    }

    #[tokio::test]
    async fn gc_keeps_pinned_blocks() {
        let (store, _tmp) = make_store().await;
        let mut ps = PinStore::in_memory();

        let data = b"pinned block";
        let cid = store.put(data).await.unwrap();

        // Pin ekle
        let record = PinRecord::new(cid.clone(), "pub".into(), None, vec![cid.clone()]);
        ps.add(record);

        let replicator = Replicator::new(Arc::clone(&store), ps, 0);
        let report = replicator.gc(false).await.unwrap();

        // Pinlenmiş blok silinmemeli
        assert_eq!(report.deleted_blocks, 0);
        assert!(store.has(&cid).await.unwrap());
    }

    #[tokio::test]
    async fn gc_dry_run_does_not_delete() {
        let (store, _tmp) = make_store().await;
        let ps = PinStore::in_memory();
        let replicator = Replicator::new(Arc::clone(&store), ps, 0);

        let data = b"dry run test";
        let cid = store.put(data).await.unwrap();

        let report = replicator.gc(true).await.unwrap();
        assert_eq!(report.deleted_blocks, 1);
        assert!(report.dry_run);
        // Dry run → blok hâlâ var
        assert!(store.has(&cid).await.unwrap());
    }

    #[tokio::test]
    async fn pin_store_persist_and_reload() {
        let tmp = tempdir().unwrap();
        let cid = Cid::from_data(b"persisted");

        {
            let mut ps = PinStore::open(tmp.path()).await.unwrap();
            let record = PinRecord::new(cid.clone(), "pub".into(), Some("test".into()), vec![cid.clone()]);
            ps.add(record);
            ps.save().await.unwrap();
        }

        {
            let ps = PinStore::open(tmp.path()).await.unwrap();
            assert!(ps.contains(&cid));
            assert_eq!(ps.list()[0].label, Some("test".into()));
        }
    }
}
