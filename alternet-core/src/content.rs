//! # AlterNet AlterFS — İçerik Adresli Dağıtık Depolama (L3)
//!
//! BLAKE3 hash ile içerik adresleme, Merkle DAG yapısı ve dosya sistemi tabanlı blok deposu.
//!
//! **Manifesto III:** Her bloğun hash'i anında doğrulanır — sahte içerik enjeksiyonu imkânsızdır.
//! **Manifesto II:** Her cihaz kendi deposunu yönetir; disk kotası kullanıcı tarafından belirlenir.
//!
//! ## Tehdit Modeli
//! - **Korunan:** İçerik bütünlüğü (BLAKE3 hash doğrulaması — SHA-3 benzeri güvenlik)
//! - **Korunan:** Sahte blok enjeksiyonu (CID = BLAKE3(veri), matematiksel garanti)
//! - **Sınır:** DHT üzerinde içerik enumerasyonu mümkün (provider records herkese açık)

use crate::error::{AlterNetError, Result};
use crate::types::{Cid, DagNode, DirEntry, CHUNK_SIZE};
use async_trait::async_trait;
use futures::future::BoxFuture;
use std::path::{Path, PathBuf};

// ═══════════════════════════════════════════════
// BlockStore Trait
// ═══════════════════════════════════════════════

/// Blok deposu soyutlaması.
///
/// Manifesto II: "Her cihaz kendi deposunu yönetir."
#[async_trait]
pub trait BlockStore: Send + Sync {
    async fn put(&self, data: &[u8]) -> Result<Cid>;
    async fn get(&self, cid: &Cid) -> Result<Option<Vec<u8>>>;
    async fn has(&self, cid: &Cid) -> Result<bool>;
    async fn delete(&self, cid: &Cid) -> Result<()>;
    async fn list_cids(&self) -> Result<Vec<Cid>>;
    async fn total_size(&self) -> Result<u64>;
}

// ═══════════════════════════════════════════════
// FsBlockStore
// ═══════════════════════════════════════════════

/// Dosya sistemi tabanlı blok deposu.
///
/// Her blok `<root>/<2-char-prefix>/<full-cid-hex>` konumunda saklanır.
/// Sharding, büyük depolarda dizin performansını korur.
pub struct FsBlockStore {
    root: PathBuf,
    quota: u64,
}

impl FsBlockStore {
    pub async fn new(root: PathBuf, quota: u64) -> Result<Self> {
        tokio::fs::create_dir_all(&root).await?;
        Ok(Self { root, quota })
    }

    /// Blok dosyasının tam yolunu döndür.
    pub fn block_path(&self, cid: &Cid) -> PathBuf {
        let hex = cid.to_hex();
        self.root.join(&hex[..2]).join(&hex)
    }
}

#[async_trait]
impl BlockStore for FsBlockStore {
    async fn put(&self, data: &[u8]) -> Result<Cid> {
        let cid = Cid::from_data(data);
        let path = self.block_path(&cid);
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        if !path.exists() {
            if self.quota > 0 {
                let current = self.total_size().await?;
                if current + data.len() as u64 > self.quota {
                    return Err(AlterNetError::QuotaExceeded {
                        used: current,
                        quota: self.quota,
                    });
                }
            }
            tokio::fs::write(&path, data).await?;
        }
        Ok(cid)
    }

    async fn get(&self, cid: &Cid) -> Result<Option<Vec<u8>>> {
        let path = self.block_path(cid);
        if !path.exists() {
            return Ok(None);
        }
        let data = tokio::fs::read(&path).await?;
        if !cid.verify(&data) {
            return Err(AlterNetError::HashMismatch {
                expected: cid.to_hex(),
                computed: Cid::from_data(&data).to_hex(),
            });
        }
        Ok(Some(data))
    }

    async fn has(&self, cid: &Cid) -> Result<bool> {
        Ok(self.block_path(cid).exists())
    }

    async fn delete(&self, cid: &Cid) -> Result<()> {
        let path = self.block_path(cid);
        if path.exists() {
            tokio::fs::remove_file(&path).await?;
        }
        Ok(())
    }

    async fn list_cids(&self) -> Result<Vec<Cid>> {
        let mut cids = Vec::new();
        if !self.root.exists() {
            return Ok(cids);
        }
        let mut dir = tokio::fs::read_dir(&self.root).await?;
        while let Some(subdir_entry) = dir.next_entry().await? {
            if subdir_entry.file_type().await?.is_dir() {
                let mut subdir = tokio::fs::read_dir(subdir_entry.path()).await?;
                while let Some(file_entry) = subdir.next_entry().await? {
                    let name = file_entry.file_name().to_string_lossy().to_string();
                    if let Ok(cid) = Cid::from_hex(&name) {
                        cids.push(cid);
                    }
                }
            }
        }
        Ok(cids)
    }

    async fn total_size(&self) -> Result<u64> {
        let mut total = 0u64;
        if !self.root.exists() {
            return Ok(total);
        }
        let mut dir = tokio::fs::read_dir(&self.root).await?;
        while let Some(subdir_entry) = dir.next_entry().await? {
            if subdir_entry.file_type().await?.is_dir() {
                let mut subdir = tokio::fs::read_dir(subdir_entry.path()).await?;
                while let Some(file_entry) = subdir.next_entry().await? {
                    if let Ok(meta) = file_entry.metadata().await {
                        total += meta.len();
                    }
                }
            }
        }
        Ok(total)
    }
}

// ═══════════════════════════════════════════════
// CBOR Helpers
// ═══════════════════════════════════════════════

pub fn cbor_encode<T: serde::Serialize>(value: &T) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    ciborium::into_writer(value, &mut buf)
        .map_err(|e| AlterNetError::CborEncode(e.to_string()))?;
    Ok(buf)
}

pub fn cbor_decode<T: serde::de::DeserializeOwned>(data: &[u8]) -> Result<T> {
    ciborium::from_reader(data)
        .map_err(|e| AlterNetError::CborDecode(e.to_string()))
}

// ═══════════════════════════════════════════════
// DAG Builder
// ═══════════════════════════════════════════════

/// Bir yoldan Merkle DAG oluştur, tüm blokları depola ve kök CID'i döndür.
///
/// Manifesto III: Her blok BLAKE3 ile hash'lenir — sahte içerik mümkün değildir.
/// Dizin yapısı özyinelemeli olduğundan `BoxFuture` kullanılır.
pub fn build_dag<'a>(store: &'a dyn BlockStore, path: &'a Path) -> BoxFuture<'a, Result<Cid>> {
    build_dag_keyed(store, path, None)
}

/// `build_dag`'in opsiyonel içerik şifreleme anahtarlı sürümü (Faz 6 — F8).
///
/// `key` verilirse her **leaf** (dosya içeriği) bloğu AES-256-GCM ile şifrelenir;
/// CID = BLAKE3(ciphertext). Dizin/Internal yapı düğümleri cleartext kalır — yani
/// dosya adları ve boyutlar görünür, **içerik anahtarsız okunamaz** (Manifesto III).
/// Bu bir kapatma bayrağı değildir; transport şifrelemesi her hâlükârda açıktır.
pub fn build_dag_keyed<'a>(
    store: &'a dyn BlockStore,
    path: &'a Path,
    key: Option<[u8; 32]>,
) -> BoxFuture<'a, Result<Cid>> {
    Box::pin(async move {
        if path.is_dir() {
            build_dir_dag(store, path, key).await
        } else {
            build_file_dag(store, path, key).await
        }
    })
}

/// Leaf verisini (opsiyonel) şifreleyip CBOR Leaf düğümü olarak depola.
async fn put_leaf(store: &dyn BlockStore, data: Vec<u8>, key: Option<[u8; 32]>) -> Result<Cid> {
    let stored = match key {
        Some(k) => crate::crypto::encrypt_content(&k, &data)
            .map_err(|e| AlterNetError::Crypto(e.to_string()))?,
        None => data,
    };
    let node = DagNode::Leaf { data: stored };
    let encoded = cbor_encode(&node)?;
    store.put(&encoded).await
}

async fn build_file_dag(store: &dyn BlockStore, path: &Path, key: Option<[u8; 32]>) -> Result<Cid> {
    let data = tokio::fs::read(path).await?;

    if data.len() <= CHUNK_SIZE {
        put_leaf(store, data, key).await
    } else {
        let mut links = Vec::new();
        let total_size = data.len() as u64;
        for chunk in data.chunks(CHUNK_SIZE) {
            let cid = put_leaf(store, chunk.to_vec(), key).await?;
            links.push(cid);
        }
        let node = DagNode::Internal { links, total_size };
        let encoded = cbor_encode(&node)?;
        store.put(&encoded).await
    }
}

async fn build_dir_dag(store: &dyn BlockStore, path: &Path, key: Option<[u8; 32]>) -> Result<Cid> {
    let mut entries = Vec::new();
    let mut read_dir = tokio::fs::read_dir(path).await?;

    while let Some(entry) = read_dir.next_entry().await? {
        let name = entry.file_name().to_string_lossy().to_string();
        if name.starts_with('.') {
            continue;
        }
        let entry_path = entry.path();
        let is_dir = entry.file_type().await?.is_dir();

        let cid = build_dag_keyed(store, &entry_path, key).await?;
        let size = dag_size(store, &cid).await?;
        entries.push(DirEntry { name, cid, size, is_dir });
    }

    // Deterministik sıralama — aynı içerik her zaman aynı CID
    entries.sort_by(|a, b| a.name.cmp(&b.name));

    let node = DagNode::Directory { entries };
    let encoded = cbor_encode(&node)?;
    store.put(&encoded).await
}

async fn dag_size(store: &dyn BlockStore, cid: &Cid) -> Result<u64> {
    let data = store
        .get(cid)
        .await?
        .ok_or_else(|| AlterNetError::BlockNotFound { cid: cid.to_hex() })?;
    let node: DagNode = cbor_decode(&data)?;
    match node {
        DagNode::Leaf { data } => Ok(data.len() as u64),
        DagNode::Internal { total_size, .. } => Ok(total_size),
        DagNode::Directory { entries } => Ok(entries.iter().map(|e| e.size).sum()),
    }
}

// ═══════════════════════════════════════════════
// DAG Extractor
// ═══════════════════════════════════════════════

/// Merkle DAG'ı dosya sistemine çıkar.
///
/// Manifesto III: Her bloğun hash'i çıkarma sırasında doğrulanır.
/// Dizin yapısı özyinelemeli olduğundan `BoxFuture` kullanılır.
pub fn extract_dag<'a>(
    store: &'a dyn BlockStore,
    root_cid: &'a Cid,
    dest: &'a Path,
) -> BoxFuture<'a, Result<()>> {
    extract_dag_keyed(store, root_cid, dest, None)
}

/// Leaf verisini (opsiyonel) çöz.
fn decode_leaf(data: Vec<u8>, key: Option<[u8; 32]>) -> Result<Vec<u8>> {
    match key {
        Some(k) => crate::crypto::decrypt_content(&k, &data)
            .map_err(|e| AlterNetError::Crypto(e.to_string())),
        None => Ok(data),
    }
}

/// `extract_dag`'in opsiyonel içerik şifre-çözme anahtarlı sürümü (Faz 6 — F8).
///
/// `key` verilirse leaf blokları AES-256-GCM ile çözülür. Yanlış anahtar → hata
/// (Manifesto III: içerik anahtarsız okunamaz).
pub fn extract_dag_keyed<'a>(
    store: &'a dyn BlockStore,
    root_cid: &'a Cid,
    dest: &'a Path,
    key: Option<[u8; 32]>,
) -> BoxFuture<'a, Result<()>> {
    Box::pin(async move {
        let data = store
            .get(root_cid)
            .await?
            .ok_or_else(|| AlterNetError::BlockNotFound { cid: root_cid.to_hex() })?;

        let node: DagNode = cbor_decode(&data)?;

        match node {
            DagNode::Leaf { data } => {
                let plain = decode_leaf(data, key)?;
                if let Some(parent) = dest.parent() {
                    tokio::fs::create_dir_all(parent).await?;
                }
                tokio::fs::write(dest, &plain).await?;
            }
            DagNode::Internal { links, .. } => {
                let mut full_data = Vec::new();
                for chunk_cid in &links {
                    let chunk_data = store
                        .get(chunk_cid)
                        .await?
                        .ok_or_else(|| AlterNetError::BlockNotFound { cid: chunk_cid.to_hex() })?;
                    let chunk_node: DagNode = cbor_decode(&chunk_data)?;
                    if let DagNode::Leaf { data } = chunk_node {
                        full_data.extend_from_slice(&decode_leaf(data, key)?);
                    } else {
                        return Err(AlterNetError::DagCorrupted(
                            "Internal düğüm çocuğu Leaf değil".into(),
                        ));
                    }
                }
                if let Some(parent) = dest.parent() {
                    tokio::fs::create_dir_all(parent).await?;
                }
                tokio::fs::write(dest, &full_data).await?;
            }
            DagNode::Directory { entries } => {
                tokio::fs::create_dir_all(dest).await?;
                for entry in entries {
                    let entry_dest = dest.join(&entry.name);
                    extract_dag_keyed(store, &entry.cid, &entry_dest, key).await?;
                }
            }
        }

        Ok(())
    })
}

/// DAG'daki tüm CID'leri topla (BFS — DHT provider duyurusu için).
pub async fn collect_all_cids(store: &dyn BlockStore, root_cid: &Cid) -> Result<Vec<Cid>> {
    let mut result = Vec::new();
    let mut queue = vec![root_cid.clone()];

    while let Some(cid) = queue.pop() {
        result.push(cid.clone());
        if let Some(data) = store.get(&cid).await? {
            let node: DagNode = cbor_decode(&data)?;
            match node {
                DagNode::Leaf { .. } => {}
                DagNode::Internal { links, .. } => queue.extend(links),
                DagNode::Directory { entries } => {
                    queue.extend(entries.into_iter().map(|e| e.cid));
                }
            }
        }
    }

    Ok(result)
}

// ═══════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    async fn make_store() -> (FsBlockStore, tempfile::TempDir) {
        let dir = tempdir().unwrap();
        let store = FsBlockStore::new(dir.path().join("blocks"), 0).await.unwrap();
        (store, dir)
    }

    #[tokio::test]
    async fn put_get_verify() {
        let (store, _tmp) = make_store().await;
        let data = b"Manifesto VII: kod yalan soylemez";
        let cid = store.put(data).await.unwrap();
        let retrieved = store.get(&cid).await.unwrap().unwrap();
        assert_eq!(data.to_vec(), retrieved);
    }

    #[tokio::test]
    async fn has_and_delete() {
        let (store, _tmp) = make_store().await;
        let data = b"test block";
        let cid = store.put(data).await.unwrap();
        assert!(store.has(&cid).await.unwrap());
        store.delete(&cid).await.unwrap();
        assert!(!store.has(&cid).await.unwrap());
    }

    #[tokio::test]
    async fn build_and_extract_small_file() {
        let (store, tmp) = make_store().await;
        let src = tmp.path().join("index.html");
        tokio::fs::write(&src, b"<h1>Hello AlterNet</h1>").await.unwrap();

        let root_cid = build_dag(&store, &src).await.unwrap();

        let out = tmp.path().join("out.html");
        extract_dag(&store, &root_cid, &out).await.unwrap();

        let content = tokio::fs::read(&out).await.unwrap();
        assert_eq!(content, b"<h1>Hello AlterNet</h1>");
    }

    #[tokio::test]
    async fn build_and_extract_directory() {
        let (store, tmp) = make_store().await;
        let src_dir = tmp.path().join("site");
        tokio::fs::create_dir_all(&src_dir).await.unwrap();
        tokio::fs::write(src_dir.join("index.html"), b"<h1>AlterNet</h1>").await.unwrap();
        tokio::fs::write(src_dir.join("style.css"), b"body{margin:0}").await.unwrap();

        let root_cid = build_dag(&store, &src_dir).await.unwrap();

        let out_dir = tmp.path().join("out");
        extract_dag(&store, &root_cid, &out_dir).await.unwrap();

        let html = tokio::fs::read(out_dir.join("index.html")).await.unwrap();
        let css = tokio::fs::read(out_dir.join("style.css")).await.unwrap();
        assert_eq!(html, b"<h1>AlterNet</h1>");
        assert_eq!(css, b"body{margin:0}");
    }

    #[tokio::test]
    async fn deterministic_cid() {
        let (store1, tmp) = make_store().await;
        let (store2, _tmp2) = make_store().await;

        let path = tmp.path().join("file.txt");
        tokio::fs::write(&path, b"hello alternet").await.unwrap();

        let cid1 = build_dag(&store1, &path).await.unwrap();
        let cid2 = build_dag(&store2, &path).await.unwrap();
        assert_eq!(cid1, cid2, "Aynı içerik her zaman aynı CID");
    }

    #[tokio::test]
    async fn collect_cids_non_empty() {
        let (store, tmp) = make_store().await;
        let src_dir = tmp.path().join("site");
        tokio::fs::create_dir_all(&src_dir).await.unwrap();
        tokio::fs::write(src_dir.join("index.html"), b"hello").await.unwrap();
        let root_cid = build_dag(&store, &src_dir).await.unwrap();
        let cids = collect_all_cids(&store, &root_cid).await.unwrap();
        assert!(!cids.is_empty());
        assert!(cids.contains(&root_cid));
    }

    #[tokio::test]
    async fn large_file_multi_chunk() {
        // 256KB'dan büyük dosya → Internal node + birden fazla Leaf oluşmalı
        let (store, tmp) = make_store().await;
        let big: Vec<u8> = (0u32..).map(|i| (i % 251) as u8).take(CHUNK_SIZE * 3 + 1).collect();
        let path = tmp.path().join("big.bin");
        tokio::fs::write(&path, &big).await.unwrap();

        let root_cid = build_dag(&store, &path).await.unwrap();

        // En az 4 blok (3 chunk leaf + 1 internal) olmalı
        let cids = collect_all_cids(&store, &root_cid).await.unwrap();
        assert!(cids.len() >= 4, "büyük dosya birden fazla blok üretmeli");

        // Round-trip doğrulama
        let out = tmp.path().join("big_out.bin");
        extract_dag(&store, &root_cid, &out).await.unwrap();
        let result = tokio::fs::read(&out).await.unwrap();
        assert_eq!(result, big, "büyük dosya byte-perfect round-trip");
    }

    #[tokio::test]
    async fn corrupt_block_rejected() {
        // Depodaki bloğu bozuk veriyle değiştir → CID::verify false dönmeli
        let (store, tmp) = make_store().await;
        let data = b"gercek veri";
        let cid = store.put(data).await.unwrap();

        // Depodan aldığımızda doğru
        let retrieved = store.get(&cid).await.unwrap().unwrap();
        assert!(cid.verify(&retrieved));

        // Bozuk veri CID'i doğrulamamalı
        let corrupt = b"bozulmus veri";
        assert!(!cid.verify(corrupt), "bozuk veri CID doğrulamasını geçemez");

        // Farklı CID — doğru veriyle eşleşmemeli
        let other_cid = Cid::from_data(b"farkli veri");
        assert!(!other_cid.verify(data), "yanlış CID doğrulanamaz");

        let _ = tmp; // TempDir canlı tut
    }

    #[tokio::test]
    async fn encrypted_content_round_trip() {
        let (store, tmp) = make_store().await;
        let key = crate::crypto::derive_content_key("gizli-site-parolasi");

        let src = tmp.path().join("secret.html");
        let body = b"<h1>Manifesto III: icerik anahtarsiz okunamaz</h1>";
        tokio::fs::write(&src, body).await.unwrap();

        // Şifreli DAG kur
        let root = build_dag_keyed(&store, &src, Some(key)).await.unwrap();

        // Doğru anahtarla çöz → byte-perfect
        let out = tmp.path().join("out.html");
        extract_dag_keyed(&store, &root, &out, Some(key)).await.unwrap();
        assert_eq!(tokio::fs::read(&out).await.unwrap(), body);

        // Yanlış anahtarla çöz → hata
        let wrong = crate::crypto::derive_content_key("yanlis");
        let out2 = tmp.path().join("out2.html");
        assert!(
            extract_dag_keyed(&store, &root, &out2, Some(wrong)).await.is_err(),
            "yanlış anahtar içeriği çözememeli"
        );

        // Anahtarsız çöz → leaf cleartext değil (decode başarısız ya da bozuk)
        let out3 = tmp.path().join("out3.html");
        let plain_attempt = extract_dag_keyed(&store, &root, &out3, None).await;
        // Şifreli baytlar düz okunursa orijinalle eşleşmemeli
        if plain_attempt.is_ok() {
            assert_ne!(tokio::fs::read(&out3).await.unwrap(), body);
        }
    }

    #[tokio::test]
    async fn empty_file_and_empty_dir() {
        let (store, tmp) = make_store().await;

        // Boş dosya
        let empty_file = tmp.path().join("empty.txt");
        tokio::fs::write(&empty_file, b"").await.unwrap();
        let cid = build_dag(&store, &empty_file).await.unwrap();
        let out = tmp.path().join("empty_out.txt");
        extract_dag(&store, &cid, &out).await.unwrap();
        let content = tokio::fs::read(&out).await.unwrap();
        assert_eq!(content, b"", "boş dosya round-trip");

        // Boş dizin
        let empty_dir = tmp.path().join("emptydir");
        tokio::fs::create_dir_all(&empty_dir).await.unwrap();
        let cid2 = build_dag(&store, &empty_dir).await.unwrap();
        let out_dir = tmp.path().join("emptydir_out");
        extract_dag(&store, &cid2, &out_dir).await.unwrap();
        assert!(out_dir.is_dir(), "boş dizin çıkarılmalı");
    }
}
