//! # AlterNet CRDT Board — Merkezi Koordinasyonsuz Ortak Durum (L7)
//!
//! Automerge CRDT üzerine forum/wiki/pano için genel, çakışmasız ortak durum.
//! İki kullanıcı aynı anda yazabilir; merge ettiklerinde her ikisi de aynı sonuca
//! yakınsar — merkezi sunucu veya koordinatör gerekmez.
//!
//! **Manifesto I:** Ortak durum için merkezi koordinasyon yoktur (CRDT yakınsaması).
//! **Manifesto II:** Her replika eşittir; herkes yazabilir, herkes merge edebilir.
//! **Manifesto IV:** Girdiler yazar imzasıyla ilişkilendirilebilir (üst katman).
//!
//! `crdt.rs` (AlterChat'ten gelen chat-spesifik Room) deseninden uyarlanmıştır;
//! burada genel bir "entry" modeli sunulur (forum başlığı, wiki sayfası, pano notu).
//!
//! ## Tehdit Modeli
//! - **Korunan:** Eşzamanlı düzenleme çakışması (Automerge CRDT determinist merge)
//! - **Sınır:** İçerik moderasyonu yok (Manifesto I) — spam filtresi üst katman/WoT işi
//! - **Sınır:** Girdi özgünlüğü için ayrıca imza gerekir (board kendisi imza zorlamaz)

use automerge::{AutoCommit, ObjType, ROOT, ReadDoc, transaction::Transactable};
use std::time::{SystemTime, UNIX_EPOCH};

/// Bir board girdisi (forum mesajı / wiki revizyonu / pano notu).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoardEntry {
    /// Girdi kimliği (yazar tarafından üretilen benzersiz id).
    pub id: String,
    /// Yazarın `alter://` adresi veya pubkey hex'i.
    pub author: String,
    /// Başlık (forum konusu / wiki sayfa adı).
    pub title: String,
    /// İçerik gövdesi.
    pub body: String,
    /// Oluşturulma zamanı (unix epoch ms).
    pub timestamp: i64,
}

/// CRDT tabanlı board: çakışmasız, dağıtık, merkeziz ortak durum.
pub struct CrdtBoard {
    pub id: String,
    doc: AutoCommit,
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

impl CrdtBoard {
    /// Yeni boş board.
    pub fn new(id: impl Into<String>) -> Self {
        let mut doc = AutoCommit::new();
        doc.put_object(ROOT, "entries", ObjType::List).unwrap();
        Self { id: id.into(), doc }
    }

    /// Serialize edilmiş board'dan yükle.
    pub fn load(id: impl Into<String>, bytes: &[u8]) -> Result<Self, String> {
        let doc = AutoCommit::load(bytes).map_err(|e| e.to_string())?;
        Ok(Self { id: id.into(), doc })
    }

    /// Board'u serialize et (P2P paylaşım / disk için).
    pub fn save(&mut self) -> Vec<u8> {
        self.doc.save()
    }

    /// Yeni bir girdi ekle.
    ///
    /// `id` yazar tarafından üretilir (örn. rastgele veya içerik hash'i); CRDT
    /// determinist merge'i sayesinde eşzamanlı eklemeler çakışmaz.
    pub fn add_entry(
        &mut self,
        id: &str,
        author: &str,
        title: &str,
        body: &str,
    ) -> Result<(), String> {
        let entries = self
            .doc
            .get(ROOT, "entries")
            .map_err(|e| e.to_string())?
            .ok_or("entries listesi yok")?
            .1;

        let idx = self.doc.length(&entries);
        let obj = self
            .doc
            .insert_object(&entries, idx, ObjType::Map)
            .map_err(|e| e.to_string())?;

        self.doc.put(&obj, "id", id).map_err(|e| e.to_string())?;
        self.doc.put(&obj, "author", author).map_err(|e| e.to_string())?;
        self.doc.put(&obj, "title", title).map_err(|e| e.to_string())?;
        self.doc.put(&obj, "body", body).map_err(|e| e.to_string())?;
        self.doc.put(&obj, "timestamp", now_ms()).map_err(|e| e.to_string())?;
        self.doc.commit();
        Ok(())
    }

    /// Başka bir replikanın board'unu merge et (P2P yakınsama).
    ///
    /// Manifesto I: Merkezi koordinasyon olmadan iki replika aynı duruma yakınsar.
    pub fn merge(&mut self, other_bytes: &[u8]) -> Result<(), String> {
        let mut other = AutoCommit::load(other_bytes).map_err(|e| e.to_string())?;
        self.doc.merge(&mut other).map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Tüm girdileri döndür.
    pub fn entries(&self) -> Result<Vec<BoardEntry>, String> {
        let mut result = Vec::new();
        let Some((_, entries)) = self.doc.get(ROOT, "entries").map_err(|e| e.to_string())? else {
            return Ok(result);
        };
        let len = self.doc.length(&entries);
        for i in 0..len {
            if let Some((_, obj)) = self.doc.get(&entries, i).map_err(|e| e.to_string())? {
                let get_str = |k: &str| {
                    self.doc
                        .get(&obj, k)
                        .ok()
                        .flatten()
                        .and_then(|(v, _)| v.to_str().map(|s| s.to_string()))
                        .unwrap_or_default()
                };
                let timestamp = self
                    .doc
                    .get(&obj, "timestamp")
                    .ok()
                    .flatten()
                    .and_then(|(v, _)| v.to_i64())
                    .unwrap_or(0);
                result.push(BoardEntry {
                    id: get_str("id"),
                    author: get_str("author"),
                    title: get_str("title"),
                    body: get_str("body"),
                    timestamp,
                });
            }
        }
        Ok(result)
    }

    /// Girdi sayısı.
    pub fn len(&self) -> usize {
        self.doc
            .get(ROOT, "entries")
            .ok()
            .flatten()
            .map(|(_, e)| self.doc.length(&e))
            .unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

// ═══════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_and_read_entries() {
        let mut board = CrdtBoard::new("forum-1");
        board.add_entry("e1", "alice", "Merhaba", "İlk konu").unwrap();
        board.add_entry("e2", "bob", "Selam", "İkinci konu").unwrap();

        let entries = board.entries().unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].title, "Merhaba");
        assert_eq!(entries[1].author, "bob");
    }

    #[test]
    fn save_load_round_trip() {
        let mut board = CrdtBoard::new("wiki");
        board.add_entry("p1", "alice", "Anasayfa", "İçerik").unwrap();
        let bytes = board.save();

        let loaded = CrdtBoard::load("wiki", &bytes).unwrap();
        let entries = loaded.entries().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].body, "İçerik");
    }

    #[test]
    fn concurrent_edits_converge() {
        // İki replika bağımsız girdiler ekler, sonra merge eder → ikisi de yakınsar.
        // Manifesto I: merkezi koordinasyon olmadan tutarlılık.
        //
        // CRDT deseni: her iki replika AYNI genesis dokümandan başlar (ortak nesne
        // kimlikleri). Bir yayıncı board'u kurar, diğerleri o bytes'tan load eder.
        let genesis = CrdtBoard::new("board").save();
        let mut alice = CrdtBoard::load("board", &genesis).unwrap();
        let mut bob = CrdtBoard::load("board", &genesis).unwrap();

        alice.add_entry("a1", "alice", "Alice'in konusu", "...").unwrap();
        bob.add_entry("b1", "bob", "Bob'un konusu", "...").unwrap();

        // Karşılıklı merge
        let alice_bytes = alice.save();
        let bob_bytes = bob.save();
        alice.merge(&bob_bytes).unwrap();
        bob.merge(&alice_bytes).unwrap();

        // Her iki replika da iki girdiyi de görmeli
        let alice_entries = alice.entries().unwrap();
        let bob_entries = bob.entries().unwrap();
        assert_eq!(alice_entries.len(), 2);
        assert_eq!(bob_entries.len(), 2);

        // Aynı id kümesine yakınsama
        let mut alice_ids: Vec<String> = alice_entries.iter().map(|e| e.id.clone()).collect();
        let mut bob_ids: Vec<String> = bob_entries.iter().map(|e| e.id.clone()).collect();
        alice_ids.sort();
        bob_ids.sort();
        assert_eq!(alice_ids, bob_ids, "iki replika aynı girdilere yakınsamalı");
    }

    #[test]
    fn empty_board() {
        let board = CrdtBoard::new("empty");
        assert!(board.is_empty());
        assert_eq!(board.entries().unwrap().len(), 0);
    }
}
