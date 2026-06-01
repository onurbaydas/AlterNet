//! Paylaşılan uygulama durumu.

use alternet_core::{
    config::AlterNetConfig,
    content::FsBlockStore,
    network::NodeHandle,
};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

/// Tarayıcı durum kapsayıcısı.
///
/// Tauri `manage()` ile global state olarak kaydedilir.
/// Her IPC komutu `tauri::State<BrowserState>` ile erişir.
pub struct BrowserState {
    pub inner: Mutex<BrowserStateInner>,
}

pub struct BrowserStateInner {
    /// libp2p node handle (None = henüz başlatılmadı).
    pub node: Option<Arc<NodeHandle>>,
    /// Blok deposu.
    pub store: Option<Arc<FsBlockStore>>,
    /// Kullanıcı yapılandırması.
    pub config: AlterNetConfig,
    /// Site çekme durumu: pubkey_hex → FetchStatus
    pub fetch_status: HashMap<String, FetchStatus>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub enum FetchStatus {
    Idle,
    Fetching { progress: u8 },
    Ready { path: String },
    Error { message: String },
}

impl BrowserState {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(BrowserStateInner {
                node: None,
                store: None,
                config: AlterNetConfig::default(),
                fetch_status: HashMap::new(),
            }),
        }
    }
}

impl Default for BrowserState {
    fn default() -> Self {
        Self::new()
    }
}
