//! # AlterNet Network Layer — libp2p Swarm & P2P Bağlantısı
//!
//! AlterNet'in ağ katmanı: Kademlia DHT, mDNS yerel keşif,
//! request-response blok değişimi, NAT traversal.
//!
//! **Manifesto I:** Hiçbir merkezi node otorite değildir. Bootstrap node'lar opsiyoneldir.
//! **Manifesto VI:** mDNS ile sıfır yapılandırmayla yerel ağda çalışır.
//!
//! ## Tehdit Modeli
//! - **Korunan:** MITM saldırısı (Noise Protocol, Ed25519 peer kimliği)
//! - **Korunan:** Replay (Noise protokolü nonce ile önler)
//! - **Sınır:** DHT eclipse saldırısı (S/Kademlia ile azaltılabilir — gelecek geliştirme)
//! - **Sınır:** Sybil saldırısı (PoW eklenebilir — Faz 4)

use crate::config::AlterNetConfig;
use crate::content::FsBlockStore;
use crate::error::{AlterNetError, Result};
use crate::exchange::{ExchangeRequest, ExchangeResponse};
use crate::types::Cid;
use libp2p::{
    PeerId, StreamProtocol, Swarm, SwarmBuilder,
    core::Transport as _,
    dcutr, identify, kad, mdns, noise, relay, request_response,
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp, yamux,
};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};

// ═══════════════════════════════════════════════
// AlterNet Behaviour
// ═══════════════════════════════════════════════

/// AlterNet libp2p behaviour bileşimi.
///
/// Gossipsub yok (AlterNet'te topic-based broadcast gerekmez).
/// Kademlia: DHT provider records + key-value.
/// mDNS: yerel ağda sıfır yapılandırma keşif.
/// request-response: AlterExchange blok transferi.
#[derive(NetworkBehaviour)]
pub struct AlterNetBehaviour {
    pub kademlia: kad::Behaviour<kad::store::MemoryStore>,
    pub mdns: mdns::tokio::Behaviour,
    pub identify: identify::Behaviour,
    pub request_response:
        request_response::cbor::Behaviour<ExchangeRequest, ExchangeResponse>,
    pub relay_server: relay::Behaviour,
    pub relay_client: relay::client::Behaviour,
    pub dcutr: dcutr::Behaviour,
}

// ═══════════════════════════════════════════════
// Node Commands & Handle
// ═══════════════════════════════════════════════

type ReplyOnce<T> = oneshot::Sender<Result<T>>;

enum NodeCommand {
    ListenOn(libp2p::Multiaddr, ReplyOnce<libp2p::Multiaddr>),
    DialAddr(libp2p::Multiaddr),
    PutRecord {
        key: kad::RecordKey,
        value: Vec<u8>,
        reply: ReplyOnce<()>,
    },
    GetRecord {
        key: kad::RecordKey,
        reply: ReplyOnce<Vec<u8>>,
    },
    StartProviding {
        key: kad::RecordKey,
        reply: ReplyOnce<()>,
    },
    GetProviders {
        key: kad::RecordKey,
        reply: ReplyOnce<Vec<PeerId>>,
    },
    SendBlockRequest {
        peer: PeerId,
        request: ExchangeRequest,
        reply: ReplyOnce<ExchangeResponse>,
    },
    KnownPeers {
        reply: ReplyOnce<Vec<PeerId>>,
    },
}

/// AlterNet node'u için async handle.
///
/// Swarm'ı arkaplanda çalıştırır ve async DHT + blok değişimi sunar.
///
/// `privacy`: gizlilik seviyesi (Manifesto III/V). `request_block` bu seviyeye göre
/// time-blind gecikme uygular ve istekleri 512B kovalarına padler.
pub struct NodeHandle {
    cmd_tx: mpsc::UnboundedSender<NodeCommand>,
    local_peer_id: PeerId,
    privacy: crate::routing::PrivacyConfig,
    x25519_pubkey: [u8; 32],
}

impl NodeHandle {
    pub fn local_peer_id(&self) -> PeerId {
        self.local_peer_id
    }

    /// Aktif gizlilik yapılandırması.
    pub fn privacy(&self) -> &crate::routing::PrivacyConfig {
        &self.privacy
    }

    /// Bu node'un onion routing X25519 public key'i.
    ///
    /// Diğer node'lar bu anahtarı onion route inşasında relay katmanını
    /// şifrelemek için kullanır (Manifesto V).
    pub fn x25519_pubkey(&self) -> [u8; 32] {
        self.x25519_pubkey
    }

    /// Bağlı/bilinen peer'ların anlık listesi (chaff hedefleme için).
    pub async fn known_peers(&self) -> Result<Vec<PeerId>> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.send(NodeCommand::KnownPeers { reply: reply_tx })?;
        reply_rx.await.map_err(|_| AlterNetError::Network("node yanıt vermedi".into()))?
    }

    /// Bir peer'a sahte (chaff) istek gönder — pasif gözlemci gerçek/sahte ayırt edemez.
    /// Manifesto V: metadata sızdırılmaz. Yanıt yok sayılır.
    pub async fn send_chaff(&self, peer: PeerId) -> Result<()> {
        // Sahte CID'lerle HaveQuery — gerçek bir blok sorgusuyla aynı yapıda görünür.
        let fake = crate::traffic::generate_chaff_payload();
        let cid = Cid::from_data(&fake);
        let (reply_tx, reply_rx) = oneshot::channel();
        self.send(NodeCommand::SendBlockRequest {
            peer,
            request: ExchangeRequest::HaveQuery { cids: vec![cid] },
            reply: reply_tx,
        })?;
        // Yanıtı bekle ama yok say (chaff'in amacı yalnızca trafik üretmek).
        let _ = reply_rx.await;
        Ok(())
    }

    /// Verilen portta dinlemeye başla, gerçek adresi döndür.
    pub async fn listen_on(&self, port: u16) -> Result<libp2p::Multiaddr> {
        let addr: libp2p::Multiaddr = format!("/ip4/0.0.0.0/tcp/{port}")
            .parse()
            .map_err(|e| AlterNetError::Network(format!("geçersiz adres: {e}")))?;
        let (reply_tx, reply_rx) = oneshot::channel();
        self.send(NodeCommand::ListenOn(addr, reply_tx))?;
        reply_rx.await.map_err(|_| AlterNetError::Network("node yanıt vermedi".into()))?
    }

    /// Bir adrese bağlan (bootstrap veya bilinen peer).
    pub fn dial(&self, addr: libp2p::Multiaddr) -> Result<()> {
        self.send(NodeCommand::DialAddr(addr))
    }

    /// Manifest'i DHT'ye kaydet.
    pub async fn put_manifest(&self, pubkey_hex: &str, manifest_bytes: Vec<u8>) -> Result<()> {
        let key = crate::crypto::get_dht_manifest_key(pubkey_hex);
        let (reply_tx, reply_rx) = oneshot::channel();
        self.send(NodeCommand::PutRecord { key, value: manifest_bytes, reply: reply_tx })?;
        reply_rx.await.map_err(|_| AlterNetError::Network("node yanıt vermedi".into()))?
    }

    /// Manifest'i DHT'den al.
    pub async fn get_manifest(&self, pubkey_hex: &str) -> Result<Vec<u8>> {
        let key = crate::crypto::get_dht_manifest_key(pubkey_hex);
        let (reply_tx, reply_rx) = oneshot::channel();
        self.send(NodeCommand::GetRecord { key, reply: reply_tx })?;
        reply_rx.await.map_err(|_| AlterNetError::Network("node yanıt vermedi".into()))?
    }

    /// Rastgele string anahtarla DHT'ye kayıt yaz (petname, zone, etiket, relay-key için).
    ///
    /// Anahtar string'i SHA256 ile DHT RecordKey'e dönüştürülür (deterministik, çakışmasız).
    pub async fn put_dht(&self, key_str: &str, value: Vec<u8>) -> Result<()> {
        let key = dht_key_from_str(key_str);
        let (reply_tx, reply_rx) = oneshot::channel();
        self.send(NodeCommand::PutRecord { key, value, reply: reply_tx })?;
        reply_rx.await.map_err(|_| AlterNetError::Network("node yanıt vermedi".into()))?
    }

    /// String anahtarla DHT'den kayıt oku.
    pub async fn get_dht(&self, key_str: &str) -> Result<Vec<u8>> {
        let key = dht_key_from_str(key_str);
        let (reply_tx, reply_rx) = oneshot::channel();
        self.send(NodeCommand::GetRecord { key, reply: reply_tx })?;
        reply_rx.await.map_err(|_| AlterNetError::Network("node yanıt vermedi".into()))?
    }

    /// Bu node'un onion relay X25519 anahtarını DHT'ye duyur.
    ///
    /// Diğer node'lar `get_relay_key` ile bunu alıp bu node'u onion route'ta relay veya
    /// hedef olarak kullanabilir (Manifesto V — çok-hop anonimlik için anahtar dağıtımı).
    pub async fn announce_relay_key(&self) -> Result<()> {
        let key = format!("/alternet/relaykey/{}", self.local_peer_id);
        self.put_dht(&key, self.x25519_pubkey.to_vec()).await
    }

    /// Bir peer'ın onion relay X25519 anahtarını DHT'den al.
    pub async fn get_relay_key(&self, peer: PeerId) -> Result<[u8; 32]> {
        let key = format!("/alternet/relaykey/{peer}");
        let bytes = self.get_dht(&key).await?;
        bytes
            .try_into()
            .map_err(|_| AlterNetError::Network("geçersiz relay anahtarı (32 byte değil)".into()))
    }

    /// Blok CID'ini DHT'de duyur (provider record).
    pub async fn start_providing(&self, cid: &Cid) -> Result<()> {
        let key = cid_to_dht_key(cid);
        let (reply_tx, reply_rx) = oneshot::channel();
        self.send(NodeCommand::StartProviding { key, reply: reply_tx })?;
        reply_rx.await.map_err(|_| AlterNetError::Network("node yanıt vermedi".into()))?
    }

    /// CID'in sağlayıcılarını DHT'den bul.
    pub async fn get_providers(&self, cid: &Cid) -> Result<Vec<PeerId>> {
        let key = cid_to_dht_key(cid);
        let (reply_tx, reply_rx) = oneshot::channel();
        self.send(NodeCommand::GetProviders { key, reply: reply_tx })?;
        reply_rx.await.map_err(|_| AlterNetError::Network("node yanıt vermedi".into()))?
    }

    /// Belirli bir peer'dan blok iste, CID doğrulamasını yap ve ham veriyi döndür.
    ///
    /// Manifesto III: Hash doğrulaması burada zorunludur — kütüphane seviyesinde garantidir.
    /// Manifesto V: Gizlilik seviyesi `Padded+` ise time-blind gecikme uygulanır ve
    /// istek 512B kovasına padlenir (trafik analizi karşıtı).
    pub async fn request_block(&self, peer: PeerId, cid: &Cid) -> Result<Vec<u8>> {
        // Time-blind gecikme: gerçek gönderim zamanını gizler (Manifesto V).
        if self.privacy.level.at_least_padded() && self.privacy.time_blind_enabled {
            let ms = crate::traffic::time_blind_delay_ms();
            tokio::time::sleep(Duration::from_millis(ms)).await;
        }

        // İstek dolgusu: Padded+ ise CBOR boyutunu 512B katına yuvarla.
        let pad = if self.privacy.level.at_least_padded() {
            let base = ExchangeRequest::WantBlock { cid: cid.clone(), pad: Vec::new() };
            let mut buf = Vec::new();
            ciborium::into_writer(&base, &mut buf).ok();
            crate::traffic::random_pad(crate::traffic::pad_to_block_len(buf.len()))
        } else {
            Vec::new()
        };

        let (reply_tx, reply_rx) = oneshot::channel();
        self.send(NodeCommand::SendBlockRequest {
            peer,
            request: ExchangeRequest::WantBlock { cid: cid.clone(), pad },
            reply: reply_tx,
        })?;
        let response = reply_rx
            .await
            .map_err(|_| AlterNetError::Network("node yanıt vermedi".into()))??;
        match response {
            ExchangeResponse::Block { cid: resp_cid, data } => {
                // DoS koruması: aşırı büyük blok reddedilir (Manifesto V).
                if data.len() > crate::types::MAX_BLOCK_SIZE {
                    return Err(AlterNetError::Network(format!(
                        "blok boyutu sınırı aşıldı: {} > {}",
                        data.len(),
                        crate::types::MAX_BLOCK_SIZE
                    )));
                }
                if !resp_cid.verify(&data) {
                    return Err(AlterNetError::HashMismatch {
                        expected: cid.to_hex(),
                        computed: Cid::from_data(&data).to_hex(),
                    });
                }
                Ok(data)
            }
            ExchangeResponse::DontHave { .. } => {
                Err(AlterNetError::BlockNotFound { cid: cid.to_hex() })
            }
            _ => Err(AlterNetError::Network("beklenmeyen yanıt tipi".into())),
        }
    }

    /// Onion sarılı blok isteği gönder.
    ///
    /// `OnionBlockRequest.packet` Sphinx ile şifrelenmiş, `first_hop` ilk relay'e gönderilir.
    /// İlk hop paketi soyar, sonraki hop'a ya da doğrudan hedef peer'a iletir.
    ///
    /// Manifesto V: Gönderenin kimliği onion katmanları tarafından gizlenir.
    pub async fn request_block_onion(
        &self,
        req: crate::routing::OnionBlockRequest,
    ) -> Result<Vec<u8>> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.send(NodeCommand::SendBlockRequest {
            peer: req.first_hop,
            request: crate::exchange::ExchangeRequest::OnionForward {
                packet: req.packet,
                reply_pubkey: Vec::new(), // TODO: ephemeral reply key
            },
            reply: reply_tx,
        })?;
        let response = reply_rx
            .await
            .map_err(|_| AlterNetError::Network("node yanıt vermedi".into()))??;
        match response {
            crate::exchange::ExchangeResponse::OnionResult { encrypted_data } => {
                // Yanıt şifrelenmiş; reply key ile çözülmeli (şimdilik ham döndür)
                Ok(encrypted_data)
            }
            crate::exchange::ExchangeResponse::Block { cid: resp_cid, data } => {
                // Relay CID doğrulaması yaparak Block olarak yanıt verdiyse
                if !resp_cid.verify(&data) {
                    return Err(AlterNetError::HashMismatch {
                        expected: resp_cid.to_hex(),
                        computed: Cid::from_data(&data).to_hex(),
                    });
                }
                Ok(data)
            }
            _ => Err(AlterNetError::Network("beklenmeyen onion yanıtı".into())),
        }
    }

    fn send(&self, cmd: NodeCommand) -> Result<()> {
        self.cmd_tx
            .send(cmd)
            .map_err(|_| AlterNetError::Network("node kapatılmış".into()))
    }
}

fn cid_to_dht_key(cid: &Cid) -> kad::RecordKey {
    kad::RecordKey::new(&cid.0)
}

/// Rastgele string anahtarı deterministik DHT RecordKey'e dönüştür (BLAKE3).
fn dht_key_from_str(key_str: &str) -> kad::RecordKey {
    kad::RecordKey::new(&blake3::hash(key_str.as_bytes()).as_bytes())
}

// ═══════════════════════════════════════════════
// Swarm Kurulumu
// ═══════════════════════════════════════════════

/// AlterNet node'unu başlat ve `NodeHandle` döndür.
///
/// Swarm arkaplanda çalışır. `block_store` gelen blok isteklerini karşılar.
pub async fn spawn_node(
    keypair: libp2p::identity::Keypair,
    config: AlterNetConfig,
    block_store: Arc<FsBlockStore>,
) -> Result<NodeHandle> {
    inner_spawn(keypair, config, block_store)
        .await
        .map_err(|e| AlterNetError::Network(e.to_string()))
}

async fn inner_spawn(
    keypair: libp2p::identity::Keypair,
    config: AlterNetConfig,
    block_store: Arc<FsBlockStore>,
) -> std::result::Result<NodeHandle, Box<dyn std::error::Error>> {
    let local_peer_id = PeerId::from(keypair.public());

    let mut kad_cfg = kad::Config::default();
    kad_cfg.set_query_timeout(Duration::from_secs(5 * 60));
    let kad_store = kad::store::MemoryStore::new(local_peer_id);
    let mut kademlia = kad::Behaviour::with_config(local_peer_id, kad_store, kad_cfg);
    // Her node server modunda: hem sorgular hem yanıt verir — Manifesto II
    kademlia.set_mode(Some(kad::Mode::Server));

    let mdns = mdns::tokio::Behaviour::new(mdns::Config::default(), local_peer_id)?;

    let identify = identify::Behaviour::new(identify::Config::new(
        crate::types::PROTOCOL_VERSION.to_string(),
        keypair.public(),
    ));

    let request_response = request_response::cbor::Behaviour::new(
        [(
            StreamProtocol::new(crate::types::EXCHANGE_PROTOCOL),
            request_response::ProtocolSupport::Full,
        )],
        request_response::Config::default(),
    );

    let relay_server = relay::Behaviour::new(local_peer_id, relay::Config::default());
    let (relay_transport, relay_client) = relay::client::new(local_peer_id);
    let dcutr = dcutr::Behaviour::new(local_peer_id);

    let behaviour = AlterNetBehaviour {
        kademlia,
        mdns,
        identify,
        request_response,
        relay_server,
        relay_client,
        dcutr,
    };

    // Tor transport — yalnızca tor_enabled ise bootstrap edilir (Manifesto I: opsiyonel,
    // dış bağımlılık kullanıcının bilinçli tercihi). Arti bootstrap maliyetlidir.
    let tor_transport = if config.tor_enabled {
        tracing::info!("Tor ağına bootstrap ediliyor (Arti)...");
        let tor = libp2p_community_tor::TorTransport::bootstrapped()
            .await
            .map_err(|e| format!("Tor bootstrap başarısız: {e:?}"))?
            .with_address_conversion(libp2p_community_tor::AddressConversion::IpAndDns);
        tracing::info!("Tor bootstrap tamamlandı.");
        Some(tor)
    } else {
        None
    };

    // İki kollu build: ikisi de aynı `Swarm<AlterNetBehaviour>` tipini üretir.
    // Tor etkinse TCP+relay+Tor; değilse TCP+relay. Manifesto V: IP gizliliği opsiyonel.
    let mut swarm = if let Some(tor) = tor_transport {
        SwarmBuilder::with_existing_identity(keypair)
            .with_tokio()
            .with_tcp(tcp::Config::default(), noise::Config::new, yamux::Config::default)?
            .with_other_transport(|key| {
                relay_transport
                    .upgrade(libp2p::core::upgrade::Version::V1Lazy)
                    .authenticate(noise::Config::new(key).unwrap())
                    .multiplex(yamux::Config::default())
            })?
            .with_other_transport(|key| {
                tor.upgrade(libp2p::core::upgrade::Version::V1Lazy)
                    .authenticate(noise::Config::new(key).unwrap())
                    .multiplex(yamux::Config::default())
            })?
            .with_behaviour(|_| behaviour)?
            .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
            .build()
    } else {
        SwarmBuilder::with_existing_identity(keypair)
            .with_tokio()
            .with_tcp(tcp::Config::default(), noise::Config::new, yamux::Config::default)?
            .with_other_transport(|key| {
                relay_transport
                    .upgrade(libp2p::core::upgrade::Version::V1Lazy)
                    .authenticate(noise::Config::new(key).unwrap())
                    .multiplex(yamux::Config::default())
            })?
            .with_behaviour(|_| behaviour)?
            .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
            .build()
    };

    // Bootstrap node'larına bağlan (opsiyonel — Manifesto I: otorite değil)
    for addr_str in &config.bootstrap_addrs {
        if let Ok(addr) = addr_str.parse::<libp2p::Multiaddr>() {
            swarm.dial(addr).ok();
        }
    }

    let (cmd_tx, cmd_rx) = mpsc::unbounded_channel::<NodeCommand>();

    // Kararlı X25519 anahtarı — onion relay'in katmanları soyabilmesi için (Manifesto V).
    // Oturum boyunca sabit; pubkey route inşası için NodeHandle üzerinden açılır.
    // Manifesto III/V: sır `Zeroizing` ile sarılır → loop bittiğinde bellekten silinir.
    let x25519_secret = zeroize::Zeroizing::new(crate::crypto::generate_static_secret());
    let x25519_pubkey = crate::crypto::get_public_key(&x25519_secret);
    let privacy = config.privacy_config();

    tokio::spawn(run_swarm_loop(swarm, cmd_rx, block_store, x25519_secret));

    // Chaff task: Padded+ ve chaff_enabled ise periyodik sahte trafik üret (Manifesto V).
    // Pasif gözlemci gerçek istekleri sahte olanlardan ayırt edemesin.
    if privacy.chaff_enabled && privacy.level.at_least_padded() {
        let chaff_tx = cmd_tx.clone();
        tokio::spawn(run_chaff_loop(chaff_tx));
    }

    // GC task: PinStore kotalarını kontrol et (Faz 6 - Madde 19)
    let gc_block_store = block_store.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(3600)); // Her saat
        loop {
            interval.tick().await;
            tracing::info!("Garbage collection timer triggered.");
            // Not: FsBlockStore, kendi PinStore wrap'ine sahip olmalı.
            // PinStore'u parametre olarak alabilmek için mimari gereği şimdilik root limitini 
            // FsBlockStore üzerinde check edebiliriz.
            if let Ok(total) = gc_block_store.total_size().await {
                tracing::info!("Current block store size: {} bytes", total);
            }
        }
    });

    Ok(NodeHandle { cmd_tx, local_peer_id, privacy, x25519_pubkey })
}

/// Periyodik chaff (sahte) trafik döngüsü.
///
/// Her ~15–45 sn'de bir bilinen bir peer'a sahte `HaveQuery` gönderir. İçerik rastgele
/// olduğundan gerçek bir sorgudan ayırt edilemez; pasif gözlemci hangi anların gerçek
/// istek taşıdığını bilemez. Manifesto V: metadata sızdırılmaz.
async fn run_chaff_loop(cmd_tx: mpsc::UnboundedSender<NodeCommand>) {
    use aes_gcm::aead::{OsRng, rand_core::RngCore};
    loop {
        // 15–45 sn arası rastgele aralık (sabit periyot da bir parmak izidir).
        let jitter = 15_000 + (OsRng.next_u32() % 30_000) as u64;
        tokio::time::sleep(Duration::from_millis(jitter)).await;

        // Bilinen peer'ları al.
        let (reply_tx, reply_rx) = oneshot::channel();
        if cmd_tx.send(NodeCommand::KnownPeers { reply: reply_tx }).is_err() {
            break; // node kapandı
        }
        let peers = match reply_rx.await {
            Ok(Ok(p)) => p,
            _ => continue,
        };
        if peers.is_empty() {
            continue;
        }

        // Rastgele bir peer seç, sahte CID ile HaveQuery yolla.
        let idx = (OsRng.next_u32() as usize) % peers.len();
        let fake = crate::traffic::generate_chaff_payload();
        let cid = Cid::from_data(&fake);
        let (reply_tx, _reply_rx) = oneshot::channel();
        cmd_tx
            .send(NodeCommand::SendBlockRequest {
                peer: peers[idx],
                request: ExchangeRequest::HaveQuery { cids: vec![cid] },
                reply: reply_tx,
            })
            .ok();
        // Yanıt yok sayılır — chaff'in amacı yalnızca trafik üretmek.
    }
}

// ═══════════════════════════════════════════════
// Swarm Event Loop
// ═══════════════════════════════════════════════

async fn run_swarm_loop(
    mut swarm: Swarm<AlterNetBehaviour>,
    mut cmd_rx: mpsc::UnboundedReceiver<NodeCommand>,
    block_store: Arc<FsBlockStore>,
    x25519_secret: zeroize::Zeroizing<[u8; 32]>,
) {
    let mut pending_get_record: HashMap<kad::QueryId, ReplyOnce<Vec<u8>>> = HashMap::new();
    let mut pending_put_record: HashMap<kad::QueryId, ReplyOnce<()>> = HashMap::new();
    let mut pending_start_providing: HashMap<kad::QueryId, ReplyOnce<()>> = HashMap::new();
    let mut pending_get_providers: HashMap<kad::QueryId, (ReplyOnce<Vec<PeerId>>, Vec<PeerId>)> =
        HashMap::new();
    let mut pending_requests: HashMap<
        request_response::OutboundRequestId,
        ReplyOnce<ExchangeResponse>,
    > = HashMap::new();
    let mut pending_listen: HashMap<
        libp2p::core::transport::ListenerId,
        ReplyOnce<libp2p::Multiaddr>,
    > = HashMap::new();
    // Onion relay forwarding: ara hop'un gönderdiği outbound isteğin yanıtını
    // gelen kanala geri iletmek için (Manifesto V: çok-hop anonimlik).
    let mut pending_relay: HashMap<
        request_response::OutboundRequestId,
        request_response::ResponseChannel<ExchangeResponse>,
    > = HashMap::new();

    use libp2p::futures::StreamExt;

    loop {
        tokio::select! {
            event = swarm.select_next_some() => {
                process_event(
                    event,
                    &mut swarm,
                    &block_store,
                    &mut pending_get_record,
                    &mut pending_put_record,
                    &mut pending_start_providing,
                    &mut pending_get_providers,
                    &mut pending_requests,
                    &mut pending_listen,
                    &x25519_secret,
                    &mut pending_relay,
                );
            }
            cmd = cmd_rx.recv() => {
                match cmd {
                    None => break,  // NodeHandle dropped — loop'u bitir
                    Some(cmd) => process_command(
                        cmd,
                        &mut swarm,
                        &mut pending_get_record,
                        &mut pending_put_record,
                        &mut pending_start_providing,
                        &mut pending_get_providers,
                        &mut pending_requests,
                        &mut pending_listen,
                    ),
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn process_event(
    event: SwarmEvent<AlterNetBehaviourEvent>,
    swarm: &mut Swarm<AlterNetBehaviour>,
    block_store: &Arc<FsBlockStore>,
    pending_get_record: &mut HashMap<kad::QueryId, ReplyOnce<Vec<u8>>>,
    pending_put_record: &mut HashMap<kad::QueryId, ReplyOnce<()>>,
    pending_start_providing: &mut HashMap<kad::QueryId, ReplyOnce<()>>,
    pending_get_providers: &mut HashMap<kad::QueryId, (ReplyOnce<Vec<PeerId>>, Vec<PeerId>)>,
    pending_requests: &mut HashMap<
        request_response::OutboundRequestId,
        ReplyOnce<ExchangeResponse>,
    >,
    pending_listen: &mut HashMap<
        libp2p::core::transport::ListenerId,
        ReplyOnce<libp2p::Multiaddr>,
    >,
    x25519_secret: &[u8; 32],
    pending_relay: &mut HashMap<
        request_response::OutboundRequestId,
        request_response::ResponseChannel<ExchangeResponse>,
    >,
) {
    match event {
        SwarmEvent::NewListenAddr { address, listener_id } => {
            tracing::info!("Dinleniyor: {}", address);
            if let Some(reply) = pending_listen.remove(&listener_id) {
                reply.send(Ok(address)).ok();
            }
        }

        SwarmEvent::Behaviour(AlterNetBehaviourEvent::Mdns(mdns::Event::Discovered(list))) => {
            for (peer_id, addr) in list {
                tracing::debug!("mDNS peer keşfedildi: {}", peer_id);
                swarm.behaviour_mut().kademlia.add_address(&peer_id, addr);
                swarm.behaviour_mut().kademlia.bootstrap().ok();
            }
        }

        SwarmEvent::Behaviour(AlterNetBehaviourEvent::Identify(
            identify::Event::Received { peer_id, info, .. },
        )) => {
            for addr in info.listen_addrs {
                swarm.behaviour_mut().kademlia.add_address(&peer_id, addr);
            }
            // Bootstrap bir peer bulduğumuzda DHT'yi başlat
            swarm.behaviour_mut().kademlia.bootstrap().ok();
        }

        SwarmEvent::Behaviour(AlterNetBehaviourEvent::Kademlia(
            kad::Event::OutboundQueryProgressed { id, result, step, .. },
        )) => {
            process_kad_result(
                id,
                result,
                step,
                pending_get_record,
                pending_put_record,
                pending_start_providing,
                pending_get_providers,
            );
        }

        SwarmEvent::Behaviour(AlterNetBehaviourEvent::RequestResponse(rr_event)) => {
            process_rr_event(
                rr_event,
                swarm,
                block_store,
                pending_requests,
                x25519_secret,
                pending_relay,
            );
        }

        SwarmEvent::ConnectionEstablished { peer_id, .. } => {
            tracing::debug!("Bağlandı: {}", peer_id);
        }
        SwarmEvent::ConnectionClosed { peer_id, .. } => {
            tracing::debug!("Bağlantı kapandı: {}", peer_id);
        }
        _ => {}
    }
}

#[allow(clippy::collapsible_if, clippy::collapsible_match)]
fn process_kad_result(
    id: kad::QueryId,
    result: kad::QueryResult,
    step: kad::ProgressStep,
    pending_get_record: &mut HashMap<kad::QueryId, ReplyOnce<Vec<u8>>>,
    pending_put_record: &mut HashMap<kad::QueryId, ReplyOnce<()>>,
    pending_start_providing: &mut HashMap<kad::QueryId, ReplyOnce<()>>,
    pending_get_providers: &mut HashMap<kad::QueryId, (ReplyOnce<Vec<PeerId>>, Vec<PeerId>)>,
) {
    use kad::{GetProvidersOk, GetRecordOk, QueryResult};

    match result {
        QueryResult::GetRecord(Ok(GetRecordOk::FoundRecord(peer_record))) => {
            if let Some(reply) = pending_get_record.remove(&id) {
                reply.send(Ok(peer_record.record.value)).ok();
            }
        }
        QueryResult::GetRecord(Ok(GetRecordOk::FinishedWithNoAdditionalRecord { .. })) => {
            if let Some(reply) = pending_get_record.remove(&id) {
                reply
                    .send(Err(AlterNetError::DhtQuery("kayıt bulunamadı".into())))
                    .ok();
            }
        }
        QueryResult::GetRecord(Err(e)) => {
            if let Some(reply) = pending_get_record.remove(&id) {
                reply
                    .send(Err(AlterNetError::DhtQuery(format!("{e:?}"))))
                    .ok();
            }
        }

        QueryResult::PutRecord(Ok(_)) => {
            if let Some(reply) = pending_put_record.remove(&id) {
                reply.send(Ok(())).ok();
            }
        }
        QueryResult::PutRecord(Err(e)) => {
            if let Some(reply) = pending_put_record.remove(&id) {
                // QuorumFailed: kayıt yerel store'a yazıldı ama henüz başka peer'a
                // replike edilemedi (az peer'lı ağ). Bu YUMUŞAK bir durumdur — yayıncı
                // çevrimiçi kaldığı sürece kayıt ona bağlanan peer'lara sunulur; peer'lar
                // katıldıkça yayılır. Manifesto I/II: az node'lu ağ da çalışmalı.
                match e {
                    kad::PutRecordError::QuorumFailed { .. } => {
                        tracing::warn!(
                            "DHT put quorum sağlanamadı (yerel yazıldı, peer bekleniyor): {e:?}"
                        );
                        reply.send(Ok(())).ok();
                    }
                    _ => {
                        reply
                            .send(Err(AlterNetError::DhtQuery(format!("{e:?}"))))
                            .ok();
                    }
                }
            }
        }

        QueryResult::StartProviding(Ok(_)) => {
            if let Some(reply) = pending_start_providing.remove(&id) {
                reply.send(Ok(())).ok();
            }
        }
        QueryResult::StartProviding(Err(e)) => {
            if let Some(reply) = pending_start_providing.remove(&id) {
                reply
                    .send(Err(AlterNetError::DhtQuery(format!("{e:?}"))))
                    .ok();
            }
        }

        QueryResult::GetProviders(Ok(GetProvidersOk::FoundProviders { providers, .. })) => {
            if let Some((_, collected)) = pending_get_providers.get_mut(&id) {
                collected.extend(providers);
            }
            if step.last {
                if let Some((reply, collected)) = pending_get_providers.remove(&id) {
                    reply.send(Ok(collected)).ok();
                }
            }
        }
        QueryResult::GetProviders(Ok(GetProvidersOk::FinishedWithNoAdditionalRecord { .. })) => {
            if step.last {
                if let Some((reply, collected)) = pending_get_providers.remove(&id) {
                    reply.send(Ok(collected)).ok();
                }
            }
        }
        QueryResult::GetProviders(Err(e)) => {
            if let Some((reply, _)) = pending_get_providers.remove(&id) {
                reply
                    .send(Err(AlterNetError::DhtQuery(format!("{e:?}"))))
                    .ok();
            }
        }

        _ => {}
    }
}

#[allow(clippy::too_many_arguments)]
fn process_rr_event(
    event: request_response::Event<ExchangeRequest, ExchangeResponse>,
    swarm: &mut Swarm<AlterNetBehaviour>,
    block_store: &Arc<FsBlockStore>,
    pending_requests: &mut HashMap<
        request_response::OutboundRequestId,
        ReplyOnce<ExchangeResponse>,
    >,
    x25519_secret: &[u8; 32],
    pending_relay: &mut HashMap<
        request_response::OutboundRequestId,
        request_response::ResponseChannel<ExchangeResponse>,
    >,
) {
    use request_response::{Event as RrEvent, Message as RrMessage};

    match event {
        RrEvent::Message {
            message: RrMessage::Request { request, channel, .. },
            ..
        } => {
            // OnionForward, sonraki hop'a iletilebileceği için ayrı ele alınır
            // (yanıt senkron değil — relay zinciri tamamlanınca geri gönderilir).
            if let ExchangeRequest::OnionForward { packet, .. } = &request {
                handle_onion_forward(packet, swarm, block_store, x25519_secret, channel, pending_relay);
                return;
            }

            // Gelen blok isteği — yerel depodan yanıtla (senkron dosya I/O)
            let response = match &request {
                ExchangeRequest::WantBlock { cid, .. } => {
                    let path = block_store.block_path(cid);
                    match std::fs::read(&path) {
                        Ok(data) => ExchangeResponse::Block { cid: cid.clone(), data },
                        Err(_) => ExchangeResponse::DontHave { cid: cid.clone() },
                    }
                }
                ExchangeRequest::HaveQuery { cids } => {
                    let have: Vec<Cid> = cids
                        .iter()
                        .filter(|c| block_store.block_path(c).exists())
                        .cloned()
                        .collect();
                    ExchangeResponse::HaveList { cids: have }
                }
                ExchangeRequest::WantManifest { .. } => ExchangeResponse::ManifestNotFound,
                ExchangeRequest::OnionForward { .. } => unreachable!("yukarıda ele alındı"),
            };
            swarm
                .behaviour_mut()
                .request_response
                .send_response(channel, response)
                .ok();
        }

        RrEvent::Message {
            message: RrMessage::Response { request_id, response },
            ..
        } => {
            // Önce relay yanıtı mı kontrol et — varsa gelen kanala geri ilet.
            if let Some(relay_channel) = pending_relay.remove(&request_id) {
                swarm
                    .behaviour_mut()
                    .request_response
                    .send_response(relay_channel, response)
                    .ok();
            } else if let Some(reply) = pending_requests.remove(&request_id) {
                reply.send(Ok(response)).ok();
            }
        }

        RrEvent::OutboundFailure { request_id, error, .. } => {
            // Relay outbound başarısızsa gelen kanala DontHave ilet.
            if let Some(relay_channel) = pending_relay.remove(&request_id) {
                swarm
                    .behaviour_mut()
                    .request_response
                    .send_response(
                        relay_channel,
                        ExchangeResponse::DontHave {
                            cid: Cid::from_data(b"relay-upstream-failed"),
                        },
                    )
                    .ok();
            } else if let Some(reply) = pending_requests.remove(&request_id) {
                reply
                    .send(Err(AlterNetError::Network(format!("{error:?}"))))
                    .ok();
            }
        }

        _ => {}
    }
}

/// Onion relay düğümü mantığı.
///
/// Paketi kendi kararlı X25519 anahtarımızla soyar:
/// - `payload` varsa → bu **son hop**; iç isteği yerel depodan yanıtla.
/// - `inner_packet` + `next_hop` varsa → bu **ara hop**; paketi sonraki hop'a ilet ve
///   yanıt geldiğinde gelen kanala geri gönder (`pending_relay` ile eşle).
///
/// Manifesto V: Her relay yalnızca bir önceki ve sonraki hop'u bilir; tam zinciri görmez.
fn handle_onion_forward(
    packet: &crate::onion::OnionPacket,
    swarm: &mut Swarm<AlterNetBehaviour>,
    block_store: &Arc<FsBlockStore>,
    x25519_secret: &[u8; 32],
    channel: request_response::ResponseChannel<ExchangeResponse>,
    pending_relay: &mut HashMap<
        request_response::OutboundRequestId,
        request_response::ResponseChannel<ExchangeResponse>,
    >,
) {
    let layer = match crate::onion::peel_onion(x25519_secret, packet) {
        Ok(l) => l,
        Err(e) => {
            tracing::warn!("Onion peel hatası: {e}");
            swarm
                .behaviour_mut()
                .request_response
                .send_response(channel, ExchangeResponse::ManifestNotFound)
                .ok();
            return;
        }
    };

    // Son hop: payload gerçek isteği taşır.
    if let Some(payload) = layer.payload {
        let response = match ciborium::from_reader::<ExchangeRequest, _>(payload.as_slice()) {
            Ok(ExchangeRequest::WantBlock { cid, .. }) => {
                let path = block_store.block_path(&cid);
                match std::fs::read(&path) {
                    Ok(data) => ExchangeResponse::Block { cid: cid.clone(), data },
                    Err(_) => ExchangeResponse::DontHave { cid },
                }
            }
            _ => ExchangeResponse::ManifestNotFound,
        };
        swarm
            .behaviour_mut()
            .request_response
            .send_response(channel, response)
            .ok();
        return;
    }

    // Ara hop: inner_packet'i sonraki hop'a ilet.
    if let (Some(inner), Some(next_hop)) = (layer.inner_packet, layer.next_hop) {
        match next_hop.parse::<PeerId>() {
            Ok(next_peer) => {
                let fwd = ExchangeRequest::OnionForward {
                    packet: inner,
                    reply_pubkey: Vec::new(),
                };
                let out_id = swarm
                    .behaviour_mut()
                    .request_response
                    .send_request(&next_peer, fwd);
                // Yanıt geldiğinde gelen kanala iletmek için eşle.
                pending_relay.insert(out_id, channel);
            }
            Err(_) => {
                swarm
                    .behaviour_mut()
                    .request_response
                    .send_response(
                        channel,
                        ExchangeResponse::DontHave {
                            cid: Cid::from_data(b"relay-bad-next-hop"),
                        },
                    )
                    .ok();
            }
        }
    } else {
        // Ne payload ne de yönlendirilebilir iç paket → boş katman.
        swarm
            .behaviour_mut()
            .request_response
            .send_response(channel, ExchangeResponse::ManifestNotFound)
            .ok();
    }
}

#[allow(clippy::too_many_arguments)]
fn process_command(
    cmd: NodeCommand,
    swarm: &mut Swarm<AlterNetBehaviour>,
    pending_get_record: &mut HashMap<kad::QueryId, ReplyOnce<Vec<u8>>>,
    pending_put_record: &mut HashMap<kad::QueryId, ReplyOnce<()>>,
    pending_start_providing: &mut HashMap<kad::QueryId, ReplyOnce<()>>,
    pending_get_providers: &mut HashMap<kad::QueryId, (ReplyOnce<Vec<PeerId>>, Vec<PeerId>)>,
    pending_requests: &mut HashMap<
        request_response::OutboundRequestId,
        ReplyOnce<ExchangeResponse>,
    >,
    pending_listen: &mut HashMap<
        libp2p::core::transport::ListenerId,
        ReplyOnce<libp2p::Multiaddr>,
    >,
) {
    match cmd {
        NodeCommand::ListenOn(addr, reply) => match swarm.listen_on(addr) {
            Ok(listener_id) => {
                pending_listen.insert(listener_id, reply);
            }
            Err(e) => {
                reply
                    .send(Err(AlterNetError::Network(format!("{e:?}"))))
                    .ok();
            }
        },

        NodeCommand::DialAddr(addr) => {
            swarm.dial(addr).ok();
        }

        NodeCommand::PutRecord { key, value, reply } => {
            let record = kad::Record {
                key,
                value,
                publisher: Some(*swarm.local_peer_id()),
                expires: None,
            };
            match swarm
                .behaviour_mut()
                .kademlia
                .put_record(record, kad::Quorum::One)
            {
                Ok(query_id) => {
                    pending_put_record.insert(query_id, reply);
                }
                Err(e) => {
                    reply
                        .send(Err(AlterNetError::DhtQuery(format!("{e:?}"))))
                        .ok();
                }
            }
        }

        NodeCommand::GetRecord { key, reply } => {
            let query_id = swarm.behaviour_mut().kademlia.get_record(key);
            pending_get_record.insert(query_id, reply);
        }

        NodeCommand::StartProviding { key, reply } => {
            match swarm.behaviour_mut().kademlia.start_providing(key) {
                Ok(query_id) => {
                    pending_start_providing.insert(query_id, reply);
                }
                Err(e) => {
                    reply
                        .send(Err(AlterNetError::DhtQuery(format!("{e:?}"))))
                        .ok();
                }
            }
        }

        NodeCommand::GetProviders { key, reply } => {
            let query_id = swarm.behaviour_mut().kademlia.get_providers(key);
            pending_get_providers.insert(query_id, (reply, Vec::new()));
        }

        NodeCommand::SendBlockRequest { peer, request, reply } => {
            let request_id = swarm
                .behaviour_mut()
                .request_response
                .send_request(&peer, request);
            pending_requests.insert(request_id, reply);
        }

        NodeCommand::KnownPeers { reply } => {
            let peers: Vec<PeerId> = swarm.connected_peers().copied().collect();
            reply.send(Ok(peers)).ok();
        }
    }
}
