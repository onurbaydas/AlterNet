//! Integration testleri: iki gerçek node arası publish → fetch → pin senaryosu.
//!
//! **Bağlayıcı Test:** "Bu, kullanıcıyı daha egemen yapıyor çünkü
//! merkezi sunucu olmadan içerik yayınlayıp alabilir."

use alternet_core::{
    config::AlterNetConfig,
    content::{BlockStore as _, FsBlockStore, build_dag, collect_all_cids, extract_dag},
    identity::{alter_uri_to_pubkey, load_or_generate_keypair, pubkey_to_alter_uri, pubkey_to_hex},
    network::spawn_node,
    publish::{
        ManifestStore, create_manifest, deserialize_manifest, serialize_manifest, verify_manifest,
    },
    routing::{PrivacyConfig, PrivacyLevel, RelayNode, RoutingLayer},
    types::{Cid, ManifestMeta},
};
use libp2p::identity::Keypair;
use std::{sync::Arc, time::Duration};
use tempfile::tempdir;

// ═══════════════════════════════════════════════
// Yardımcı — test node başlat
// ═══════════════════════════════════════════════

async fn test_node(
    data_dir: &std::path::Path,
) -> (alternet_core::network::NodeHandle, Arc<FsBlockStore>, AlterNetConfig) {
    let mut config = AlterNetConfig::default();
    config.data_dir = data_dir.to_path_buf();
    config.listen_port = 0;
    config.mdns_enabled = true;

    let keypair = load_or_generate_keypair(":memory:").unwrap();
    let store = Arc::new(
        FsBlockStore::new(data_dir.join("blocks"), 0).await.unwrap(),
    );
    let node = spawn_node(keypair, config.clone(), Arc::clone(&store)).await.unwrap();
    (node, store, config)
}

// ═══════════════════════════════════════════════
// Birim testler — DAG roundtrip
// ═══════════════════════════════════════════════

#[tokio::test]
async fn dag_roundtrip_single_file() {
    let tmp = tempdir().unwrap();
    let store = FsBlockStore::new(tmp.path().join("blocks"), 0).await.unwrap();

    let src = tmp.path().join("hello.html");
    tokio::fs::write(&src, b"<h1>Manifesto VII: Kod yalan soylemez</h1>")
        .await
        .unwrap();

    let root_cid = build_dag(&store, &src).await.unwrap();
    let out = tmp.path().join("out.html");
    extract_dag(&store, &root_cid, &out).await.unwrap();

    let content = tokio::fs::read(&out).await.unwrap();
    assert_eq!(content, b"<h1>Manifesto VII: Kod yalan soylemez</h1>");
}

#[tokio::test]
async fn dag_roundtrip_directory() {
    let tmp = tempdir().unwrap();
    let store = FsBlockStore::new(tmp.path().join("blocks"), 0).await.unwrap();

    let site = tmp.path().join("site");
    tokio::fs::create_dir_all(&site).await.unwrap();
    tokio::fs::write(site.join("index.html"), b"<h1>AlterNet</h1>").await.unwrap();
    tokio::fs::write(site.join("style.css"), b"body{margin:0}").await.unwrap();
    let sub = site.join("sub");
    tokio::fs::create_dir_all(&sub).await.unwrap();
    tokio::fs::write(sub.join("page.html"), b"<p>subpage</p>").await.unwrap();

    let root_cid = build_dag(&store, &site).await.unwrap();
    let out = tmp.path().join("out");
    extract_dag(&store, &root_cid, &out).await.unwrap();

    assert_eq!(
        tokio::fs::read(out.join("index.html")).await.unwrap(),
        b"<h1>AlterNet</h1>"
    );
    assert_eq!(
        tokio::fs::read(out.join("style.css")).await.unwrap(),
        b"body{margin:0}"
    );
    assert_eq!(
        tokio::fs::read(out.join("sub").join("page.html")).await.unwrap(),
        b"<p>subpage</p>"
    );
}

// ═══════════════════════════════════════════════
// Birim testler — Manifest imza
// ═══════════════════════════════════════════════

#[test]
fn manifest_sign_and_verify() {
    let keypair = Keypair::generate_ed25519();
    let cid = Cid::from_data(b"test content");
    let manifest = create_manifest(
        cid.clone(),
        &keypair,
        1,
        ManifestMeta { title: Some("Test".into()), ..Default::default() },
    )
    .unwrap();

    assert!(verify_manifest(&manifest).is_ok());

    // Serialization roundtrip
    let bytes = serialize_manifest(&manifest).unwrap();
    let m2 = deserialize_manifest(&bytes).unwrap();
    assert!(verify_manifest(&m2).is_ok());
    assert_eq!(m2.sequence, 1);
}

#[test]
fn manifest_tampering_detected() {
    let keypair = Keypair::generate_ed25519();
    let cid = Cid::from_data(b"test content");
    let mut manifest = create_manifest(cid, &keypair, 1, ManifestMeta::default()).unwrap();
    manifest.sequence = 999;
    assert!(verify_manifest(&manifest).is_err(), "Tampered manifest must be rejected");
}

// ═══════════════════════════════════════════════
// Integration testi — Alice yayınlar, Bob local store'dan alır
// ═══════════════════════════════════════════════

#[tokio::test]
async fn local_publish_and_extract() {
    let tmp = tempdir().unwrap();

    // Alice'in site içeriği
    let site = tmp.path().join("alice_site");
    tokio::fs::create_dir_all(&site).await.unwrap();
    tokio::fs::write(site.join("index.html"), b"<h1>Alice'in Sitesi</h1>").await.unwrap();
    tokio::fs::write(site.join("about.html"), b"<p>AlterNet ile yayinlandim</p>").await.unwrap();

    // Alice: DAG oluştur + manifest imzala
    let keypair = Keypair::generate_ed25519();
    let pubkey_bytes = keypair.public().encode_protobuf();
    let uri = pubkey_to_alter_uri(&pubkey_bytes);

    let store = FsBlockStore::new(tmp.path().join("blocks"), 0).await.unwrap();
    let root_cid = build_dag(&store, &site).await.unwrap();
    let manifest = create_manifest(
        root_cid.clone(),
        &keypair,
        1,
        ManifestMeta { title: Some("Alice's Site".into()), ..Default::default() },
    )
    .unwrap();

    // Manifest doğrulama
    verify_manifest(&manifest).unwrap();

    // Manifest CBOR roundtrip
    let manifest_bytes = serialize_manifest(&manifest).unwrap();
    let manifest2 = deserialize_manifest(&manifest_bytes).unwrap();
    verify_manifest(&manifest2).unwrap();
    assert_eq!(manifest2.root_cid, root_cid);

    // URI decode
    let pubkey_decoded = alter_uri_to_pubkey(&uri).unwrap();
    assert_eq!(pubkey_bytes, pubkey_decoded);

    // Bob: aynı depodan çıkar (P2P olmadan, sadece local store testi)
    let out = tmp.path().join("bob_fetched");
    extract_dag(&store, &root_cid, &out).await.unwrap();

    assert_eq!(
        tokio::fs::read(out.join("index.html")).await.unwrap(),
        b"<h1>Alice'in Sitesi</h1>"
    );
    assert_eq!(
        tokio::fs::read(out.join("about.html")).await.unwrap(),
        b"<p>AlterNet ile yayinlandim</p>"
    );
}

// ═══════════════════════════════════════════════
// Integration testi — P2P block exchange (iki node)
// ═══════════════════════════════════════════════

#[tokio::test]
async fn p2p_block_request_response() {
    let tmp = tempdir().unwrap();

    // Alice: blok deposu oluştur
    let alice_dir = tmp.path().join("alice");
    tokio::fs::create_dir_all(&alice_dir).await.unwrap();
    let alice_store = Arc::new(
        FsBlockStore::new(alice_dir.join("blocks"), 0).await.unwrap(),
    );

    // Test verisi blok olarak kaydet
    let test_data = b"Manifesto III: Guvenlik varsayilandir";
    let test_cid = alice_store.put(test_data).await.unwrap();

    // Alice node'u başlat
    let alice_keypair = load_or_generate_keypair(":memory:").unwrap();
    let mut alice_config = AlterNetConfig::default();
    alice_config.data_dir = alice_dir.clone();
    alice_config.mdns_enabled = true;
    let alice_node = spawn_node(alice_keypair, alice_config, Arc::clone(&alice_store))
        .await
        .unwrap();
    let alice_addr = alice_node.listen_on(0).await.unwrap();
    let alice_peer_id = alice_node.local_peer_id();

    // Bob node'u başlat
    let bob_dir = tmp.path().join("bob");
    tokio::fs::create_dir_all(&bob_dir).await.unwrap();
    let bob_store = Arc::new(
        FsBlockStore::new(bob_dir.join("blocks"), 0).await.unwrap(),
    );
    let bob_keypair = load_or_generate_keypair(":memory:").unwrap();
    let mut bob_config = AlterNetConfig::default();
    bob_config.data_dir = bob_dir.clone();
    bob_config.mdns_enabled = true;
    let bob_node = spawn_node(bob_keypair, bob_config, Arc::clone(&bob_store))
        .await
        .unwrap();
    bob_node.listen_on(0).await.unwrap();

    // Bob, Alice'e doğrudan bağlan
    let alice_p2p_addr = format!(
        "{}/p2p/{}",
        alice_addr,
        alice_peer_id
    )
    .parse()
    .unwrap();
    bob_node.dial(alice_p2p_addr).unwrap();

    // Bağlantı kurulması için kısa bekle
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Bob, Alice'den bloğu iste
    let data = tokio::time::timeout(
        Duration::from_secs(10),
        bob_node.request_block(alice_peer_id, &test_cid),
    )
    .await
    .expect("timeout")
    .expect("request_block failed");

    // Hash doğrulama (request_block içinde yapılır ama biz de doğrulayalım)
    assert_eq!(data, test_data);
    assert!(test_cid.verify(&data));
}

// ═══════════════════════════════════════════════
// Integration testi — DHT manifest put/get (iki node)
// ═══════════════════════════════════════════════

#[tokio::test]
async fn dht_manifest_put_get() {
    let tmp = tempdir().unwrap();

    // Alice: manifest oluştur ve DHT'ye koy
    let alice_keypair = Keypair::generate_ed25519();
    let pubkey_bytes = alice_keypair.public().encode_protobuf();
    let pubkey_hex = pubkey_to_hex(&pubkey_bytes);

    let cid = Cid::from_data(b"site content");
    let manifest = create_manifest(cid, &alice_keypair, 1, ManifestMeta::default()).unwrap();
    let manifest_bytes = serialize_manifest(&manifest).unwrap();

    let alice_dir = tmp.path().join("alice");
    tokio::fs::create_dir_all(&alice_dir).await.unwrap();
    let alice_store = Arc::new(FsBlockStore::new(alice_dir.join("blocks"), 0).await.unwrap());
    let mut alice_config = AlterNetConfig::default();
    alice_config.data_dir = alice_dir.clone();
    alice_config.mdns_enabled = true;
    let alice_node =
        spawn_node(alice_keypair, alice_config, Arc::clone(&alice_store)).await.unwrap();
    let alice_addr = alice_node.listen_on(0).await.unwrap();
    let alice_peer_id = alice_node.local_peer_id();

    // Bob: Alice'e bağlan
    let bob_dir = tmp.path().join("bob");
    tokio::fs::create_dir_all(&bob_dir).await.unwrap();
    let bob_store = Arc::new(FsBlockStore::new(bob_dir.join("blocks"), 0).await.unwrap());
    let bob_keypair = Keypair::generate_ed25519();
    let mut bob_config = AlterNetConfig::default();
    bob_config.data_dir = bob_dir.clone();
    bob_config.mdns_enabled = true;
    let bob_node =
        spawn_node(bob_keypair, bob_config, Arc::clone(&bob_store)).await.unwrap();
    bob_node.listen_on(0).await.unwrap();

    // Bob, Alice'e doğrudan dial et
    let alice_full_addr = format!("{}/p2p/{}", alice_addr, alice_peer_id)
        .parse()
        .unwrap();
    bob_node.dial(alice_full_addr).unwrap();

    // Bağlantı, identify ve DHT bootstrap için bekle
    // (Kademlia routing table dolmadan PUT başarısız olur)
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Manifest'i DHT'ye koy (routing table dolu olduktan sonra)
    tokio::time::timeout(
        Duration::from_secs(10),
        alice_node.put_manifest(&pubkey_hex, manifest_bytes.clone()),
    )
    .await
    .expect("timeout")
    .expect("put_manifest failed");

    // Bob manifest'i al
    let fetched_bytes = tokio::time::timeout(
        Duration::from_secs(15),
        bob_node.get_manifest(&pubkey_hex),
    )
    .await
    .expect("timeout")
    .expect("get_manifest failed");

    // Deserialize ve doğrula
    let fetched_manifest = deserialize_manifest(&fetched_bytes).unwrap();
    verify_manifest(&fetched_manifest).unwrap();
    assert_eq!(fetched_manifest.sequence, 1);
    assert_eq!(fetched_manifest.author, manifest.author);
}

// ═══════════════════════════════════════════════
// Integration testi — Pin / Seed
// Alice yayınlar → Carol pin'ler → Alice kapanır → Bob, Carol'dan alır
// ═══════════════════════════════════════════════

#[tokio::test]
async fn pin_seed_alice_offline() {
    let tmp = tempdir().unwrap();

    // Alice: içerik oluştur + depola
    let alice_dir = tmp.path().join("alice");
    tokio::fs::create_dir_all(&alice_dir).await.unwrap();
    let alice_store = Arc::new(
        FsBlockStore::new(alice_dir.join("blocks"), 0).await.unwrap(),
    );
    let test_data = b"Manifesto II: Her cihaz sunucu ve istemcidir.";
    let test_cid = alice_store.put(test_data).await.unwrap();

    let alice_keypair = load_or_generate_keypair(":memory:").unwrap();
    let mut alice_config = AlterNetConfig::default();
    alice_config.data_dir = alice_dir.clone();
    alice_config.mdns_enabled = false;
    let alice_node = spawn_node(alice_keypair, alice_config, Arc::clone(&alice_store))
        .await
        .unwrap();
    let alice_addr = alice_node.listen_on(0).await.unwrap();
    let alice_peer_id = alice_node.local_peer_id();

    // Carol: Alice'e bağlan, bloğu indir, kendi deposuna kaydet
    let carol_dir = tmp.path().join("carol");
    tokio::fs::create_dir_all(&carol_dir).await.unwrap();
    let carol_store = Arc::new(
        FsBlockStore::new(carol_dir.join("blocks"), 0).await.unwrap(),
    );
    let carol_keypair = load_or_generate_keypair(":memory:").unwrap();
    let mut carol_config = AlterNetConfig::default();
    carol_config.data_dir = carol_dir.clone();
    carol_config.mdns_enabled = false;
    let carol_node = spawn_node(carol_keypair, carol_config, Arc::clone(&carol_store))
        .await
        .unwrap();
    carol_node.listen_on(0).await.unwrap();

    let alice_full = format!("{}/p2p/{}", alice_addr, alice_peer_id).parse().unwrap();
    carol_node.dial(alice_full).unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Carol, Alice'den bloğu ister
    let data = tokio::time::timeout(
        Duration::from_secs(10),
        carol_node.request_block(alice_peer_id, &test_cid),
    )
    .await
    .unwrap()
    .unwrap();
    carol_store.put(&data).await.unwrap();
    assert_eq!(data.as_slice(), test_data);

    // Alice çevrimdışı oluyor (NodeHandle drop → event loop biter)
    drop(alice_node);
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Bob: Alice'in adresini bilmiyor, Carol'a bağlanıyor
    let bob_dir = tmp.path().join("bob");
    tokio::fs::create_dir_all(&bob_dir).await.unwrap();
    let bob_store = Arc::new(
        FsBlockStore::new(bob_dir.join("blocks"), 0).await.unwrap(),
    );
    let bob_keypair = load_or_generate_keypair(":memory:").unwrap();
    let mut bob_config = AlterNetConfig::default();
    bob_config.data_dir = bob_dir.clone();
    bob_config.mdns_enabled = false;
    let bob_node = spawn_node(bob_keypair, bob_config, Arc::clone(&bob_store))
        .await
        .unwrap();
    bob_node.listen_on(0).await.unwrap();

    let carol_peer_id = carol_node.local_peer_id();
    // Carol'ın dinleme adresini öğren
    let carol_addr_str = format!("{}/p2p/{}", carol_node.listen_on(0).await.unwrap_or_else(|_| {
        // fallback — mevcut listener
        "/ip4/127.0.0.1/tcp/0".parse().unwrap()
    }), carol_peer_id);
    // Yeni listen port oluşturmak yerine Carol'ı Bob'a doğrudan dial ettir
    // Bunun için Carol'ın gerçek adresini test_node yardımcısından alırız.
    // Basit yaklaşım: Bob → Carol doğrudan dial (peer_id ile değil, addr ile)
    // Ama addr bilmeden dial edemeyiz. Carol'ı da ikinci kez listen_on yapalım.
    let carol_addr2 = carol_node.listen_on(0).await.unwrap();
    let carol_full = format!("{}/p2p/{}", carol_addr2, carol_peer_id).parse().unwrap();
    bob_node.dial(carol_full).unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Bob, Carol'dan bloğu alır (Alice çevrimdışı olmasına rağmen)
    let data_from_carol = tokio::time::timeout(
        Duration::from_secs(10),
        bob_node.request_block(carol_peer_id, &test_cid),
    )
    .await
    .expect("timeout")
    .expect("Carol'dan blok alınamadı");

    assert_eq!(data_from_carol.as_slice(), test_data);
    assert!(test_cid.verify(&data_from_carol), "Carol'dan gelen blok hash doğrulandı");

    let _ = carol_addr_str; // suppress warning
}

// ═══════════════════════════════════════════════
// Integration testi — Bozuk Blok Reddi
// ═══════════════════════════════════════════════

#[tokio::test]
async fn bad_block_rejected() {
    let tmp = tempdir().unwrap();

    // Peer A: gerçek bir blok depola
    let a_dir = tmp.path().join("a");
    tokio::fs::create_dir_all(&a_dir).await.unwrap();
    let a_store = Arc::new(FsBlockStore::new(a_dir.join("blocks"), 0).await.unwrap());
    let real_data = b"gercek veri";
    let real_cid = a_store.put(real_data).await.unwrap();

    let a_keypair = load_or_generate_keypair(":memory:").unwrap();
    let mut a_config = AlterNetConfig::default();
    a_config.data_dir = a_dir.clone();
    a_config.mdns_enabled = false;
    let a_node = spawn_node(a_keypair, a_config, Arc::clone(&a_store)).await.unwrap();
    let a_addr = a_node.listen_on(0).await.unwrap();
    let a_peer_id = a_node.local_peer_id();

    // Peer B
    let b_dir = tmp.path().join("b");
    tokio::fs::create_dir_all(&b_dir).await.unwrap();
    let b_store = Arc::new(FsBlockStore::new(b_dir.join("blocks"), 0).await.unwrap());
    let b_keypair = load_or_generate_keypair(":memory:").unwrap();
    let mut b_config = AlterNetConfig::default();
    b_config.data_dir = b_dir.clone();
    b_config.mdns_enabled = false;
    let b_node = spawn_node(b_keypair, b_config, Arc::clone(&b_store)).await.unwrap();
    b_node.listen_on(0).await.unwrap();

    let a_full = format!("{}/p2p/{}", a_addr, a_peer_id).parse().unwrap();
    b_node.dial(a_full).unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;

    // B, var olmayan bir CID ister → DontHave → BlockNotFound hatası
    let fake_cid = Cid::from_data(b"var olmayan veri");
    let result = tokio::time::timeout(
        Duration::from_secs(5),
        b_node.request_block(a_peer_id, &fake_cid),
    )
    .await
    .expect("timeout");

    assert!(result.is_err(), "var olmayan blok için hata bekleniyor");

    // CID doğrulaması: gerçek veri başka bir CID ile eşleşmemeli
    assert!(!fake_cid.verify(real_data), "yanlış CID gerçek veriyi doğrulayamaz");
    assert!(real_cid.verify(real_data), "doğru CID doğrulanmalı");
}

// ═══════════════════════════════════════════════
// Integration testi — Tampered Manifest Reddi (DHT üzerinden)
// ═══════════════════════════════════════════════

#[tokio::test]
async fn bad_manifest_rejected() {
    let tmp = tempdir().unwrap();
    let alice_keypair = Keypair::generate_ed25519();
    let pubkey_bytes = alice_keypair.public().encode_protobuf();
    let pubkey_hex = pubkey_to_hex(&pubkey_bytes);

    let cid = Cid::from_data(b"icerik");
    let mut manifest =
        create_manifest(cid, &alice_keypair, 1, ManifestMeta::default()).unwrap();
    // İmzalandıktan sonra root_cid'i değiştir → imza bozulur
    manifest.root_cid = Cid::from_data(b"sahte icerik");
    let tampered_bytes = serialize_manifest(&manifest).unwrap();

    // Alice node
    let alice_dir = tmp.path().join("alice");
    tokio::fs::create_dir_all(&alice_dir).await.unwrap();
    let alice_store =
        Arc::new(FsBlockStore::new(alice_dir.join("blocks"), 0).await.unwrap());
    let mut alice_config = AlterNetConfig::default();
    alice_config.data_dir = alice_dir.clone();
    alice_config.mdns_enabled = false;
    let alice_node =
        spawn_node(alice_keypair, alice_config, Arc::clone(&alice_store)).await.unwrap();
    let alice_addr = alice_node.listen_on(0).await.unwrap();
    let alice_peer_id = alice_node.local_peer_id();

    // Bob node
    let bob_dir = tmp.path().join("bob");
    tokio::fs::create_dir_all(&bob_dir).await.unwrap();
    let bob_store =
        Arc::new(FsBlockStore::new(bob_dir.join("blocks"), 0).await.unwrap());
    let bob_keypair = load_or_generate_keypair(":memory:").unwrap();
    let mut bob_config = AlterNetConfig::default();
    bob_config.data_dir = bob_dir.clone();
    bob_config.mdns_enabled = false;
    let bob_node =
        spawn_node(bob_keypair, bob_config, Arc::clone(&bob_store)).await.unwrap();
    bob_node.listen_on(0).await.unwrap();

    // Bob, Alice'e bağlan ve routing table'ın dolmasını bekle
    let alice_full = format!("{}/p2p/{}", alice_addr, alice_peer_id).parse().unwrap();
    bob_node.dial(alice_full).unwrap();
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Routing table hazır; Alice tampered manifest'i DHT'ye koyuyor
    tokio::time::timeout(
        Duration::from_secs(10),
        alice_node.put_manifest(&pubkey_hex, tampered_bytes),
    )
    .await
    .expect("put timeout")
    .expect("put_manifest failed");

    // Bob, manifest'i alıyor
    let fetched_bytes = tokio::time::timeout(
        Duration::from_secs(15),
        bob_node.get_manifest(&pubkey_hex),
    )
    .await
    .expect("get timeout")
    .expect("get_manifest failed");

    let fetched = deserialize_manifest(&fetched_bytes).unwrap();
    // İmza doğrulaması başarısız olmalı — Manifesto VII garantisi
    assert!(
        verify_manifest(&fetched).is_err(),
        "bozulmuş imzalı manifest kabul edilmemeli"
    );
}

// ═══════════════════════════════════════════════
// Integration testi — ManifestStore Replay/Rollback Reddi
// ═══════════════════════════════════════════════

#[test]
fn manifest_store_replay_and_rollback() {
    let keypair = Keypair::generate_ed25519();
    let mut store = ManifestStore::new();
    let cid = Cid::from_data(b"test");

    // seq=5 kabul edilmeli
    let m5 = create_manifest(cid.clone(), &keypair, 5, ManifestMeta::default()).unwrap();
    store.accept(&m5).expect("seq=5 kabul edilmeli");

    // seq=5 tekrar → replay saldırısı → reddedilmeli
    let m5_again = create_manifest(cid.clone(), &keypair, 5, ManifestMeta::default()).unwrap();
    assert!(store.accept(&m5_again).is_err(), "seq=5 replay reddedilmeli");

    // seq=3 → rollback saldırısı → reddedilmeli
    let m3 = create_manifest(cid.clone(), &keypair, 3, ManifestMeta::default()).unwrap();
    assert!(store.accept(&m3).is_err(), "seq=3 rollback reddedilmeli");

    // seq=6 → geçerli güncelleme → kabul edilmeli
    let m6 = create_manifest(cid.clone(), &keypair, 6, ManifestMeta::default()).unwrap();
    store.accept(&m6).expect("seq=6 kabul edilmeli");
}

// ═══════════════════════════════════════════════
// Integration testi — Padded gizlilik: ağ üzerinden blok byte-perfect
// (time-blind delay + 512B istek dolgusu fetch'i bozmamalı)
// ═══════════════════════════════════════════════

#[tokio::test]
async fn padded_privacy_fetch_byte_perfect() {
    let tmp = tempdir().unwrap();

    // Alice (Padded gizlilik) bir blok depolar
    let alice_dir = tmp.path().join("alice");
    tokio::fs::create_dir_all(&alice_dir).await.unwrap();
    let alice_store = Arc::new(FsBlockStore::new(alice_dir.join("blocks"), 0).await.unwrap());
    let data = b"Manifesto V: Mahremiyet onurdur - padded mod testi";
    let cid = alice_store.put(data).await.unwrap();

    let mut alice_config = AlterNetConfig::default();
    alice_config.data_dir = alice_dir.clone();
    alice_config.mdns_enabled = false;
    alice_config.privacy_level = PrivacyLevel::Padded; // padding + time-blind
    let alice_kp = load_or_generate_keypair(":memory:").unwrap();
    let alice = spawn_node(alice_kp, alice_config, Arc::clone(&alice_store)).await.unwrap();
    let alice_addr = alice.listen_on(0).await.unwrap();
    let alice_peer = alice.local_peer_id();

    // Bob (Padded gizlilik) Alice'e bağlanır ve bloğu ister
    let bob_dir = tmp.path().join("bob");
    tokio::fs::create_dir_all(&bob_dir).await.unwrap();
    let bob_store = Arc::new(FsBlockStore::new(bob_dir.join("blocks"), 0).await.unwrap());
    let mut bob_config = AlterNetConfig::default();
    bob_config.data_dir = bob_dir.clone();
    bob_config.mdns_enabled = false;
    bob_config.privacy_level = PrivacyLevel::Padded;
    let bob_kp = load_or_generate_keypair(":memory:").unwrap();
    let bob = spawn_node(bob_kp, bob_config, Arc::clone(&bob_store)).await.unwrap();
    bob.listen_on(0).await.unwrap();

    bob.dial(format!("{}/p2p/{}", alice_addr, alice_peer).parse().unwrap()).unwrap();
    tokio::time::sleep(Duration::from_millis(400)).await;

    // request_block padding+delay uygular ama içerik byte-perfect gelmeli
    let fetched = tokio::time::timeout(
        Duration::from_secs(15),
        bob.request_block(alice_peer, &cid),
    )
    .await
    .expect("timeout")
    .expect("padded fetch başarısız");

    assert_eq!(fetched.as_slice(), data, "Padded modda içerik byte-perfect olmalı");
    assert!(cid.verify(&fetched));
}

// ═══════════════════════════════════════════════
// Integration testi — Onion çok-hop relay
// Requester R → relay M → hedef T (bloğu sunar). R kimliği T'den gizli.
// ═══════════════════════════════════════════════

#[tokio::test]
async fn onion_multihop_relay_fetch() {
    let tmp = tempdir().unwrap();

    async fn make(dir: std::path::PathBuf) -> (alternet_core::network::NodeHandle, Arc<FsBlockStore>, libp2p::Multiaddr, libp2p::PeerId) {
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let store = Arc::new(FsBlockStore::new(dir.join("blocks"), 0).await.unwrap());
        let mut cfg = AlterNetConfig::default();
        cfg.data_dir = dir;
        cfg.mdns_enabled = false;
        let kp = load_or_generate_keypair(":memory:").unwrap();
        let node = spawn_node(kp, cfg, Arc::clone(&store)).await.unwrap();
        let addr = node.listen_on(0).await.unwrap();
        let peer = node.local_peer_id();
        (node, store, addr, peer)
    }

    // Hedef T: bloğu depolar
    let (target, target_store, target_addr, target_peer) = make(tmp.path().join("target")).await;
    let data = b"Manifesto V: onion ile gizli istek - cok hop relay testi";
    let cid = target_store.put(data).await.unwrap();

    // Relay M
    let (relay, _relay_store, relay_addr, relay_peer) = make(tmp.path().join("relay")).await;

    // Requester R
    let (req, _req_store, _req_addr, _req_peer) = make(tmp.path().join("req")).await;

    // Bağlantılar: R→M, M→T
    req.dial(format!("{}/p2p/{}", relay_addr, relay_peer).parse().unwrap()).unwrap();
    relay.dial(format!("{}/p2p/{}", target_addr, target_peer).parse().unwrap()).unwrap();
    tokio::time::sleep(Duration::from_millis(600)).await;

    // Onion route: [M, T] — M ara hop, T son hop (bloğu sunar)
    let route: Vec<RelayNode> = vec![
        RelayNode { peer_id: relay_peer, x25519_pubkey: relay.x25519_pubkey() },
        RelayNode { peer_id: target_peer, x25519_pubkey: target.x25519_pubkey() },
    ];

    let routing = RoutingLayer::new(PrivacyConfig {
        level: PrivacyLevel::Onion { hops: 2 },
        chaff_enabled: false,
        time_blind_enabled: false,
    });

    let fetched = tokio::time::timeout(
        Duration::from_secs(20),
        routing.fetch_block(&req, relay_peer, &cid, Some(&route)),
    )
    .await
    .expect("onion timeout")
    .expect("onion fetch başarısız");

    assert_eq!(fetched.as_slice(), data, "Onion relay üzerinden içerik byte-perfect olmalı");
}
