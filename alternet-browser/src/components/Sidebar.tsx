/**
 * Sidebar — kimlik, pinler ve yayınlama
 */

import { useState, useEffect } from "react";
import { listen } from "@tauri-apps/api/event";
import { open } from "@tauri-apps/plugin-dialog";
import { ipc, IdentityInfo, PinInfo } from "../lib/ipc";

interface Props {
  onNavigate: (uri: string) => void;
}

export function Sidebar({ onNavigate }: Props) {
  const [tab, setTab] = useState<"identity" | "pins" | "publish">("identity");
  const [identity, setIdentity] = useState<IdentityInfo | null>(null);
  const [pins, setPins] = useState<PinInfo[]>([]);
  const [publishing, setPublishing] = useState(false);
  const [publishResult, setPublishResult] = useState<string | null>(null);
  const [publishTitle, setPublishTitle] = useState("");
  const [copyMsg, setCopyMsg] = useState("");

  useEffect(() => {
    ipc.getIdentity().then(setIdentity).catch(console.error);
    ipc.listPins().then(setPins).catch(console.error);

    const unlisten = listen("site-published", () => {
      ipc.listPins().then(setPins).catch(console.error);
    });
    return () => { unlisten.then(fn => fn()); };
  }, []);

  async function handlePublish() {
    const selected = await open({
      directory: true,
      multiple: false,
      title: "Yayınlanacak klasörü seç",
    });
    if (!selected) return;

    const path = typeof selected === "string" ? selected : selected[0];
    setPublishing(true);
    setPublishResult(null);
    try {
      const result = await ipc.publishSite(
        path,
        publishTitle || undefined,
        undefined
      );
      setPublishResult(result.alter_uri);
      setPins(await ipc.listPins());
    } catch (e) {
      setPublishResult(`Hata: ${e}`);
    } finally {
      setPublishing(false);
    }
  }

  function copyToClipboard(text: string) {
    navigator.clipboard.writeText(text).then(() => {
      setCopyMsg("Kopyalandı!");
      setTimeout(() => setCopyMsg(""), 2000);
    });
  }

  return (
    <aside
      className="glass"
      style={{
        width: 260,
        display: "flex",
        flexDirection: "column",
        borderRadius: 0,
        borderLeft: "none",
        borderTop: "none",
        borderBottom: "none",
      }}
    >
      {/* Tab bar */}
      <div style={{ display: "flex", borderBottom: "1px solid var(--glass-border)", flexWrap: "wrap" }}>
        {(["identity", "pins", "publish", "boards", "discovery", "apps"] as const).map((t) => (
          <button
            key={t}
            className="btn-ghost"
            onClick={() => setTab(t as any)}
            style={{
              flex: "1 1 30%",
              padding: "0.4rem 0",
              fontSize: "0.70rem",
              fontWeight: tab === t ? 700 : 400,
              color: tab === t ? "var(--accent)" : "var(--text-muted)",
              borderBottom: tab === t ? "2px solid var(--accent)" : "2px solid transparent",
              borderRadius: 0,
            }}
          >
            {t === "identity" ? "Kimlik" : t === "pins" ? "Pinler" : t === "publish" ? "Yayınla" : t === "boards" ? "Panolar" : t === "discovery" ? "Keşfet" : "App(WASM)"}
          </button>
        ))}
      </div>

      <div style={{ flex: 1, overflowY: "auto", padding: "1rem" }}>
        {/* Kimlik sekmesi */}
        {tab === "identity" && (
          <div style={{ display: "flex", flexDirection: "column", gap: "0.75rem" }}>
            <h3 style={{ fontSize: "0.85rem", color: "var(--text-muted)", marginBottom: "0.25rem" }}>
              Ed25519 Kimliğin
            </h3>
            {identity ? (
              <>
                <div className="glass-sm" style={{ padding: "0.75rem" }}>
                  <div style={{ fontSize: "0.7rem", color: "var(--text-muted)", marginBottom: "0.3rem" }}>
                    alter:// Adresin
                  </div>
                  <div
                    className="mono truncate"
                    style={{ fontSize: "0.75rem", color: "var(--accent)", cursor: "pointer" }}
                    onClick={() => copyToClipboard(identity.alter_uri)}
                    title="Kopyala"
                  >
                    {identity.alter_uri.slice(0, 40)}…
                  </div>
                </div>
                <div className="glass-sm" style={{ padding: "0.75rem" }}>
                  <div style={{ fontSize: "0.7rem", color: "var(--text-muted)", marginBottom: "0.3rem" }}>
                    Peer ID
                  </div>
                  <div className="mono truncate" style={{ fontSize: "0.72rem" }}>
                    {identity.peer_id.slice(0, 32)}…
                  </div>
                </div>
                <button
                  className="btn-ghost"
                  style={{ width: "100%", fontSize: "0.8rem" }}
                  onClick={() => copyToClipboard(identity.alter_uri)}
                >
                  {copyMsg || "Adresi Kopyala"}
                </button>
              </>
            ) : (
              <div style={{ color: "var(--text-muted)", fontSize: "0.8rem" }}>
                Yükleniyor...
              </div>
            )}
            <div style={{ fontSize: "0.7rem", color: "var(--text-muted)", marginTop: "0.5rem" }}>
              Manifesto I: Hesap yok, kayıt yok.<br />
              Kimliğin bu anahtardır.
            </div>
          </div>
        )}

        {/* Pinler sekmesi */}
        {tab === "pins" && (
          <div style={{ display: "flex", flexDirection: "column", gap: "0.5rem" }}>
            <h3 style={{ fontSize: "0.85rem", color: "var(--text-muted)" }}>
              Pinlenmiş Siteler ({pins.length})
            </h3>
            {pins.length === 0 ? (
              <div style={{ color: "var(--text-muted)", fontSize: "0.8rem" }}>
                Henüz pinlenmiş site yok.<br />
                <span style={{ fontSize: "0.72rem" }}>
                  Manifesto II: Siteyi pinlemek yeniden barındırmak demektir.
                </span>
              </div>
            ) : (
              pins.map((pin) => (
                <div
                  key={pin.root_cid}
                  className="glass-sm"
                  style={{ padding: "0.6rem", cursor: "pointer" }}
                  onClick={() =>
                    onNavigate(
                      `alter://${pin.author_pubkey_hex}`
                    )
                  }
                >
                  <div style={{ fontSize: "0.8rem", fontWeight: 600 }}>
                    {pin.label || "İsimsiz Site"}
                  </div>
                  <div
                    className="mono truncate"
                    style={{ fontSize: "0.7rem", color: "var(--text-muted)" }}
                  >
                    {pin.author_pubkey_hex.slice(0, 20)}…
                  </div>
                  <div style={{ fontSize: "0.7rem", color: "var(--text-muted)" }}>
                    {pin.block_count} blok
                  </div>
                </div>
              ))
            )}
          </div>
        )}

        {/* Yayınla sekmesi */}
        {tab === "publish" && (
          <div style={{ display: "flex", flexDirection: "column", gap: "0.75rem" }}>
            <h3 style={{ fontSize: "0.85rem", color: "var(--text-muted)" }}>
              Siteyi Yayınla
            </h3>
            <p style={{ fontSize: "0.75rem", color: "var(--text-muted)", lineHeight: 1.5 }}>
              Bir klasör seç → merkezi sunucu olmadan alter:// adresi döner.
            </p>
            <input
              placeholder="Site başlığı (opsiyonel)"
              value={publishTitle}
              onChange={(e) => setPublishTitle(e.target.value)}
              style={{ padding: "0.5rem", width: "100%", fontSize: "0.85rem" }}
            />
            <button
              className="btn-primary"
              onClick={handlePublish}
              disabled={publishing}
              style={{ width: "100%" }}
            >
              {publishing ? "Yayınlanıyor..." : "📁 Klasör Seç & Yayınla"}
            </button>

            {publishResult && (
              <div
                className="glass-sm"
                style={{
                  padding: "0.75rem",
                  background: publishResult.startsWith("Hata")
                    ? "rgba(224,64,80,0.1)"
                    : "rgba(64,192,112,0.1)",
                }}
              >
                {publishResult.startsWith("Hata") ? (
                  <div style={{ color: "var(--error)", fontSize: "0.8rem" }}>
                    {publishResult}
                  </div>
                ) : (
                  <>
                    <div style={{ fontSize: "0.75rem", color: "var(--success)", marginBottom: "0.4rem" }}>
                      ✓ Yayınlandı!
                    </div>
                    <div
                      className="mono truncate"
                      style={{ fontSize: "0.72rem", cursor: "pointer" }}
                      onClick={() => copyToClipboard(publishResult)}
                      title="Kopyala"
                    >
                      {publishResult}
                    </div>
                    <div style={{ display: "flex", gap: "0.5rem", marginTop: "0.5rem" }}>
                      <button
                        className="btn-ghost"
                        style={{ flex: 1, fontSize: "0.75rem" }}
                        onClick={() => copyToClipboard(publishResult)}
                      >
                        Kopyala
                      </button>
                      <button
                        className="btn-primary"
                        style={{ flex: 1, fontSize: "0.75rem" }}
                        onClick={() => onNavigate(publishResult)}
                      >
                        Aç
                      </button>
                    </div>
                  </>
                )}
              </div>
            )}
          </div>
        )}
        {/* Panolar sekmesi */}
        {tab === "boards" && (
          <div style={{ display: "flex", flexDirection: "column", gap: "0.75rem" }}>
            <h3 style={{ fontSize: "0.85rem", color: "var(--text-muted)" }}>
              CRDT Panoları
            </h3>
            <div className="glass-sm" style={{ padding: "0.75rem" }}>
              <div style={{ fontSize: "0.75rem", color: "var(--text-muted)", marginBottom: "0.5rem" }}>
                Geliştirme aşamasında (Madde 9)
              </div>
              <p style={{ fontSize: "0.7rem", color: "var(--text-muted)" }}>
                Merkeziyetsiz forumlar ve vikiler automerge ile yönetilir. P2P ağında eşzamanlı değişiklikler çözümlenir.
              </p>
            </div>
          </div>
        )}

        {/* Keşfet sekmesi */}
        {tab === "discovery" && (
          <div style={{ display: "flex", flexDirection: "column", gap: "0.75rem" }}>
            <h3 style={{ fontSize: "0.85rem", color: "var(--text-muted)" }}>
              DHT ile Keşfet
            </h3>
            <input
              placeholder="Örn: #news, #tech"
              style={{ padding: "0.5rem", width: "100%", fontSize: "0.85rem" }}
            />
            <button className="btn-primary" style={{ width: "100%" }}>
              Etiket Ara
            </button>
            <div style={{ fontSize: "0.7rem", color: "var(--text-muted)", marginTop: "0.5rem" }}>
              Ağda bu etiketi içeren manifestolar aranır.
            </div>
          </div>
        )}

        {/* Uygulamalar sekmesi */}
        {tab === "apps" && (
          <div style={{ display: "flex", flexDirection: "column", gap: "0.75rem" }}>
            <h3 style={{ fontSize: "0.85rem", color: "var(--text-muted)" }}>
              WASM Uygulamaları
            </h3>
            <div className="glass-sm" style={{ padding: "0.75rem" }}>
              <button className="btn-ghost" style={{ width: "100%", marginBottom: "0.5rem" }}>
                Uygulama Yükle (.wasm)
              </button>
              <p style={{ fontSize: "0.7rem", color: "var(--text-muted)" }}>
                Uygulamalar katı sandbox içinde çalışır (Manifesto VII). Sistem saati veya ağ erişimi izne tabidir.
              </p>
            </div>
          </div>
        )}
      </div>
    </aside>
  );
}
