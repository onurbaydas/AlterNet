/**
 * AlterNet Browser — Ana Uygulama
 *
 * Manifesto VI: Tarayıcıyı aç, adresi yaz, içeriği gör.
 */

import { useState, useCallback, useEffect } from "react";
import { listen } from "@tauri-apps/api/event";
import { AddressBar } from "./components/AddressBar";
import { BrowserContent } from "./components/BrowserContent";
import { BrowserStatusBar, FetchStatusKind } from "./components/BrowserStatusBar";
import { Sidebar } from "./components/Sidebar";
import { PublishPanel } from "./components/PublishPanel";
import { ipc } from "./lib/ipc";

export default function App() {
  const [history, setHistory] = useState<string[]>([]);
  const [historyIndex, setHistoryIndex] = useState(-1);
  const [isLoading, setIsLoading] = useState(false);
  const [showPublish, setShowPublish] = useState(false);

  // Fetch status state for BrowserStatusBar
  const [fetchStatus, setFetchStatus] = useState<FetchStatusKind>("idle");
  const [fetchUrl, setFetchUrl] = useState("");
  const [blocksDownloaded, setBlocksDownloaded] = useState<number | undefined>(undefined);
  const [blocksTotal, setBlocksTotal] = useState<number | undefined>(undefined);
  const [errorMessage, setErrorMessage] = useState<string | undefined>(undefined);

  const currentUri = history[historyIndex] ?? null;

  // Listen to Tauri fetch-progress events
  useEffect(() => {
    const unlisteners: Array<() => void> = [];

    listen<{ uri?: string; url?: string }>("fetch-started", (event) => {
      const url = event.payload?.uri ?? event.payload?.url ?? "";
      setFetchUrl(url);
      setFetchStatus("fetching");
      setBlocksDownloaded(undefined);
      setBlocksTotal(undefined);
      setErrorMessage(undefined);
    }).then((fn) => unlisteners.push(fn));

    listen<{ uri?: string; url?: string; blocks_downloaded?: number; blocksDownloaded?: number; blocks_total?: number; blocksTotal?: number }>(
      "fetch-progress",
      (event) => {
        const p = event.payload;
        const downloaded = p.blocks_downloaded ?? p.blocksDownloaded;
        const total = p.blocks_total ?? p.blocksTotal;
        if (downloaded !== undefined) setBlocksDownloaded(downloaded);
        if (total !== undefined) setBlocksTotal(total);
        setFetchStatus("fetching");
      }
    ).then((fn) => unlisteners.push(fn));

    listen<{ uri?: string; url?: string }>("fetch-complete", (_event) => {
      setFetchStatus("loaded");
    }).then((fn) => unlisteners.push(fn));

    listen<{ uri?: string; url?: string; error?: string; message?: string; offline?: boolean }>(
      "fetch-error",
      (event) => {
        const p = event.payload;
        const msg = p.error ?? p.message ?? "Bilinmeyen hata";
        const isOffline = p.offline === true || msg.toLowerCase().includes("peer") || msg.toLowerCase().includes("offline");
        setErrorMessage(msg);
        setFetchStatus(isOffline ? "offline" : "error");
      }
    ).then((fn) => unlisteners.push(fn));

    return () => {
      unlisteners.forEach((fn) => fn());
    };
  }, []);

  const navigate = useCallback(
    async (uri: string) => {
      const trimmed = uri.trim();
      if (!trimmed) return;

      setIsLoading(true);

      // Fetch durumunu sıfırla — yeni navigasyon
      setFetchUrl(trimmed);
      setFetchStatus("fetching");
      setBlocksDownloaded(undefined);
      setBlocksTotal(undefined);
      setErrorMessage(undefined);

      // Geçmişi güncelle
      const newHistory = history.slice(0, historyIndex + 1);
      newHistory.push(trimmed);
      setHistory(newHistory);
      setHistoryIndex(newHistory.length - 1);

      // Arka planda çekmeyi başlat
      try {
        await ipc.fetchSite(trimmed);
        // Tauri event gelmezse fallback olarak durumu güncelle
        setFetchStatus((prev) => (prev === "fetching" ? "loaded" : prev));
      } catch (err) {
        // Fetch hatası: Tauri event gelmezse fallback
        const msg = err instanceof Error ? err.message : String(err);
        const isOffline = msg.toLowerCase().includes("peer") || msg.toLowerCase().includes("offline");
        setErrorMessage(msg);
        setFetchStatus((prev) => (prev === "fetching" ? (isOffline ? "offline" : "error") : prev));
      } finally {
        setIsLoading(false);
      }
    },
    [history, historyIndex]
  );

  const goBack = useCallback(() => {
    if (historyIndex > 0) setHistoryIndex((i) => i - 1);
  }, [historyIndex]);

  const goForward = useCallback(() => {
    if (historyIndex < history.length - 1) setHistoryIndex((i) => i + 1);
  }, [history, historyIndex]);

  const refresh = useCallback(() => {
    if (currentUri) {
      ipc.fetchSite(currentUri).catch(console.error);
    }
  }, [currentUri]);

  return (
    <div
      style={{
        height: "100vh",
        display: "flex",
        flexDirection: "column",
        background:
          "linear-gradient(135deg, var(--bg-deep) 0%, var(--bg-mid) 100%)",
      }}
    >
      {/* Başlık çubuğu */}
      <div
        style={{
          height: 36,
          display: "flex",
          alignItems: "center",
          padding: "0 1rem",
          background: "rgba(0,0,0,0.3)",
          borderBottom: "1px solid var(--glass-border)",
          userSelect: "none",
          WebkitAppRegion: "drag" as React.CSSProperties["WebkitAppRegion"],
          gap: "0.5rem",
        }}
      >
        <span style={{ color: "var(--accent)", fontWeight: 700, fontSize: "0.85rem" }}>
          ⬡ AlterNet
        </span>
        {currentUri && (
          <span
            className="mono truncate"
            style={{ fontSize: "0.72rem", color: "var(--text-muted)", flex: 1 }}
          >
            {currentUri}
          </span>
        )}
        {!currentUri && <span className="flex-spacer" />}
        {/* Publish shortcut in title bar — not draggable region */}
        <button
          type="button"
          className="btn-publish"
          onClick={() => setShowPublish(true)}
        >
          + Publish
        </button>
      </div>

      {/* Publish panel overlay */}
      {showPublish && (
        <PublishPanel
          onClose={() => setShowPublish(false)}
          onNavigate={(uri) => {
            setShowPublish(false);
            navigate(uri);
          }}
        />
      )}

      {/* Adres çubuğu */}
      <AddressBar
        currentUri={currentUri ?? ""}
        onNavigate={navigate}
        onBack={goBack}
        onForward={goForward}
        onRefresh={refresh}
        canBack={historyIndex > 0}
        canForward={historyIndex < history.length - 1}
        isLoading={isLoading}
      />

      {/* Fetch durum çubuğu */}
      <BrowserStatusBar
        status={fetchStatus}
        url={fetchUrl}
        blocksDownloaded={blocksDownloaded}
        blocksTotal={blocksTotal}
        errorMessage={errorMessage}
      />

      {/* Ana alan */}
      <div className="app-main-area">
        {/* İçerik — uri yoksa boş durum göster */}
        <BrowserContent uri={currentUri} />

        {/* Kenar çubuğu */}
        <Sidebar onNavigate={navigate} />
      </div>
    </div>
  );
}
