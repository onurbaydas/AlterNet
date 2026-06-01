/**
 * AlterNet Browser — Ana Uygulama
 *
 * Manifesto VI: Tarayıcıyı aç, adresi yaz, içeriği gör.
 */

import { useState, useCallback } from "react";
import { AddressBar } from "./components/AddressBar";
import { BrowserContent } from "./components/BrowserContent";
import { Sidebar } from "./components/Sidebar";
import { ipc } from "./lib/ipc";

export default function App() {
  const [history, setHistory] = useState<string[]>([]);
  const [historyIndex, setHistoryIndex] = useState(-1);
  const [isLoading, setIsLoading] = useState(false);

  const currentUri = history[historyIndex] ?? null;

  const navigate = useCallback(
    async (uri: string) => {
      const trimmed = uri.trim();
      if (!trimmed) return;

      setIsLoading(true);

      // Geçmişi güncelle
      const newHistory = history.slice(0, historyIndex + 1);
      newHistory.push(trimmed);
      setHistory(newHistory);
      setHistoryIndex(newHistory.length - 1);

      // Arka planda çekmeyi başlat
      try {
        await ipc.fetchSite(trimmed);
      } catch {
        // Fetch hatası loading page'den görünür
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
      </div>

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

      {/* Ana alan */}
      <div style={{ flex: 1, display: "flex", overflow: "hidden" }}>
        {/* İçerik */}
        <BrowserContent uri={currentUri} />

        {/* Kenar çubuğu */}
        <Sidebar onNavigate={navigate} />
      </div>
    </div>
  );
}
