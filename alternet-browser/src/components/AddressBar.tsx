/**
 * AddressBar — alter:// adres çubuğu
 *
 * Manifesto VI: Kullanıcı bir adresi yazıp Enter'a basar — hepsi bu.
 */

import { useState, useRef, useEffect } from "react";
import { ipc } from "../lib/ipc";

interface Props {
  currentUri: string;
  onNavigate: (uri: string) => void;
  onBack: () => void;
  onForward: () => void;
  onRefresh: () => void;
  canBack: boolean;
  canForward: boolean;
  isLoading: boolean;
}

export function AddressBar({
  currentUri,
  onNavigate,
  onBack,
  onForward,
  onRefresh,
  canBack,
  canForward,
  isLoading,
}: Props) {
  const [input, setInput] = useState(currentUri);
  const [resolving, setResolving] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  // Dış navigasyon değişince input güncelle
  useEffect(() => {
    if (document.activeElement !== inputRef.current) {
      setInput(currentUri);
    }
  }, [currentUri]);

  // Yükleme başlayınca (isLoading true → false geçişi değil, true anında) input'u canlı URI ile güncelle
  // Yükleme tamamlayınca currentUri zaten set edilmiş olur — input'u güncelleme useEffect'e bırakılır


  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    const raw = input.trim();
    if (!raw) return;

    // alter:// ile başlamıyorsa petname çözümü dene
    if (!raw.startsWith("alter://")) {
      setResolving(true);
      try {
        const resolved = await ipc.resolveName(raw);
        setInput(resolved);
        onNavigate(resolved);
      } catch {
        // Çözülemedi — olduğu gibi dene
        onNavigate(raw.startsWith("alter://") ? raw : `alter://${raw}`);
      } finally {
        setResolving(false);
      }
    } else {
      onNavigate(raw);
    }
  }

  return (
    <form
      onSubmit={handleSubmit}
      style={{
        display: "flex",
        alignItems: "center",
        gap: "0.5rem",
        padding: "0.5rem 0.75rem",
        background: "rgba(255,255,255,0.04)",
        borderBottom: "1px solid var(--glass-border)",
      }}
    >
      {/* Geri / İleri / Yenile */}
      <button
        type="button"
        className="btn-ghost"
        onClick={onBack}
        disabled={!canBack}
        title="Geri"
        style={{ fontSize: "1.1rem", padding: "0.3rem 0.5rem" }}
      >
        ←
      </button>
      <button
        type="button"
        className="btn-ghost"
        onClick={onForward}
        disabled={!canForward}
        title="İleri"
        style={{ fontSize: "1.1rem", padding: "0.3rem 0.5rem" }}
      >
        →
      </button>
      <button
        type="button"
        className="btn-ghost"
        onClick={onRefresh}
        title="Yenile"
        style={{ fontSize: "1rem", padding: "0.3rem 0.5rem" }}
      >
        {isLoading ? "⏳" : "↻"}
      </button>

      {/* Adres alanı */}
      <div style={{ flex: 1, position: "relative" }}>
        <span
          style={{
            position: "absolute",
            left: "0.6rem",
            top: "50%",
            transform: "translateY(-50%)",
            color: "var(--accent)",
            fontSize: "0.8rem",
            fontWeight: 600,
            pointerEvents: "none",
            opacity: input.startsWith("alter://") ? 0 : 0.6,
          }}
        >
          alter://
        </span>
        <input
          ref={inputRef}
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onFocus={(e) => e.target.select()}
          placeholder="alter://abc123... veya petname"
          style={{
            width: "100%",
            padding: "0.45rem 2.2rem 0.45rem 0.75rem",
            fontSize: "0.875rem",
            fontFamily: "'JetBrains Mono', monospace",
          }}
        />
        {/* Yükleme spinner — sağ kenarda */}
        {(isLoading || resolving) && (
          <span className="address-spinner">◌</span>
        )}
        <style>{`
          @keyframes alternet-spin {
            from { rotate: 0deg; }
            to   { rotate: 360deg; }
          }
        `}</style>
      </div>

      <button
        type="submit"
        className="btn-primary"
        disabled={resolving || isLoading}
        style={{ padding: "0.45rem 1rem", fontSize: "0.875rem" }}
      >
        {resolving ? "…" : "Git"}
      </button>
    </form>
  );
}
