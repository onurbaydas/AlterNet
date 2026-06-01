/**
 * BrowserStatusBar — fetch durumu göstergesi
 *
 * Manifesto VI: Kullanıcı her an ne olduğunu bilir.
 */

import { useEffect, useRef, useState } from "react";

export type FetchStatusKind =
  | "idle"
  | "fetching"
  | "loaded"
  | "error"
  | "offline";

interface Props {
  status: FetchStatusKind;
  url: string;
  blocksDownloaded?: number;
  blocksTotal?: number;
  errorMessage?: string;
}

export function BrowserStatusBar({
  status,
  url,
  blocksDownloaded,
  blocksTotal,
  errorMessage,
}: Props) {
  // "loaded" durumunda kısa süre göster sonra gizle
  const [visible, setVisible] = useState(false);
  const [fading, setFading] = useState(false);
  const fadeTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    if (fadeTimer.current) {
      clearTimeout(fadeTimer.current);
      fadeTimer.current = null;
    }

    if (status === "idle") {
      setVisible(false);
      setFading(false);
      return;
    }

    setFading(false);
    setVisible(true);

    if (status === "loaded") {
      // 1.8 s tam görünür, sonra 400 ms fade out
      fadeTimer.current = setTimeout(() => {
        setFading(true);
        fadeTimer.current = setTimeout(() => {
          setVisible(false);
          setFading(false);
        }, 400);
      }, 1800);
    }

    return () => {
      if (fadeTimer.current) clearTimeout(fadeTimer.current);
    };
  }, [status]);

  if (!visible) return null;

  // progress yüzdesi
  const pct =
    blocksTotal && blocksTotal > 0
      ? Math.round((blocksDownloaded ?? 0) / blocksTotal * 100)
      : null;

  /* ---- renk / ikon per durum ---- */
  const palette: Record<
    FetchStatusKind,
    { bg: string; border: string; color: string }
  > = {
    idle: {
      bg: "transparent",
      border: "transparent",
      color: "transparent",
    },
    fetching: {
      bg: "rgba(120,80,255,0.08)",
      border: "rgba(120,80,255,0.3)",
      color: "var(--accent, #7850ff)",
    },
    loaded: {
      bg: "rgba(40,180,100,0.08)",
      border: "rgba(40,180,100,0.35)",
      color: "#3dba78",
    },
    error: {
      bg: "rgba(220,60,60,0.08)",
      border: "rgba(220,60,60,0.35)",
      color: "#e04040",
    },
    offline: {
      bg: "rgba(200,140,30,0.08)",
      border: "rgba(200,140,30,0.35)",
      color: "#c89030",
    },
  };

  const p = palette[status];

  const containerStyle: React.CSSProperties = {
    display: "flex",
    flexDirection: "column",
    gap: 4,
    padding: "0.3rem 0.75rem",
    background: p.bg,
    borderTop: `1px solid ${p.border}`,
    fontSize: "0.78rem",
    fontFamily: "'JetBrains Mono', monospace",
    color: p.color,
    userSelect: "none",
    opacity: fading ? 0 : 1,
    transition: fading ? "opacity 0.4s ease" : "opacity 0.15s ease",
  };

  /* ---- progress bar (fetching) ---- */
  const progressBar =
    status === "fetching" && blocksTotal && blocksTotal > 0 ? (
      <div
        style={{
          height: 2,
          background: "rgba(120,80,255,0.15)",
          borderRadius: 2,
          overflow: "hidden",
        }}
      >
        <div
          style={{
            height: "100%",
            width: `${pct}%`,
            background: "var(--accent, #7850ff)",
            transition: "width 0.3s ease",
            borderRadius: 2,
          }}
        />
      </div>
    ) : status === "fetching" ? (
      /* indeterminate pulse — opacity-only animation (compositor-only) */
      <div
        style={{
          height: 2,
          background: "rgba(120,80,255,0.15)",
          borderRadius: 2,
          overflow: "hidden",
        }}
      >
        <div className="status-indeterminate-bar" />
        <style>{`
          @keyframes alternet-indeterminate {
            0%, 100% { opacity: 0.25; }
            50%       { opacity: 1; }
          }
        `}</style>
      </div>
    ) : null;

  /* ---- message line ---- */
  let message: string;
  if (status === "fetching") {
    const truncated =
      url.length > 48 ? url.slice(0, 45) + "…" : url;
    if (blocksTotal && blocksTotal > 0) {
      message = `Getiriliyor: ${truncated}  (${blocksDownloaded ?? 0} / ${blocksTotal} blok  ${pct}%)`;
    } else {
      message = `Getiriliyor: ${truncated}`;
    }
  } else if (status === "loaded") {
    message = `✓ Yüklendi`;
  } else if (status === "error") {
    message = `✗ Hata: ${errorMessage ?? "Bilinmeyen hata"}`;
  } else {
    // offline
    message = `⚠ Peer bulunamadı — site mevcut olmayabilir`;
  }

  return (
    <div style={containerStyle} aria-live="polite" role="status">
      <span style={{ whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
        {message}
      </span>
      {progressBar}
    </div>
  );
}
