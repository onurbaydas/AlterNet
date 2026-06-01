/**
 * BrowserContent — alter:// içerik görüntüleyici
 *
 * Manifesto VI: Adres çubuğuna yaz, içeriği gör.
 */

import { useEffect, useRef, useState } from "react";
import { listen } from "@tauri-apps/api/event";

interface Props {
  uri: string | null;
}

export function BrowserContent({ uri }: Props) {
  const iframeRef = useRef<HTMLIFrameElement>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!uri) return;

    setLoading(true);

    // iframe'in alter:// adresine yönlendir
    if (iframeRef.current) {
      iframeRef.current.src = uri.endsWith("/")
        ? uri + "index.html"
        : uri + "/index.html";
    }

    // site-ready eventi dinle: içerik gelince yenile
    const unlisten = listen("site-ready", (event) => {
      if (event.payload === uri && iframeRef.current) {
        iframeRef.current.src = iframeRef.current.src;
      }
    });

    return () => {
      unlisten.then(fn => fn());
    };
  }, [uri]);

  if (!uri) {
    return <WelcomePage />;
  }

  return (
    <div style={{ flex: 1, position: "relative", overflow: "hidden" }}>
      {loading && (
        <div
          style={{
            position: "absolute",
            top: 0,
            left: 0,
            right: 0,
            height: 2,
            background: "linear-gradient(90deg, var(--accent), transparent)",
            animation: "progress 2s ease infinite",
          }}
        />
      )}
      <iframe
        ref={iframeRef}
        title="AlterNet Content"
        onLoad={() => setLoading(false)}
        onError={() => setLoading(false)}
        style={{
          width: "100%",
          height: "100%",
          border: "none",
          background: "#fff",
        }}
        sandbox="allow-scripts allow-same-origin"
      />
      <style>{`
        @keyframes progress {
          0%   { transform: scaleX(0); transform-origin: left; }
          50%  { transform: scaleX(0.7); transform-origin: left; }
          100% { transform: scaleX(1); transform-origin: left; opacity: 0; }
        }
      `}</style>
    </div>
  );
}

function WelcomePage() {
  return (
    <div
      style={{
        flex: 1,
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        background: "linear-gradient(135deg, var(--bg-deep) 0%, var(--bg-mid) 100%)",
      }}
    >
      <div
        className="glass"
        style={{
          maxWidth: 520,
          padding: "3rem",
          textAlign: "center",
          background: "rgba(120, 80, 255, 0.06)",
        }}
      >
        <div style={{ fontSize: "3rem", marginBottom: "1rem" }}>⬡</div>
        <h1
          style={{
            fontSize: "1.6rem",
            fontWeight: 700,
            color: "var(--accent)",
            marginBottom: "0.75rem",
          }}
        >
          AlterNet Browser
        </h1>
        <p style={{ color: "var(--text-muted)", lineHeight: 1.7, marginBottom: "1.5rem" }}>
          Sunucusuz, hesapsız, sansüre dayanıklı web.<br />
          Adres çubuğuna bir <code style={{ color: "var(--accent)" }}>alter://</code> adresi
          yaz ve Enter'a bas.
        </p>
        <div
          className="glass-sm"
          style={{
            padding: "1rem",
            textAlign: "left",
            fontSize: "0.8rem",
            color: "var(--text-muted)",
            lineHeight: 1.8,
          }}
        >
          <div>I. Tek Otorite Allah'tır — Kapatılacak merkez yok</div>
          <div>II. Ağ Kullanıcılara Aittir — Her cihaz hem istemci hem sunucu</div>
          <div>III. Güvenlik Varsayılandır — Şifreleme kapatılamaz</div>
          <div>VII. Kod Söz Verir — İmzasız içerik görüntülenemez</div>
        </div>
      </div>
    </div>
  );
}
