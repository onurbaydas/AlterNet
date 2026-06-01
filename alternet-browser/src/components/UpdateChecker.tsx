import { useEffect, useState } from "react";
import { check } from "@tauri-apps/plugin-updater";
import { relaunch } from "@tauri-apps/plugin-process";

interface UpdateInfo {
  version: string;
  body: string | null | undefined;
}

export default function UpdateChecker() {
  const [update, setUpdate] = useState<UpdateInfo | null>(null);
  const [installing, setInstalling] = useState(false);

  useEffect(() => {
    check()
      .then((result) => {
        if (result?.available) {
          setUpdate({ version: result.version, body: result.body });
        }
      })
      .catch(() => {
        // Silently ignore update check failures — never interrupt the user
      });
  }, []);

  if (!update) return null;

  const handleUpdate = async () => {
    if (installing) return;
    setInstalling(true);
    try {
      const result = await check();
      if (result?.available) {
        await result.downloadAndInstall();
        await relaunch();
      }
    } catch {
      // Silently ignore installation errors
      setInstalling(false);
    }
  };

  return (
    <div
      style={{
        position: "fixed",
        top: 0,
        left: 0,
        right: 0,
        zIndex: 9999,
        backgroundColor: "#1a73e8",
        color: "#fff",
        padding: "8px 16px",
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        fontSize: "14px",
      }}
    >
      <span>Update available: v{update.version}</span>
      <button
        onClick={handleUpdate}
        disabled={installing}
        style={{
          backgroundColor: "#fff",
          color: "#1a73e8",
          border: "none",
          borderRadius: "4px",
          padding: "4px 12px",
          cursor: installing ? "not-allowed" : "pointer",
          fontWeight: 600,
          fontSize: "13px",
        }}
      >
        {installing ? "Installing..." : "Download & Restart"}
      </button>
    </div>
  );
}
