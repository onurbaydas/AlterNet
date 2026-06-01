/**
 * PublishPanel — Full-featured publish flow for AlterNet sites.
 *
 * Flow:
 *   1. Pick a folder (Tauri dialog plugin)
 *   2. Pre-publish validation (index.html presence, size, file count)
 *   3. Fill in site metadata (title, description, tags)
 *   4. Publish → show alter:// URI with prominent Copy button
 *
 * Manifesto I: Merkezi sunucu yok — DHT'ye doğrudan yayınlanır.
 * Manifesto VII: Her manifest Ed25519 ile imzalanır.
 */

import { useState, useCallback } from "react";
import { open } from "@tauri-apps/plugin-dialog";
import { ipc, FolderValidation } from "../lib/ipc";

interface Props {
  onClose: () => void;
  onNavigate: (uri: string) => void;
}

type Step = "setup" | "publishing" | "success" | "error";

const MAX_TITLE_LEN = 100;
const MAX_DESC_LEN = 500;
const SIZE_WARN_BYTES = 50 * 1024 * 1024; // 50 MB

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

export function PublishPanel({ onClose, onNavigate }: Props) {
  const [step, setStep] = useState<Step>("setup");

  // Folder selection
  const [folderPath, setFolderPath] = useState("");
  const [validation, setValidation] = useState<FolderValidation | null>(null);
  const [validating, setValidating] = useState(false);

  // Metadata form
  const [title, setTitle] = useState("");
  const [description, setDescription] = useState("");
  const [tags, setTags] = useState("");

  // Results
  const [alterUri, setAlterUri] = useState("");
  const [blockCount, setBlockCount] = useState(0);
  const [errorMsg, setErrorMsg] = useState("");
  const [copied, setCopied] = useState(false);
  const [publishLog, setPublishLog] = useState("");

  const selectFolder = useCallback(async () => {
    const selected = await open({
      directory: true,
      multiple: false,
      title: "Select folder to publish",
    });
    if (!selected) return;
    const path = typeof selected === "string" ? selected : selected[0];
    setFolderPath(path);
    setValidation(null);

    setValidating(true);
    try {
      const result = await ipc.validatePublishFolder(path);
      setValidation(result);
    } catch (e) {
      // Validation failed — proceed without it (non-blocking)
      console.warn("Folder validation failed:", e);
    } finally {
      setValidating(false);
    }
  }, []);

  const handlePublish = useCallback(async () => {
    if (!folderPath || !title.trim()) return;

    setStep("publishing");
    setPublishLog("Building DAG from folder…");

    try {
      const tagList = tags
        .split(",")
        .map((t) => t.trim())
        .filter(Boolean);

      const result = await ipc.publishSite(
        folderPath,
        title.trim(),
        description.trim() || undefined
      );

      setAlterUri(result.alter_uri);
      setBlockCount(result.block_count);
      void tagList; // tags field will be used once the Rust API accepts it
      setStep("success");
    } catch (e) {
      setErrorMsg(String(e));
      setStep("error");
    }
  }, [folderPath, title, description, tags]);

  const copyUri = useCallback(() => {
    navigator.clipboard.writeText(alterUri).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2500);
    });
  }, [alterUri]);

  const canPublish =
    folderPath.length > 0 &&
    title.trim().length > 0 &&
    title.trim().length <= MAX_TITLE_LEN;

  // ─── Overlay backdrop ────────────────────────────────────────────────────
  return (
    <div
      style={{
        position: "fixed",
        inset: 0,
        zIndex: 1000,
        background: "rgba(7, 7, 26, 0.82)",
        backdropFilter: "blur(6px)",
        WebkitBackdropFilter: "blur(6px)",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
      }}
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      {/* Panel card */}
      <div
        className="glass"
        style={{
          width: "min(540px, 92vw)",
          maxHeight: "88vh",
          display: "flex",
          flexDirection: "column",
          overflow: "hidden",
          boxShadow: "0 24px 80px rgba(0,0,0,0.7)",
          border: "1px solid rgba(120, 80, 255, 0.3)",
        }}
      >
        {/* Header */}
        <div
          style={{
            padding: "1.1rem 1.4rem 0.9rem",
            borderBottom: "1px solid var(--glass-border)",
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            flexShrink: 0,
          }}
        >
          <div>
            <div
              style={{
                fontSize: "1.05rem",
                fontWeight: 700,
                color: "var(--accent)",
                letterSpacing: "0.02em",
              }}
            >
              Publish to AlterNet
            </div>
            <div
              style={{
                fontSize: "0.72rem",
                color: "var(--text-muted)",
                marginTop: "0.15rem",
              }}
            >
              No servers. No accounts. Just your key and the DHT.
            </div>
          </div>
          <button
            className="btn-ghost"
            onClick={onClose}
            style={{ fontSize: "1.1rem", padding: "0.3rem 0.6rem", lineHeight: 1 }}
            aria-label="Close"
          >
            ✕
          </button>
        </div>

        {/* Scrollable body */}
        <div style={{ flex: 1, overflowY: "auto", padding: "1.2rem 1.4rem" }}>
          {/* ─── SETUP STEP ──────────────────────────────────────────── */}
          {step === "setup" && (
            <div style={{ display: "flex", flexDirection: "column", gap: "1.1rem" }}>
              {/* Step 1: Folder */}
              <section>
                <SectionLabel number={1} text="Choose site folder" />
                <button
                  className="btn-ghost"
                  onClick={selectFolder}
                  disabled={validating}
                  style={{
                    width: "100%",
                    padding: "0.75rem 1rem",
                    border: "1px dashed rgba(120, 80, 255, 0.45)",
                    borderRadius: "var(--radius-sm)",
                    textAlign: "left",
                    color: folderPath ? "var(--text-primary)" : "var(--text-muted)",
                    fontSize: "0.82rem",
                    fontFamily: folderPath ? "monospace" : "inherit",
                    display: "flex",
                    alignItems: "center",
                    gap: "0.6rem",
                  }}
                >
                  <span style={{ fontSize: "1.1rem" }}>
                    {validating ? "⏳" : folderPath ? "📂" : "📁"}
                  </span>
                  <span style={{ flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                    {validating
                      ? "Scanning folder…"
                      : folderPath || "Click to pick a folder"}
                  </span>
                  {folderPath && !validating && (
                    <span style={{ color: "var(--accent)", fontSize: "0.72rem", flexShrink: 0 }}>
                      Change
                    </span>
                  )}
                </button>

                {/* Validation results */}
                {validation && !validating && (
                  <div
                    style={{
                      marginTop: "0.55rem",
                      display: "flex",
                      flexDirection: "column",
                      gap: "0.4rem",
                    }}
                  >
                    {/* File count + size row */}
                    <div
                      className="glass-sm"
                      style={{
                        padding: "0.6rem 0.8rem",
                        display: "flex",
                        gap: "1.2rem",
                        fontSize: "0.78rem",
                        color: "var(--text-muted)",
                      }}
                    >
                      <span>
                        <strong style={{ color: "var(--text-primary)" }}>
                          {validation.file_count}
                        </strong>{" "}
                        files
                      </span>
                      <span>
                        <strong style={{ color: "var(--text-primary)" }}>
                          {formatBytes(validation.total_bytes)}
                        </strong>{" "}
                        total
                      </span>
                    </div>

                    {/* Warning: no index.html */}
                    {!validation.has_index_html && (
                      <WarningBox text="No index.html found. Your site may not display correctly in browsers." />
                    )}

                    {/* Warning: large folder */}
                    {validation.total_bytes > SIZE_WARN_BYTES && (
                      <WarningBox
                        text={`Warning: Large site (${formatBytes(validation.total_bytes)}). Publishing may take a long time and use significant bandwidth.`}
                      />
                    )}
                  </div>
                )}
              </section>

              {/* Step 2: Metadata */}
              <section>
                <SectionLabel number={2} text="Site metadata" />

                <div style={{ display: "flex", flexDirection: "column", gap: "0.65rem" }}>
                  {/* Title */}
                  <div>
                    <label
                      style={{
                        display: "block",
                        fontSize: "0.75rem",
                        color: "var(--text-muted)",
                        marginBottom: "0.3rem",
                      }}
                    >
                      Title{" "}
                      <span style={{ color: "var(--error)", marginLeft: "0.1rem" }}>*</span>
                    </label>
                    <div style={{ position: "relative" }}>
                      <input
                        type="text"
                        placeholder="My AlterNet Site"
                        value={title}
                        onChange={(e) =>
                          setTitle(e.target.value.slice(0, MAX_TITLE_LEN))
                        }
                        style={{
                          width: "100%",
                          padding: "0.55rem 3.5rem 0.55rem 0.75rem",
                          fontSize: "0.88rem",
                          borderColor:
                            title.length > 0 && title.trim().length === 0
                              ? "var(--error)"
                              : undefined,
                        }}
                        autoFocus
                      />
                      <span
                        style={{
                          position: "absolute",
                          right: "0.6rem",
                          top: "50%",
                          transform: "translateY(-50%)",
                          fontSize: "0.68rem",
                          color:
                            title.length >= MAX_TITLE_LEN
                              ? "var(--error)"
                              : "var(--text-muted)",
                          pointerEvents: "none",
                        }}
                      >
                        {title.length}/{MAX_TITLE_LEN}
                      </span>
                    </div>
                  </div>

                  {/* Description */}
                  <div>
                    <label
                      style={{
                        display: "block",
                        fontSize: "0.75rem",
                        color: "var(--text-muted)",
                        marginBottom: "0.3rem",
                      }}
                    >
                      Description{" "}
                      <span style={{ fontSize: "0.65rem" }}>(optional)</span>
                    </label>
                    <textarea
                      placeholder="A short description shown in search results…"
                      value={description}
                      onChange={(e) =>
                        setDescription(e.target.value.slice(0, MAX_DESC_LEN))
                      }
                      rows={3}
                      style={{
                        width: "100%",
                        padding: "0.55rem 0.75rem",
                        fontSize: "0.85rem",
                        resize: "vertical",
                        minHeight: "70px",
                        lineHeight: 1.5,
                      }}
                    />
                    <div
                      style={{
                        textAlign: "right",
                        fontSize: "0.68rem",
                        color:
                          description.length >= MAX_DESC_LEN
                            ? "var(--error)"
                            : "var(--text-muted)",
                        marginTop: "0.15rem",
                      }}
                    >
                      {description.length}/{MAX_DESC_LEN}
                    </div>
                  </div>

                  {/* Tags */}
                  <div>
                    <label
                      style={{
                        display: "block",
                        fontSize: "0.75rem",
                        color: "var(--text-muted)",
                        marginBottom: "0.3rem",
                      }}
                    >
                      Tags{" "}
                      <span style={{ fontSize: "0.65rem" }}>
                        (optional, comma-separated)
                      </span>
                    </label>
                    <input
                      type="text"
                      placeholder="news, tech, art"
                      value={tags}
                      onChange={(e) => setTags(e.target.value)}
                      style={{ width: "100%", padding: "0.55rem 0.75rem", fontSize: "0.85rem" }}
                    />
                    {tags.trim().length > 0 && (
                      <div
                        style={{
                          display: "flex",
                          flexWrap: "wrap",
                          gap: "0.3rem",
                          marginTop: "0.4rem",
                        }}
                      >
                        {tags
                          .split(",")
                          .map((t) => t.trim())
                          .filter(Boolean)
                          .map((tag) => (
                            <span
                              key={tag}
                              style={{
                                background: "rgba(120, 80, 255, 0.18)",
                                border: "1px solid rgba(120, 80, 255, 0.35)",
                                borderRadius: "20px",
                                padding: "0.1rem 0.55rem",
                                fontSize: "0.72rem",
                                color: "var(--accent)",
                              }}
                            >
                              #{tag}
                            </span>
                          ))}
                      </div>
                    )}
                  </div>
                </div>
              </section>
            </div>
          )}

          {/* ─── PUBLISHING STEP ─────────────────────────────────────── */}
          {step === "publishing" && (
            <div
              style={{
                display: "flex",
                flexDirection: "column",
                alignItems: "center",
                gap: "1.2rem",
                padding: "2rem 0",
                textAlign: "center",
              }}
            >
              <div style={{ fontSize: "2.5rem", animation: "alternet-spin 1.2s linear infinite", display: "inline-block" }}>
                ⬡
              </div>
              <div>
                <div style={{ fontSize: "1rem", fontWeight: 600, color: "var(--accent)" }}>
                  Publishing to AlterNet…
                </div>
                <div style={{ fontSize: "0.78rem", color: "var(--text-muted)", marginTop: "0.4rem" }}>
                  Building DAG, signing manifest, announcing to DHT.
                </div>
              </div>
              <div
                className="glass-sm"
                style={{
                  width: "100%",
                  padding: "0.7rem 1rem",
                  fontSize: "0.75rem",
                  color: "var(--text-muted)",
                  textAlign: "left",
                  fontFamily: "monospace",
                }}
              >
                {publishLog || "Initializing…"}
              </div>
              <div style={{ fontSize: "0.72rem", color: "var(--text-muted)" }}>
                This may take up to 30 seconds while the node joins the DHT.
              </div>
            </div>
          )}

          {/* ─── SUCCESS STEP ────────────────────────────────────────── */}
          {step === "success" && (
            <div style={{ display: "flex", flexDirection: "column", gap: "1.1rem" }}>
              {/* Hero success message */}
              <div
                style={{
                  background: "rgba(64, 192, 112, 0.12)",
                  border: "1px solid rgba(64, 192, 112, 0.35)",
                  borderRadius: "var(--radius)",
                  padding: "1.1rem 1.2rem",
                  textAlign: "center",
                }}
              >
                <div style={{ fontSize: "2rem", marginBottom: "0.4rem" }}>
                  ✓
                </div>
                <div
                  style={{
                    fontSize: "1.05rem",
                    fontWeight: 700,
                    color: "var(--success)",
                    marginBottom: "0.3rem",
                  }}
                >
                  Your site is live!
                </div>
                <div style={{ fontSize: "0.78rem", color: "var(--text-muted)" }}>
                  Share this link — anyone with AlterNet can open it.
                </div>
              </div>

              {/* URI display */}
              <div
                className="glass-sm"
                style={{ padding: "0.9rem 1rem" }}
              >
                <div
                  style={{
                    fontSize: "0.7rem",
                    color: "var(--text-muted)",
                    marginBottom: "0.45rem",
                    textTransform: "uppercase",
                    letterSpacing: "0.06em",
                  }}
                >
                  alter:// address
                </div>
                <div
                  className="mono"
                  style={{
                    fontSize: "0.78rem",
                    color: "var(--accent)",
                    wordBreak: "break-all",
                    lineHeight: 1.55,
                    userSelect: "all",
                  }}
                >
                  {alterUri}
                </div>
              </div>

              {/* Large copy button */}
              <button
                className="btn-primary"
                onClick={copyUri}
                style={{
                  width: "100%",
                  padding: "0.85rem",
                  fontSize: "0.95rem",
                  fontWeight: 700,
                  letterSpacing: "0.03em",
                  background: copied
                    ? "var(--success)"
                    : "var(--accent)",
                  transition: "background 0.25s",
                }}
              >
                {copied ? "✓ Copied!" : "Copy Link"}
              </button>

              {/* Stats row */}
              <div
                style={{
                  display: "flex",
                  gap: "0.8rem",
                  fontSize: "0.75rem",
                  color: "var(--text-muted)",
                }}
              >
                <div
                  className="glass-sm"
                  style={{ flex: 1, padding: "0.55rem 0.7rem", textAlign: "center" }}
                >
                  <div style={{ fontWeight: 700, color: "var(--text-primary)", fontSize: "0.95rem" }}>
                    {blockCount}
                  </div>
                  <div>blocks</div>
                </div>
                {validation && (
                  <>
                    <div
                      className="glass-sm"
                      style={{ flex: 1, padding: "0.55rem 0.7rem", textAlign: "center" }}
                    >
                      <div style={{ fontWeight: 700, color: "var(--text-primary)", fontSize: "0.95rem" }}>
                        {validation.file_count}
                      </div>
                      <div>files</div>
                    </div>
                    <div
                      className="glass-sm"
                      style={{ flex: 1, padding: "0.55rem 0.7rem", textAlign: "center" }}
                    >
                      <div style={{ fontWeight: 700, color: "var(--text-primary)", fontSize: "0.95rem" }}>
                        {formatBytes(validation.total_bytes)}
                      </div>
                      <div>size</div>
                    </div>
                  </>
                )}
              </div>

              {/* Open / Publish Another */}
              <div style={{ display: "flex", gap: "0.65rem" }}>
                <button
                  className="btn-ghost"
                  onClick={() => onNavigate(alterUri)}
                  style={{ flex: 1, fontSize: "0.85rem" }}
                >
                  Open Site
                </button>
                <button
                  className="btn-ghost"
                  onClick={() => {
                    setStep("setup");
                    setFolderPath("");
                    setValidation(null);
                    setTitle("");
                    setDescription("");
                    setTags("");
                    setAlterUri("");
                    setCopied(false);
                  }}
                  style={{ flex: 1, fontSize: "0.85rem" }}
                >
                  Publish Another
                </button>
              </div>
            </div>
          )}

          {/* ─── ERROR STEP ──────────────────────────────────────────── */}
          {step === "error" && (
            <div style={{ display: "flex", flexDirection: "column", gap: "1rem" }}>
              <div
                style={{
                  background: "rgba(224, 64, 80, 0.1)",
                  border: "1px solid rgba(224, 64, 80, 0.35)",
                  borderRadius: "var(--radius)",
                  padding: "1rem 1.1rem",
                  textAlign: "center",
                }}
              >
                <div style={{ fontSize: "2rem", marginBottom: "0.35rem" }}>✗</div>
                <div style={{ fontSize: "0.95rem", fontWeight: 700, color: "var(--error)", marginBottom: "0.4rem" }}>
                  Publish failed
                </div>
                <div
                  className="mono"
                  style={{
                    fontSize: "0.75rem",
                    color: "var(--text-muted)",
                    wordBreak: "break-word",
                    lineHeight: 1.5,
                    textAlign: "left",
                  }}
                >
                  {errorMsg}
                </div>
              </div>
              <button
                className="btn-ghost"
                onClick={() => setStep("setup")}
                style={{ width: "100%" }}
              >
                Back to Setup
              </button>
            </div>
          )}
        </div>

        {/* Footer actions — only shown on setup step */}
        {step === "setup" && (
          <div
            style={{
              padding: "0.9rem 1.4rem 1.1rem",
              borderTop: "1px solid var(--glass-border)",
              display: "flex",
              gap: "0.65rem",
              flexShrink: 0,
            }}
          >
            <button
              className="btn-ghost"
              onClick={onClose}
              style={{ flex: "0 0 auto", fontSize: "0.85rem" }}
            >
              Cancel
            </button>
            <button
              className="btn-primary"
              onClick={handlePublish}
              disabled={!canPublish}
              style={{
                flex: 1,
                fontSize: "0.92rem",
                fontWeight: 700,
                padding: "0.7rem",
                opacity: canPublish ? 1 : undefined,
              }}
            >
              {!folderPath
                ? "Select a folder first"
                : !title.trim()
                ? "Enter a title to continue"
                : "Publish to AlterNet"}
            </button>
          </div>
        )}
      </div>
    </div>
  );
}

// ─── Small helper components ───────────────────────────────────────────────

function SectionLabel({ number, text }: { number: number; text: string }) {
  return (
    <div
      style={{
        display: "flex",
        alignItems: "center",
        gap: "0.55rem",
        marginBottom: "0.6rem",
      }}
    >
      <span
        style={{
          width: "1.4rem",
          height: "1.4rem",
          borderRadius: "50%",
          background: "rgba(120, 80, 255, 0.25)",
          border: "1px solid rgba(120, 80, 255, 0.45)",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          fontSize: "0.7rem",
          fontWeight: 700,
          color: "var(--accent)",
          flexShrink: 0,
        }}
      >
        {number}
      </span>
      <span style={{ fontSize: "0.82rem", fontWeight: 600, color: "var(--text-primary)" }}>
        {text}
      </span>
    </div>
  );
}

function WarningBox({ text }: { text: string }) {
  return (
    <div
      style={{
        background: "rgba(224, 160, 48, 0.10)",
        border: "1px solid rgba(224, 160, 48, 0.35)",
        borderRadius: "var(--radius-sm)",
        padding: "0.55rem 0.75rem",
        fontSize: "0.76rem",
        color: "#e0a030",
        display: "flex",
        gap: "0.5rem",
        alignItems: "flex-start",
        lineHeight: 1.5,
      }}
    >
      <span style={{ flexShrink: 0, marginTop: "0.05rem" }}>⚠</span>
      <span>{text}</span>
    </div>
  );
}
