import { useState, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";

// --- Types ---
interface BoardItem {
  id: string;
  author: string;
  content: string;
  timestamp: number;
}

interface BoardProps {
  channelName: string;
}

export function Board({ channelName }: BoardProps) {
  const [items, setItems] = useState<BoardItem[]>([]);
  const [newItem, setNewItem] = useState("");

  useEffect(() => {
    // 1. Initial Load of CRDT items
    invoke<BoardItem[]>("get_board_items", { channel_name: channelName })
      .then(data => setItems(data))
      .catch(console.error);

    // 2. Poll or Listen for CRDT sync events
    // In a real Automerge implementation, we would subscribe to 'board-updated' events
    const interval = setInterval(() => {
      invoke<BoardItem[]>("get_board_items", { channel_name: channelName })
        .then(data => setItems(data))
        .catch(() => {});
    }, 5000);

    return () => clearInterval(interval);
  }, [channelName]);

  const handleAdd = async () => {
    if (!newItem.trim()) return;
    try {
      await invoke("add_board_item", { channel_name: channelName, content: newItem });
      setNewItem("");
      // Optimistic update could go here
    } catch (err) {
      console.error(err);
    }
  };

  return (
    <div className="board-panel glass-panel" style={{ display: 'flex', flexDirection: 'column', height: '100%', padding: '16px' }}>
      <div className="board-header" style={{ borderBottom: '1px solid #1a2a3a', paddingBottom: '12px', marginBottom: '16px' }}>
        <h2 style={{ margin: 0, color: 'var(--text-normal)' }}>{channelName} Board</h2>
        <span style={{ fontSize: '12px', color: 'var(--accent-cyan)' }}>CRDT Synchronized</span>
      </div>

      <div className="board-items" style={{ flex: 1, overflowY: 'auto', display: 'flex', gap: '12px', flexWrap: 'wrap', alignContent: 'flex-start' }}>
        {items.map(item => (
          <div key={item.id} className="board-card" style={{ background: '#2b2d31', padding: '12px', borderRadius: '8px', minWidth: '200px', border: '1px solid #1e1f22' }}>
            <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginBottom: '8px' }}>
              {item.author.substring(0, 8)} • {new Date(item.timestamp).toLocaleTimeString()}
            </div>
            <div style={{ color: 'var(--text-normal)', fontSize: '14px' }}>
              {item.content}
            </div>
          </div>
        ))}
      </div>

      <div className="board-input" style={{ marginTop: '16px', display: 'flex', gap: '8px' }}>
        <input 
          type="text" 
          value={newItem} 
          onChange={e => setNewItem(e.target.value)} 
          placeholder="Add a new item to the board..." 
          style={{ flex: 1, padding: '10px', background: '#1e1f22', border: '1px solid #1a2a3a', borderRadius: '6px', color: '#dbdee1' }}
        />
        <button onClick={handleAdd} className="cyber-btn primary">Post</button>
      </div>
    </div>
  );
}
