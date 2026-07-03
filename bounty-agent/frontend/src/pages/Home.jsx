import { useState, useEffect, useRef, useCallback } from "react";
import { api, createWS } from "../api";
import Sidebar   from "../components/Sidebar";
import Chat      from "../components/Chat";
import Dashboard from "../components/Dashboard";

const AGENT_LOG_TYPES = new Set([
  "agent_status", "agent_log", "agent_tool", "agent_tool_result",
  "agent_error", "report_ready",
]);

export default function Home() {
  const [agents,     setAgents]     = useState([]);
  const [messages,   setMessages]   = useState([]);
  const [findings,   setFindings]   = useState([]);
  const [stats,      setStats]      = useState(null);
  const [brainCount, setBrainCount] = useState(0);
  const [view,          setView]          = useState("chat");
  const [wsReady,       setWsReady]       = useState(false);
  const [selectedAgent, setSelectedAgent] = useState(null);
  const wsRef = useRef(null);

  const tier = localStorage.getItem("ba_tier") || "free";
  const role = localStorage.getItem("ba_role") || "user";

  // ── Push message to chat ───────────────────────────────────────────────────
  const pushMsg = useCallback((msg) => {
    setMessages(prev => [...prev, msg]);
  }, []);

  // ── WebSocket ─────────────────────────────────────────────────────────────
  useEffect(() => {
    function connect() {
      const ws = createWS(handleWS);
      wsRef.current = ws;

      ws.onopen = () => {
        setWsReady(true);
        pushMsg({ role: "system", type: "system", message: "Connected to BountyAgent swarm." });
      };

      ws.onclose = () => {
        setWsReady(false);
        // Reconnect after 3s
        setTimeout(connect, 3000);
      };
    }

    connect();
    return () => wsRef.current?.close();
  }, []);

  function handleWS(data) {
    const { type } = data;

    if (type === "connected") {
      setAgents(data.agents || []);
      setBrainCount(data.brain_techniques || 0);
      return;
    }

    if (type === "brain_update") {
      setBrainCount(data.total_techniques || 0);
      pushMsg({ role: "system", type: "system", message: `Global brain updated: ${data.technique?.title || "new technique"}` });
      return;
    }

    if (type === "new_finding") {
      setFindings(prev => [data.finding, ...prev]);
      pushMsg({ role: "agent", ...data });
      // Refresh stats
      api.getStats().then(setStats).catch(() => {});
      return;
    }

    if (type === "agent_status") {
      setAgents(prev => {
        const idx = prev.findIndex(a => a.agent_id === data.agent_id);
        const updated = { agent_id: data.agent_id, status: data.status, target: data.target, mode: data.mode };
        return idx >= 0
          ? prev.map((a, i) => i === idx ? { ...a, ...updated } : a)
          : [...prev, updated];
      });
      if (data.message) {
        pushMsg({ role: "agent", type: "chat_response", agent_id: data.agent_id, message: data.message });
      }
      return;
    }

    if (type === "agent_log") {
      pushMsg({ role: "agent", type: "chat_response", agent_id: data.agent_id, message: `> ${data.message}` });
      return;
    }

    if (type === "report_ready") {
      pushMsg({ role: "agent", type: "chat_response", agent_id: data.agent_id, message: `Report saved: ${data.report_path}` });
      return;
    }

    // Generic: route to chat
    if ([
      "chat_response", "findings_list", "swarm_status",
      "targets_list", "report", "brain_snapshot",
    ].includes(type)) {
      pushMsg({ role: "agent", ...data });
    }
  }

  // ── Initial data load ──────────────────────────────────────────────────────
  useEffect(() => {
    api.listFindings({ limit: 50 }).then(r => setFindings(r.findings || [])).catch(() => {});
    api.getStats().then(setStats).catch(() => {});
    api.listAgents().then(r => setAgents(r.agents || [])).catch(() => {});
  }, []);

  // ── Send chat message ──────────────────────────────────────────────────────
  function sendMessage(text) {
    pushMsg({ role: "user", type: "chat_response", message: text });
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify({ type: "chat", message: text }));
    } else {
      pushMsg({ role: "system", type: "system", message: "Not connected. Reconnecting…" });
    }
  }

  // ── Stop agent ────────────────────────────────────────────────────────────
  async function stopAgent(agentId) {
    try {
      await api.stopAgent(agentId);
      setAgents(prev => prev.filter(a => a.agent_id !== agentId));
    } catch {}
  }

  return (
    <div className="flex h-screen overflow-hidden bg-surface">
      {/* Sidebar */}
      <Sidebar
        agents={agents}
        findings={findings}
        brainCount={brainCount}
        tier={tier}
        role={role}
        onStop={stopAgent}
        selectedAgent={selectedAgent}
        onSelectAgent={setSelectedAgent}
      />

      {/* Main area */}
      <div className="flex-1 flex flex-col min-w-0">
        {/* Top bar */}
        <header className="h-12 border-b border-surface-4 bg-surface-1 flex items-center px-4 gap-3 shrink-0">
          <div className="flex gap-1">
            <TabBtn active={view === "chat"} onClick={() => setView("chat")}>Chat</TabBtn>
            <TabBtn active={view === "dashboard"} onClick={() => setView("dashboard")}>Dashboard</TabBtn>
          </div>

          <div className="ml-auto flex items-center gap-3 text-xs text-gray-500">
            <span className={wsReady ? "text-accent-green" : "text-accent-red"}>
              {wsReady ? "● Live" : "○ Reconnecting"}
            </span>
            <span>{agents.filter(a => a.status === "running").length} running</span>
            <span>{findings.length} findings</span>
          </div>
        </header>

        {/* Content */}
        <div className="flex-1 overflow-hidden">
          {view === "chat" ? (
            <Chat messages={messages} onSend={sendMessage} disabled={!wsReady} selectedAgent={selectedAgent} />
          ) : (
            <Dashboard findings={findings} stats={stats} />
          )}
        </div>
      </div>
    </div>
  );
}

function TabBtn({ active, onClick, children }) {
  return (
    <button
      onClick={onClick}
      className={`text-xs px-3 py-1 rounded-md transition-colors ${
        active
          ? "bg-surface-3 text-white"
          : "text-gray-500 hover:text-white"
      }`}
    >
      {children}
    </button>
  );
}
