import { useNavigate } from "react-router-dom";
import AgentStatus from "./AgentStatus";

const TIER_BADGE = {
  free:       "bg-gray-700 text-gray-300",
  pro:        "bg-accent/20 text-accent",
  enterprise: "bg-accent-purple/20 text-accent-purple",
  admin:      "bg-accent-red/20 text-accent-red",
};

export default function Sidebar({ agents, findings, brainCount, tier, role, onStop, selectedAgent, onSelectAgent }) {
  const nav = useNavigate();

  function logout() {
    localStorage.clear();
    nav("/login");
  }

  const critical = findings.filter(f => f.severity === "critical").length;
  const high     = findings.filter(f => f.severity === "high").length;
  const running  = agents.filter(a => a.status === "running").length;

  return (
    <aside className="w-64 min-h-screen bg-surface-1 border-r border-surface-4 flex flex-col">
      {/* Brand */}
      <div className="p-4 border-b border-surface-4">
        <div className="flex items-center gap-2">
          <span className="text-2xl">🎯</span>
          <div>
            <div className="text-white font-semibold leading-tight">BountyAgent</div>
            <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded uppercase ${role === "admin" ? TIER_BADGE.admin : (TIER_BADGE[tier] || TIER_BADGE.free)}`}>
              {role === "admin" ? "admin" : tier}
            </span>
          </div>
        </div>
      </div>

      {/* Quick stats */}
      <div className="grid grid-cols-3 gap-1 p-3 border-b border-surface-4">
        <Stat label="Running" value={running} color="text-accent-green" />
        <Stat label="Findings" value={findings.length} color="text-accent" />
        <Stat label="Critical" value={critical} color="text-accent-red" />
      </div>

      {/* Global brain indicator */}
      <div className="px-3 py-2 border-b border-surface-4">
        <div className="flex items-center justify-between text-xs">
          <span className="text-gray-500">Global Brain</span>
          <span className="text-accent-purple font-mono font-medium">{brainCount} techniques</span>
        </div>
        <div className="w-full bg-surface-4 rounded-full h-1 mt-1.5">
          <div
            className="bg-accent-purple h-1 rounded-full transition-all duration-500"
            style={{ width: `${Math.min(100, (brainCount / 500) * 100)}%` }}
          />
        </div>
      </div>

      {/* Agents */}
      <div className="flex-1 overflow-y-auto p-3 space-y-2">
        <div className="text-xs text-gray-500 font-medium mb-2">
          AGENTS ({agents.length})
        </div>
        {agents.length === 0 && (
          <div className="text-xs text-gray-600 text-center py-4">
            No active agents.<br />
            <span className="text-accent">/swarm start 1</span>
          </div>
        )}
        {selectedAgent && (
          <button
            onClick={() => onSelectAgent(null)}
            className="w-full text-[10px] text-gray-500 hover:text-white border border-surface-4 rounded-md py-1 mb-1 transition-colors"
          >
            ← All agents
          </button>
        )}
        {agents.map(a => (
          <AgentStatus
            key={a.agent_id}
            agent={a}
            onStop={onStop}
            selected={selectedAgent === a.agent_id}
            onSelect={onSelectAgent}
          />
        ))}
      </div>

      {/* Footer */}
      <div className="p-3 border-t border-surface-4">
        <button
          onClick={logout}
          className="w-full text-xs text-gray-500 hover:text-white transition-colors py-1"
        >
          Sign out
        </button>
      </div>
    </aside>
  );
}

function Stat({ label, value, color }) {
  return (
    <div className="bg-surface-2 rounded-lg p-2 text-center">
      <div className={`text-lg font-bold font-mono ${color}`}>{value}</div>
      <div className="text-[10px] text-gray-500">{label}</div>
    </div>
  );
}
