import { getAgent } from "../utils/agents";

export default function AgentStatus({ agent, onStop, selected, onSelect }) {
  const status = agent.status || "idle";
  const { label, palette } = getAgent(agent.agent_id);

  const isRunning = status === "running";
  const borderCls = selected
    ? `${palette.border} border-2`
    : isRunning
      ? "border-surface-4"
      : "border-surface-3";

  return (
    <div
      onClick={() => onSelect?.(selected ? null : agent.agent_id)}
      className={`border rounded-lg p-3 text-xs transition-all cursor-pointer
        ${selected ? "bg-surface-3" : "bg-surface-2 hover:bg-surface-3"}
        ${borderCls}`}
    >
      <div className="flex items-center justify-between mb-1.5">
        <div className="flex items-center gap-1.5">
          <span className={`w-1.5 h-1.5 rounded-full ${palette.dot} ${isRunning ? "animate-pulse" : "opacity-50"}`} />
          <span className={`font-semibold ${palette.text}`}>{label}</span>
        </div>
        {status !== "stopped" && (
          <button
            onClick={e => { e.stopPropagation(); onStop(agent.agent_id); }}
            className="text-gray-600 hover:text-accent-red transition-colors px-1"
            title="Stop agent"
          >
            ✕
          </button>
        )}
      </div>

      <div className="text-gray-400 capitalize">{status}</div>

      {agent.target && (
        <div className="text-gray-500 truncate mt-0.5 text-[10px]" title={agent.target}>
          {agent.target.replace(/^https?:\/\//, "").slice(0, 35)}
        </div>
      )}

      {agent.mode && (
        <div className={`mt-1 inline-block px-1.5 py-0.5 rounded text-[10px] font-medium ${
          agent.mode === "disclosure"
            ? "bg-accent-purple/20 text-accent-purple"
            : "bg-accent/20 text-accent"
        }`}>
          {agent.mode}
        </div>
      )}
    </div>
  );
}
