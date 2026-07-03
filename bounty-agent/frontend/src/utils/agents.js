export const AGENT_PALETTE = [
  { text: "text-emerald-400", border: "border-emerald-500", dim: "text-emerald-600", dot: "bg-emerald-400" },
  { text: "text-blue-400",    border: "border-blue-500",    dim: "text-blue-600",    dot: "bg-blue-400"    },
  { text: "text-purple-400",  border: "border-purple-500",  dim: "text-purple-600",  dot: "bg-purple-400"  },
  { text: "text-orange-400",  border: "border-orange-500",  dim: "text-orange-600",  dot: "bg-orange-400"  },
  { text: "text-cyan-400",    border: "border-cyan-500",    dim: "text-cyan-600",    dot: "bg-cyan-400"    },
  { text: "text-pink-400",    border: "border-pink-500",    dim: "text-pink-600",    dot: "bg-pink-400"    },
  { text: "text-yellow-400",  border: "border-yellow-500",  dim: "text-yellow-600",  dot: "bg-yellow-400"  },
  { text: "text-red-400",     border: "border-red-500",     dim: "text-red-600",     dot: "bg-red-400"     },
];

const registry = {};
let counter = 0;

export function getAgent(agentId) {
  if (!agentId) return { label: "Agent", palette: AGENT_PALETTE[0] };
  if (!registry[agentId]) {
    const idx = counter % AGENT_PALETTE.length;
    registry[agentId] = { label: `Agent ${counter + 1}`, palette: AGENT_PALETTE[idx] };
    counter++;
  }
  return registry[agentId];
}
