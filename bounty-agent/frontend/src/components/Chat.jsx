import { useState, useEffect, useRef, useMemo } from "react";
import FindingCard from "./FindingCard";
import { getAgent, AGENT_PALETTE } from "../utils/agents";

const COMMANDS = [
  ["/hunt",                          "Discover programs from every platform & source"],
  ["/hunt --min-bounty 500",         "Programs paying $500+"],
  ["/hunt --min-bounty 1000",        "Programs paying $1000+"],
  ["/hunt --platforms twitter,web",  "Find new programs on Twitter + web"],
  ["/swarm start [n]",               "Spin up n agents to start hunting"],
  ["/swarm stop",                    "Kill all agents"],
  ["/swarm status",                  "Show all agents"],
  ["/targets add <url>",             "Manually add a target"],
  ["/targets",                       "List your targets"],
  ["/findings",                      "Show all findings"],
  ["/report <id>",                   "View full report for a finding"],
  ["/mode bounty",                   "Set bounty mode"],
  ["/mode disclosure",               "Set disclosure mode"],
  ["/brain",                         "Show global technique brain"],
];

const SEVERITY_COLOR = {
  critical: "text-accent-red",
  high:     "text-accent-orange",
  medium:   "text-yellow-400",
  low:      "text-accent",
  info:     "text-gray-400",
};


// Collapse repeated "No targets available" messages into one with a counter
function collapseMessages(messages) {
  const out = [];
  for (const msg of messages) {
    const isNoTarget = (
      (msg.type === "agent_status" || msg.role === "agent") &&
      (msg.message || "").includes("No targets available")
    );
    const last = out[out.length - 1];
    if (
      isNoTarget &&
      last?.isNoTarget &&
      last.agent_id === msg.agent_id
    ) {
      last._count = (last._count || 1) + 1;
    } else {
      out.push({ ...msg, isNoTarget, _count: 1 });
    }
  }
  return out;
}

const PLATFORM_META = {
  hackerone:     { label: "HackerOne",      color: "text-green-400",   bg: "border-green-400/20" },
  bugcrowd:      { label: "Bugcrowd",       color: "text-orange-400",  bg: "border-orange-400/20" },
  intigriti:     { label: "Intigriti",      color: "text-purple-400",  bg: "border-purple-400/20" },
  immunefi:      { label: "Immunefi ⛓",     color: "text-yellow-300",  bg: "border-yellow-300/20" },
  yeswehack:     { label: "YesWeHack",      color: "text-blue-400",    bg: "border-blue-400/20"  },
  hackenproof:   { label: "HackenProof",    color: "text-red-400",     bg: "border-red-400/20"   },
  openbugbounty: { label: "OpenBugBounty",  color: "text-gray-400",    bg: "border-gray-400/20"  },
  twitter:       { label: "Twitter/X",      color: "text-sky-400",     bg: "border-sky-400/20"   },
  web:           { label: "Web",            color: "text-gray-400",    bg: "border-gray-400/20"  },
};

function ProgramCard({ prog }) {
  const meta = PLATFORM_META[prog.platform] || { label: prog.platform, color: "text-gray-400", bg: "border-surface-4" };
  const isTwitter = prog.platform === "twitter";
  const isWeb     = prog.platform === "web";

  const bountyLabel = prog.max_bounty
    ? `$${(prog.min_bounty || 0).toLocaleString()}–$${Number(prog.max_bounty).toLocaleString()} ${prog.currency || "USD"}`
    : isTwitter || isWeb ? "Program announcement" : "VDP (no bounty)";

  return (
    <div className={`bg-surface-2 border ${meta.bg} rounded-lg p-3 text-xs space-y-1`}>
      <div className="flex items-center justify-between gap-2">
        <span className="text-white font-medium truncate">{prog.name}</span>
        <span className={`font-mono shrink-0 ${prog.max_bounty ? "text-accent-green" : "text-gray-500"}`}>
          {bountyLabel}
        </span>
      </div>
      <div className="flex items-center gap-2">
        <span className={`text-[10px] font-medium ${meta.color}`}>{meta.label}</span>
        {!isTwitter && !isWeb && prog.scope?.length > 0 && (
          <span className="text-gray-600 truncate">· {prog.scope.slice(0, 2).join(", ")}{prog.scope.length > 2 ? ` +${prog.scope.length - 2}` : ""}</span>
        )}
        {isTwitter && prog.author && (
          <span className="text-gray-600">· @{prog.handle}</span>
        )}
      </div>
      {isTwitter && prog.description && (
        <div className="text-gray-500 italic line-clamp-2">{prog.description}</div>
      )}
      {!isTwitter && !isWeb && prog.category === "web3" && (
        <div className="text-gray-600 text-[10px]">crypto/DeFi</div>
      )}
      <a
        href={prog.submit_url || prog.url}
        target="_blank"
        rel="noreferrer"
        className={`inline-block text-[10px] hover:underline ${meta.color}`}
      >
        {isTwitter ? "View tweet →" : isWeb ? "Visit →" : "Submit report →"}
      </a>
    </div>
  );
}

function AgentLabel({ agentId, suffix }) {
  const { label, palette } = getAgent(agentId);
  return (
    <span className={`font-semibold ${palette.text}`}>
      {label}{suffix ? ` ${suffix}` : ""}
    </span>
  );
}

function Message({ msg }) {
  const isAgent  = msg.role === "agent";
  const isSystem = msg.role === "system";
  const { label, palette } = getAgent(msg.agent_id);

  if (msg.isNoTarget) {
    return (
      <div className={`py-0.5 text-xs border-l-2 pl-2 ${palette.border} ${palette.dim}`}>
        <span className={palette.text}>{label}</span>
        {" "}— waiting for targets
        {msg._count > 1 && (
          <span className="ml-1 text-gray-600">(×{msg._count})</span>
        )}
      </div>
    );
  }

  if (msg.type === "new_finding") {
    return (
      <div className="py-1">
        <div className="text-xs text-accent-green mb-1 flex items-center gap-1">
          <span>⚡</span> New finding from <AgentLabel agentId={msg.agent_id} />
          {msg.finding?.program_name && (
            <span className="text-gray-500 ml-1">· {msg.finding.program_name}</span>
          )}
        </div>
        <FindingCard finding={msg.finding} inline />
        {msg.finding?.submit_url && (
          <a
            href={msg.finding.submit_url}
            target="_blank"
            rel="noreferrer"
            className="inline-block mt-1 text-xs bg-accent/10 border border-accent/30 text-accent hover:bg-accent/20 px-3 py-1 rounded-lg transition-colors"
          >
            🏆 Claim reward on {msg.finding.platform || "platform"} →
          </a>
        )}
      </div>
    );
  }

  if (msg.type === "programs_discovered") {
    const programs = msg.programs || [];
    const byPlatform = msg.by_platform || {};
    const platformSummary = Object.entries(byPlatform)
      .filter(([, n]) => n > 0)
      .map(([pl, n]) => `${PLATFORM_META[pl]?.label || pl} (${n})`)
      .join(" · ");

    return (
      <div className="py-1 space-y-2">
        <div className="text-xs text-accent-green font-medium">
          🔍 Found {programs.length} program(s) — added top {msg.added_as_targets || 0} as targets
        </div>
        {platformSummary && (
          <div className="text-[10px] text-gray-500">{platformSummary}</div>
        )}
        {msg.message && (
          <div className="text-xs text-gray-400">{msg.message}</div>
        )}
        <div className="space-y-1.5 max-h-80 overflow-y-auto pr-1">
          {programs.slice(0, 10).map((p, i) => <ProgramCard key={i} prog={p} />)}
          {programs.length > 10 && (
            <div className="text-xs text-gray-600 text-center py-1">
              +{programs.length - 10} more programs added as targets
            </div>
          )}
        </div>
      </div>
    );
  }

  if (msg.type === "agent_blocker") {
    return (
      <div className="py-1">
        <div className="text-xs text-accent-orange mb-1 flex items-center gap-1">
          <span>⚠</span> <AgentLabel agentId={msg.agent_id} suffix="blocked" />
        </div>
        <div className="bg-surface-2 border border-accent-orange/30 rounded-lg p-3 text-xs space-y-1">
          <div className="text-white">{msg.blocker}</div>
          {msg.what_i_need && (
            <div className="text-gray-400">
              <span className="text-accent-orange">Needs:</span> {msg.what_i_need}
            </div>
          )}
          {msg.what_ill_do_without_it && (
            <div className="text-gray-500">
              <span className="text-gray-400">Fallback:</span> {msg.what_ill_do_without_it}
            </div>
          )}
        </div>
      </div>
    );
  }

  if (msg.type === "findings_list") {
    return (
      <div className="py-1 space-y-2">
        <div className="text-xs text-gray-500">Findings ({msg.findings?.length || 0})</div>
        {(msg.findings || []).map(f => <FindingCard key={String(f.id)} finding={f} />)}
      </div>
    );
  }

  if (msg.type === "swarm_status") {
    const agents = msg.agents || [];
    return (
      <div className="py-1">
        <div className="text-xs text-gray-500 mb-1">Swarm — {agents.length} agent(s)</div>
        {agents.length === 0 && <div className="text-xs text-gray-600">No active agents.</div>}
        {agents.map(a => {
          const { label: aLabel, palette: ap } = getAgent(a.agent_id);
          return (
            <div key={a.agent_id} className="text-xs text-gray-300 py-0.5 flex items-center gap-2">
              <span className={a.status === "running" ? "text-accent-green" : "text-gray-600"}>●</span>
              <span className={`font-semibold ${ap.text}`}>{aLabel}</span>
              <span className="text-gray-600">— {a.status}{a.target ? ` → ${a.target}` : ""}</span>
            </div>
          );
        })}
      </div>
    );
  }

  if (msg.type === "targets_list") {
    return (
      <div className="py-1">
        <div className="text-xs text-gray-500 mb-1">Targets ({msg.targets?.length || 0})</div>
        {(msg.targets || []).map((t, i) => (
          <div key={i} className="text-xs font-mono py-0.5 flex items-center gap-2">
            <span className={t.status === "claimed" ? "text-accent-orange" : t.status === "completed" ? "text-accent-green" : "text-gray-400"}>
              {t.status === "claimed" ? "⟳" : t.status === "completed" ? "✓" : "○"}
            </span>
            <span className="text-gray-300">{t.url}</span>
            {t.program_name && <span className="text-gray-600">[{t.program_name}]</span>}
            <span className="text-gray-700">[{t.mode}]</span>
          </div>
        ))}
      </div>
    );
  }

  if (msg.type === "report") {
    return (
      <div className="py-1">
        <div className="text-xs text-gray-500 mb-1">Report for {msg.finding?.vuln_type}</div>
        <div className="prose text-xs bg-surface-2 border border-surface-4 rounded-lg p-3 max-h-96 overflow-y-auto whitespace-pre-wrap">
          {msg.content || "Report not available."}
        </div>
        {msg.finding?.submit_url && (
          <a
            href={msg.finding.submit_url}
            target="_blank"
            rel="noreferrer"
            className="inline-block mt-2 text-xs bg-accent/10 border border-accent/30 text-accent hover:bg-accent/20 px-3 py-1 rounded-lg transition-colors"
          >
            🏆 Claim reward →
          </a>
        )}
      </div>
    );
  }

  if (msg.type === "brain_snapshot") {
    return (
      <div className="py-1">
        <div className="text-xs text-gray-400 mb-1">
          Global Brain — {msg.total} techniques indexed
        </div>
        {(msg.top_techniques || []).slice(0, 5).map((t, i) => (
          <div key={i} className="text-xs text-gray-500 py-0.5 font-mono">
            [{t.category}] {t.title}
          </div>
        ))}
      </div>
    );
  }

  if (msg.type === "agent_heat") {
    const HEAT_STYLES = {
      cold:     "text-blue-400 border-blue-700/50",
      warm:     "text-yellow-400 border-yellow-700/50",
      hot:      "text-orange-400 border-orange-700/50",
      critical: "text-red-400 border-red-700/50",
    };
    const HEAT_ICONS = { cold: "❄", warm: "~", hot: "▲", critical: "!!" };
    const s = HEAT_STYLES[msg.label] || "text-gray-400 border-gray-700";
    return (
      <div className={`py-0.5 text-xs border-l-2 pl-2 ${s}`}>
        {HEAT_ICONS[msg.label] || "~"} <AgentLabel agentId={msg.agent_id} /> → <span className="font-bold uppercase">{msg.label}</span> — <span className="font-mono">{msg.model?.split("/").pop() || msg.model}</span>
      </div>
    );
  }

  if (msg.type === "hive_intel") {
    return (
      <div className="py-0.5 text-xs border-l-2 border-purple-600/60 pl-2 text-purple-300">
        ⚡ swarm → <AgentLabel agentId={msg.agent_id} />: <span className="font-mono">{msg.pattern}</span> [{msg.category}]
      </div>
    );
  }

  if (msg.type === "agent_error") {
    return (
      <div className="py-0.5">
        <div className="text-xs text-red-400 mb-0.5">error <AgentLabel agentId={msg.agent_id} /></div>
        <div className="text-xs text-red-300/70 font-mono">{msg.error}</div>
      </div>
    );
  }

  // agent_log / agent_tool / agent_tool_result / agent_status
  if (msg.type === "agent_log" || msg.type === "agent_tool" || msg.type === "agent_tool_result" || msg.type === "agent_status") {
    const isReady = (msg.message || "").includes("Agent ready");
    const toolLabel = msg.type === "agent_tool" ? `🔧 ${msg.tool}` : null;

    return (
      <div className={`py-0.5 border-l-2 pl-2 ${palette.border}`}>
        <div className="text-xs mb-0.5 flex items-center gap-1.5">
          <span className={`font-semibold ${palette.text}`}>{label}</span>
          {toolLabel && <span className="text-gray-500">{toolLabel}</span>}
          {isReady && <span className="text-gray-600">ready</span>}
        </div>
        <div className="text-xs text-gray-500 font-mono leading-relaxed">
          {msg.message || msg.input_preview || msg.result_preview || ""}
        </div>
      </div>
    );
  }

  return (
    <div className={`py-1 ${isSystem ? "opacity-60" : ""}`}>
      <div className={`text-xs mb-1 ${isAgent ? palette.text : isSystem ? "text-gray-600" : "text-gray-400"}`}>
        {isAgent ? label : isSystem ? "system" : "you"}
      </div>
      <div className={`text-sm leading-relaxed whitespace-pre-wrap ${isAgent ? "text-gray-200" : isSystem ? "text-gray-500" : "text-white"}`}>
        {msg.message || msg.text || ""}
      </div>
    </div>
  );
}

export default function Chat({ messages, onSend, disabled, selectedAgent }) {
  const [input, setInput]           = useState("");
  const [showHelp, setShowHelp]     = useState(false);
  const [suggestion, setSuggestion] = useState("");
  const bottomRef = useRef(null);
  const inputRef  = useRef(null);

  const { label: agentLabel, palette: agentPalette } = selectedAgent
    ? getAgent(selectedAgent)
    : { label: null, palette: null };

  const filtered = useMemo(() => {
    if (!selectedAgent) return messages;
    return messages.filter(m =>
      m.role === "user" ||
      m.role === "system" ||
      m.agent_id === selectedAgent
    );
  }, [messages, selectedAgent]);

  const collapsed = useMemo(() => collapseMessages(filtered), [filtered]);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [collapsed]);

  function handleInput(e) {
    const val = e.target.value;
    setInput(val);
    if (val.startsWith("/")) {
      const match = COMMANDS.find(([cmd]) => cmd.startsWith(val));
      setSuggestion(match ? match[0] : "");
    } else {
      setSuggestion("");
    }
  }

  function handleKey(e) {
    if (e.key === "Tab" && suggestion) {
      e.preventDefault();
      setInput(suggestion.split(" ")[0] + " ");
      setSuggestion("");
    }
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      send();
    }
  }

  function send() {
    const msg = input.trim();
    if (!msg || disabled) return;
    onSend(msg);
    setInput("");
    setSuggestion("");
  }

  return (
    <div className="flex flex-col h-full">
      {/* Agent filter header */}
      {selectedAgent && agentLabel && (
        <div className={`px-4 py-2 border-b border-surface-4 flex items-center gap-2 text-xs bg-surface-1`}>
          <span className={`w-2 h-2 rounded-full ${agentPalette.dot}`} />
          <span className={`font-semibold ${agentPalette.text}`}>{agentLabel}</span>
          <span className="text-gray-500">— showing this agent only</span>
          <span className="ml-auto text-gray-600">{collapsed.filter(m => m.agent_id === selectedAgent).length} messages</span>
        </div>
      )}

      {/* Messages */}
      <div className="flex-1 overflow-y-auto px-4 py-4 space-y-3">
        {collapsed.length === 0 && (
          <div className="text-center text-gray-600 text-sm mt-12">
            <div className="text-3xl mb-3">🎯</div>
            <div className="text-white mb-1">BountyAgent Swarm</div>
            <div className="text-xs text-gray-500 mb-4">Tech, finance, gaming, healthcare, govt — all niches</div>
            <div className="inline-block text-left space-y-1">
              {[COMMANDS[0], COMMANDS[1], COMMANDS[4], COMMANDS[8]].map(([cmd, desc]) => (
                <div
                  key={cmd}
                  onClick={() => setInput(cmd)}
                  className="text-xs cursor-pointer hover:text-accent transition-colors"
                >
                  <span className="text-accent font-mono">{cmd}</span>
                  <span className="text-gray-600 ml-2">— {desc}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {collapsed.map((msg, i) => (
          <Message key={i} msg={msg} />
        ))}
        <div ref={bottomRef} />
      </div>

      {/* Help tooltip */}
      {showHelp && (
        <div className="mx-4 mb-2 bg-surface-2 border border-surface-4 rounded-lg p-3">
          <div className="text-xs text-gray-500 mb-1.5 font-medium">Commands</div>
          {COMMANDS.map(([cmd, desc]) => (
            <div
              key={cmd}
              className="text-xs py-0.5 cursor-pointer hover:text-white transition-colors flex gap-2"
              onClick={() => { setInput(cmd); setShowHelp(false); inputRef.current?.focus(); }}
            >
              <span className="text-accent font-mono w-52 shrink-0">{cmd}</span>
              <span className="text-gray-500">{desc}</span>
            </div>
          ))}
        </div>
      )}

      {/* Input bar */}
      <div className="px-4 pb-4">
        <div className="relative bg-surface-2 border border-surface-4 rounded-xl focus-within:border-accent/50 transition-colors">
          {suggestion && (
            <div className="absolute left-3 top-3 text-sm text-gray-600 pointer-events-none">
              <span className="invisible">{input}</span>
              <span>{suggestion.slice(input.length)}</span>
            </div>
          )}
          <textarea
            ref={inputRef}
            value={input}
            onChange={handleInput}
            onKeyDown={handleKey}
            placeholder="Message the swarm… or /hunt to find programs"
            rows={1}
            disabled={disabled}
            className="w-full bg-transparent text-white text-sm px-3 pt-3 pb-10 resize-none focus:outline-none placeholder-gray-600"
            style={{ maxHeight: "120px" }}
          />
          <div className="absolute bottom-2 right-2 flex items-center gap-2">
            <button
              onClick={() => setShowHelp(h => !h)}
              className="text-gray-500 hover:text-white text-xs px-2 py-1 rounded transition-colors"
            >
              /help
            </button>
            <button
              onClick={send}
              disabled={!input.trim() || disabled}
              className="bg-accent hover:bg-blue-500 disabled:opacity-30 text-white text-xs px-3 py-1.5 rounded-lg transition-colors"
            >
              Send ↵
            </button>
          </div>
        </div>
        <div className="text-[10px] text-gray-700 mt-1 text-center">
          Tab to autocomplete slash commands · Enter to send
        </div>
      </div>
    </div>
  );
}
