import { useState } from "react";
import { api } from "../api";

const SEV = {
  critical: { bg: "bg-red-900/30",    border: "border-red-500/40",    text: "text-red-400",    label: "CRITICAL" },
  high:     { bg: "bg-orange-900/30", border: "border-orange-500/40", text: "text-orange-400", label: "HIGH"     },
  medium:   { bg: "bg-yellow-900/30", border: "border-yellow-500/40", text: "text-yellow-400", label: "MEDIUM"   },
  low:      { bg: "bg-blue-900/30",   border: "border-blue-500/40",   text: "text-blue-400",   label: "LOW"      },
  info:     { bg: "bg-gray-900/30",   border: "border-gray-500/40",   text: "text-gray-400",   label: "INFO"     },
};

export default function FindingCard({ finding, inline = false }) {
  const [expanded, setExpanded]   = useState(inline);
  const [report, setReport]       = useState(null);
  const [loadingRep, setLoadingRep] = useState(false);

  const sev = SEV[finding.severity] || SEV.info;

  async function loadReport() {
    if (report) { setExpanded(e => !e); return; }
    setLoadingRep(true);
    try {
      const res = await api.getReport(String(finding.id));
      setReport(res.content);
      setExpanded(true);
    } catch {
      setReport("Report not available yet.");
      setExpanded(true);
    } finally {
      setLoadingRep(false);
    }
  }

  return (
    <div className={`border rounded-lg overflow-hidden text-xs transition-all ${sev.bg} ${sev.border}`}>
      {/* Header row */}
      <div
        className="flex items-center gap-2 px-3 py-2 cursor-pointer select-none"
        onClick={() => setExpanded(e => !e)}
      >
        <span className={`font-bold text-[10px] px-1.5 py-0.5 rounded border ${sev.bg} ${sev.border} ${sev.text}`}>
          {sev.label}
        </span>
        <span className="text-white font-medium flex-1 truncate">{finding.vuln_type}</span>
        {finding.cvss_score && (
          <span className={`font-mono font-bold ${sev.text}`}>
            {finding.cvss_score.toFixed(1)}
          </span>
        )}
        {finding.confirmed && (
          <span className="text-accent-green text-[10px] font-medium">✓ CONFIRMED</span>
        )}
        <span className="text-gray-500">{expanded ? "▲" : "▼"}</span>
      </div>

      {/* URL bar */}
      <div className="px-3 pb-2 text-gray-500 truncate font-mono text-[11px]">
        {finding.url}
      </div>

      {/* Expanded detail */}
      {expanded && (
        <div className="border-t border-surface-4 px-3 py-3 space-y-2">
          {finding.description && (
            <p className="text-gray-300 leading-relaxed">{finding.description}</p>
          )}

          {finding.cvss_vector && (
            <div className="font-mono text-[11px] text-gray-500 bg-surface-2 rounded px-2 py-1 break-all">
              {finding.cvss_vector}
            </div>
          )}

          <button
            onClick={loadReport}
            disabled={loadingRep}
            className="text-accent hover:underline text-[11px] mt-1 disabled:opacity-50"
          >
            {loadingRep ? "Loading report…" : report ? "Hide report" : "View full report →"}
          </button>

          {report && (
            <div className="prose max-w-none text-[12px] bg-surface-2 rounded-lg p-3 max-h-96 overflow-y-auto mt-2 whitespace-pre-wrap">
              {report}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
