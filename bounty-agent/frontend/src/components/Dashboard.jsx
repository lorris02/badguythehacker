import FindingCard from "./FindingCard";

const SEV_ORDER = ["critical", "high", "medium", "low", "info"];

export default function Dashboard({ findings, stats }) {
  const sorted = [...findings].sort(
    (a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity)
  );

  return (
    <div className="p-4 space-y-4 overflow-y-auto h-full">
      {/* Stats row */}
      {stats && (
        <div className="grid grid-cols-4 gap-3">
          <StatCard label="Total Findings" value={stats.total_findings} color="text-accent" />
          <StatCard label="Confirmed" value={stats.confirmed} color="text-accent-green" />
          <StatCard label="Critical" value={stats.by_severity?.critical || 0} color="text-accent-red" />
          <StatCard label="Sessions" value={stats.total_sessions} color="text-accent-purple" />
        </div>
      )}

      {/* Findings list */}
      <div>
        <div className="text-xs font-medium text-gray-500 mb-2">ALL FINDINGS</div>
        {sorted.length === 0 ? (
          <div className="text-gray-600 text-sm text-center py-8">
            No findings yet. Start a swarm to begin hunting.
          </div>
        ) : (
          <div className="space-y-2">
            {sorted.map(f => (
              <FindingCard key={String(f.id)} finding={f} />
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

function StatCard({ label, value, color }) {
  return (
    <div className="bg-surface-1 border border-surface-4 rounded-lg p-3">
      <div className={`text-2xl font-bold font-mono ${color}`}>{value ?? "—"}</div>
      <div className="text-xs text-gray-500 mt-0.5">{label}</div>
    </div>
  );
}
