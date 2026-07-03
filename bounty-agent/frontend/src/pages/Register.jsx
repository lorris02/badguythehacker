import { useState } from "react";
import { useNavigate, Link } from "react-router-dom";
import { api } from "../api";

const TIER_FEATURES = {
  free:       ["1 agent", "5 targets", "Basic reports", "Global brain (read)"],
  pro:        ["5 agents", "Unlimited targets", "CVSS reports", "Global brain (contribute)", "PDF export"],
  enterprise: ["Unlimited agents", "Priority targets", "Full brain access", "Custom integrations"],
};

export default function Register() {
  const nav = useNavigate();
  const [form, setForm] = useState({ email: "", password: "", confirm: "" });
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function submit(e) {
    e.preventDefault();
    if (form.password !== form.confirm) { setError("Passwords don't match"); return; }
    setLoading(true); setError("");
    try {
      const res = await api.register(form.email, form.password);
      localStorage.setItem("ba_token", res.access_token);
      localStorage.setItem("ba_tier",  res.tier);
      localStorage.setItem("ba_role",  res.role || "user");
      nav("/");
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="min-h-screen bg-surface flex items-center justify-center p-4">
      <div className="w-full max-w-md">
        <div className="text-center mb-8">
          <div className="text-4xl mb-2">🎯</div>
          <h1 className="text-2xl font-semibold text-white">BountyAgent</h1>
          <p className="text-gray-400 text-sm mt-1">Create your account — free tier to start</p>
        </div>

        <form onSubmit={submit} className="bg-surface-1 border border-surface-4 rounded-xl p-6 space-y-4 mb-4">
          <h2 className="text-lg font-medium text-white">Create account</h2>

          {error && (
            <div className="bg-red-900/30 border border-accent-red/40 text-accent-red text-sm rounded-lg px-3 py-2">
              {error}
            </div>
          )}

          {["email", "password", "confirm"].map(field => (
            <div key={field}>
              <label className="block text-xs text-gray-400 mb-1 capitalize">
                {field === "confirm" ? "Confirm password" : field}
              </label>
              <input
                type={field === "email" ? "email" : "password"}
                value={form[field]}
                onChange={e => setForm(f => ({ ...f, [field]: e.target.value }))}
                required
                className="w-full bg-surface-2 border border-surface-4 rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:border-accent transition-colors"
                placeholder={field === "email" ? "you@example.com" : "••••••••"}
              />
            </div>
          ))}

          <button
            type="submit"
            disabled={loading}
            className="w-full bg-accent hover:bg-blue-500 disabled:opacity-50 text-white rounded-lg py-2 text-sm font-medium transition-colors"
          >
            {loading ? "Creating account..." : "Get started free"}
          </button>
        </form>

        {/* Tier comparison */}
        <div className="grid grid-cols-3 gap-2 mb-4">
          {Object.entries(TIER_FEATURES).map(([tier, features]) => (
            <div key={tier} className={`bg-surface-1 border rounded-lg p-3 ${tier === "pro" ? "border-accent/50" : "border-surface-4"}`}>
              <div className="text-xs font-semibold text-white capitalize mb-1">{tier}</div>
              {features.map(f => (
                <div key={f} className="text-xs text-gray-400 flex items-center gap-1 mt-0.5">
                  <span className="text-accent-green">✓</span> {f}
                </div>
              ))}
            </div>
          ))}
        </div>

        <p className="text-center text-sm text-gray-500">
          Already have an account?{" "}
          <Link to="/login" className="text-accent hover:underline">Sign in</Link>
        </p>
      </div>
    </div>
  );
}
