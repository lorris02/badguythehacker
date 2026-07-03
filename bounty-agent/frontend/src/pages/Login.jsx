import { useState } from "react";
import { useNavigate, Link } from "react-router-dom";
import { api } from "../api";

export default function Login() {
  const nav = useNavigate();
  const [form, setForm] = useState({ email: "", password: "" });
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function submit(e) {
    e.preventDefault();
    setLoading(true);
    setError("");
    try {
      const res = await api.login(form.email, form.password);
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
      <div className="w-full max-w-sm">
        {/* Logo */}
        <div className="text-center mb-8">
          <div className="text-4xl mb-2">🎯</div>
          <h1 className="text-2xl font-semibold text-white">BountyAgent</h1>
          <p className="text-gray-400 text-sm mt-1">Autonomous bug bounty swarm</p>
        </div>

        <form onSubmit={submit} className="bg-surface-1 border border-surface-4 rounded-xl p-6 space-y-4">
          <h2 className="text-lg font-medium text-white">Sign in</h2>

          {error && (
            <div className="bg-red-900/30 border border-accent-red/40 text-accent-red text-sm rounded-lg px-3 py-2">
              {error}
            </div>
          )}

          <div>
            <label className="block text-xs text-gray-400 mb-1">Email</label>
            <input
              type="email"
              value={form.email}
              onChange={e => setForm(f => ({ ...f, email: e.target.value }))}
              required
              className="w-full bg-surface-2 border border-surface-4 rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:border-accent transition-colors"
              placeholder="you@example.com"
            />
          </div>

          <div>
            <label className="block text-xs text-gray-400 mb-1">Password</label>
            <input
              type="password"
              value={form.password}
              onChange={e => setForm(f => ({ ...f, password: e.target.value }))}
              required
              className="w-full bg-surface-2 border border-surface-4 rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:border-accent transition-colors"
              placeholder="••••••••"
            />
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full bg-accent hover:bg-blue-500 disabled:opacity-50 text-white rounded-lg py-2 text-sm font-medium transition-colors"
          >
            {loading ? "Signing in..." : "Sign in"}
          </button>
        </form>

        <p className="text-center text-sm text-gray-500 mt-4">
          No account?{" "}
          <Link to="/register" className="text-accent hover:underline">Create one</Link>
        </p>
      </div>
    </div>
  );
}
