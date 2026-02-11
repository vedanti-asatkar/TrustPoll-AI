"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:5000";
const WALLET_REGEX = /^WALLET_[A-Z0-9]{4,8}$/;

export default function LoginPage() {
  const router = useRouter();
  const [email, setEmail] = useState("");
  const [wallet, setWallet] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const handleLogin = async () => {
    const cleanEmail = email.trim();
    const cleanWallet = wallet.trim();

    if (!cleanEmail || !cleanWallet) {
      setError("Please fill in all fields.");
      return;
    }
    if (!WALLET_REGEX.test(cleanWallet)) {
      setError("Wallet must follow format: WALLET_XXXX");
      return;
    }

    setLoading(true);
    setError("");

    try {
      const res = await fetch(`${API_BASE}/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: cleanEmail, wallet: cleanWallet }),
      });

      if (res.ok) {
        localStorage.setItem("user_wallet", cleanWallet);
        localStorage.setItem("user_email", cleanEmail);
        router.push("/vote");
      } else {
        const data = await res.json();
        setError(data.error || "Login failed.");
      }
    } catch (err) {
      setError("Network error. Please try again.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="relative min-h-screen overflow-hidden text-slate-100">
      <div className="pointer-events-none absolute inset-0 grid-overlay" />
      <div className="pointer-events-none absolute inset-0 noise-overlay" />
      <div className="pointer-events-none absolute -top-24 left-10 h-80 w-80 rounded-full bg-cyan-500/10 blur-3xl" />
      <div className="pointer-events-none absolute -bottom-20 right-0 h-96 w-96 rounded-full bg-amber-300/10 blur-3xl" />
      <div className="pointer-events-none absolute right-[15%] top-[30%] h-64 w-64 rounded-full aurora" />
      <div className="mx-auto flex min-h-screen max-w-4xl items-center px-6 py-16">
        <div className="glass-panel w-full rounded-3xl p-10 shadow-2xl">
          <div className="grid gap-8 lg:grid-cols-[1fr_1fr] lg:items-center">
            <div className="space-y-4">
              <div className="inline-flex items-center gap-3 rounded-full border border-slate-700/60 bg-slate-950/70 px-4 py-2 text-xs font-semibold uppercase tracking-[0.3em] text-slate-300">
                Secure Access
                <span className="h-1.5 w-6 rounded-full bg-gradient-to-r from-cyan-400 via-sky-400 to-amber-300" />
              </div>
              <h2 className="font-display text-3xl font-semibold text-slate-100">Student Login</h2>
              <p className="text-sm text-slate-400">
                Verify your wallet and continue to the secure voting space.
              </p>
              <div className="panel rounded-2xl p-4 text-sm text-slate-300">
                Voting is protected by anomaly detection and unique wallet enforcement.
              </div>
            </div>

            <div className="space-y-6">
              <div>
                <label className="block text-sm font-medium text-slate-300">Email</label>
                <input
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className="input-shell mt-2 block w-full rounded-xl px-4 py-2 text-sm text-slate-100 shadow-sm focus:border-sky-400 focus:outline-none focus:ring-2 focus:ring-sky-500/40"
                  placeholder="VIT Email"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-slate-300">Wallet Address</label>
                <input
                  type="text"
                  value={wallet}
                  onChange={(e) => setWallet(e.target.value)}
                  className="input-shell mt-2 block w-full rounded-xl px-4 py-2 text-sm text-slate-100 shadow-sm focus:border-sky-400 focus:outline-none focus:ring-2 focus:ring-sky-500/40"
                  placeholder="WALLET_XXXX"
                />
              </div>

              {error && <p className="text-sm text-rose-300">{error}</p>}

              <button
                onClick={handleLogin}
                disabled={loading}
                className="glow-button inline-flex w-full items-center justify-center rounded-xl bg-sky-500 px-4 py-2 text-sm font-semibold text-slate-900 shadow-sm transition hover:bg-sky-400 disabled:opacity-60"
              >
                {loading ? "Logging in..." : "Login"}
              </button>

              <div className="text-center">
                <p className="text-sm text-slate-400">
                  Don&apos;t have an account?{" "}
                  <Link href="/" className="font-semibold text-sky-300 hover:text-sky-200">
                    Register here
                  </Link>
                </p>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
