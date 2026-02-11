"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:5000";
const WALLET_REGEX = /^WALLET_[A-Z0-9]{4,8}$/;

export default function RegisterPage() {
  const router = useRouter();
  const [email, setEmail] = useState("");
  const [wallet, setWallet] = useState("");
  const [otp, setOtp] = useState("");
  const [step, setStep] = useState<1 | 2>(1);
  const [cooldown, setCooldown] = useState(0);
  const [loading, setLoading] = useState(false);
  const [regMessage, setRegMessage] = useState<{ text: string; type: "success" | "error" } | null>(null);
  const [auditWallet, setAuditWallet] = useState("");
  const [auditHash, setAuditHash] = useState("");
  const [auditTx, setAuditTx] = useState("");
  const [auditResult, setAuditResult] = useState<{
    verified: boolean;
    onchain_note?: string;
    decision_hash?: string;
    error?: string;
  } | null>(null);
  const [auditLoading, setAuditLoading] = useState(false);

  const handleStartVerification = async () => {
    if (loading) return;
    const cleanEmail = email.trim();
    const cleanWallet = wallet.trim().toUpperCase();

    if (!cleanEmail || !cleanWallet) {
      setRegMessage({ text: "Please fill in all fields.", type: "error" });
      return;
    }
    if (!WALLET_REGEX.test(cleanWallet)) {
      setRegMessage({ text: "Wallet must follow format: WALLET_XXXX", type: "error" });
      return;
    }

    setLoading(true);
    setRegMessage(null);

    try {
      const res = await fetch(`${API_BASE}/register/start`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: cleanEmail, wallet: cleanWallet }),
      });

      const data = await res.json();

      if (res.ok) {
        setRegMessage({ text: data.message || "Verification code sent.", type: "success" });
        setStep(2);
        setCooldown(30);
      } else {
        setRegMessage({ text: data.error || "Failed to send verification code.", type: "error" });
      }
    } catch {
      setRegMessage({ text: "Network error. Please try again.", type: "error" });
    } finally {
      setLoading(false);
    }
  };

  const handleVerify = async () => {
    if (loading) return;
    const cleanEmail = email.trim();
    const cleanWallet = wallet.trim().toUpperCase();
    const cleanOtp = otp.trim();

    if (!cleanOtp) {
      setRegMessage({ text: "Please enter the verification code.", type: "error" });
      return;
    }

    setLoading(true);
    setRegMessage(null);

    try {
      const res = await fetch(`${API_BASE}/register/verify`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: cleanEmail, wallet: cleanWallet, otp: cleanOtp }),
      });

      const data = await res.json();

      if (res.ok) {
        setRegMessage({ text: data.message || "Registration complete!", type: "success" });
        setTimeout(() => {
          router.push("/login");
        }, 1500);
      } else {
        setRegMessage({ text: data.error || "Verification failed.", type: "error" });
      }
    } catch {
      setRegMessage({ text: "Network error. Please try again.", type: "error" });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (cooldown <= 0) return;
    const timer = setTimeout(() => setCooldown((v) => v - 1), 1000);
    return () => clearTimeout(timer);
  }, [cooldown]);

  const handleVerifyHash = async () => {
    if (!auditTx || !auditHash) {
      setAuditResult({ verified: false, error: "Tx ID and hash are required." });
      return;
    }
    setAuditLoading(true);
    setAuditResult(null);
    try {
      const res = await fetch(`${API_BASE}/verify-decision`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ tx_id: auditTx, decision_hash: auditHash, wallet: auditWallet || undefined }),
      });
      const data = await res.json();
      if (res.ok) {
        setAuditResult({ verified: data.verified, onchain_note: data.onchain_note, decision_hash: data.decision_hash });
      } else {
        setAuditResult({ verified: false, error: data.error || "Verification failed." });
      }
    } catch {
      setAuditResult({ verified: false, error: "Network error." });
    } finally {
      setAuditLoading(false);
    }
  };

  return (
    <div className="relative min-h-screen overflow-hidden text-slate-100">
      <div className="pointer-events-none absolute inset-0 grid-overlay" />
      <div className="pointer-events-none absolute inset-0 noise-overlay" />
      <div className="pointer-events-none absolute left-[-10%] top-[-20%] h-96 w-96 rounded-full bg-cyan-400/10 blur-3xl" />
      <div className="pointer-events-none absolute right-[-10%] top-[10%] h-[28rem] w-[28rem] rounded-full bg-amber-300/10 blur-3xl" />
      <div className="pointer-events-none absolute bottom-[-10%] left-[20%] h-[24rem] w-[24rem] rounded-full bg-violet-500/10 blur-3xl" />
      <div className="pointer-events-none absolute right-[10%] top-[25%] h-64 w-64 rounded-full aurora" />

      <div className="mx-auto flex min-h-screen max-w-6xl items-center px-6 py-16">
        <div className="grid w-full gap-12 lg:grid-cols-[1.1fr_0.9fr]">
          <div className="space-y-8">
            <div className="inline-flex items-center gap-3 rounded-full border border-slate-700/60 bg-slate-950/70 px-4 py-2 text-xs font-semibold uppercase tracking-[0.3em] text-slate-300 shadow-sm fade-in-up">
              TrustPoll Protocol
              <span className="h-1.5 w-6 rounded-full bg-gradient-to-r from-cyan-400 via-sky-400 to-amber-300" />
            </div>
            <div className="space-y-4 fade-in-up delay-1">
              <h1 className="font-display text-4xl font-semibold tracking-tight text-slate-100 sm:text-6xl">
                Register with a verified VIT email.
              </h1>
              <p className="max-w-xl text-base text-slate-300 sm:text-lg">
                Your email is the voting identity. Wallets provide blockchain proof, not extra votes.
              </p>
            </div>
            <div className="grid gap-4 sm:grid-cols-2 fade-in-up delay-2">
              <div className="panel rounded-2xl p-5">
                <p className="text-sm font-semibold text-slate-100">Email‑first identity</p>
                <p className="mt-1 text-sm text-slate-400">One verified email equals one vote.</p>
              </div>
              <div className="panel rounded-2xl p-5">
                <p className="text-sm font-semibold text-slate-100">On‑chain audit</p>
                <p className="mt-1 text-sm text-slate-400">Decision hashes anchored on Algorand.</p>
              </div>
            </div>
            <div className="text-sm text-slate-400">
              Already verified?{" "}
              <Link href="/login" className="font-semibold text-sky-300 hover:text-sky-200">
                Log in here
              </Link>
              .
            </div>
          </div>

          <div className="glass-panel rounded-3xl p-8 shadow-2xl">
            <div className="space-y-6">
              <div>
                <h2 className="font-display text-2xl font-semibold text-slate-100">
                  New Student Registration
                </h2>
                <p className="mt-2 text-sm text-slate-400">
                  Register your VIT email and wallet to access the ballot.
                </p>
              </div>

              <div className="flex flex-wrap items-center gap-3 text-xs font-semibold uppercase tracking-[0.2em] text-slate-400">
                <span
                  className={`rounded-full px-3 py-1 ${
                    step === 1 ? "bg-sky-500/20 text-sky-200" : "bg-slate-800/70"
                  }`}
                >
                  Step 1: Email
                </span>
                <span
                  className={`rounded-full px-3 py-1 ${
                    step === 2 ? "bg-amber-400/20 text-amber-200" : "bg-slate-800/70"
                  }`}
                >
                  Step 2: OTP
                </span>
                {cooldown > 0 && (
                  <span className="badge-ember rounded-full px-3 py-1">
                    Resend in {cooldown}s
                  </span>
                )}
              </div>

              <div className="space-y-4">
                <div>
                  <label htmlFor="email" className="block text-sm font-medium text-slate-300">
                    Email Address
                  </label>
                  <input
                    id="email"
                    name="email"
                    type="email"
                    required
                    placeholder="VIT Email (@vit.edu)"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    className="input-shell mt-2 block w-full rounded-xl px-4 py-2 text-sm text-slate-100 shadow-sm focus:border-sky-400 focus:outline-none focus:ring-2 focus:ring-sky-500/40"
                  />
                </div>

                <div>
                  <label htmlFor="wallet" className="block text-sm font-medium text-slate-300">
                    Wallet Address
                  </label>
                  <input
                    id="wallet"
                    name="wallet"
                    type="text"
                    required
                    placeholder="WALLET_XXXX"
                    value={wallet}
                    onChange={(e) => setWallet(e.target.value)}
                    className="input-shell mt-2 block w-full rounded-xl px-4 py-2 text-sm text-slate-100 shadow-sm focus:border-sky-400 focus:outline-none focus:ring-2 focus:ring-sky-500/40"
                  />
                  <p className="mt-2 text-xs text-slate-500">Use demo wallet format: WALLET_XXXX</p>
                </div>
                {step === 2 && (
                  <div>
                    <label htmlFor="otp" className="block text-sm font-medium text-slate-300">
                      Verification Code
                    </label>
                    <input
                      id="otp"
                      name="otp"
                      type="text"
                      inputMode="numeric"
                      maxLength={6}
                      placeholder="Enter 6-digit code"
                      value={otp}
                      onChange={(e) => setOtp(e.target.value)}
                      className="input-shell mt-2 block w-full rounded-xl px-4 py-2 text-sm text-slate-100 shadow-sm focus:border-amber-400 focus:outline-none focus:ring-2 focus:ring-amber-500/40"
                    />
                  </div>
                )}
              </div>

              {step === 1 ? (
                <button
                  onClick={handleStartVerification}
                  disabled={loading || cooldown > 0}
                  className="glow-button inline-flex w-full items-center justify-center gap-2 rounded-xl bg-sky-500 px-4 py-2 text-sm font-semibold text-slate-900 shadow-sm transition hover:bg-sky-400 disabled:cursor-not-allowed disabled:opacity-60"
                >
                  {cooldown > 0 ? `Resend in ${cooldown}s` : loading ? "Sending..." : "Send Verification Code"}
                </button>
              ) : (
                <div className="space-y-3">
                  <button
                    onClick={handleVerify}
                    disabled={loading}
                    className="glow-button inline-flex w-full items-center justify-center gap-2 rounded-xl bg-amber-400 px-4 py-2 text-sm font-semibold text-slate-900 shadow-sm transition hover:bg-amber-300 disabled:cursor-not-allowed disabled:opacity-60"
                  >
                    {loading ? "Verifying..." : "Verify & Register"}
                  </button>
                  <button
                    onClick={handleStartVerification}
                    disabled={loading || cooldown > 0}
                    className="w-full text-sm font-semibold text-sky-300 transition hover:text-sky-200 disabled:cursor-not-allowed disabled:opacity-60"
                  >
                    {cooldown > 0 ? `Resend code in ${cooldown}s` : "Resend verification code"}
                  </button>
                </div>
              )}

              {regMessage && (
                <div
                  className={`rounded-xl border px-4 py-3 text-sm font-medium ${
                    regMessage.type === "success"
                      ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-200"
                      : "border-rose-500/40 bg-rose-500/10 text-rose-200"
                  }`}
                >
                  {regMessage.text}
                </div>
              )}
            </div>
          </div>
        </div>
      </div>

      <div className="mx-auto w-full max-w-6xl px-6 pb-20">
        <div className="panel-strong rounded-3xl p-8">
          <div className="flex flex-wrap items-center justify-between gap-4">
            <div>
              <h3 className="font-display text-2xl font-semibold text-slate-100">Audit & Verification</h3>
              <p className="mt-2 text-sm text-slate-400">
                Verify that a decision hash was anchored on Algorand and remains untampered.
              </p>
            </div>
            <span className="chip rounded-full px-3 py-2 text-xs uppercase tracking-[0.2em] text-slate-300">
              On-chain proof
            </span>
          </div>

          <div className="mt-6 grid gap-4 md:grid-cols-3">
            <div>
              <label className="block text-sm font-medium text-slate-300">Wallet (optional)</label>
              <input
                value={auditWallet}
                onChange={(e) => setAuditWallet(e.target.value)}
                placeholder="WALLET_XXXX"
                className="input-shell mt-2 block w-full rounded-xl px-4 py-2 text-sm text-slate-100 shadow-sm focus:border-sky-400 focus:outline-none focus:ring-2 focus:ring-sky-500/40"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-slate-300">Decision Hash</label>
              <input
                value={auditHash}
                onChange={(e) => setAuditHash(e.target.value)}
                placeholder="d34f...ccc8"
                className="input-shell mt-2 block w-full rounded-xl px-4 py-2 text-sm text-slate-100 shadow-sm focus:border-sky-400 focus:outline-none focus:ring-2 focus:ring-sky-500/40"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-slate-300">Algorand Tx ID</label>
              <input
                value={auditTx}
                onChange={(e) => setAuditTx(e.target.value)}
                placeholder="Z3ZT7K..."
                className="input-shell mt-2 block w-full rounded-xl px-4 py-2 text-sm text-slate-100 shadow-sm focus:border-sky-400 focus:outline-none focus:ring-2 focus:ring-sky-500/40"
              />
            </div>
          </div>

          <div className="mt-5 flex flex-wrap items-center gap-3">
            <button
              onClick={handleVerifyHash}
              disabled={auditLoading}
              className="glow-button rounded-xl bg-emerald-400 px-4 py-2 text-sm font-semibold text-slate-900 shadow-sm transition hover:bg-emerald-300 disabled:opacity-60"
            >
              {auditLoading ? "Verifying..." : "Verify On-chain"}
            </button>
            {auditResult && auditResult.verified && (
              <span className="rounded-full border border-emerald-400/40 bg-emerald-400/10 px-3 py-2 text-xs font-semibold text-emerald-200">
                Verified on-chain
              </span>
            )}
            {auditResult && !auditResult.verified && (
              <span className="rounded-full border border-rose-500/40 bg-rose-500/10 px-3 py-2 text-xs font-semibold text-rose-200">
                {auditResult.error || "Not verified"}
              </span>
            )}
          </div>

          {auditResult && (
            <div className="mt-4 rounded-2xl border border-slate-700/70 bg-slate-900/60 px-4 py-3 text-xs text-slate-300">
              <div>On-chain note: {auditResult.onchain_note || "—"}</div>
              <div>Decision hash: {auditResult.decision_hash || auditHash || "—"}</div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
