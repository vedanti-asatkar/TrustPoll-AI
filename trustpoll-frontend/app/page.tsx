"use client";

import { useEffect, useState } from "react";
import Link from "next/link";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:5000";

type PublicResult = { id: number; name: string; votes: number };

export default function HomePage() {
  const [results, setResults] = useState<PublicResult[]>([]);
  const [published, setPublished] = useState(false);
  const [resultsError, setResultsError] = useState("");

  useEffect(() => {
    const loadResults = async () => {
      try {
        const res = await fetch(`${API_BASE}/results`);
        const data = await res.json();
        if (res.ok) {
          setPublished(Boolean(data.published));
          setResults(Array.isArray(data.results) ? data.results : []);
        } else {
          setResultsError(data.error || "Failed to load results.");
        }
      } catch {
        setResultsError("Network error while loading results.");
      }
    };
    loadResults();
  }, []);

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
                Campus voting with verifiable trust and AI oversight.
              </h1>
              <p className="max-w-xl text-base text-slate-300 sm:text-lg">
                A blockchain-inspired ballot experience with rapid anomaly detection. Every vote is
                accountable, transparent, and protected from abuse.
              </p>
            </div>
            <div className="grid gap-4 sm:grid-cols-2 fade-in-up delay-2">
              <div className="panel rounded-2xl p-5">
                <p className="text-sm font-semibold text-slate-100">Verified participation</p>
                <p className="mt-1 text-sm text-slate-400">One verified email. One vote. No silent edits.</p>
              </div>
              <div className="panel rounded-2xl p-5">
                <p className="text-sm font-semibold text-slate-100">On-chain audit trail</p>
                <p className="mt-1 text-sm text-slate-400">Every decision hash anchored to Algorand.</p>
              </div>
            </div>
            <div className="flex flex-wrap gap-3 text-xs uppercase tracking-[0.2em] text-slate-400 fade-in-up delay-3">
              <span className="chip rounded-full px-3 py-2">Email OTP</span>
              <span className="chip rounded-full px-3 py-2">Consensus checks</span>
              <span className="chip rounded-full px-3 py-2">Tamper detection</span>
            </div>
          </div>

          <div className="glass-panel rounded-3xl p-8 shadow-2xl">
            <div className="space-y-6">
              <div>
                <h2 className="font-display text-2xl font-semibold text-slate-100">
                  Start Voting
                </h2>
                <p className="mt-2 text-sm text-slate-400">
                  Register your verified email to join the election or return to vote.
                </p>
              </div>

              <div className="space-y-3">
                <Link
                  href="/register"
                  className="glow-button inline-flex w-full items-center justify-center rounded-xl bg-sky-500 px-4 py-3 text-sm font-semibold text-slate-900 shadow-sm transition hover:bg-sky-400"
                >
                  Register to Vote
                </Link>
                <Link
                  href="/login"
                  className="inline-flex w-full items-center justify-center rounded-xl border border-slate-700/70 bg-slate-900/70 px-4 py-3 text-sm font-semibold text-slate-200 transition hover:border-sky-400/60"
                >
                  Log In
                </Link>
              </div>

              <div className="rounded-2xl border border-slate-700/70 bg-slate-900/70 px-4 py-3 text-sm text-slate-300">
                Results are published only when the admin finalizes the election.
              </div>
            </div>
          </div>
        </div>
      </div>

      <div className="mx-auto w-full max-w-6xl px-6 pb-20">
        <div className="panel-strong rounded-3xl p-8">
          <div className="flex flex-wrap items-center justify-between gap-4">
            <div>
              <h3 className="font-display text-2xl font-semibold text-slate-100">Public Results</h3>
              <p className="mt-2 text-sm text-slate-400">
                Results appear only after an admin publishes them.
              </p>
            </div>
            <span className="chip rounded-full px-3 py-2 text-xs uppercase tracking-[0.2em] text-slate-300">
              Transparency
            </span>
          </div>

          <div className="mt-6">
            {!published && (
              <div className="rounded-2xl border border-slate-700/70 bg-slate-900/60 px-4 py-6 text-center text-sm text-slate-400">
                Results are not yet published.
              </div>
            )}
            {published && resultsError && (
              <div className="rounded-2xl border border-rose-500/40 bg-rose-500/10 px-4 py-6 text-center text-sm text-rose-200">
                {resultsError}
              </div>
            )}
            {published && !resultsError && (
              <div className="grid gap-4 md:grid-cols-2">
                {results.length === 0 ? (
                  <div className="rounded-2xl border border-slate-700/70 bg-slate-900/60 px-4 py-6 text-center text-sm text-slate-400">
                    No votes recorded yet.
                  </div>
                ) : (
                  results.map((entry) => (
                    <div key={entry.id} className="rounded-2xl border border-slate-700/70 bg-slate-900/60 px-4 py-4">
                      <p className="text-sm font-semibold text-slate-100">{entry.name}</p>
                      <p className="mt-2 text-xs uppercase tracking-[0.2em] text-slate-400">
                        Votes
                      </p>
                      <p className="mt-1 text-2xl font-semibold text-emerald-200">{entry.votes}</p>
                    </div>
                  ))
                )}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
