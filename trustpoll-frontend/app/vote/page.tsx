"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:5000";

interface Candidate {
  id: number;
  name: string;
}

export default function VotePage() {
  const router = useRouter();
  const [wallet, setWallet] = useState("");
  const [email, setEmail] = useState("");
  const [candidates, setCandidates] = useState<Candidate[]>([]);
  const [selectedCandidate, setSelectedCandidate] = useState<number | null>(null);
  const [loading, setLoading] = useState(false);
  const [status, setStatus] = useState<{ type: "success" | "error"; text: string } | null>(null);

  useEffect(() => {
    const storedWallet = localStorage.getItem("user_wallet");
    const storedEmail = localStorage.getItem("user_email");
    if (!storedWallet || !storedEmail) {
      router.push("/login");
      return;
    }
    setWallet(storedWallet);
    setEmail(storedEmail);

    const loadCandidates = async () => {
      try {
        const res = await fetch(`${API_BASE}/candidates`);
        if (res.ok) {
          const data = await res.json();
          setCandidates(data);
        } else {
          setStatus({ type: "error", text: "Failed to load candidates." });
        }
      } catch {
        setStatus({ type: "error", text: "Network error while loading candidates." });
      }
    };

    loadCandidates();
  }, [router]);

  const handleVote = async () => {
    if (!selectedCandidate) {
      setStatus({ type: "error", text: "Please select a candidate." });
      return;
    }

    const selected = candidates.find((c) => c.id === selectedCandidate);
    const confirmed = window.confirm(
      `Confirm your vote for ${selected?.name || "this candidate"}? This action cannot be undone.`
    );
    if (!confirmed) return;

    setLoading(true);
    setStatus(null);

    try {
      const attemptRes = await fetch(`${API_BASE}/vote-attempt`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          email,
          wallet,
          candidate_id: selectedCandidate,
          election_id: "demo-1",
          ip_hash: "client",
          device_fingerprint_hash: "client",
        }),
      });

      const attemptData = await attemptRes.json();
      if (!attemptRes.ok || attemptData.status !== "accepted") {
        setStatus({
          type: "error",
          text: attemptData.reason || "Vote rejected by integrity checks.",
        });
        return;
      }

      const voteRes = await fetch(`${API_BASE}/vote`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, wallet, candidate_id: selectedCandidate }),
      });

      const voteData = await voteRes.json();
      if (voteRes.ok) {
        setStatus({ type: "success", text: voteData.message || "Vote cast successfully." });
        setSelectedCandidate(null);
      } else {
        setStatus({ type: "error", text: voteData.error || "Failed to cast vote." });
      }
    } catch {
      setStatus({ type: "error", text: "Network error. Please try again." });
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="relative min-h-screen overflow-hidden text-slate-100">
      <div className="pointer-events-none absolute inset-0 grid-overlay" />
      <div className="pointer-events-none absolute inset-0 noise-overlay" />
      <div className="pointer-events-none absolute -top-24 left-0 h-80 w-80 rounded-full bg-cyan-500/10 blur-3xl" />
      <div className="pointer-events-none absolute -bottom-24 right-10 h-96 w-96 rounded-full bg-violet-500/10 blur-3xl" />
      <div className="pointer-events-none absolute right-[20%] top-[15%] h-64 w-64 rounded-full aurora" />
      <div className="mx-auto flex min-h-screen max-w-5xl items-center px-6 py-16">
        <div className="w-full space-y-8">
          <div className="glass-panel flex flex-col gap-4 rounded-3xl p-8 sm:flex-row sm:items-center sm:justify-between">
            <div>
              <h1 className="font-display text-3xl font-semibold text-slate-100">Cast Your Vote</h1>
              <p className="mt-2 text-sm text-slate-400">
                Confirm your candidate selection. Once submitted, it cannot be changed.
              </p>
            </div>
            <div className="neon-border rounded-2xl bg-slate-950/70 px-4 py-3 text-xs font-semibold uppercase tracking-widest text-slate-400">
              Wallet
              <div className="mt-2 text-sm font-medium normal-case text-slate-100">
                {wallet || "Loading..."}
              </div>
            </div>
          </div>

          <div className="glass-panel rounded-3xl p-8">
            <div className="flex items-center justify-between">
              <h2 className="font-display text-2xl font-semibold text-slate-100">
                Select a Candidate
              </h2>
              <span className="rounded-full bg-slate-800/80 px-3 py-1 text-xs font-semibold text-slate-300">
                {candidates.length} options
              </span>
            </div>

            <div className="mt-6 grid gap-4 sm:grid-cols-2">
              {candidates.length === 0 ? (
                <p className="text-sm text-slate-400">No candidates available.</p>
              ) : (
                candidates.map((candidate) => {
                  const isSelected = selectedCandidate === candidate.id;
                  return (
                    <label
                      key={candidate.id}
                      className={`flex items-center gap-3 rounded-2xl border px-4 py-4 text-sm font-medium transition ${
                        isSelected
                          ? "border-amber-400/80 bg-amber-400/10 text-amber-100 shadow-sm"
                          : "border-slate-700/70 bg-slate-900/60 text-slate-300 hover:border-sky-400/60 hover:bg-slate-900/80"
                      }`}
                    >
                      <input
                        type="radio"
                        name="candidate"
                        value={candidate.id}
                        checked={isSelected}
                        onChange={() => setSelectedCandidate(candidate.id)}
                        className="h-4 w-4 text-sky-400 focus:ring-sky-500/40"
                      />
                      {candidate.name}
                    </label>
                  );
                })
              )}
            </div>

            {status && (
              <div
                className={`mt-6 rounded-2xl border px-4 py-3 text-sm font-medium ${
                  status.type === "success"
                    ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-200"
                    : "border-rose-500/40 bg-rose-500/10 text-rose-200"
                }`}
              >
                {status.text}
              </div>
            )}

            <button
              onClick={handleVote}
              disabled={loading || candidates.length === 0}
              className="glow-button mt-6 inline-flex w-full items-center justify-center rounded-xl bg-emerald-400 px-4 py-3 text-sm font-semibold text-slate-900 shadow-sm transition hover:bg-emerald-300 disabled:cursor-not-allowed disabled:opacity-60"
            >
              {loading ? "Submitting..." : "Submit Vote"}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
