"use client";

import { useState } from "react";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:5000";
const ADMIN_EMAIL = "kalyani.bhintade@vit.edu";

interface Stats {
  users: number;
  vote_attempts: number;
  ai_flags: number;
}

interface AiFlag {
  wallet: string;
  reason: string;
  severity: number;
  created_at: string;
}

interface Candidate {
  id: number;
  name: string;
  votes: number;
}

interface FairnessReport {
  election_id: string;
  fairness_score: number;
  metrics: {
    total_attempts: number;
    total_votes_cast: number;
    tampering_attempts_detected: number;
    duplicate_attempts_blocked: number;
    abnormal_timing_clusters: number;
    suspicious_ip_clusters: number;
    admin_high_risk_events?: number;
    admin_critical_events?: number;
    governance_missing_anchor_records?: number;
  };
  penalties: {
    tampering_penalty: number;
    duplicate_penalty: number;
    timing_penalty: number;
    ip_penalty: number;
  };
  formula: {
    equation: string;
  };
  governance?: {
    governance_integrity_status?: "HEALTHY" | "COMPROMISED";
    tampering_detection_result?: string;
  };
  governance_risk_flag?: boolean;
  fairness_hash: string;
  algorand_tx_id: string | null;
  anchored: boolean;
  computed_at: string | null;
}

interface GovernanceAudit {
  total_admin_high_risk_events: number;
  total_admin_critical_events: number;
  anchored_high_risk_events: number;
  blockchain_admin_anchor_count: number;
  blockchain_verification_status: string;
  tampering_detection_result: string;
  missing_hash_count: number;
  governance_integrity_status: "HEALTHY" | "COMPROMISED";
}

export default function AdminPage() {
  const [email, setEmail] = useState("");
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [authError, setAuthError] = useState("");

  const [stats, setStats] = useState<Stats | null>(null);
  const [flags, setFlags] = useState<AiFlag[]>([]);
  const [candidates, setCandidates] = useState<Candidate[]>([]);
  const [loading, setLoading] = useState(false);
  const [actionLoading, setActionLoading] = useState<string | null>(null);
  const [newCandidate, setNewCandidate] = useState("");
  const [addingCandidate, setAddingCandidate] = useState(false);
  const [candidateMessage, setCandidateMessage] = useState<string | null>(null);
  const [blockMessage, setBlockMessage] = useState<string | null>(null);
  const [resultsPublished, setResultsPublished] = useState(false);
  const [resultsLoading, setResultsLoading] = useState(false);
  const [resultsMessage, setResultsMessage] = useState<string | null>(null);
  const [fairness, setFairness] = useState<FairnessReport | null>(null);
  const [fairnessLoading, setFairnessLoading] = useState(false);
  const [fairnessMessage, setFairnessMessage] = useState<string | null>(null);
  const [governanceAudit, setGovernanceAudit] = useState<GovernanceAudit | null>(null);

  const handleLogin = () => {
    if (email.trim() === ADMIN_EMAIL) {
      setIsAuthenticated(true);
      setAuthError("");
      fetchDashboardData();
    } else {
      setAuthError("Unauthorized access");
    }
  };

  const fetchDashboardData = async () => {
    setLoading(true);
    try {
      const [statsRes, flagsRes, candidatesRes, fairnessRes, governanceRes] = await Promise.all([
        fetch(`${API_BASE}/admin/stats`),
        fetch(`${API_BASE}/admin/ai-flags`),
        fetch(`${API_BASE}/admin/candidates?admin_id=${encodeURIComponent(ADMIN_EMAIL)}`),
        fetch(`${API_BASE}/admin/fairness-index?election_id=demo-1`),
        fetch(`${API_BASE}/admin/governance-audit?election_id=demo-1`),
      ]);

      if (statsRes.ok) setStats(await statsRes.json());
      if (flagsRes.ok) setFlags(await flagsRes.json());
      if (candidatesRes.ok) setCandidates(await candidatesRes.json());
      if (fairnessRes.ok) setFairness(await fairnessRes.json());
      if (governanceRes.ok) {
        const governanceData = await governanceRes.json();
        setGovernanceAudit(governanceData.audit || null);
      }

      const resultsRes = await fetch(`${API_BASE}/admin/results-status`);
      if (resultsRes.ok) {
        const resultsData = await resultsRes.json();
        setResultsPublished(Boolean(resultsData.published));
      }
    } catch (error) {
      console.error("Failed to fetch admin data", error);
    } finally {
      setLoading(false);
    }
  };

  const handleGenerateFairnessIndex = async () => {
    setFairnessLoading(true);
    setFairnessMessage(null);
    try {
      const res = await fetch(`${API_BASE}/admin/fairness-index`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ election_id: "demo-1", anchor: true, admin_id: ADMIN_EMAIL }),
      });
      const data = await res.json();
      if (res.ok) {
        setFairness(data);
        setFairnessMessage(data.anchored ? "Fairness index generated and anchored on Algorand." : "Fairness index generated, but anchoring failed.");
        const governanceRes = await fetch(`${API_BASE}/admin/governance-audit?election_id=demo-1`);
        if (governanceRes.ok) {
          const governanceData = await governanceRes.json();
          setGovernanceAudit(governanceData.audit || null);
        }
      } else {
        setFairnessMessage(data.error || "Failed to generate fairness index.");
      }
    } catch (error) {
      console.error("Failed to generate fairness index", error);
      setFairnessMessage("Network error while generating fairness index.");
    } finally {
      setFairnessLoading(false);
    }
  };

  const handleAcknowledge = async (userKey: string) => {
    setActionLoading(userKey);
    try {
      const res = await fetch(`${API_BASE}/admin/acknowledge-flag`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ wallet: userKey, admin_id: ADMIN_EMAIL }),
      });

      if (res.ok) {
        const flagsRes = await fetch(`${API_BASE}/admin/ai-flags`);
        if (flagsRes.ok) setFlags(await flagsRes.json());
      }
    } catch (error) {
      console.error("Failed to acknowledge flag", error);
    } finally {
      setActionLoading(null);
    }
  };

  const handleAddCandidate = async () => {
    const trimmedName = newCandidate.trim();
    if (!trimmedName) return;
    setAddingCandidate(true);
    setCandidateMessage(null);
    try {
      const res = await fetch(`${API_BASE}/admin/add-candidate`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name: trimmedName, admin_id: ADMIN_EMAIL }),
      });
      if (res.ok) {
        setNewCandidate("");
        setCandidateMessage("Candidate added. Voters can refresh to see the update.");
        const cRes = await fetch(`${API_BASE}/admin/candidates?admin_id=${encodeURIComponent(ADMIN_EMAIL)}`);
        if (cRes.ok) setCandidates(await cRes.json());
      } else {
        const data = await res.json();
        setCandidateMessage(data.error || "Failed to add candidate.");
      }
    } catch {
      console.error("Failed to add candidate");
      setCandidateMessage("Network error while adding candidate.");
    } finally {
      setAddingCandidate(false);
    }
  };

  const handleBlockWallet = async (userKey: string) => {
    setActionLoading(userKey);
    setBlockMessage(null);
    try {
      const res = await fetch(`${API_BASE}/admin/block-wallet`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ wallet: userKey, minutes: 30, admin_id: ADMIN_EMAIL }),
      });
      const data = await res.json();
      if (res.ok) {
        setBlockMessage(`User blocked until ${new Date(data.blocked_until).toLocaleString()}.`);
      } else {
        setBlockMessage(data.error || "Failed to block user.");
      }
    } catch (error) {
      console.error("Failed to block user", error);
      setBlockMessage("Network error while blocking user.");
    } finally {
      setActionLoading(null);
    }
  };

  const handleDeleteCandidate = async (id: number, name: string) => {
    const confirmed = window.confirm(`Delete candidate "${name}"? This cannot be undone.`);
    if (!confirmed) return;

    setActionLoading(String(id));
    try {
      const res = await fetch(`${API_BASE}/admin/delete-candidate`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id, admin_id: ADMIN_EMAIL }),
      });
      if (res.ok) {
        const cRes = await fetch(`${API_BASE}/admin/candidates?admin_id=${encodeURIComponent(ADMIN_EMAIL)}`);
        if (cRes.ok) setCandidates(await cRes.json());
      } else {
        const data = await res.json();
        setCandidateMessage(data.error || "Failed to delete candidate.");
      }
    } catch (error) {
      console.error("Failed to delete candidate", error);
      setCandidateMessage("Network error while deleting candidate.");
    } finally {
      setActionLoading(null);
    }
  };

  const handlePublishResults = async (publish: boolean) => {
    const actionLabel = publish ? "publish" : "unpublish";
    const confirmed = window.confirm(`Are you sure you want to ${actionLabel} the results?`);
    if (!confirmed) return;

    setResultsLoading(true);
    setResultsMessage(null);
    try {
      const res = await fetch(`${API_BASE}/admin/publish-results`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ published: publish, admin_id: ADMIN_EMAIL }),
      });
      if (res.ok) {
        setResultsPublished(publish);
        setResultsMessage(publish ? "Results are now public." : "Results are now hidden.");
        const governanceRes = await fetch(`${API_BASE}/admin/governance-audit?election_id=demo-1`);
        if (governanceRes.ok) {
          const governanceData = await governanceRes.json();
          setGovernanceAudit(governanceData.audit || null);
        }
      } else {
        const data = await res.json();
        setResultsMessage(data.error || "Failed to update results status.");
      }
    } catch (error) {
      console.error("Failed to update results status", error);
      setResultsMessage("Network error while updating results.");
    } finally {
      setResultsLoading(false);
    }
  };

  const getSeverityColor = (severity: number) => {
    if (severity >= 7) return "text-red-600 bg-red-50 border-red-200";
    if (severity >= 4) return "text-yellow-600 bg-yellow-50 border-yellow-200";
    return "text-green-600 bg-green-50 border-green-200";
  };

  if (!isAuthenticated) {
    return (
      <div className="relative min-h-screen overflow-hidden text-slate-100">
        <div className="pointer-events-none absolute inset-0 grid-overlay" />
        <div className="pointer-events-none absolute inset-0 noise-overlay" />
        <div className="pointer-events-none absolute -top-24 right-0 h-80 w-80 rounded-full bg-sky-500/10 blur-3xl" />
        <div className="pointer-events-none absolute -bottom-24 left-10 h-96 w-96 rounded-full bg-amber-300/10 blur-3xl" />
        <div className="mx-auto flex min-h-screen max-w-3xl items-center px-6 py-16">
          <div className="glass-panel w-full rounded-3xl p-10 shadow-2xl">
            <div className="space-y-6 text-center">
              <div className="inline-flex items-center gap-2 rounded-full border border-slate-700/70 bg-slate-900/70 px-4 py-2 text-xs font-semibold uppercase tracking-[0.2em] text-slate-300">
                Secure Admin Access
                <span className="h-1.5 w-1.5 rounded-full bg-cyan-400" />
              </div>
              <div>
                <h2 className="font-display text-3xl font-semibold text-slate-100">Admin Console</h2>
                <p className="mt-2 text-sm text-slate-400">Enter your authorized email to view governance analytics.</p>
              </div>
            </div>
            <div className="mt-8 space-y-4">
              <div>
                <label htmlFor="email" className="block text-sm font-medium text-slate-300">Admin Email</label>
                <input
                  type="email"
                  id="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className="input-shell mt-2 block w-full rounded-xl px-4 py-2 text-sm text-slate-100 shadow-sm focus:border-sky-400 focus:outline-none focus:ring-2 focus:ring-sky-500/40"
                  placeholder="admin@vit.edu"
                />
              </div>
              {authError && <p className="text-sm text-rose-300">{authError}</p>}
              <button onClick={handleLogin} className="glow-button w-full rounded-xl bg-sky-500 px-4 py-2 text-sm font-semibold text-slate-900 shadow-sm transition hover:bg-sky-400">
                Access Dashboard
              </button>
            </div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="relative min-h-screen overflow-hidden text-slate-100">
      <div className="pointer-events-none absolute inset-0 grid-overlay" />
      <div className="pointer-events-none absolute inset-0 noise-overlay" />
      <div className="pointer-events-none absolute -top-24 right-0 h-80 w-80 rounded-full bg-sky-500/10 blur-3xl" />
      <div className="pointer-events-none absolute -bottom-24 left-10 h-96 w-96 rounded-full bg-violet-500/10 blur-3xl" />
      <div className="pointer-events-none absolute right-[18%] top-[12%] h-64 w-64 rounded-full aurora" />
      <div className="mx-auto max-w-6xl space-y-8 px-6 py-12">
        <div className="glass-panel flex flex-wrap items-center justify-between gap-4 rounded-3xl px-6 py-5">
          <div>
            <h1 className="font-display text-3xl font-semibold text-slate-100">Admin Dashboard</h1>
            <p className="mt-1 text-sm text-slate-400">Governance oversight and live election signals.</p>
          </div>
          <button onClick={() => setIsAuthenticated(false)} className="rounded-full border border-slate-700/70 bg-slate-900/70 px-4 py-2 text-sm font-semibold text-slate-300 transition hover:text-slate-100">
            Logout
          </button>
        </div>

        {loading && !stats ? (
          <div className="glass-panel rounded-3xl px-6 py-12 text-center text-slate-400">Loading dashboard data...</div>
        ) : (
          <>
            <div className="grid grid-cols-1 gap-6 sm:grid-cols-3">
              <div className="panel rounded-3xl p-6">
                <dt className="text-xs font-semibold uppercase tracking-[0.2em] text-slate-400">Registered Users</dt>
                <dd className="mt-3 text-3xl font-semibold text-slate-100">{stats?.users || 0}</dd>
              </div>
              <div className="panel rounded-3xl p-6">
                <dt className="text-xs font-semibold uppercase tracking-[0.2em] text-slate-400">Vote Attempts</dt>
                <dd className="mt-3 text-3xl font-semibold text-slate-100">{stats?.vote_attempts || 0}</dd>
              </div>
              <div className="panel rounded-3xl p-6">
                <dt className="text-xs font-semibold uppercase tracking-[0.2em] text-slate-400">AI Flags</dt>
                <dd className="mt-3 text-3xl font-semibold text-rose-300">{stats?.ai_flags || 0}</dd>
              </div>
            </div>

            <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
              <div className="glass-panel rounded-3xl p-6">
                <h3 className="font-display text-xl font-semibold text-slate-100">Add Candidate</h3>
                <div className="mt-4 flex flex-col gap-4 sm:flex-row">
                  <input
                    type="text"
                    value={newCandidate}
                    onChange={(e) => setNewCandidate(e.target.value)}
                    placeholder="Candidate Name"
                    className="input-shell block w-full rounded-xl px-4 py-2 text-sm text-slate-100 shadow-sm focus:border-sky-400 focus:outline-none focus:ring-2 focus:ring-sky-500/40"
                  />
                  <button onClick={handleAddCandidate} disabled={addingCandidate} className="glow-button rounded-xl bg-sky-500 px-4 py-2 text-sm font-semibold text-slate-900 shadow-sm transition hover:bg-sky-400 disabled:opacity-60">
                    {addingCandidate ? "Adding..." : "Add"}
                  </button>
                </div>
                {candidateMessage && <p className="mt-3 text-sm text-slate-400">{candidateMessage}</p>}
              </div>

              <div className="glass-panel rounded-3xl p-6">
                <h3 className="font-display text-xl font-semibold text-slate-100">Publish Results</h3>
                <p className="mt-2 text-sm text-slate-400">Results are hidden by default until an admin publishes them.</p>
                <div className="mt-4 flex flex-wrap gap-3">
                  <button onClick={() => handlePublishResults(true)} disabled={resultsLoading || resultsPublished} className="glow-button rounded-xl bg-emerald-400 px-4 py-2 text-sm font-semibold text-slate-900 shadow-sm transition hover:bg-emerald-300 disabled:opacity-60">
                    {resultsPublished ? "Results Published" : "Publish Results"}
                  </button>
                  <button onClick={() => handlePublishResults(false)} disabled={resultsLoading || !resultsPublished} className="rounded-xl border border-slate-700/70 bg-slate-900/70 px-4 py-2 text-sm font-semibold text-slate-300 transition hover:text-slate-100 disabled:opacity-60">
                    Hide Results
                  </button>
                </div>
                {resultsMessage && <p className="mt-3 text-sm text-slate-400">{resultsMessage}</p>}
              </div>

              <div className="glass-panel rounded-3xl p-6 lg:col-span-2">
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <h3 className="font-display text-xl font-semibold text-slate-100">Fairness Index</h3>
                  <button onClick={handleGenerateFairnessIndex} disabled={fairnessLoading} className="glow-button rounded-xl bg-amber-400 px-4 py-2 text-sm font-semibold text-slate-900 shadow-sm transition hover:bg-amber-300 disabled:opacity-60">
                    {fairnessLoading ? "Computing..." : "Generate & Anchor"}
                  </button>
                </div>
                <p className="mt-2 text-sm text-slate-400">Transparent integrity score based on tampering, duplicate attempts, timing anomalies, and suspicious admin activity.</p>

                {fairness && (
                  <div className="mt-4 space-y-4">
                    <div className="rounded-2xl border border-slate-700/70 bg-slate-900/60 px-4 py-4">
                      <p className="text-xs uppercase tracking-[0.2em] text-slate-400">Election Integrity Score</p>
                      <p className="mt-2 text-4xl font-semibold text-emerald-300">{fairness.fairness_score.toFixed(1)}%</p>
                      <p className="mt-2 text-xs text-slate-400">{fairness.formula?.equation}</p>
                      {fairness.governance_risk_flag && (
                        <p className="mt-2 text-xs font-semibold text-rose-300">Governance risk flag is active</p>
                      )}
                    </div>
                    <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
                      <div className="rounded-2xl border border-slate-700/70 bg-slate-900/60 px-4 py-3 text-sm text-slate-300">Tampering attempts detected: <span className="font-semibold text-slate-100">{fairness.metrics.tampering_attempts_detected}</span></div>
                      <div className="rounded-2xl border border-slate-700/70 bg-slate-900/60 px-4 py-3 text-sm text-slate-300">Duplicate attempts blocked: <span className="font-semibold text-slate-100">{fairness.metrics.duplicate_attempts_blocked}</span></div>
                      <div className="rounded-2xl border border-slate-700/70 bg-slate-900/60 px-4 py-3 text-sm text-slate-300">Abnormal timing clusters: <span className="font-semibold text-slate-100">{fairness.metrics.abnormal_timing_clusters}</span></div>
                      <div className="rounded-2xl border border-slate-700/70 bg-slate-900/60 px-4 py-3 text-sm text-slate-300">Suspicious IP clusters: <span className="font-semibold text-slate-100">{fairness.metrics.suspicious_ip_clusters}</span></div>
                      <div className="rounded-2xl border border-slate-700/70 bg-slate-900/60 px-4 py-3 text-sm text-slate-300">Admin high-risk events: <span className="font-semibold text-slate-100">{fairness.metrics.admin_high_risk_events || 0}</span></div>
                      <div className="rounded-2xl border border-slate-700/70 bg-slate-900/60 px-4 py-3 text-sm text-slate-300">Admin critical events: <span className="font-semibold text-slate-100">{fairness.metrics.admin_critical_events || 0}</span></div>
                    </div>
                    <div className="rounded-2xl border border-slate-700/70 bg-slate-900/60 px-4 py-3 text-xs text-slate-300">
                      <div>Computation hash: {fairness.fairness_hash}</div>
                      <div className="mt-1">Anchored tx: {fairness.algorand_tx_id || "Not anchored yet"}</div>
                      <div className="mt-1">Computed at: {fairness.computed_at ? new Date(fairness.computed_at).toLocaleString() : "Unknown"}</div>
                    </div>
                  </div>
                )}

                {fairnessMessage && <p className="mt-3 text-sm text-slate-400">{fairnessMessage}</p>}
              </div>

              <div className="glass-panel rounded-3xl p-6 lg:col-span-2">
                <h3 className="font-display text-xl font-semibold text-slate-100">Governance Integrity Audit</h3>
                <p className="mt-2 text-sm text-slate-400">Blockchain-backed audit trail for high-risk admin actions.</p>
                {governanceAudit && governanceAudit.governance_integrity_status === "COMPROMISED" && (
                  <div className="mt-4 rounded-2xl border border-rose-500/50 bg-rose-500/10 px-4 py-3 text-sm font-semibold text-rose-200">
                    ⚠ Governance Integrity Compromised
                  </div>
                )}
                {governanceAudit ? (
                  <div className="mt-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
                    <div className="rounded-2xl border border-slate-700/70 bg-slate-900/60 px-4 py-3 text-sm text-slate-300">Total high-risk events: <span className="font-semibold text-slate-100">{governanceAudit.total_admin_high_risk_events}</span></div>
                    <div className="rounded-2xl border border-slate-700/70 bg-slate-900/60 px-4 py-3 text-sm text-slate-300">Total critical events: <span className="font-semibold text-slate-100">{governanceAudit.total_admin_critical_events}</span></div>
                    <div className="rounded-2xl border border-slate-700/70 bg-slate-900/60 px-4 py-3 text-sm text-slate-300">Blockchain verification: <span className="font-semibold text-slate-100">{governanceAudit.blockchain_verification_status}</span></div>
                    <div className="rounded-2xl border border-slate-700/70 bg-slate-900/60 px-4 py-3 text-sm text-slate-300">Tampering detection: <span className="font-semibold text-slate-100">{governanceAudit.tampering_detection_result}</span></div>
                  </div>
                ) : (
                  <p className="mt-4 text-sm text-slate-500">Governance audit data will appear after the first monitored admin events.</p>
                )}
              </div>

              <div className="glass-panel rounded-3xl p-6">
                <h3 className="font-display text-xl font-semibold text-slate-100">Live Vote Counts</h3>
                <div className="mt-4 space-y-3">
                  {candidates.map((candidate) => (
                    <div key={candidate.id} className="flex flex-wrap items-center justify-between gap-2 rounded-2xl border border-slate-700/70 bg-slate-900/60 px-4 py-3">
                      <div>
                        <p className="text-sm font-semibold text-slate-100">{candidate.name}</p>
                        <span className="mt-1 inline-flex rounded-full bg-slate-800 px-3 py-1 text-xs font-semibold text-slate-100">{candidate.votes} votes</span>
                      </div>
                      <button onClick={() => handleDeleteCandidate(candidate.id, candidate.name)} disabled={actionLoading === String(candidate.id)} className="rounded-full border border-rose-500/40 bg-rose-500/10 px-3 py-1 text-xs font-semibold text-rose-200 transition hover:text-rose-100 disabled:opacity-50">
                        {actionLoading === String(candidate.id) ? "Deleting..." : "Delete"}
                      </button>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            <div className="glass-panel overflow-hidden rounded-3xl">
              <div className="border-b border-slate-700/70 px-6 py-4">
                <h3 className="font-display text-xl font-semibold text-slate-100">AI Anomaly Flags</h3>
              </div>
              <div className="overflow-x-auto">
                <table className="min-w-full divide-y divide-slate-700/70">
                  <thead className="bg-slate-900/70">
                    <tr>
                      <th scope="col" className="px-6 py-3 text-left text-xs font-semibold uppercase tracking-[0.2em] text-slate-400">User Key</th>
                      <th scope="col" className="px-6 py-3 text-left text-xs font-semibold uppercase tracking-[0.2em] text-slate-400">Reason</th>
                      <th scope="col" className="px-6 py-3 text-left text-xs font-semibold uppercase tracking-[0.2em] text-slate-400">Severity</th>
                      <th scope="col" className="px-6 py-3 text-left text-xs font-semibold uppercase tracking-[0.2em] text-slate-400">Time</th>
                      <th scope="col" className="px-6 py-3 text-left text-xs font-semibold uppercase tracking-[0.2em] text-slate-400">Action</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-700/70 bg-slate-900/40">
                    {flags.length === 0 ? (
                      <tr>
                        <td colSpan={5} className="px-6 py-6 text-center text-sm text-slate-400">No active flags detected.</td>
                      </tr>
                    ) : (
                      flags.map((flag, idx) => (
                        <tr key={`${flag.wallet}-${idx}`}>
                          <td className="whitespace-nowrap px-6 py-4 text-sm font-semibold text-slate-100">{flag.wallet}</td>
                          <td className="px-6 py-4 text-sm text-slate-300">{flag.reason}</td>
                          <td className="whitespace-nowrap px-6 py-4 text-sm">
                            <span className={`inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-semibold border ${getSeverityColor(flag.severity)}`}>{flag.severity}/10</span>
                          </td>
                          <td className="whitespace-nowrap px-6 py-4 text-sm text-slate-300">{new Date(flag.created_at).toLocaleString()}</td>
                          <td className="whitespace-nowrap px-6 py-4 text-sm">
                            <div className="flex flex-wrap items-center gap-2">
                              <button onClick={() => handleAcknowledge(flag.wallet)} disabled={actionLoading === flag.wallet} className="rounded-full border border-slate-700/70 bg-slate-900/70 px-3 py-1 text-xs font-semibold text-slate-300 transition hover:text-slate-100 disabled:opacity-50">
                                {actionLoading === flag.wallet ? "Processing..." : "Mark as Reviewed"}
                              </button>
                              <button onClick={() => handleBlockWallet(flag.wallet)} disabled={actionLoading === flag.wallet} className="rounded-full border border-rose-500/40 bg-rose-500/10 px-3 py-1 text-xs font-semibold text-rose-200 transition hover:text-rose-100 disabled:opacity-50">
                                Block 30m
                              </button>
                            </div>
                          </td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
              {blockMessage && <div className="border-t border-slate-700/70 px-6 py-4 text-sm text-slate-300">{blockMessage}</div>}
            </div>
          </>
        )}
      </div>
    </div>
  );
}
