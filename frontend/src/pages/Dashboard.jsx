import React, { useEffect, useState } from 'react';
import {
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  Legend,
  ResponsiveContainer,
  CartesianGrid,
} from 'recharts';
import api from '../api';
import { verdictTheme } from '../components/verdictStyles';

const COLORS = {
  MALICIOUS: '#ef4444',
  SUSPICIOUS: '#f59e0b',
  CLEAN: '#22c55e',
  PREVIOUSLY_MALICIOUS: '#f97316',
  UNRATED: '#64748b',
  OTHER: '#6b7280',
};

function bucket(verdict = '') {
  const v = String(verdict).toUpperCase();
  // PREVIOUSLY_MALICIOUS must be checked before MALICIOUS (it contains it)
  if (v.includes('PREVIOUSLY')) return 'PREVIOUSLY_MALICIOUS';
  if (v.includes('MALICIOUS')) return 'MALICIOUS';
  if (v.includes('SUSPICIOUS') || v.includes('ANOMALY')) return 'SUSPICIOUS';
  if (v.includes('CLEAN') || v.includes('NO ANOMALY')) return 'CLEAN';
  if (v.includes('UNRATED')) return 'UNRATED';
  return 'OTHER';
}

function StatCard({ label, value, accent }) {
  return (
    <div className="rounded-xl border border-gray-800 bg-gray-900/60 p-5">
      <p className="text-xs uppercase tracking-widest text-gray-500 mb-2">
        {label}
      </p>
      <p className={`text-3xl font-extrabold font-mono ${accent}`}>{value}</p>
    </div>
  );
}

function Dashboard() {
  const [items, setItems] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [approved, setApproved] = useState(0);
  const [rejected, setRejected] = useState(0);
  const [pending, setPending] = useState(0);
  const [showMitreInfo, setShowMitreInfo] = useState(false);
  const [verdictFilter, setVerdictFilter] = useState(null);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const res = await api.get('/investigations');
        const invs = res.data?.investigations || [];
        setItems(invs);
        const decisionsData = await Promise.all(
          invs.map(async (inv) => {
            try {
              const decisionRes = await api.get(
                `/investigations/${inv.investigation_id}/decision`
              );
              return decisionRes.data?.analyst_decision?.decision
                || null;
            } catch {
              return null;
            }
          })
        );
        const approvedCount = decisionsData
          .filter(decision => decision === 'approve').length;
        const rejectedCount = decisionsData
          .filter(decision => decision === 'reject').length;
        const pendingCount = decisionsData
          .filter(decision => decision === null).length;
        setApproved(approvedCount);
        setRejected(rejectedCount);
        setPending(pendingCount);
      } catch (e) {
        setError(e?.message || 'Failed to load dashboard data.');
      } finally {
        setLoading(false);
      }
    };
    fetchData();
    const interval = setInterval(fetchData, 5000);
    return () => clearInterval(interval);
  }, []);

  if (loading) {
    return (
      <div className="flex items-center justify-center py-24 text-gray-500 gap-3">
        <span className="h-6 w-6 rounded-full border-2 border-gray-700 border-t-blue-500 animate-spin" />
        Loading dashboard…
      </div>
    );
  }

  if (error) {
    return (
      <div className="max-w-3xl mx-auto px-6 py-20">
        <div className="rounded-lg border border-red-500/40 bg-red-500/10 px-4 py-3 text-sm text-red-400">
          {error}
        </div>
      </div>
    );
  }

  const total = items.length;
  const malicious = items.filter((i) => bucket(i.verdict) === 'MALICIOUS').length;
  const clean = items.filter((i) => bucket(i.verdict) === 'CLEAN').length;
  const suspicious = items.filter((i) => bucket(i.verdict) === 'SUSPICIOUS').length;
  const previouslyMalicious = items.filter((i) => bucket(i.verdict) === 'PREVIOUSLY_MALICIOUS').length;
  const unrated = items.filter((i) => bucket(i.verdict) === 'UNRATED').length;
  const avgRisk =
    total > 0
      ? Math.round(
          items.reduce((s, i) => s + (Number(i.risk_score) || 0), 0) / total
        )
      : 0;

  const pieData = [
    { name: 'Malicious', value: malicious, key: 'MALICIOUS' },
    { name: 'Previously Malicious', value: previouslyMalicious, key: 'PREVIOUSLY_MALICIOUS' },
    { name: 'Suspicious', value: suspicious, key: 'SUSPICIOUS' },
    { name: 'Clean', value: clean, key: 'CLEAN' },
    { name: 'Unrated', value: unrated, key: 'UNRATED' },
  ].filter((d) => d.value > 0);

  const barData = items
    .slice(0, 7)
    .map(inv => ({
      name: (inv.target || inv.input_value || '').slice(0, 10),
      risk: typeof inv.risk_score === 'number' ? inv.risk_score : 0
    }));

  const displayedInvestigations = verdictFilter
    ? items.filter(i => i.verdict === verdictFilter.toUpperCase())
    : items;

  const recent = [...displayedInvestigations]
    .sort((a, b) => String(b.timestamp).localeCompare(String(a.timestamp)))
    .slice(0, 6);

  const getRiskBarColor = (score) => {
    if (score >= 70) return '#ef4444';
    if (score >= 30) return '#f59e0b';
    return '#10b981';
  };

  // Most common MITRE technique across all investigations
  const mitreCount = {};
  items.forEach((inv) => {
    const techniques = inv.mitre_mapping || inv.full_report?.mitre_mapping || [];
    techniques.forEach((t) => {
      const key = t.technique_id || t.id || '';
      if (key) mitreCount[key] = (mitreCount[key] || 0) + 1;
    });
  });
  const topMitre = Object.entries(mitreCount).sort((a, b) => b[1] - a[1])[0];
  const topMitreName = topMitre ? topMitre[0] : 'N/A';

  const mitreExplanations = {
    'T1566': 'Phishing — attacker sends deceptive emails or messages to trick users into revealing credentials or installing malware.',
    'T1090': 'Proxy — attacker routes traffic through intermediary systems (like Tor) to hide their real location.',
    'T1110': 'Brute Force — attacker tries many passwords systematically to gain unauthorized access.',
    'T1078': 'Valid Accounts — attacker uses stolen legitimate credentials to access systems.',
    'T1059': 'Command & Scripting — attacker runs malicious scripts to execute commands on victim systems.',
  };
  const mitreInfo = mitreExplanations[topMitreName] ||
    'A commonly observed attack technique detected across investigations.';

  if (total === 0) {
    return (
      <div className="max-w-3xl mx-auto px-6 py-20 text-center">
        <h1 className="text-3xl font-bold mb-4">SOC Operations Dashboard</h1>
        <p className="text-gray-400">
          No data yet. Run some investigations to populate the dashboard.
        </p>
      </div>
    );
  }

  return (
    <div className="max-w-6xl mx-auto px-6 py-10">
      <h1 className="text-3xl font-bold mb-8">
        SOC Operations Dashboard
        <span style={{
          fontSize: '12px',
          fontWeight: '400',
          color: '#10b981',
          marginLeft: '12px',
          verticalAlign: 'middle'
        }}>
          ● Live · auto-updates
        </span>
      </h1>

      {/* Stat cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
        <StatCard label="Total Investigations" value={total} accent="text-blue-400" />
        <StatCard label="Malicious" value={malicious} accent="text-red-400" />
        <StatCard label="Clean" value={clean} accent="text-green-400" />
        <StatCard label="Avg Risk Score" value={avgRisk} accent="text-amber-400" />

        <div className="bg-gray-800 rounded-xl p-4
          border border-gray-700">
          <p className="text-xs text-gray-400 uppercase
            tracking-widest mb-2">TRUE POSITIVES</p>
          <p className="text-3xl font-bold"
            style={{color: '#10b981'}}>
            {approved}
          </p>
          <p className="text-xs text-gray-500 mt-1">
            Approved by analyst
          </p>
        </div>

        <div className="bg-gray-800 rounded-xl p-4
          border border-gray-700">
          <p className="text-xs text-gray-400 uppercase
            tracking-widest mb-2">FALSE POSITIVES</p>
          <p className="text-3xl font-bold"
            style={{color: '#ef4444'}}>
            {rejected}
          </p>
          <p className="text-xs text-gray-500 mt-1">
            Rejected by analyst
          </p>
        </div>

        <div className="bg-gray-800 rounded-xl p-4
          border border-gray-700">
          <p className="text-xs text-gray-400 uppercase
            tracking-widest mb-2">PENDING REVIEW</p>
          <p className="text-3xl font-bold"
            style={{color: pending > 10 ? '#ef4444' : pending > 0 ? '#f59e0b' : '#10b981'}}>
            {pending}
          </p>
          <p className="text-xs text-gray-500 mt-1">
            Awaiting decision
          </p>
        </div>

        <div
          onClick={() => setShowMitreInfo((s) => !s)}
          className="bg-gray-800 rounded-xl p-4
          border border-gray-700"
          style={{cursor: 'pointer'}}>
          <p className="text-xs text-gray-400 uppercase
            tracking-widest mb-2">TOP MITRE TECHNIQUE</p>
          <p className="text-3xl font-bold font-mono"
            style={{color: '#60a5fa'}}>
            {topMitreName}
          </p>
          <p className="text-xs mt-1" style={{color: '#60a5fa'}}>
            {showMitreInfo ? '▲ Hide' : '▼ What is this?'}
          </p>
          {showMitreInfo && (
            <div style={{
              fontSize: '11px',
              color: '#94a3b8',
              marginTop: '8px',
              padding: '8px',
              background: '#0d1526',
              borderRadius: '6px',
              lineHeight: '1.5'
            }}>
              {mitreInfo}
            </div>
          )}
        </div>
      </div>

      {/* Charts */}
      <div className="grid lg:grid-cols-2 gap-6 mb-8">
        <div className="rounded-xl border border-gray-800 bg-gray-900/60 p-6">
          <h3 className="text-xs uppercase tracking-widest text-gray-500 mb-4">
            Verdict Distribution
          </h3>
          <ResponsiveContainer width="100%" height={260}>
            <PieChart>
              <Pie
                data={pieData}
                dataKey="value"
                nameKey="name"
                cx="50%"
                cy="50%"
                outerRadius={90}
                innerRadius={50}
                paddingAngle={3}
                label
                style={{ cursor: 'pointer' }}
                onClick={(data) => {
                  setVerdictFilter(
                    verdictFilter === data.name ? null : data.name
                  );
                }}
              >
                {pieData.map((d) => (
                  <Cell key={d.key} fill={COLORS[d.key]} />
                ))}
              </Pie>
              <Tooltip
                contentStyle={{
                  background: '#111827',
                  border: '1px solid #374151',
                  borderRadius: 8,
                  color: '#fff',
                }}
              />
              <Legend
                formatter={(value) => (
                  <span style={{ color: '#9ca3af', fontSize: '12px' }}>
                    {value}
                  </span>
                )}
              />
            </PieChart>
          </ResponsiveContainer>
        </div>

        <div className="rounded-xl border border-gray-800 bg-gray-900/60 p-6">
          <h3 className="text-xs uppercase tracking-widest text-gray-500 mb-4">
            Recent Risk Scores
          </h3>
          <ResponsiveContainer width="100%" height={260}>
            <BarChart data={barData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1f2937" />
              <XAxis
                dataKey="name"
                tickFormatter={(val) =>
                  val.length > 8 ? val.slice(0, 8) + '..' : val
                }
                tick={{ fill: '#6b7280', fontSize: 11 }}
              />
              <YAxis domain={[0, 100]} tick={{ fill: '#9ca3af', fontSize: 11 }} />
              <Tooltip
                cursor={{ fill: '#1f2937' }}
                contentStyle={{
                  backgroundColor: '#1e293b',
                  border: '1px solid #334155',
                  borderRadius: '8px',
                  color: '#f1f5f9',
                }}
                labelStyle={{ color: '#94a3b8' }}
                itemStyle={{ color: '#f1f5f9' }}
              />
              <Bar dataKey="risk" name="Risk Score" minPointSize={4} radius={[4, 4, 0, 0]}>
                {barData.map((entry, index) => (
                  <Cell key={index} fill={getRiskBarColor(entry.risk)} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Recent table */}
      {verdictFilter && (
        <div style={{
          fontSize: '12px',
          color: '#60a5fa',
          marginBottom: '8px'
        }}>
          Showing: {verdictFilter} only —
          <span
            onClick={() => setVerdictFilter(null)}
            style={{cursor:'pointer', marginLeft:'6px',
                    color:'#94a3b8'}}
          >
            Clear filter ✕
          </span>
        </div>
      )}
      <div className="rounded-xl border border-gray-800 bg-gray-900/60 overflow-hidden">
        <h3 className="text-xs uppercase tracking-widest text-gray-500 px-6 pt-5 pb-3">
          Recent Investigations
        </h3>
        <table className="w-full text-sm">
          <thead>
            <tr className="text-left text-gray-500 border-b border-gray-800">
              <th className="px-6 py-3 font-medium">ID</th>
              <th className="px-6 py-3 font-medium">Target</th>
              <th className="px-6 py-3 font-medium">Verdict</th>
              <th className="px-6 py-3 font-medium text-right">Risk</th>
            </tr>
          </thead>
          <tbody>
            {recent.map((i) => {
              const theme = verdictTheme(i.verdict);
              return (
                <tr
                  key={i.investigation_id}
                  className="border-b border-gray-800/60 hover:bg-gray-800/40 transition"
                >
                  <td className="px-6 py-3 font-mono text-blue-400 text-xs">
                    {i.investigation_id}
                  </td>
                  <td className="px-6 py-3 font-mono text-gray-200 truncate max-w-[180px]">
                    {i.input_value}
                  </td>
                  <td className="px-6 py-3">
                    <span className={`font-semibold ${theme.text}`}>
                      {theme.label}
                    </span>
                  </td>
                  <td className="px-6 py-3 text-right font-mono">
                    <span
                      style={{
                        color: i.risk_score >= 70 ? '#ef4444' : i.risk_score >= 30 ? '#f59e0b' : '#10b981',
                        fontWeight: '700'
                      }}
                    >
                      {i.risk_score}
                    </span>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export default Dashboard;
