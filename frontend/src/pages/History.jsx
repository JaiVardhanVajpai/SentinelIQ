import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import api, { BASE_URL } from '../api';
import { verdictTheme } from '../components/verdictStyles';

function History() {
  const [items, setItems] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const navigate = useNavigate();

  const load = async () => {
    setLoading(true);
    setError('');
    try {
      const res = await api.get('/investigations');
      const list = res.data?.investigations || [];
      // Newest first (backend already sorts, but be safe)
      list.sort((a, b) => String(b.timestamp).localeCompare(String(a.timestamp)));
      const enriched = await Promise.all(
        list.map(async (inv) => {
          try {
            const decRes = await api.get(
              `/investigations/${inv.investigation_id}/decision`
            );
            return {
              ...inv,
              analyst_decision:
                decRes.data?.analyst_decision || null
            };
          } catch {
            return { ...inv, analyst_decision: null };
          }
        })
      );
      setItems(enriched);
    } catch (e) {
      setError(e?.message || 'Failed to load investigations.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, []);

  const viewReport = (item) => {
    const full = item.full_report || item;
    localStorage.setItem('sentineliq_result', JSON.stringify(full));
    navigate('/results');
  };

  const downloadPdf = (id) => {
    window.open(`${BASE_URL}/investigations/${id}/report`, '_blank');
  };

  const remove = async (id) => {
    if (!window.confirm(`Delete investigation ${id}? This cannot be undone.`))
      return;
    try {
      await api.delete(`/investigations/${id}`);
      setItems((prev) => prev.filter((x) => x.investigation_id !== id));
    } catch (e) {
      alert('Delete failed: ' + (e?.message || 'unknown error'));
    }
  };

  return (
    <div className="max-w-5xl mx-auto px-6 py-10">
      <div className="flex items-center justify-between mb-8">
        <h1 className="text-3xl font-bold">Investigation History</h1>
        <button
          onClick={load}
          className="text-sm px-3 py-1.5 rounded-lg border border-gray-700 text-gray-400 hover:text-white hover:bg-gray-800 transition"
        >
          Refresh
        </button>
      </div>

      {loading && (
        <div className="flex items-center justify-center py-20 text-gray-500 gap-3">
          <span className="h-6 w-6 rounded-full border-2 border-gray-700 border-t-blue-500 animate-spin" />
          Loading investigations…
        </div>
      )}

      {error && !loading && (
        <div className="rounded-lg border border-red-500/40 bg-red-500/10 px-4 py-3 text-sm text-red-400">
          {error}
        </div>
      )}

      {!loading && !error && items.length === 0 && (
        <div className="rounded-2xl border border-dashed border-gray-800 bg-gray-900/40 py-20 text-center">
          <p className="text-gray-400 mb-4">No investigations yet.</p>
          <button
            onClick={() => navigate('/')}
            className="px-5 py-2.5 rounded-lg bg-blue-600 hover:bg-blue-500 transition font-medium"
          >
            Run your first investigation
          </button>
        </div>
      )}

      <div className="space-y-3">
        {items.map((item) => {
          const theme = verdictTheme(item.verdict);
          return (
            <div
              key={item.investigation_id}
              className="rounded-xl border border-gray-800 bg-gray-900/60 p-5 hover:border-gray-700 transition-all duration-200 flex flex-col lg:flex-row lg:items-center gap-4"
            >
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-3 mb-1">
                  <span className="font-mono text-xs text-blue-400">
                    {item.investigation_id}
                  </span>
                  <span
                    className={`px-2 py-0.5 rounded text-xs font-bold ${theme.bg} ${theme.text} ring-1 ${theme.ring}`}
                  >
                    {theme.label}
                  </span>
                  {item.analyst_decision ? (
                    <span
                      className="text-xs font-bold px-2 py-0.5
                        rounded-full ml-2"
                      style={{
                        background:
                          item.analyst_decision.decision === 'approve'
                          ? 'rgba(16,185,129,0.15)'
                          : item.analyst_decision.decision === 'reject'
                          ? 'rgba(239,68,68,0.15)'
                          : 'rgba(245,158,11,0.15)',
                        color:
                          item.analyst_decision.decision === 'approve'
                          ? '#10b981'
                          : item.analyst_decision.decision === 'reject'
                          ? '#ef4444'
                          : '#f59e0b',
                        border: '1px solid currentColor'
                      }}>
                      {item.analyst_decision.decision === 'approve'
                        ? '✓ APPROVED'
                        : item.analyst_decision.decision === 'reject'
                        ? '✗ REJECTED'
                        : '↑ ESCALATED'}
                    </span>
                  ) : (
                    <span
                      className="text-xs px-2 py-0.5 rounded-full
                        ml-2"
                      style={{
                        background: 'rgba(107,114,128,0.15)',
                        color: '#6b7280',
                        border: '1px solid #6b7280'
                      }}>
                      ⏳ PENDING
                    </span>
                  )}
                </div>
                <p className="font-mono text-sm text-gray-200 truncate">
                  {item.input_value}
                </p>
                <p className="text-xs text-gray-500 mt-1">{item.timestamp}</p>
              </div>

              <div className="flex items-center gap-6">
                <div className="text-center">
                  <p className="text-xs text-gray-500">Risk</p>
                  <p className={`font-mono text-lg font-bold ${theme.text}`}>
                    {item.risk_score}
                  </p>
                </div>

                <div className="flex gap-2">
                  <button
                    onClick={() => viewReport(item)}
                    className="px-3 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-sm font-medium transition"
                  >
                    View Report
                  </button>
                  <button
                    onClick={() => downloadPdf(item.investigation_id)}
                    className="px-3 py-1.5 rounded-lg border border-gray-700 hover:bg-gray-800 text-sm font-medium transition"
                  >
                    Download PDF
                  </button>
                  <button
                    onClick={() => remove(item.investigation_id)}
                    className="px-3 py-1.5 rounded-lg border border-red-500/40 text-red-400 hover:bg-red-500/10 text-sm font-medium transition"
                  >
                    Delete
                  </button>
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

export default History;
