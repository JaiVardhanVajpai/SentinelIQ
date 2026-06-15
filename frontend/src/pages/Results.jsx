import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import api, { BASE_URL } from '../api';
import {
  verdictTheme,
  severityTheme,
  riskBarColor,
} from '../components/verdictStyles';

function ScoreBar({ label, score }) {
  const n = Number(score) || 0;
  return (
    <div>
      <div className="flex justify-between text-sm mb-1.5">
        <span className="text-gray-400">{label}</span>
        <span className="font-mono text-gray-200">{n} / 100</span>
      </div>
      <div className="h-2.5 w-full rounded-full bg-gray-800 overflow-hidden">
        <div
          className={`h-full rounded-full ${riskBarColor(n)} transition-all duration-700`}
          style={{ width: `${Math.min(100, Math.max(2, n))}%` }}
        />
      </div>
    </div>
  );
}

function Card({ title, children }) {
  return (
    <div className="rounded-xl border border-gray-800 bg-gray-900/60 p-6">
      {title && (
        <h3 className="text-xs uppercase tracking-widest text-gray-500 mb-4">
          {title}
        </h3>
      )}
      {children}
    </div>
  );
}

function Results() {
  const [data, setData] = useState(null);
  const [decision, setDecision] = useState(null);
  const [analystNote, setAnalystNote] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [decisionError, setDecisionError] = useState("");
  const [decisionSuccess, setDecisionSuccess] = useState("");
  const navigate = useNavigate();

  useEffect(() => {
    const raw = localStorage.getItem('sentineliq_result');
    if (raw) {
      try {
        setData(JSON.parse(raw));
      } catch (e) {
        setData(null);
      }
    }
  }, []);

  useEffect(() => {
    const loadDecision = async () => {
      if (!data?.investigation_id) return;
      try {
        const res = await api.get(
          `/investigations/${data.investigation_id}/decision`
        );
        if (res.data?.analyst_decision) {
          setDecision(res.data.analyst_decision);
        }
      } catch (err) {
        console.log("No decision yet");
      }
    };
    loadDecision();
  }, [data]);

  const submitDecision = async (decisionType) => {
    if (submitting) return;
    setSubmitting(true);
    setDecisionError("");
    setDecisionSuccess("");
    try {
      await api.post(
        `/investigations/${data.investigation_id}/decision`,
        {
          decision: decisionType,
          analyst_note: analystNote
        }
      );
      setDecision({
        decision: decisionType,
        analyst_note: analystNote,
        decided_at: new Date().toISOString(),
        decided_by: "analyst"
      });
      setDecisionSuccess(
        `Decision recorded: ${decisionType.toUpperCase()}`
      );
    } catch (err) {
      setDecisionError("Failed to save decision. Try again.");
    } finally {
      setSubmitting(false);
    }
  };

  if (!data) {
    return (
      <div className="max-w-3xl mx-auto px-6 py-20 text-center">
        <p className="text-gray-400 mb-6">
          No investigation loaded. Run an investigation first.
        </p>
        <button
          onClick={() => navigate('/')}
          className="px-5 py-2.5 rounded-lg bg-blue-600 hover:bg-blue-500 transition font-medium"
        >
          New Investigation
        </button>
      </div>
    );
  }

  const theme = verdictTheme(data.verdict);
  const mitre = Array.isArray(data.mitre_mapping) ? data.mitre_mapping : [];
  const ai = data.ai_explanation || {};
  const intel = data.threat_intel || {};

  const downloadPdf = () => {
    window.open(
      `${BASE_URL}/investigations/${data.investigation_id}/report`,
      '_blank'
    );
  };

  const parseMarkdown = (text) => {
    if (!text) return null;
    const parts = text.split(/\*\*(.*?)\*\*/g);
    return parts.map((part, i) =>
      i % 2 === 1
        ? <strong key={i} className="text-white font-semibold">{part}</strong>
        : <span key={i}>{part}</span>
    );
  };

  return (
    <div className="max-w-5xl mx-auto px-6 py-10">
      {/* Verdict banner */}
      <div
        className={`rounded-2xl border ${theme.ring} ring-1 ${theme.bg} p-6 mb-6 flex flex-col md:flex-row md:items-center md:justify-between gap-4`}
      >
        <div>
          <p className="text-xs uppercase tracking-widest text-gray-400 mb-1">
            Verdict
          </p>
          <h1 className={`text-4xl font-extrabold ${theme.text}`}>
            {theme.label}
          </h1>
          <p className="mt-2 text-gray-400 font-mono text-sm">
            {String(data.input_type).toUpperCase()} &middot; {data.input_value}
          </p>
        </div>
        <span
          className={`self-start md:self-center px-4 py-1.5 rounded-lg text-sm font-bold ${severityTheme(
            data.severity
          )}`}
        >
          {String(data.severity || 'UNKNOWN').toUpperCase()}
        </span>
      </div>

      {/* ID + scores */}
      <div className="grid md:grid-cols-2 gap-6 mb-6">
        <Card title="Investigation">
          <div className="space-y-2 text-sm">
            <div className="flex justify-between">
              <span className="text-gray-400">ID</span>
              <span className="font-mono text-blue-400">
                {data.investigation_id}
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-400">Timestamp</span>
              <span className="font-mono text-gray-300">{data.timestamp}</span>
            </div>
          </div>
        </Card>
        <Card title="Scoring">
          <div className="space-y-4">
            <ScoreBar label="Risk Score" score={data.risk_score} />
            <ScoreBar label="Confidence Score" score={data.confidence_score} />
          </div>
        </Card>
      </div>

      {/* Recommended action */}
      <div className="rounded-xl border border-blue-500/30 bg-blue-500/10 p-5 mb-6">
        <p className="text-xs uppercase tracking-widest text-blue-300 mb-1">
          Recommended Action
        </p>
        <p className="text-lg font-semibold text-white">
          {data.recommended_action || 'No action required'}
        </p>
      </div>

      {/* Risk Score Breakdown (Explainability Panel) */}
      {data.risk_breakdown &&
       data.risk_breakdown.length > 0 && (
        <div className="mb-6 p-6 rounded-xl border
          border-gray-700"
          style={{background: '#0d1526'}}>

          <h3 className="text-xs font-medium
            text-gray-400 tracking-widest
            uppercase mb-1">
            RISK SCORE BREAKDOWN
          </h3>
          <p className="text-xs text-gray-500 mb-4">
            How each signal contributed to the
            final risk score
          </p>

          <div className="space-y-4">
            {data.risk_breakdown.map((item, index) => {
              const pct = data.risk_score > 0
                ? Math.round(
                    (item.contribution / data.risk_score)
                    * 100
                  )
                : 0;

              const barColor =
                item.contribution >= 40
                  ? '#ef4444'
                  : item.contribution >= 20
                  ? '#f59e0b'
                  : '#10b981';

              return (
                <div key={index}>
                  <div className="flex justify-between
                    items-center mb-1">
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-medium
                        text-white">
                        {item.source}
                      </span>
                      <span className="text-xs
                        text-gray-500">
                        {item.weight}
                      </span>
                    </div>
                    <span className="text-sm font-bold"
                      style={{color: barColor}}>
                      +{item.contribution} pts
                    </span>
                  </div>

                  <div className="w-full rounded-full
                    h-2 mb-1"
                    style={{background: '#1e293b'}}>
                    <div
                      className="h-2 rounded-full
                        transition-all duration-500"
                      style={{
                        width: `${Math.min(100, pct)}%`,
                        background: barColor
                      }}
                    />
                  </div>

                  <p className="text-xs text-gray-500">
                    {item.reason}
                  </p>
                </div>
              );
            })}
          </div>

          <div className="mt-4 pt-4 border-t
            border-gray-700 flex justify-between
            items-center">
            <span className="text-xs text-gray-500">
              {data.risk_breakdown.length} signal
              {data.risk_breakdown.length !== 1
                ? 's' : ''} analyzed
            </span>
            <span className="text-xs font-medium px-3
              py-1 rounded-full"
              style={{
                background: data.risk_score >= 70
                  ? 'rgba(239,68,68,0.15)'
                  : data.risk_score >= 30
                  ? 'rgba(245,158,11,0.15)'
                  : 'rgba(16,185,129,0.15)',
                color: data.risk_score >= 70
                  ? '#ef4444'
                  : data.risk_score >= 30
                  ? '#f59e0b'
                  : '#10b981',
                border: '1px solid currentColor'
              }}>
              {data.risk_score >= 70
                ? 'CRITICAL THREAT'
                : data.risk_score >= 30
                ? 'MODERATE RISK'
                : 'LOW RISK'}
            </span>
          </div>
        </div>
      )}

      {/* MITRE */}
      {mitre.length > 0 && (
        <div className="mb-6">
          <h3 className="text-xs uppercase tracking-widest text-gray-500 mb-3">
            MITRE ATT&amp;CK Mapping
          </h3>
          <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-3">
            {mitre.map((m, i) => (
              <div
                key={i}
                className="rounded-xl border border-gray-800 bg-gray-900/60 p-4 hover:border-blue-500/50 hover:shadow-lg hover:shadow-blue-500/10 transition-all duration-200"
              >
                <div className="flex items-center justify-between mb-1">
                  <span className="font-mono text-blue-400 font-bold">
                    {m.technique_id}
                  </span>
                  {m.score != null && (
                    <span className="font-mono text-xs text-gray-500">
                      {Number(m.score).toFixed(2)}
                    </span>
                  )}
                </div>
                <p className="text-sm text-white font-medium">{m.name}</p>
                {m.tactic && (
                  <p className="text-xs text-gray-500 mt-1">{m.tactic}</p>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* AI Explanation */}
      {ai.explanation && (
        <Card title="AI Explanation (RAG-Grounded)">
          <div className="flex flex-wrap gap-2 mb-4 text-xs">
            <span className="px-2 py-1 rounded bg-gray-800 font-mono text-gray-300">
              {ai.ai_model}
            </span>
            <span className="px-2 py-1 rounded bg-gray-800 font-mono text-gray-300">
              Primary: {ai.primary_mitre}
            </span>
            <span
              className={`px-2 py-1 rounded font-mono ${
                ai.grounded
                  ? 'bg-green-500/15 text-green-400'
                  : 'bg-amber-500/15 text-amber-400'
              }`}
            >
              {ai.grounded ? 'GROUNDED' : 'UNGROUNDED'}
            </span>
          </div>
          <p className="text-gray-300 leading-relaxed whitespace-pre-line">
            {parseMarkdown(ai.explanation)}
          </p>
        </Card>
      )}

      {/* Threat Intel */}
      <div className="mt-6">
        <Card title="Threat Intelligence">
          <div className="grid sm:grid-cols-2 gap-y-2 gap-x-8 text-sm">
            {Object.entries(intel)
              .filter(
                ([, v]) => v != null && typeof v !== 'object'
              )
              .map(([k, v]) => (
                <div key={k} className="flex justify-between border-b border-gray-800/60 py-1.5">
                  <span className="text-gray-400 capitalize">
                    {k.replace(/_/g, ' ')}
                  </span>
                  <span className="font-mono text-gray-200 text-right ml-4 break-all">
                    {String(v)}
                  </span>
                </div>
              ))}
          </div>
        </Card>
      </div>

      {/* Analyst Decision Section */}
      <div className="mb-8 p-6 rounded-xl border border-gray-700"
        style={{background: '#0d1526'}}>

        <h3 className="text-xs font-medium text-gray-400
          tracking-widest uppercase mb-4">
          ANALYST DECISION
        </h3>

        {decision ? (
          <div className="rounded-lg p-4 border"
            style={{
              background: decision.decision === 'approve'
                ? 'rgba(16,185,129,0.1)'
                : decision.decision === 'reject'
                ? 'rgba(239,68,68,0.1)'
                : 'rgba(245,158,11,0.1)',
              borderColor: decision.decision === 'approve'
                ? '#10b981'
                : decision.decision === 'reject'
                ? '#ef4444'
                : '#f59e0b'
            }}>
            <div className="flex items-center gap-3 mb-2">
              <span className="text-2xl">
                {decision.decision === 'approve' ? '✓'
                 : decision.decision === 'reject' ? '✗'
                 : '↑'}
              </span>
              <div>
                <p className="font-bold text-white text-lg uppercase">
                  {decision.decision}
                </p>
                <p className="text-xs text-gray-400">
                  {decision.decided_at
                    ? new Date(decision.decided_at)
                      .toLocaleString()
                    : 'Just now'}
                  {' '}&bull;{' '}
                  {decision.decided_by || 'analyst'}
                </p>
              </div>
            </div>
            {decision.analyst_note && (
              <p className="text-sm text-gray-300 mt-2
                border-t border-gray-600 pt-2">
                Note: {decision.analyst_note}
              </p>
            )}
            <button
              onClick={() => {
                setDecision(null);
                setDecisionSuccess("");
                setAnalystNote("");
              }}
              className="mt-3 text-xs text-gray-500
                hover:text-gray-300 underline">
              Change decision
            </button>
          </div>
        ) : (
          <div>
            <p className="text-sm text-gray-400 mb-4">
              Review the investigation above and record
              your analyst decision.
            </p>

            <textarea
              value={analystNote}
              onChange={(e) => setAnalystNote(e.target.value)}
              placeholder="Add analyst note (optional)..."
              rows={2}
              className="w-full mb-4 px-3 py-2 rounded-lg
                text-sm text-gray-300
                border border-gray-700
                focus:outline-none focus:border-blue-500"
              style={{background: '#111c35'}}
            />

            {decisionError && (
              <p className="text-red-400 text-sm mb-3">
                {decisionError}
              </p>
            )}

            {decisionSuccess && (
              <p className="text-green-400 text-sm mb-3">
                {decisionSuccess}
              </p>
            )}

            <div className="grid grid-cols-3 gap-3">
              <button
                onClick={() => submitDecision('approve')}
                disabled={submitting}
                className="py-3 px-4 rounded-lg font-bold
                  text-sm uppercase tracking-wider
                  transition-all duration-200
                  disabled:opacity-50 disabled:cursor-not-allowed"
                style={{
                  background: 'rgba(16,185,129,0.15)',
                  border: '1px solid #10b981',
                  color: '#10b981'
                }}
                onMouseEnter={e =>
                  e.target.style.background =
                  'rgba(16,185,129,0.3)'}
                onMouseLeave={e =>
                  e.target.style.background =
                  'rgba(16,185,129,0.15)'}>
                {submitting ? '...' : '✓ Approve'}
              </button>

              <button
                onClick={() => submitDecision('reject')}
                disabled={submitting}
                className="py-3 px-4 rounded-lg font-bold
                  text-sm uppercase tracking-wider
                  transition-all duration-200
                  disabled:opacity-50 disabled:cursor-not-allowed"
                style={{
                  background: 'rgba(239,68,68,0.15)',
                  border: '1px solid #ef4444',
                  color: '#ef4444'
                }}
                onMouseEnter={e =>
                  e.target.style.background =
                  'rgba(239,68,68,0.3)'}
                onMouseLeave={e =>
                  e.target.style.background =
                  'rgba(239,68,68,0.15)'}>
                {submitting ? '...' : '✗ Reject'}
              </button>

              <button
                onClick={() => submitDecision('escalate')}
                disabled={submitting}
                className="py-3 px-4 rounded-lg font-bold
                  text-sm uppercase tracking-wider
                  transition-all duration-200
                  disabled:opacity-50 disabled:cursor-not-allowed"
                style={{
                  background: 'rgba(245,158,11,0.15)',
                  border: '1px solid #f59e0b',
                  color: '#f59e0b'
                }}
                onMouseEnter={e =>
                  e.target.style.background =
                  'rgba(245,158,11,0.3)'}
                onMouseLeave={e =>
                  e.target.style.background =
                  'rgba(245,158,11,0.15)'}>
                {submitting ? '...' : '↑ Escalate'}
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Actions */}
      <div className="mt-8 flex flex-col sm:flex-row gap-3">
        <button
          onClick={downloadPdf}
          className="flex-1 rounded-xl bg-blue-600 hover:bg-blue-500 py-3 font-semibold transition shadow-lg shadow-blue-600/30"
        >
          Download PDF Report
        </button>
        <button
          onClick={() => navigate('/')}
          className="flex-1 rounded-xl border border-gray-700 hover:bg-gray-800 py-3 font-semibold transition"
        >
          New Investigation
        </button>
      </div>
    </div>
  );
}

export default Results;
