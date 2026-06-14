import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { BASE_URL } from '../api';
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
