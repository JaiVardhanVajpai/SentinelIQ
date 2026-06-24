import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import api from '../api';

const TABS = [
  { id: 'url', label: 'URL', hint: 'Scan a web address for phishing & malware' },
  { id: 'ip', label: 'IP', hint: 'Check an IP against abuse & reputation feeds' },
  { id: 'login', label: 'LOGIN', hint: 'Detect brute force & impossible travel' },
];

const SAMPLE_LOGIN = `[
  { "username": "admin", "ip": "10.0.0.5", "status": "fail", "timestamp": "2026-06-14T10:00:00", "lat": 28.6, "lon": 77.2 },
  { "username": "admin", "ip": "10.0.0.5", "status": "fail", "timestamp": "2026-06-14T10:01:00", "lat": 28.6, "lon": 77.2 }
]`;

function Home() {
  const [tab, setTab] = useState('ip');
  const [value, setValue] = useState('');
  const [eventsText, setEventsText] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const navigate = useNavigate();

  const runInvestigation = async () => {
    setError('');

    // Build the request body based on the active tab
    let body;
    if (tab === 'login') {
      let parsed;
      try {
        parsed = JSON.parse(eventsText || SAMPLE_LOGIN);
      } catch (e) {
        setError('Login events must be valid JSON (an array of event objects).');
        return;
      }
      body = { input_type: 'login', events: parsed };
    } else {
      if (!value.trim()) {
        setError(`Please enter a ${tab.toUpperCase()} to investigate.`);
        return;
      }
      body = { input_type: tab, input_value: value.trim() };
    }

    setLoading(true);
    try {
      const res = await api.post('/investigate', body);
      localStorage.setItem('sentineliq_result', JSON.stringify(res.data));
      navigate('/results');
    } catch (e) {
      const detail =
        e?.response?.data?.detail || e?.message || 'Investigation failed.';
      setError(typeof detail === 'string' ? detail : JSON.stringify(detail));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="max-w-4xl mx-auto px-6 py-14">
      {/* Hero */}
      <div className="text-center mb-10">
        <div className="inline-flex items-center gap-2 px-3 py-1 mb-5 rounded-full border border-gray-800 bg-gray-900 text-xs text-gray-400">
          <span className="h-2 w-2 rounded-full bg-blue-500 animate-pulse" />
          Real-time threat intelligence
        </div>
        <h1 className="text-4xl md:text-5xl font-extrabold tracking-tight">
          AI-Powered Threat <span className="text-blue-400">Investigation</span> Engine
        </h1>
        <p className="mt-4 text-gray-400 max-w-2xl mx-auto">
          Analyze URLs, IPs, and Login Events with real threat intelligence,
          MITRE ATT&amp;CK mapping, and grounded AI explanations.
        </p>
      </div>

      {/* Card */}
      <div className="rounded-2xl border border-gray-800 bg-gray-900/60 shadow-2xl shadow-black/40 p-6 md:p-8">
        {/* Tabs */}
        <div className="grid grid-cols-3 gap-2 p-1 rounded-xl bg-gray-950 border border-gray-800 mb-6">
          {TABS.map((t) => (
            <button
              key={t.id}
              onClick={() => {
                setTab(t.id);
                setError('');
              }}
              className={[
                'py-2.5 rounded-lg text-sm font-semibold transition-all duration-200',
                tab === t.id
                  ? 'bg-blue-500/15 text-blue-400 ring-1 ring-blue-500/50 shadow-lg shadow-blue-500/10'
                  : 'text-gray-400 hover:text-white hover:bg-gray-800',
              ].join(' ')}
            >
              {t.label}
            </button>
          ))}
        </div>

        <p className="text-xs text-gray-500 mb-4">
          {TABS.find((t) => t.id === tab)?.hint}
        </p>

        {/* Input */}
        {tab === 'login' ? (
          <textarea
            value={eventsText}
            onChange={(e) => setEventsText(e.target.value)}
            placeholder={SAMPLE_LOGIN}
            rows={8}
            className="w-full rounded-xl bg-gray-950 border border-gray-800 px-4 py-3 font-mono text-sm text-gray-200 placeholder-gray-600 focus:outline-none focus:ring-2 focus:ring-blue-500/60 transition"
          />
        ) : (
          <input
            type="text"
            value={value}
            onChange={(e) => setValue(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter') {
                runInvestigation();
              }
            }}
            placeholder={
              tab === 'url' ? 'https://suspicious-site.example' : '185.220.101.45'
            }
            className="w-full rounded-xl bg-gray-950 border border-gray-800 px-4 py-3.5 font-mono text-sm text-gray-200 placeholder-gray-600 focus:outline-none focus:ring-2 focus:ring-blue-500/60 transition"
          />
        )}

        {/* Error */}
        {error && (
          <div className="mt-4 rounded-lg border border-red-500/40 bg-red-500/10 px-4 py-3 text-sm text-red-400">
            {error}
          </div>
        )}

        {/* Button */}
        <button
          onClick={runInvestigation}
          disabled={loading}
          className="mt-6 w-full flex items-center justify-center gap-3 rounded-xl bg-blue-600 hover:bg-blue-500 disabled:opacity-60 disabled:cursor-not-allowed py-3.5 font-semibold tracking-wide transition-all duration-200 shadow-lg shadow-blue-600/30"
        >
          {loading ? (
            <>
              <span className="h-5 w-5 rounded-full border-2 border-white/40 border-t-white animate-spin" />
              INVESTIGATING…
            </>
          ) : (
            'INVESTIGATE'
          )}
        </button>
      </div>

      {/* Stats bar */}
      <div className="mt-8 text-center">
        <p className="text-xs uppercase tracking-widest text-gray-600 mb-3">
          Powered by
        </p>
        <div className="flex flex-wrap items-center justify-center gap-3 text-sm">
          {['VirusTotal', 'AbuseIPDB', 'MITRE ATT&CK', 'Groq AI'].map((s) => (
            <span
              key={s}
              className="px-3 py-1.5 rounded-lg border border-gray-800 bg-gray-900 text-gray-400"
            >
              {s}
            </span>
          ))}
        </div>
      </div>
    </div>
  );
}

export default Home;
