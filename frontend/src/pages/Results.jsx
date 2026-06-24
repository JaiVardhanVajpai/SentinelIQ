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

const MITIGATION_DETAILS = {
  "M1031": {
    how_to: [
      "Deploy IDS/IPS solutions at network perimeter",
      "Configure signatures for known attack patterns",
      "Enable deep packet inspection on suspicious traffic"
    ],
    tools: ["Snort", "Suricata", "Palo Alto IPS", "Cisco Firepower"],
    difficulty: "Medium"
  },
  "M1021": {
    how_to: [
      "Deploy web proxy with URL filtering enabled",
      "Block access to newly registered domains",
      "Implement DNS filtering for known malicious domains"
    ],
    tools: ["Zscaler", "Cisco Umbrella", "Bluecoat", "Squid Proxy"],
    difficulty: "Easy"
  },
  "M1036": {
    how_to: [
      "Set account lockout after 5 failed attempts",
      "Implement progressive delay between login attempts",
      "Alert on multiple failed logins from same IP"
    ],
    tools: ["Active Directory GPO", "Azure AD", "Okta", "CrowdStrike"],
    difficulty: "Easy"
  },
  "M1032": {
    how_to: [
      "Enforce MFA for all remote access and VPN",
      "Use authenticator apps over SMS where possible",
      "Implement MFA for privileged account access"
    ],
    tools: ["Duo Security", "Microsoft Authenticator", "Google Auth", "Okta MFA"],
    difficulty: "Easy"
  },
  "M1037": {
    how_to: [
      "Block known Tor exit node IP ranges at firewall",
      "Subscribe to threat intel feeds for Tor IPs",
      "Monitor and alert on traffic to anonymous proxies"
    ],
    tools: ["Palo Alto NGFW", "Fortinet", "pfSense", "Emerging Threats Feed"],
    difficulty: "Medium"
  },
  "M1026": {
    how_to: [
      "Audit privileged accounts quarterly",
      "Implement just-in-time privileged access",
      "Remove unnecessary admin rights from accounts"
    ],
    tools: ["CyberArk PAM", "BeyondTrust", "Microsoft PIM", "HashiCorp Vault"],
    difficulty: "Hard"
  }
};

function Results() {
  const [data, setData] = useState(null);
  const [decision, setDecision] = useState(null);
  const [analystNote, setAnalystNote] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [decisionError, setDecisionError] = useState("");
  const [decisionSuccess, setDecisionSuccess] = useState("");
  const [expandedMitigation, setExpandedMitigation] = useState(null);
  const [soarData, setSoarData] = useState(null);
  const [soarLoading, setSoarLoading] = useState(false);
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
        // No analyst decision recorded yet — leave decision unset
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

  const fetchSoar = async () => {
    if (!data?.investigation_id) return;
    setSoarLoading(true);
    try {
      const res = await api.get(
        `/soar-alert/${data.investigation_id}`
      );
      setSoarData(res.data);
    } catch (e) {
      setSoarData(null);
    } finally {
      setSoarLoading(false);
    }
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

  const formatKey = (key) => {
    const labels = {
      'type': 'Type',
      'ip': 'IP Address',
      'url': 'URL',
      'abuse_score': 'Abuse Score',
      'country': 'Country',
      'isp': 'ISP',
      'domain': 'Domain',
      'usage_type': 'Usage Type',
      'total_reports': 'Total Reports',
      'verdict': 'Verdict',
      'malicious_engines': 'Malicious Engines',
      'harmless_engines': 'Harmless Engines',
      'suspicious_engines': 'Suspicious Engines',
      'total_engines': 'Total Engines',
      'risk_score': 'Risk Score',
      'explainability': 'Explainability'
    };
    return labels[key] ||
      key.replace(/_/g, ' ')
         .replace(/\b\w/g, l => l.toUpperCase());
  };

  const getCountryName = (code) => {
    const countries = {
      'DE': 'Germany',
      'US': 'United States',
      'CN': 'China',
      'RU': 'Russia',
      'IN': 'India',
      'GB': 'United Kingdom',
      'FR': 'France',
      'NL': 'Netherlands',
      'UA': 'Ukraine',
      'BR': 'Brazil',
      'KR': 'South Korea',
      'JP': 'Japan',
      'CA': 'Canada',
      'AU': 'Australia',
      'SG': 'Singapore',
      'HK': 'Hong Kong',
      'TR': 'Turkey',
      'IR': 'Iran',
      'KP': 'North Korea',
      'PK': 'Pakistan'
    };
    return countries[code]
      ? `${code} — ${countries[code]}`
      : code;
  };

  const formatValue = (key, value) => {
    if (key === 'country') {
      return getCountryName(String(value));
    }
    if (key === 'type') {
      const typeMap = {
        'ip_analysis': 'IP Analysis',
        'url_analysis': 'URL Analysis',
        'login_analysis': 'Login Analysis'
      };
      return typeMap[String(value)] ||
        String(value)
          .replace(/_/g, ' ')
          .replace(/\b\w/g, l => l.toUpperCase());
    }
    if (key === 'abuse_score') {
      return `${value} / 100`;
    }
    return String(value);
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
                style={{ overflow: 'hidden' }}
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
                <p className="text-sm text-white font-medium" style={{ overflow: 'hidden', textOverflow: 'ellipsis' }}>{m.name}</p>
                {m.tactic && (
                  <p className="text-xs text-gray-500 mt-1">{m.tactic}</p>
                )}
                {m.mitigations && m.mitigations.length > 0 && (
                  <div style={{
                    marginTop: '10px',
                    paddingTop: '10px',
                    borderTop: '1px solid rgba(255,255,255,0.08)'
                  }}>
                    <p style={{
                      fontSize: '10px',
                      color: '#64748b',
                      textTransform: 'uppercase',
                      letterSpacing: '0.05em',
                      marginBottom: '6px'
                    }}>
                      Recommended Mitigations
                    </p>
                    {m.mitigations.map((mit, mi) => {
                      const details = MITIGATION_DETAILS[mit.id];
                      const isExpanded = expandedMitigation === `${m.technique_id}-${mit.id}`;
                      return (
                        <div key={mi} style={{ marginBottom: '6px' }}>
                          <div
                            onClick={() => setExpandedMitigation(
                              isExpanded ? null : `${m.technique_id}-${mit.id}`
                            )}
                            style={{
                              display: 'flex',
                              alignItems: 'flex-start',
                              gap: '6px',
                              cursor: 'pointer',
                              padding: '6px',
                              borderRadius: '6px',
                              background: isExpanded
                                ? 'rgba(59,130,246,0.08)'
                                : 'transparent',
                              border: isExpanded
                                ? '1px solid rgba(59,130,246,0.2)'
                                : '1px solid transparent',
                              transition: 'all 0.2s'
                            }}
                          >
                            <span style={{
                              fontSize: '10px',
                              fontWeight: '600',
                              color: '#3b82f6',
                              backgroundColor: 'rgba(59,130,246,0.1)',
                              padding: '1px 5px',
                              borderRadius: '3px',
                              flexShrink: 0,
                              marginTop: '1px'
                            }}>
                              {mit.id}
                            </span>
                            <div style={{ flex: 1 }}>
                              <span style={{
                                fontSize: '11px',
                                color: '#94a3b8',
                                fontWeight: '500'
                              }}>
                                {mit.name}
                              </span>
                              <p style={{
                                fontSize: '12px',
                                color: '#64748b',
                                margin: '1px 0 0 0',
                                display: '-webkit-box',
                                WebkitLineClamp: 3,
                                WebkitBoxOrient: 'vertical',
                                overflow: 'hidden'
                              }}>
                                {mit.description}
                              </p>
                            </div>
                            <span style={{
                              fontSize: '10px',
                              color: '#475569',
                              flexShrink: 0,
                              marginTop: '2px'
                            }}>
                              {isExpanded ? '▲' : '▼'}
                            </span>
                          </div>

                          {isExpanded && details && (
                            <div style={{
                              margin: '4px 0 0 0',
                              padding: '10px 12px',
                              background: 'rgba(15, 23, 42, 0.6)',
                              borderRadius: '6px',
                              border: '1px solid rgba(59,130,246,0.15)'
                            }}>
                              <div style={{ marginBottom: '10px' }}>
                                <p style={{
                                  fontSize: '10px',
                                  color: '#3b82f6',
                                  textTransform: 'uppercase',
                                  letterSpacing: '0.05em',
                                  marginBottom: '6px',
                                  fontWeight: '600'
                                }}>
                                  How to Implement
                                </p>
                                {details.how_to.map((step, si) => (
                                  <div key={si} style={{
                                    display: 'flex',
                                    gap: '6px',
                                    marginBottom: '4px',
                                    alignItems: 'flex-start'
                                  }}>
                                    <span style={{
                                      fontSize: '10px',
                                      color: '#3b82f6',
                                      flexShrink: 0,
                                      marginTop: '1px'
                                    }}>
                                      {si + 1}.
                                    </span>
                                    <span style={{
                                      fontSize: '11px',
                                      color: '#94a3b8'
                                    }}>
                                      {step}
                                    </span>
                                  </div>
                                ))}
                              </div>

                              <div style={{ marginBottom: '10px' }}>
                                <p style={{
                                  fontSize: '10px',
                                  color: '#3b82f6',
                                  textTransform: 'uppercase',
                                  letterSpacing: '0.05em',
                                  marginBottom: '6px',
                                  fontWeight: '600'
                                }}>
                                  Common Tools
                                </p>
                                <div style={{
                                  display: 'flex',
                                  flexWrap: 'wrap',
                                  gap: '4px'
                                }}>
                                  {details.tools.map((tool, ti) => (
                                    <span key={ti} style={{
                                      fontSize: '10px',
                                      color: '#64748b',
                                      background: 'rgba(100,116,139,0.1)',
                                      border: '1px solid rgba(100,116,139,0.2)',
                                      padding: '2px 6px',
                                      borderRadius: '4px'
                                    }}>
                                      {tool}
                                    </span>
                                  ))}
                                </div>
                              </div>

                              <div style={{
                                display: 'flex',
                                alignItems: 'center',
                                justifyContent: 'space-between'
                              }}>
                                <div style={{
                                  display: 'flex',
                                  alignItems: 'center',
                                  gap: '6px'
                                }}>
                                  <span style={{
                                    fontSize: '10px',
                                    color: '#64748b',
                                    textTransform: 'uppercase',
                                    letterSpacing: '0.05em'
                                  }}>
                                    Difficulty:
                                  </span>
                                  <span style={{
                                    fontSize: '10px',
                                    fontWeight: '600',
                                    color: details.difficulty === 'Easy'
                                      ? '#10b981'
                                      : details.difficulty === 'Medium'
                                      ? '#f59e0b'
                                      : '#ef4444',
                                    background: details.difficulty === 'Easy'
                                      ? 'rgba(16,185,129,0.1)'
                                      : details.difficulty === 'Medium'
                                      ? 'rgba(245,158,11,0.1)'
                                      : 'rgba(239,68,68,0.1)',
                                    padding: '2px 6px',
                                    borderRadius: '4px'
                                  }}>
                                    {details.difficulty}
                                  </span>
                                </div>

                                <a
                                  href={`https://attack.mitre.org/mitigations/${mit.id}`}
                                  target="_blank"
                                  rel="noopener noreferrer"
                                  style={{
                                    fontSize: '10px',
                                    color: '#3b82f6',
                                    textDecoration: 'none'
                                  }}
                                  onClick={e => e.stopPropagation()}
                                >
                                  MITRE Reference →
                                </a>
                              </div>
                            </div>
                          )}
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* AI Explanation */}
      {ai.explanation && (
        <Card title="AI Explanation (RAG-Grounded)">
          <div className="flex flex-wrap gap-2 mb-4 text-xs" style={{ padding: '16px' }}>
            <span className="px-2 py-1 rounded bg-gray-800 font-mono text-gray-300" style={{ marginBottom: '8px' }}>
              {ai.ai_model}
            </span>
            <span className="px-2 py-1 rounded bg-gray-800 font-mono text-gray-300" style={{ marginBottom: '8px' }}>
              Primary: {ai.primary_mitre}
            </span>
            <span
              className={`px-2 py-1 rounded font-mono ${
                ai.grounded
                  ? 'bg-green-500/15 text-green-400'
                  : 'bg-amber-500/15 text-amber-400'
              }`}
              style={{ marginBottom: '8px' }}
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
                ([k, v]) =>
                  v != null &&
                  typeof v !== 'object' &&
                  k !== 'explainability'
              )
              .map(([k, v]) => (
                <div key={k} className="flex justify-between border-b border-gray-800/60 py-1.5">
                  <span className="text-gray-400">
                    {formatKey(k)}
                  </span>
                  <span className="font-mono text-gray-200 text-right ml-4 break-all">
                    {k === 'verdict' ? (
                      <span
                        style={{
                          color: String(v) === 'MALICIOUS'
                            ? '#ef4444'
                            : String(v) === 'CLEAN'
                            ? '#10b981'
                            : String(v) === 'SUSPICIOUS'
                            ? '#f59e0b'
                            : String(v) === 'PREVIOUSLY_MALICIOUS'
                            ? '#f97316'
                            : String(v) === 'UNRATED'
                            ? '#64748b'
                            : 'inherit'
                        }}
                      >
                        {String(formatValue(k, v)).replace(/_/g, ' ')}
                      </span>
                    ) : (
                      formatValue(k, v)
                    )}
                  </span>
                </div>
              ))}
          </div>
        </Card>
      </div>

      {/* Investigation Timeline */}
      {data.timeline && data.timeline.length > 0 && (
        <div className="mt-6 mb-6 p-6 rounded-xl border border-gray-700"
          style={{background: '#0d1526'}}>
          <h3 className="text-xs font-medium text-gray-400
            tracking-widest uppercase mb-4">
            Investigation Timeline
          </h3>
          <div className="relative">
            <div className="absolute left-3 top-0 bottom-0
              w-px bg-gray-700" />
            {data.timeline.map((step, index) => (
              <div key={index}
                className="relative flex gap-4 mb-4 last:mb-0">
                <div className="relative z-10 flex-shrink-0">
                  <div className="w-6 h-6 rounded-full flex
                    items-center justify-center"
                    style={{
                      background: step.status === 'complete'
                        ? 'rgba(16,185,129,0.2)'
                        : 'rgba(245,158,11,0.2)',
                      border: `1px solid ${
                        step.status === 'complete'
                          ? '#10b981' : '#f59e0b'
                      }`
                    }}>
                    <div className="w-2 h-2 rounded-full"
                      style={{
                        background: step.status === 'complete'
                          ? '#10b981' : '#f59e0b'
                      }} />
                  </div>
                </div>
                <div style={{
                  flex: 1,
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'flex-start',
                  gap: '8px'
                }}>
                  <div style={{flex: 1}}>
                    <p className="text-sm font-medium text-white mb-1">
                      {step.step}
                    </p>
                    <p className="text-xs text-gray-400">
                      {step.detail}
                    </p>
                  </div>
                  <span style={{
                    fontSize: '11px',
                    color: '#475569',
                    flexShrink: 0,
                    whiteSpace: 'nowrap',
                    marginTop: '2px',
                    fontFamily: 'monospace'
                  }}>
                    {new Date(step.time).toLocaleTimeString([], {
                      hour: '2-digit',
                      minute: '2-digit',
                      second: '2-digit'
                    })}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

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

      {data.risk_score >= 75 && (
        <div style={{
          marginTop: '16px',
          padding: '20px',
          borderRadius: '12px',
          background: '#0d1526',
          border: '1px solid #7f1d1d'
        }}>
          <div style={{ marginBottom: '14px' }}>
            <div style={{
              display: 'flex',
              alignItems: 'flex-start',
              justifyContent: 'space-between',
              gap: '16px',
              marginBottom: '8px'
            }}>
              <p style={{
                fontSize: '13px',
                fontWeight: '600',
                color: '#f87171'
              }}>
                SOAR SIMULATION
              </p>
              {!soarData && (
                <button
                  onClick={fetchSoar}
                  disabled={soarLoading}
                  style={{
                    flexShrink: 0,
                    padding: '6px 14px',
                    borderRadius: '8px',
                    background: soarLoading
                      ? '#1e293b' : 'rgba(239,68,68,0.1)',
                    border: '1px solid #7f1d1d',
                    color: '#f87171',
                    fontSize: '12px',
                    cursor: soarLoading
                      ? 'not-allowed' : 'pointer',
                    fontWeight: '500',
                    whiteSpace: 'nowrap'
                  }}
                >
                  {soarLoading ? 'Generating...' : 'Generate SOAR Alert'}
                </button>
              )}
            </div>
            <p style={{ fontSize: '12px', color: '#94a3b8', marginBottom: '4px' }}>
              High-risk alert — automated response triggered
            </p>
            <p style={{ fontSize: '12px', color: '#475569', lineHeight: '1.6' }}>
              SOAR (Security Orchestration, Automation & Response)
              simulates what enterprise security tools do automatically
              when a critical threat is confirmed — assign playbooks,
              trigger containment actions, and create incident tickets.
            </p>
          </div>

          {soarData && soarData.soar_triggered && (
            <div>
              <div style={{
                display: 'flex',
                gap: '8px',
                marginBottom: '14px'
              }}>
                <span style={{
                  fontSize: '11px',
                  fontWeight: '700',
                  padding: '3px 10px',
                  borderRadius: '20px',
                  background: 'rgba(239,68,68,0.15)',
                  color: '#f87171'
                }}>
                  {soarData.severity}
                </span>
                <span style={{
                  fontSize: '11px',
                  padding: '3px 10px',
                  borderRadius: '20px',
                  background: 'rgba(59,130,246,0.1)',
                  color: '#60a5fa'
                }}>
                  {soarData.alert_id}
                </span>
              </div>

              <div style={{ marginBottom: '14px' }}>
                <p style={{
                  fontSize: '11px',
                  color: '#64748b',
                  textTransform: 'uppercase',
                  letterSpacing: '.05em',
                  marginBottom: '8px'
                }}>
                  Recommended Playbooks
                </p>
                <p style={{ fontSize: '11px', color: '#475569', marginBottom: '8px' }}>
                  Based on detected MITRE techniques — these are the
                  standard response procedures a SOC team would follow:
                </p>
                {soarData.recommended_playbooks.map(
                  (p, i) => (
                    <div key={i} style={{
                      fontSize: '12px',
                      color: '#fbbf24',
                      padding: '6px 10px',
                      background: 'rgba(245,158,11,0.08)',
                      borderRadius: '6px',
                      marginBottom: '4px',
                      borderLeft: '3px solid #f59e0b'
                    }}>
                      {p}
                    </div>
                  )
                )}
              </div>

              <div style={{ marginBottom: '14px' }}>
                <p style={{
                  fontSize: '11px',
                  color: '#64748b',
                  textTransform: 'uppercase',
                  letterSpacing: '.05em',
                  marginBottom: '8px'
                }}>
                  Action Items
                </p>
                {soarData.action_items.map((a, i) => (
                  <div key={i} style={{
                    fontSize: '12px',
                    color: '#e2e8f0',
                    padding: '4px 0',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '8px'
                  }}>
                    <span style={{ color: '#ef4444' }}>
                      →
                    </span>
                    {a}
                  </div>
                ))}
              </div>

              <div>
                <p style={{
                  fontSize: '11px',
                  color: '#64748b',
                  textTransform: 'uppercase',
                  letterSpacing: '.05em',
                  marginBottom: '8px'
                }}>
                  Auto Actions Triggered
                </p>
                {soarData.auto_actions.map((a, i) => (
                  <div key={i} style={{
                    fontSize: '12px',
                    color: '#4ade80',
                    padding: '4px 0',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '8px'
                  }}>
                    <span>✓</span>
                    {a}
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

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
