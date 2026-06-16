import React, { useState } from 'react';
import api from '../api';

function ThreatHunt() {
  const [indicator, setIndicator] = useState('');
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState(null);
  const [error, setError] = useState('');
  const [expandedMitre, setExpandedMitre] = useState(null);

  const hunt = async () => {
    if (!indicator.trim()) return;
    setLoading(true);
    setError('');
    setResults(null);
    try {
      const res = await api.get(
        `/hunt?indicator=${encodeURIComponent(indicator.trim())}`
      );
      setResults(res.data);
    } catch (err) {
      setError('Hunt failed — check backend connection');
    } finally {
      setLoading(false);
    }
  };

  const mitreDescriptions = {
    'T1090': 'Proxy — Attacker routes traffic through intermediary systems like Tor or VPNs to hide their real location and evade detection.',
    'T1566': 'Phishing — Attacker sends deceptive emails or messages to trick users into revealing credentials or downloading malware.',
    'T1110': 'Brute Force — Attacker systematically tries many passwords to gain unauthorized access to accounts.',
    'T1078': 'Valid Accounts — Attacker uses stolen legitimate credentials to access systems without triggering alerts.',
    'T1059': 'Command & Scripting — Attacker runs malicious scripts to execute commands on compromised systems.',
    'T1055': 'Process Injection — Attacker injects malicious code into legitimate running processes to evade detection.',
    'T1036': 'Masquerading — Attacker disguises malicious activity as legitimate software or processes.',
    'T1083': 'File Discovery — Attacker enumerates files and directories to find sensitive information.',
    'T1082': 'System Information Discovery — Attacker gathers details about the target system and environment.',
    'T1071': 'Application Layer Protocol — Attacker uses standard protocols like HTTP/DNS to blend C2 traffic with normal traffic.',
    'T1105': 'Ingress Tool Transfer — Attacker downloads additional tools or malware onto the compromised system.',
    'T1027': 'Obfuscated Files — Attacker encodes or encrypts malicious content to evade security tools.',
    'T1140': 'Deobfuscate/Decode — Attacker decodes or decrypts files or information to execute malicious content.',
    'T1574': 'Hijack Execution Flow — Attacker hijacks the way programs execute to run malicious code.',
    'T1003': 'OS Credential Dumping — Attacker extracts credentials from operating system memory or files.',
    'T1018': 'Remote System Discovery — Attacker identifies other systems on the network to expand access.',
    'T1021': 'Remote Services — Attacker uses legitimate remote access tools like RDP or SSH to move laterally.',
    'T1048': 'Exfiltration Over Alternative Protocol — Attacker steals data using uncommon protocols to avoid detection.',
    'T1041': 'Exfiltration Over C2 Channel — Attacker sends stolen data back through the same channel used for control.',
    'T1486': 'Data Encrypted for Impact — Attacker encrypts victim data to cause disruption (ransomware).',
  };

  return (
    <div className="min-h-screen" style={{background: '#0a0f1e'}}>
      <div className="max-w-5xl mx-auto px-6 py-10">

        <div className="mb-8">
          <h1 className="text-2xl font-bold text-white mb-2">
            Threat Hunting
          </h1>
          <p style={{color: '#94a3b8', fontSize: '14px'}}>
            Search all past investigations by IP, URL, or domain.
            Find every time an indicator appeared and how it
            was classified.
          </p>
        </div>

        <div style={{display: 'flex', gap: '12px', marginBottom: '32px'}}>
          <input
            type="text"
            value={indicator}
            onChange={e => setIndicator(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && hunt()}
            placeholder="Enter IP, URL, or domain to hunt..."
            style={{
              flex: 1,
              padding: '12px 16px',
              borderRadius: '12px',
              background: '#111827',
              border: '1px solid #374151',
              color: 'white',
              fontSize: '14px',
              outline: 'none'
            }}
          />
          <button
            onClick={hunt}
            disabled={loading}
            style={{
              padding: '12px 24px',
              borderRadius: '12px',
              background: loading ? '#1e293b' : '#2563eb',
              color: 'white',
              fontWeight: '600',
              fontSize: '14px',
              border: 'none',
              cursor: loading ? 'not-allowed' : 'pointer'
            }}
          >
            {loading ? 'Hunting...' : 'Hunt'}
          </button>
        </div>

        {error && (
          <div style={{
            marginBottom: '24px',
            padding: '16px',
            borderRadius: '12px',
            background: 'rgba(239,68,68,0.1)',
            border: '1px solid #7f1d1d'
          }}>
            <p style={{color: '#f87171', fontSize: '14px'}}>
              {error}
            </p>
          </div>
        )}

        {results && results.total_found === 0 && (
          <div style={{
            padding: '32px',
            borderRadius: '12px',
            background: '#0d1526',
            border: '1px solid #374151',
            textAlign: 'center'
          }}>
            <p style={{color: '#94a3b8', fontSize: '14px'}}>
              No investigations found for "{indicator}"
            </p>
          </div>
        )}

        {results && results.total_found > 0 && (
          <div>
            <div style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(4, 1fr)',
              gap: '12px',
              marginBottom: '24px'
            }}>
              <div style={{
                padding: '16px',
                borderRadius: '12px',
                background: '#0d1526',
                border: '1px solid #374151'
              }}>
                <p style={{
                  fontSize: '11px',
                  color: '#64748b',
                  textTransform: 'uppercase',
                  letterSpacing: '0.05em',
                  marginBottom: '4px'
                }}>Total Found</p>
                <p style={{
                  fontSize: '28px',
                  fontWeight: '700',
                  color: '#60a5fa'
                }}>
                  {results.total_found}
                </p>
              </div>
              <div style={{
                padding: '16px',
                borderRadius: '12px',
                background: '#0d1526',
                border: '1px solid #374151'
              }}>
                <p style={{
                  fontSize: '11px',
                  color: '#64748b',
                  textTransform: 'uppercase',
                  letterSpacing: '0.05em',
                  marginBottom: '4px'
                }}>Avg Risk</p>
                <p style={{
                  fontSize: '28px',
                  fontWeight: '700',
                  color: results.summary.avg_risk_score >= 70
                    ? '#ef4444'
                    : results.summary.avg_risk_score >= 30
                    ? '#f59e0b' : '#10b981'
                }}>
                  {results.summary.avg_risk_score}
                </p>
              </div>
              <div style={{
                padding: '16px',
                borderRadius: '12px',
                background: '#0d1526',
                border: '1px solid #374151'
              }}>
                <p style={{
                  fontSize: '11px',
                  color: '#64748b',
                  textTransform: 'uppercase',
                  letterSpacing: '0.05em',
                  marginBottom: '4px'
                }}>Max Risk</p>
                <p style={{
                  fontSize: '28px',
                  fontWeight: '700',
                  color: '#ef4444'
                }}>
                  {results.summary.max_risk_score}
                </p>
              </div>
              <div style={{
                padding: '16px',
                borderRadius: '12px',
                background: '#0d1526',
                border: '1px solid #374151'
              }}>
                <p style={{
                  fontSize: '11px',
                  color: '#64748b',
                  textTransform: 'uppercase',
                  letterSpacing: '0.05em',
                  marginBottom: '4px'
                }}>Verdicts</p>
                {Object.entries(results.summary.verdicts)
                  .map(([v, c]) => (
                    <p key={v} style={{
                      fontSize: '12px',
                      fontWeight: '600',
                      color: v === 'MALICIOUS'
                        ? '#ef4444'
                        : v === 'CLEAN'
                        ? '#10b981' : '#f59e0b'
                    }}>
                      {v}: {c}
                    </p>
                  ))}
              </div>
            </div>

            {results.summary.top_mitre_techniques.length > 0 &&
             results.summary.avg_risk_score > 0 && (
              <div style={{
                padding: '16px',
                borderRadius: '12px',
                background: '#0d1526',
                border: '1px solid #374151',
                marginBottom: '24px'
              }}>
                <p style={{
                  fontSize: '11px',
                  color: '#64748b',
                  textTransform: 'uppercase',
                  letterSpacing: '0.05em',
                  marginBottom: '12px'
                }}>
                  Top MITRE Techniques
                </p>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px' }}>
                  {results.summary.top_mitre_techniques.map((t, i) => {
                    const techId = t.technique.split(' ')[0];
                    const desc = mitreDescriptions[techId] ||
                      `${t.technique} — A detected attack technique. Click to see count.`;
                    const isOpen = expandedMitre === i;
                    return (
                      <div key={i} style={{ display: 'flex', flexDirection: 'column' }}>
                        <span
                          onClick={() => setExpandedMitre(isOpen ? null : i)}
                          style={{
                            fontSize: '12px',
                            padding: '5px 14px',
                            borderRadius: '20px',
                            fontWeight: '500',
                            background: 'rgba(59,130,246,0.1)',
                            color: '#60a5fa',
                            border: '1px solid rgba(59,130,246,0.2)',
                            cursor: 'pointer',
                            userSelect: 'none'
                          }}
                        >
                          {t.technique}
                          <span style={{ color: '#ef4444', marginLeft: '6px', fontWeight: '700' }}>
                            ×{t.count}
                          </span>
                          <span style={{ marginLeft: '6px', fontSize: '10px' }}>
                            {isOpen ? '▲' : '▼'}
                          </span>
                        </span>
                        {isOpen && (
                          <div style={{
                            marginTop: '6px',
                            padding: '10px 14px',
                            borderRadius: '8px',
                            background: '#0d1526',
                            border: '1px solid #1e293b',
                            fontSize: '12px',
                            color: '#94a3b8',
                            lineHeight: '1.6',
                            maxWidth: '300px'
                          }}>
                            {desc}
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              </div>
            )}

            <div>
              <p style={{
                fontSize: '11px',
                color: '#64748b',
                textTransform: 'uppercase',
                letterSpacing: '0.05em',
                marginBottom: '12px'
              }}>
                Investigation History
              </p>
              <div style={{display: 'flex', flexDirection: 'column', gap: '8px'}}>
                {results.results.map((inv, i) => (
                  <div key={i} style={{
                    padding: '16px',
                    borderRadius: '12px',
                    background: '#0d1526',
                    border: '1px solid #374151',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    gap: '16px'
                  }}>
                    <div style={{flex: 1, minWidth: 0}}>
                      <p style={{
                        fontSize: '12px',
                        color: '#60a5fa',
                        fontFamily: 'monospace',
                        marginBottom: '4px'
                      }}>
                        {inv.investigation_id}
                      </p>
                      <p style={{
                        fontSize: '14px',
                        color: '#e2e8f0',
                        overflow: 'hidden',
                        textOverflow: 'ellipsis',
                        whiteSpace: 'nowrap'
                      }}>
                        {inv.target || inv.input_value}
                      </p>
                      <p style={{
                        fontSize: '12px',
                        color: '#64748b',
                        marginTop: '4px'
                      }}>
                        {new Date(inv.timestamp).toLocaleString()}
                      </p>
                    </div>
                    <div style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: '12px',
                      flexShrink: 0
                    }}>
                      <span style={{
                        fontSize: '16px',
                        fontWeight: '700',
                        color: inv.risk_score >= 70
                          ? '#ef4444'
                          : inv.risk_score >= 30
                          ? '#f59e0b' : '#10b981'
                      }}>
                        {inv.risk_score}/100
                      </span>
                      <span style={{
                        fontSize: '11px',
                        fontWeight: '700',
                        padding: '4px 10px',
                        borderRadius: '20px',
                        background: inv.verdict === 'MALICIOUS'
                          ? 'rgba(239,68,68,0.15)'
                          : inv.verdict === 'CLEAN'
                          ? 'rgba(16,185,129,0.15)'
                          : 'rgba(245,158,11,0.15)',
                        color: inv.verdict === 'MALICIOUS'
                          ? '#ef4444'
                          : inv.verdict === 'CLEAN'
                          ? '#10b981' : '#f59e0b'
                      }}>
                        {inv.verdict}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

export default ThreatHunt;
