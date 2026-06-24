import React, { useState, useRef } from 'react';
import api from '../api';

const riskColor = (score) => {
  if (score === null || score === undefined) return '#64748b';
  if (score >= 70) return '#ef4444';
  if (score >= 30) return '#f59e0b';
  return '#10b981';
};

const verdictStyle = (v) => ({
  MALICIOUS: { bg: 'rgba(239,68,68,0.15)', color: '#ef4444' },
  CLEAN:     { bg: 'rgba(16,185,129,0.15)', color: '#10b981' },
  PREVIOUSLY_MALICIOUS: { bg: 'rgba(249,115,22,0.15)', color: '#f97316' },
  UNRATED:   { bg: 'rgba(100,116,139,0.15)', color: '#64748b' },
  'NO DATA': { bg: 'rgba(100,116,139,0.15)', color: '#64748b' },
}[v] ?? { bg: 'rgba(245,158,11,0.15)', color: '#f59e0b' });

function BulkUpload() {
  const [file, setFile]       = useState(null);
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState(null);
  const [error, setError]     = useState('');
  const [filter, setFilter]   = useState('all');
  const fileRef = useRef();

  const handleFile = (e) => {
    const selectedFile = e.target.files[0];
    if (selectedFile && selectedFile.name.endsWith('.csv')) {
      setFile(selectedFile); setError(''); setResults(null);
    } else {
      setError('Please upload a valid .csv file');
    }
  };

  const handleDrop = (e) => {
    e.preventDefault();
    const selectedFile = e.dataTransfer.files[0];
    if (selectedFile && selectedFile.name.endsWith('.csv')) {
      setFile(selectedFile); setError(''); setResults(null);
    } else {
      setError('Please upload a valid .csv file');
    }
  };

  const submit = async () => {
    if (!file) return;
    setLoading(true); setError(''); setResults(null);
    try {
      const form = new FormData();
      form.append('file', file);
      const res = await api.post('/bulk-investigate', form, {
        headers: { 'Content-Type': 'multipart/form-data' }
      });
      setResults(res.data);
    } catch (err) {
      setError('Upload failed — check backend connection');
    } finally {
      setLoading(false);
    }
  };

  const exportCSV = () => {
    if (!results) return;
    const headers = ['indicator','verdict','risk_score',
                     'times_seen','last_seen','investigation_id'];
    const rows = results.results.map(r =>
      headers.map(h =>
        `"${(r[h] ?? '').toString().replace(/"/g,'""')}"`
      ).join(',')
    );
    const csv = [headers.join(','), ...rows].join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href = url;
    a.download = `bulk_results_${Date.now()}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const filtered = results?.results?.filter(r => {
    if (filter === 'flagged') return r.risk_score >= 70;
    if (filter === 'clean')   return r.risk_score !== null && r.risk_score < 30;
    if (filter === 'nodata')  return r.status === 'not_found';
    return true;
  }) ?? [];

  const summary = results?.summary;

  return (
    <div style={{ minHeight:'100vh', background:'#0a0f1e', color:'#e2e8f0' }}>
      <div style={{ maxWidth:'1000px', margin:'0 auto', padding:'40px 24px' }}>

        <div style={{ marginBottom:'28px' }}>
          <h1 style={{ fontSize:'22px', fontWeight:'700',
                       color:'#f1f5f9', marginBottom:'6px' }}>
            Bulk IOC Analysis
          </h1>
          <p style={{ fontSize:'13px', color:'#64748b' }}>
            Upload a CSV with an <code style={{color:'#60a5fa'}}>ip</code>,{' '}
            <code style={{color:'#60a5fa'}}>url</code>, or{' '}
            <code style={{color:'#60a5fa'}}>indicator</code> column.
            System checks all entries against past investigations.
          </p>
        </div>

        {/* Drop zone */}
        <div
          onDrop={handleDrop}
          onDragOver={e => e.preventDefault()}
          onClick={() => fileRef.current.click()}
          style={{
            border: `2px dashed ${file ? '#3b82f6' : '#374151'}`,
            borderRadius:'12px', padding:'40px',
            textAlign:'center', cursor:'pointer',
            background: file ? 'rgba(59,130,246,0.05)' : '#111827',
            marginBottom:'16px', transition:'border-color .2s'
          }}
        >
          <input
            ref={fileRef} type="file"
            accept=".csv" onChange={handleFile}
            style={{ display:'none' }}
          />
          <div style={{ fontSize:'32px', marginBottom:'8px' }}>📂</div>
          <p style={{ fontSize:'14px', color: file ? '#60a5fa' : '#64748b' }}>
            {file ? file.name : 'Click or drag & drop a CSV file here'}
          </p>
          {file && (
            <p style={{ fontSize:'12px', color:'#475569', marginTop:'4px' }}>
              {(file.size / 1024).toFixed(1)} KB
            </p>
          )}
        </div>

        {/* Sample CSV hint */}
        <div style={{
          background:'#111827', border:'1px solid #1e293b',
          borderRadius:'8px', padding:'12px 16px',
          marginBottom:'16px', fontSize:'12px', color:'#475569'
        }}>
          <span style={{ color:'#64748b' }}>Sample CSV format: </span>
          <code style={{ color:'#60a5fa' }}>
            ip{'\n'}185.220.101.45{'\n'}8.8.8.8
          </code>
          <span style={{ color:'#64748b', marginLeft:'16px' }}>
            or column named <code style={{color:'#60a5fa'}}>url</code> or{' '}
            <code style={{color:'#60a5fa'}}>indicator</code>
          </span>
        </div>

        {error && (
          <div style={{
            marginBottom:'16px', padding:'12px 16px',
            borderRadius:'8px', background:'rgba(239,68,68,0.1)',
            border:'1px solid #7f1d1d', color:'#f87171', fontSize:'13px'
          }}>{error}</div>
        )}

        <div style={{ display:'flex', gap:'10px', marginBottom:'28px' }}>
          <button onClick={submit} disabled={!file || loading} style={{
            padding:'12px 28px', borderRadius:'12px',
            background: (!file || loading) ? '#1e293b' : '#2563eb',
            color:'white', fontWeight:'600', fontSize:'14px',
            border:'none', cursor: (!file || loading) ? 'not-allowed' : 'pointer'
          }}>
            {loading ? 'Analyzing...' : 'Analyze CSV'}
          </button>
          {results && (
            <button onClick={exportCSV} style={{
              padding:'12px 20px', borderRadius:'12px',
              background:'#1e293b', border:'1px solid #334155',
              color:'#94a3b8', fontSize:'13px', cursor:'pointer'
            }}>
              ⬇ Export Results CSV
            </button>
          )}
        </div>

        {results && (
          <div>
            {/* Summary cards */}
            <div style={{
              display:'grid', gridTemplateColumns:'repeat(4,1fr)',
              gap:'10px', marginBottom:'20px'
            }}>
              {[
                { label:'Total Processed', val:results.total_processed, color:'#60a5fa' },
                { label:'High Risk', val:summary.flagged_high_risk, color:'#ef4444' },
                { label:'Clean', val:summary.clean, color:'#10b981' },
                { label:'Needs Investigation', val:summary.needs_investigation, color:'#f59e0b' },
              ].map(({ label, val, color }) => (
                <div key={label} style={{
                  padding:'16px', borderRadius:'12px',
                  background:'#0d1526', border:'1px solid #1e293b'
                }}>
                  <p style={{ fontSize:'11px', color:'#64748b',
                               textTransform:'uppercase', letterSpacing:'.05em',
                               marginBottom:'6px' }}>{label}</p>
                  <p style={{ fontSize:'26px', fontWeight:'700', color }}>
                    {val}
                  </p>
                </div>
              ))}
            </div>

            {/* Filter tabs */}
            <div style={{ display:'flex', gap:'8px', marginBottom:'14px' }}>
              {[
                { key:'all',     label:`All (${results.total_processed})` },
                { key:'flagged', label:`High Risk (${summary.flagged_high_risk})` },
                { key:'clean',   label:`Clean (${summary.clean})` },
                { key:'nodata',  label:`No Data (${summary.no_data})` },
              ].map(({ key, label }) => (
                <button key={key} onClick={() => setFilter(key)} style={{
                  padding:'6px 14px', borderRadius:'8px', fontSize:'12px',
                  border: filter === key
                    ? '1px solid #3b82f6'
                    : '1px solid #374151',
                  background: filter === key
                    ? 'rgba(59,130,246,0.1)' : '#111827',
                  color: filter === key ? '#60a5fa' : '#64748b',
                  cursor:'pointer'
                }}>{label}</button>
              ))}
            </div>

            {/* Results table */}
            <div style={{
              background:'#0d1526', border:'1px solid #1e293b',
              borderRadius:'12px', overflow:'hidden'
            }}>
              <table style={{ width:'100%', borderCollapse:'collapse' }}>
                <thead>
                  <tr style={{ borderBottom:'1px solid #1e293b' }}>
                    {['Indicator','Verdict','Risk Score',
                      'Times Seen','MITRE','Last Seen'].map(h => (
                      <th key={h} style={{
                        padding:'12px 16px', textAlign:'left',
                        fontSize:'11px', color:'#64748b',
                        textTransform:'uppercase', letterSpacing:'.05em',
                        fontWeight:'500'
                      }}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {filtered.map((r, i) => {
                    const vs = verdictStyle(r.verdict);
                    return (
                      <tr key={i} style={{
                        borderBottom:'1px solid #111827',
                        background: i % 2 === 0
                          ? 'transparent' : 'rgba(255,255,255,0.01)'
                      }}>
                        <td style={{
                          padding:'12px 16px', fontSize:'13px',
                          color:'#60a5fa', fontFamily:'monospace'
                        }}>{r.indicator}</td>
                        <td style={{ padding:'12px 16px' }}>
                          <span style={{
                            fontSize:'11px', fontWeight:'700',
                            padding:'3px 10px', borderRadius:'20px',
                            background: vs.bg, color: vs.color
                          }}>{String(r.verdict).replace(/_/g, ' ')}</span>
                        </td>
                        <td style={{
                          padding:'12px 16px', fontSize:'14px',
                          fontWeight:'700',
                          color: riskColor(r.risk_score)
                        }}>
                          {r.risk_score !== null ? `${r.risk_score}/100` : '—'}
                        </td>
                        <td style={{
                          padding:'12px 16px', fontSize:'13px',
                          color: r.times_seen > 0 ? '#e2e8f0' : '#475569'
                        }}>
                          {r.times_seen > 0 ? `${r.times_seen}x` : '—'}
                        </td>
                        <td style={{ padding:'12px 16px' }}>
                          <div style={{ display:'flex', gap:'4px', flexWrap:'wrap' }}>
                            {r.mitre?.map((m, j) => (
                              <span key={j} style={{
                                fontSize:'10px', padding:'2px 6px',
                                borderRadius:'4px',
                                background:'rgba(59,130,246,0.1)',
                                color:'#60a5fa',
                                border:'1px solid rgba(59,130,246,0.2)'
                              }}>{m}</span>
                            ))}
                            {(!r.mitre || r.mitre.length === 0) && (
                              <span style={{ fontSize:'12px', color:'#475569' }}>—</span>
                            )}
                          </div>
                        </td>
                        <td style={{
                          padding:'12px 16px', fontSize:'12px',
                          color:'#475569'
                        }}>
                          {r.last_seen
                            ? new Date(r.last_seen).toLocaleDateString('en-GB', {
                                day:'2-digit', month:'short', year:'numeric'
                              })
                            : '—'}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

export default BulkUpload;
