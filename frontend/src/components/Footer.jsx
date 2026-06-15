import React from 'react';

function Footer() {
  return (
    <footer
      style={{
        borderTop: '0.5px solid #1e293b',
        background: '#0a0f1e',
        padding: '20px 24px',
        marginTop: 'auto'
      }}>
      <div
        style={{
          maxWidth: '1152px',
          margin: '0 auto',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          flexWrap: 'wrap',
          gap: '8px'
        }}>
        <p style={{
          fontSize: '12px',
          color: '#475569',
          margin: 0
        }}>
          © 2026 SentinelIQ — AI-Assisted SOC Triage Engine
        </p>
        <p style={{
          fontSize: '12px',
          color: '#475569',
          margin: 0
        }}>
          Built by{' '}
          <a
            href="https://github.com/JaiVardhanVajpai"
            target="_blank"
            rel="noopener noreferrer"
            style={{
              color: '#3b82f6',
              textDecoration: 'none'
            }}
            onMouseEnter={e =>
              e.target.style.textDecoration = 'underline'}
            onMouseLeave={e =>
              e.target.style.textDecoration = 'none'}>
            Jai Vardhan Vajpai
          </a>
          {' '}· BML Munjal University · B.Tech CSE 2027
        </p>
      </div>
    </footer>
  );
}

export default Footer;
