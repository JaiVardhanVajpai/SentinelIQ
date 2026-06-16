import React from 'react';
import { NavLink } from 'react-router-dom';

const links = [
  { to: '/', label: 'Investigate', end: true },
  { to: '/history', label: 'History', end: false },
  { to: '/dashboard', label: 'Dashboard', end: false },
  { to: '/hunt', label: 'Hunt', end: false },
  { to: '/bulk', label: 'Bulk Upload', end: false },
];

function Navbar() {
  const linkClass = ({ isActive }) =>
    [
      'px-4 py-2 rounded-md text-sm font-medium transition-all duration-200',
      isActive
        ? 'bg-blue-500/10 text-blue-400 ring-1 ring-blue-500/40'
        : 'text-gray-400 hover:text-white hover:bg-gray-800',
    ].join(' ');

  return (
    <nav className="sticky top-0 z-50 bg-gray-900/80 backdrop-blur border-b border-gray-800">
      <div className="max-w-7xl mx-auto px-6 h-16 flex items-center justify-between">
        {/* Logo */}
        <div className="flex items-center gap-3">
          <div className="relative">
            <div className="h-10 w-10 rounded-lg bg-gradient-to-br from-blue-500 to-blue-700 flex items-center justify-center font-bold text-xl shadow-lg shadow-blue-500/40">
              S
            </div>
            <span className="absolute inset-0 rounded-lg ring-2 ring-blue-400/30 animate-pulse" />
          </div>
          <div className="leading-tight">
            <div className="text-lg font-bold tracking-wide">
              Sentinel<span className="text-blue-400">IQ</span>
            </div>
            <div className="text-[10px] uppercase tracking-[0.2em] text-gray-500">
              SOC Triage Engine
            </div>
          </div>
        </div>

        {/* Links */}
        <div className="flex items-center gap-2">
          {links.map((l) => (
            <NavLink key={l.to} to={l.to} end={l.end} className={linkClass}>
              {l.label}
            </NavLink>
          ))}
        </div>

        {/* Version badge */}
        <div className="hidden sm:flex items-center gap-2">
          <span className="h-2 w-2 rounded-full bg-green-500 animate-pulse" />
          <span className="font-mono text-xs px-2 py-1 rounded border border-gray-700 text-gray-400">
            v4.0
          </span>
        </div>
      </div>
    </nav>
  );
}

export default Navbar;
