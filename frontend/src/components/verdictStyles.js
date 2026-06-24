// Shared verdict / severity color logic so every page stays consistent.

export function verdictTheme(verdict = '') {
  const v = String(verdict).toUpperCase();
  // Display label: underscores → spaces (e.g. PREVIOUSLY_MALICIOUS)
  const label = v.replace(/_/g, ' ');
  // NOTE: check PREVIOUSLY_MALICIOUS before MALICIOUS, since the
  // string contains "MALICIOUS" and would otherwise match red.
  if (v.includes('PREVIOUSLY')) {
    return {
      text: 'text-orange-400',      // #fb923c text on #f97316 family
      bg: 'bg-orange-500/10',
      ring: 'ring-orange-500/40',
      solid: 'bg-orange-600',
      bar: 'bg-orange-500',          // orange-500 = #f97316
      label,
    };
  }
  if (v.includes('MALICIOUS')) {
    return {
      text: 'text-red-400',
      bg: 'bg-red-500/10',
      ring: 'ring-red-500/40',
      solid: 'bg-red-600',
      bar: 'bg-red-500',
      label,
    };
  }
  if (v.includes('SUSPICIOUS') || v.includes('ANOMALY')) {
    return {
      text: 'text-amber-400',
      bg: 'bg-amber-500/10',
      ring: 'ring-amber-500/40',
      solid: 'bg-amber-500',
      bar: 'bg-amber-500',
      label,
    };
  }
  if (v.includes('CLEAN') || v.includes('NO ANOMALY') || v.includes('LOW RISK')) {
    return {
      text: 'text-green-400',
      bg: 'bg-green-500/10',
      ring: 'ring-green-500/40',
      solid: 'bg-green-600',
      bar: 'bg-green-500',
      label,
    };
  }
  if (v.includes('UNRATED')) {
    return {
      text: 'text-slate-400',        // slate family = #64748b
      bg: 'bg-slate-500/10',
      ring: 'ring-slate-500/40',
      solid: 'bg-slate-600',
      bar: 'bg-slate-500',           // slate-500 = #64748b
      label,
    };
  }
  return {
    text: 'text-gray-300',
    bg: 'bg-gray-500/10',
    ring: 'ring-gray-500/40',
    solid: 'bg-gray-600',
    bar: 'bg-gray-500',
    label: label || 'UNKNOWN',
  };
}

export function severityTheme(severity = '') {
  const s = String(severity).toUpperCase();
  if (s === 'CRITICAL') return 'bg-red-600 text-white';
  if (s === 'HIGH') return 'bg-orange-500 text-white';
  if (s === 'MEDIUM') return 'bg-amber-500 text-black';
  if (s === 'LOW') return 'bg-green-600 text-white';
  return 'bg-gray-600 text-white';
}

export function riskBarColor(score = 0) {
  const n = Number(score) || 0;
  if (n >= 75) return 'bg-red-500';
  if (n >= 50) return 'bg-orange-500';
  if (n >= 25) return 'bg-amber-500';
  return 'bg-green-500';
}
