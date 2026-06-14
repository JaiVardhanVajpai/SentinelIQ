// Shared verdict / severity color logic so every page stays consistent.

export function verdictTheme(verdict = '') {
  const v = String(verdict).toUpperCase();
  if (v.includes('MALICIOUS')) {
    return {
      text: 'text-red-400',
      bg: 'bg-red-500/10',
      ring: 'ring-red-500/40',
      solid: 'bg-red-600',
      bar: 'bg-red-500',
      label: v,
    };
  }
  if (v.includes('SUSPICIOUS') || v.includes('ANOMALY')) {
    return {
      text: 'text-amber-400',
      bg: 'bg-amber-500/10',
      ring: 'ring-amber-500/40',
      solid: 'bg-amber-500',
      bar: 'bg-amber-500',
      label: v,
    };
  }
  if (v.includes('CLEAN') || v.includes('NO ANOMALY') || v.includes('LOW RISK')) {
    return {
      text: 'text-green-400',
      bg: 'bg-green-500/10',
      ring: 'ring-green-500/40',
      solid: 'bg-green-600',
      bar: 'bg-green-500',
      label: v,
    };
  }
  return {
    text: 'text-gray-300',
    bg: 'bg-gray-500/10',
    ring: 'ring-gray-500/40',
    solid: 'bg-gray-600',
    bar: 'bg-gray-500',
    label: v || 'UNKNOWN',
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
